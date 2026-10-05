import Foundation
import Network
import NetworkExtension
import os

private let log = Logger(subsystem: ElliottIDs.filterBundleID, category: "filter")

/// Policy, verdicts, paused flows and the XPC link to the app. All state lives on `queue`, except `policy`,
/// which `handleNewFlow` reads synchronously under `policyLock`.
final class FilterService: NSObject, NSXPCListenerDelegate, FilterXPC {
    static let shared = FilterService()

    weak var provider: NEFilterDataProvider?

    private let queue = DispatchQueue(label: "elliott.filter")
    private let policyLock = OSAllocatedUnfairLock(initialState: FilterPolicy())
    private var listener: NSXPCListener?
    private var app: NSXPCConnection?
    private var outbox: [FlowEvent] = []         // batched for the app
    private var backlog: [FlowEvent] = []        // kept while no app is connected
    private var pending: [String: Pending] = [:] // paused flows by ConnectionKey.id

    private struct Pending {
        var flows: [NEFilterFlow]
        var request: ApprovalRequest
    }

    private let policyURL: URL = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("policy.json")
    }()

    override init() {
        super.init()
        if let data = try? Data(contentsOf: policyURL),
           let saved = try? JSONDecoder.elliott.decode(FilterPolicy.self, from: data) {
            policyLock.withLock { $0 = saved }
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 0.5, repeating: 0.5)
        timer.setEventHandler { [weak self] in self?.flush() }
        timer.resume()
        flushTimer = timer
    }
    private var flushTimer: DispatchSourceTimer?

    func startListening() {
        let l = NSXPCListener(machServiceName: ElliottIDs.machService)
        l.delegate = self
        l.resume()
        listener = l
    }

    // MARK: Verdicts

    func verdict(for flow: NEFilterSocketFlow) -> NEFilterNewFlowVerdict {
        guard var event = makeEvent(flow) else { return .allow() }
        if Self.isLoopback(event.remoteAddress) { return .allow() }

        // Our own traffic (LLM server, firewall API) never needs approval.
        if event.teamID == ElliottIDs.teamID && event.signingID == ElliottIDs.appBundleID { return .allow() }

        // System DNS always passes; its answers are read to learn IP → hostname.
        if event.appleSigned && event.signingID == "com.apple.mDNSResponder" && event.remotePort == 53 {
            if event.proto == .udp {
                return .filterDataVerdict(withFilterInbound: true, peekInboundBytes: 4096,
                                          filterOutbound: false, peekOutboundBytes: 0)
            }
            return .allow()
        }

        let policy = policyLock.withLock { $0 }
        if let rule = RuleBook.decide(event, rules: policy.rules) {
            event.ruleID = rule.id
            event.outcome = rule.verdict == .allow ? .allowed : .denied
            report(event)
            return rule.verdict == .allow ? .allow() : .drop()
        }
        if !policy.lockdown || (policy.trustAppleSigned && event.appleSigned) {
            event.outcome = .allowed
            report(event)
            return .allow()
        }

        // Lockdown and no rule: pause until the user answers.
        var connected = false
        queue.sync { connected = app != nil }
        guard connected else {
            event.outcome = .denied
            report(event)
            return .drop()
        }
        event.outcome = .pending
        report(event)
        queue.async { self.park(flow, event: event, timeout: policy.approvalTimeout) }
        return .pause()
    }

    private func park(_ flow: NEFilterFlow, event: FlowEvent, timeout: Double) {
        let key = event.key
        if var p = pending[key.id] {
            p.flows.append(flow)
            p.request.waiting = p.flows.count
            pending[key.id] = p
            return
        }
        let request = ApprovalRequest(key: key, event: event, waiting: 1, deadline: Date().addingTimeInterval(timeout))
        pending[key.id] = Pending(flows: [flow], request: request)
        if let data = try? JSONEncoder.elliott.encode(request) { appProxy?.approvalNeeded(data) }
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self, let p = self.pending[key.id], p.request.deadline == request.deadline else { return }
            log.info("approval timed out for \(key.id, privacy: .public)")
            self.finish(key.id, allow: false)
        }
    }

    private func finish(_ keyID: String, allow: Bool) {
        guard let p = pending.removeValue(forKey: keyID) else { return }
        for flow in p.flows {
            provider?.resumeFlow(flow, with: allow ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
        }
    }

    func providerStopped() {
        queue.async { for id in self.pending.keys { self.finish(id, allow: false) } }
    }

    // MARK: Events

    private func makeEvent(_ flow: NEFilterSocketFlow) -> FlowEvent? {
        guard let remote = Self.endpoint(flow.remoteFlowEndpoint) else { return nil }
        let local = Self.endpoint(flow.localFlowEndpoint)
        let identity = flow.sourceAppAuditToken.map(CodeIdentity.inspect) ?? CodeIdentity(path: "unknown")
        let proto: Proto = flow.socketProtocol == IPPROTO_TCP ? .tcp : flow.socketProtocol == IPPROTO_UDP ? .udp : .other
        var hostname = flow.remoteHostname ?? remote.host
        if hostname == nil { hostname = DNSCache.shared.name(for: remote.address) }
        return FlowEvent(pid: identity.pid, processPath: identity.path, signingID: identity.signingID,
                         teamID: identity.teamID, appleSigned: identity.appleSigned,
                         direction: flow.direction == .inbound ? .inbound : .outbound, proto: proto,
                         localAddress: local?.address, localPort: local?.port,
                         remoteAddress: remote.address, remotePort: remote.port,
                         remoteHostname: hostname, outcome: .allowed,
                         hostnameSource: hostname == nil ? nil : "filter")
    }

    /// (address, port, hostname if the endpoint is a name)
    private static func endpoint(_ ep: Network.NWEndpoint?) -> (address: String, port: Int, host: String?)? {
        guard case .hostPort(let host, let port)? = ep else { return nil }
        switch host {
        case .ipv4(let a): return ("\(a)", Int(port.rawValue), nil)
        case .ipv6(let a): return ("\(a)".components(separatedBy: "%")[0], Int(port.rawValue), nil)
        case .name(let n, _): return (n, Int(port.rawValue), n)
        @unknown default: return nil
        }
    }

    static func isLoopback(_ a: String) -> Bool {
        a.hasPrefix("127.") || a == "::1" || a == "localhost" || a.hasPrefix("::ffff:127.")
    }

    private func report(_ e: FlowEvent) {
        queue.async { self.outbox.append(e) }
    }

    private func flush() {
        guard !outbox.isEmpty else { return }
        let batch = outbox
        outbox.removeAll(keepingCapacity: true)
        if let proxy = appProxy, let data = try? JSONEncoder.elliott.encode(batch) {
            proxy.flowsSeen(data)
        } else {
            backlog.append(contentsOf: batch)
            if backlog.count > 5000 { backlog.removeFirst(backlog.count - 5000) }
        }
    }

    // MARK: XPC

    private var appProxy: AppXPC? {
        app?.remoteObjectProxyWithErrorHandler { error in log.error("app proxy: \(error.localizedDescription)") } as? AppXPC
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Only the Elliott app signed by our team may drive the filter.
        c.setCodeSigningRequirement(ElliottIDs.requirement(for: ElliottIDs.appBundleID))
        c.exportedInterface = NSXPCInterface(with: FilterXPC.self)
        c.exportedObject = self
        c.remoteObjectInterface = NSXPCInterface(with: AppXPC.self)
        c.invalidationHandler = { [weak self, weak c] in
            self?.queue.async { if self?.app === c { self?.app = nil } }
        }
        c.resume()
        queue.async { self.app = c }
        return true
    }

    func hello(reply: @escaping (Data) -> Void) {
        queue.async {
            let data = (try? JSONEncoder.elliott.encode(self.backlog)) ?? Data("[]".utf8)
            self.backlog.removeAll()
            reply(data)
            // Re-announce anything still waiting (the app may have restarted).
            for p in self.pending.values {
                if let d = try? JSONEncoder.elliott.encode(p.request) { self.appProxy?.approvalNeeded(d) }
            }
        }
    }

    func setPolicy(_ data: Data, reply: @escaping (Bool) -> Void) {
        guard let policy = try? JSONDecoder.elliott.decode(FilterPolicy.self, from: data) else { return reply(false) }
        policyLock.withLock { $0 = policy }
        try? data.write(to: policyURL, options: .atomic)
        // Leaving lockdown releases everything that was waiting.
        if !policy.lockdown { queue.async { for id in self.pending.keys { self.finish(id, allow: true) } } }
        reply(true)
    }

    func resolve(keyID: String, allow: Bool) {
        queue.async { self.finish(keyID, allow: allow) }
    }
}
