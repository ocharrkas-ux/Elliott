import AppKit
import Combine
import CryptoKit
import Foundation
import SystemConfiguration
import UserNotifications

struct AppSettings: Codable, Equatable {
    var lockdown = false
    var trustAppleSigned = true
    var approvalTimeout: Double = 60
    var llm = LLMSettings()
    var pan = PANSettings()
    var intel = IntelSettings()
    var suggestionsEnabled = true
    var edr = EDRSettings()
    var vuln = VulnSettings()
    var remediation = RemediationSettings()
    /// Read hostnames from DNS answers and TLS server names (needs the helper; root for packet capture).
    var captureNames = true
    var mesh = MeshSettings()
    var netscan = NetScanSettings()

    init() {}

    // Settings saved by older versions lack newer keys; fill those with defaults instead of failing.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = AppSettings()
        lockdown = try c.decodeIfPresent(Bool.self, forKey: .lockdown) ?? d.lockdown
        trustAppleSigned = try c.decodeIfPresent(Bool.self, forKey: .trustAppleSigned) ?? d.trustAppleSigned
        approvalTimeout = try c.decodeIfPresent(Double.self, forKey: .approvalTimeout) ?? d.approvalTimeout
        llm = try c.decodeIfPresent(LLMSettings.self, forKey: .llm) ?? d.llm
        pan = try c.decodeIfPresent(PANSettings.self, forKey: .pan) ?? d.pan
        intel = try c.decodeIfPresent(IntelSettings.self, forKey: .intel) ?? d.intel
        suggestionsEnabled = try c.decodeIfPresent(Bool.self, forKey: .suggestionsEnabled) ?? d.suggestionsEnabled
        edr = try c.decodeIfPresent(EDRSettings.self, forKey: .edr) ?? d.edr
        vuln = try c.decodeIfPresent(VulnSettings.self, forKey: .vuln) ?? d.vuln
        remediation = try c.decodeIfPresent(RemediationSettings.self, forKey: .remediation) ?? d.remediation
        captureNames = try c.decodeIfPresent(Bool.self, forKey: .captureNames) ?? d.captureNames
        mesh = try c.decodeIfPresent(MeshSettings.self, forKey: .mesh) ?? d.mesh
        netscan = try c.decodeIfPresent(NetScanSettings.self, forKey: .netscan) ?? d.netscan
    }
}

enum RuleScope: String, CaseIterable, Identifiable {
    case exact = "This destination and port"
    case host = "This destination, any port"
    case domain = "This domain and its subdomains"
    case app = "Everything this app does"
    case anyAppHost = "Any app → this destination"
    case anyAppDomain = "Any app → this domain and its subdomains"
    var id: String { rawValue }
    var label: String {
        switch self {
        case .exact: "dest + port"
        case .host: "any port"
        case .domain: "domain"
        case .app: "everything"
        case .anyAppHost: "any app → dest"
        case .anyAppDomain: "any app → domain"
        }
    }

    /// Domain scopes need an outbound connection to a hostname; "any app" scopes need an outbound connection.
    func applies(to p: Profile) -> Bool {
        switch self {
        case .exact, .host, .app: return true
        case .anyAppHost: return p.key.direction == .outbound
        case .domain, .anyAppDomain: return p.key.direction == .outbound && RuleScope.domain(of: p) != nil
        }
    }

    func title(for p: Profile) -> String {
        let d = RuleScope.domain(of: p).map { "*.\($0)" } ?? ""
        switch self {
        case .domain: return "This app → \(d)"
        case .anyAppHost: return "Any app → \(p.hostname ?? p.key.host)"
        case .anyAppDomain: return "Any app → \(d)"
        default: return rawValue
        }
    }

    /// The registrable domain of the destination ("github.com" for "api.github.com"); nil for IPs.
    static func domain(of p: Profile) -> String? {
        let host = p.hostname ?? p.key.host
        guard !RiskHeuristics.isIPLiteral(host), host.contains(".") else { return nil }
        return Advisor.registrableDomain(host)
    }
}

/// What the user asked to capture: an application, a destination (IP, FQDN or *.domain), or both.
struct CaptureTarget: Hashable {
    var appPath: String?
    var appName: String?
    var destination: String?
    var label: String { "\(appName ?? "any app") → \(destination ?? "anywhere")" }
    func covers(_ p: Profile) -> Bool {
        if let appPath, appPath != p.processPath { return false }
        if let destination {
            return Rule.hostMatches(destination, addresses: [], hostname: p.hostname, address: p.key.host)
                || p.addresses.contains(destination)
        }
        return true
    }
}

/// Who a rule covers and where it goes, chosen separately in the console.
struct RuleTarget: Hashable {
    enum Who: Hashable { case app, signer, anyApp }
    enum Dest: Hashable { case exact, fqdn, ip, domain, everywhere }
    var who: Who
    var dest: Dest

    /// Choices that make sense for this connection.
    static func whoOptions(_ p: Profile) -> [Who] {
        guard p.key.direction == .outbound else { return [.app] }   // inbound stays per app
        return p.signer.ruleKey != nil ? [.app, .signer, .anyApp] : [.app, .anyApp]
    }
    static func destOptions(_ p: Profile, who: Who) -> [Dest] {
        var d: [Dest] = p.key.direction == .outbound ? [.exact] : [.exact, .ip]
        if p.key.direction == .outbound {
            if let h = p.hostname, !RiskHeuristics.isIPLiteral(h) { d.append(.fqdn) }
            if RiskHeuristics.isIPLiteral(p.key.host) || !p.addresses.isEmpty { d.append(.ip) }
            if RuleScope.domain(of: p) != nil { d.append(.domain) }
        }
        if who == .app { d.append(.everywhere) }   // "everything" for a signer or any app is too broad here
        return d
    }

    static func whoTitle(_ w: Who, _ p: Profile) -> String {
        switch w {
        case .app: "Only \(p.appName)"
        case .signer: "Apps signed by \(p.signer.display)"
        case .anyApp: "Any app"
        }
    }
    static func destTitle(_ d: Dest, _ p: Profile) -> String {
        switch d {
        case .exact: "\(p.destination) on port \(p.key.port) only"
        case .fqdn: "\(p.hostname ?? "") (any port)"
        case .ip: "\(ip(p)) (any port)"
        case .domain: "*.\(RuleScope.domain(of: p) ?? "") (any port)"
        case .everywhere: p.key.direction == .outbound ? "Any destination" : "Anyone, any port"
        }
    }
    static func ip(_ p: Profile) -> String {
        RiskHeuristics.isIPLiteral(p.key.host) ? p.key.host : (p.addresses.first ?? p.key.host)
    }

    var label: String {
        let w = switch who { case .app: "app"; case .signer: "signer"; case .anyApp: "any app" }
        let d = switch dest { case .exact: "dest + port"; case .fqdn: "fqdn"; case .ip: "ip"; case .domain: "domain"; case .everywhere: "everything" }
        return "\(w) → \(d)"
    }
}

extension RuleScope {
    var target: RuleTarget {
        switch self {
        case .exact: RuleTarget(who: .app, dest: .exact)
        case .host: RuleTarget(who: .app, dest: .ip)
        case .domain: RuleTarget(who: .app, dest: .domain)
        case .app: RuleTarget(who: .app, dest: .everywhere)
        case .anyAppHost: RuleTarget(who: .anyApp, dest: .fqdn)
        case .anyAppDomain: RuleTarget(who: .anyApp, dest: .domain)
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var profiles: [String: Profile] = [:]
    @Published private(set) var recent: [FlowEvent] = []          // live log, newest first
    @Published private(set) var rules: [Rule] = []
    @Published var settings = AppSettings() { didSet { if settings != oldValue { settingsChanged(oldValue) } } }
    @Published private(set) var approvals: [ApprovalRequest] = []
    @Published private(set) var analyzingID: String?
    @Published private(set) var suggestingID: String?
    @Published private(set) var decisions: [Decision] = []
    @Published private(set) var intel: [String: IPIntel] = [:]
    @Published private(set) var intelRefreshing = false
    @Published private(set) var intelRevision = 0
    @Published var section: MainSection = .console
    @Published private(set) var findings: [Finding] = []
    /// Processes live in their own store: they change every few seconds, and only the Processes table shows them.
    let processStore = ProcessStore()
    var processes: [ProcInfo] { processStore.list }
    @Published private(set) var launchItems: [LaunchItem] = []
    @Published private(set) var triagingID: UUID?
    @Published private(set) var vulnFindings: [VulnFinding] = []
    @Published private(set) var components: [Component] = []
    @Published private(set) var vulnScanning = false
    @Published private(set) var vulnProgress: (String, Double) = ("", 0)
    @Published private(set) var vulnErrors: [String] = []
    @Published private(set) var reachJudgingID: String?
    @Published private(set) var remediations: [RemediationRecord] = []
    @Published private(set) var remediating = false
    @Published private(set) var remediationLog: [String] = []
    @Published var nvdKey: String = Keychain.get("nvd-api-key") ?? "" {
        didSet { Keychain.set(nvdKey, for: "nvd-api-key") }
    }   // bumps when feeds reload, for the settings view
    @Published private(set) var llmStatus = "Waiting for connections"
    @Published private(set) var syncReport: SyncReport?
    @Published private(set) var syncing = false
    @Published var panKey: String = Keychain.get("pan-api-key") ?? "" {
        didSet { Keychain.set(panKey, for: "pan-api-key") }
    }

    let filter = FilterClient()
    let helper = HelperClient()
    private let passive = PassiveMonitor()
    private var analysisQueue: [String] = []
    private var analysisFailures: [String: Int] = [:]
    private var suggestQueue: [String] = []
    private var onlineQueue: [String] = []
    private var onlineTask: Task<Void, Never>?
    private var notifiedBad: Set<String> = []
    private(set) lazy var threatIntel = ThreatIntel(directory: dir)
    let edr = EDRMonitor()
    private var triageQueue: [UUID] = []
    @Published private(set) var pcaps: [PcapStatus] = []
    private var activeCaptures: [UUID: (target: CaptureTarget, spec: PcapSpec)] = [:]
    private var capturePoller: Task<Void, Never>?
    private var wireCursor: Double = 0
    private var wireSeen: [String: Date] = [:]
    private var identityCache: [String: (String?, String?, Bool)] = [:]
    nonisolated let processCache = ProcessSnapshotCache()
    /// Detections the user marked benign and then cleared: they stay silenced.
    private var suppressedFindingKeys: Set<String> = []
    private var reachQueue: [String] = []
    private let jobs = BackgroundJobs()
    let names = NameResolver()
    @Published private(set) var nameCapture: (active: Bool, interfaces: [String]) = (false, [])
    @Published private(set) var captureIsolation: (unprivileged: Bool?, sandboxed: Bool?) = (nil, nil)
    @Published private(set) var unsolicitedDNS = 0
    private var reportedUnsolicited = 0
    private var helperCaptureOn = false
    /// New TLS connections wait briefly for their ClientHello's server name before being filed.
    private var heldForName: [(event: FlowEvent, deadline: Date)] = []
    private var nameTask: Task<Void, Never>?
    static let intelInterval: TimeInterval = 3 * 3600
    static let exploitInterval: TimeInterval = 3 * 3600
    /// Findings first seen in the most recent scan (not on the first scan ever).
    @Published private(set) var newVulnIDs: Set<String> = []
    @Published private(set) var exploitChecking = false
    private(set) lazy var vulnDB = VulnDB(directory: dir)
    private var edrBaseline: [String] = []
    private var analysisTask: Task<Void, Never>?
    private var saveTask: Task<Void, Never>?
    private var syncTask: Task<Void, Never>?
    private var bag: Set<AnyCancellable> = []
    private let dir: URL

    enum Backend { case filter, packetFilter, none }
    /// The Network Extension filter (per-app, if this build has it) wins; else the pf helper; else observe only.
    var backend: Backend { filter.connected ? .filter : helper.connected ? .packetFilter : .none }
    var enforcing: Bool { backend != .none }
    /// Only the ElliottNE build (paid developer team) is entitled to run the content-filter system extension.
    let hasFilterExtension: Bool = {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        let value = SecTaskCopyValueForEntitlement(task, "com.apple.developer.networking.networkextension" as CFString, nil)
        return (value as? [String])?.isEmpty == false
    }()

    /// Unit tests run inside the app (it's their host). They must not read or write the user's data, start
    /// monitors, talk to the helper or run scheduled jobs.
    static let isTestHost = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil


    init() {
        if Self.isTestHost {
            dir = FileManager.default.temporaryDirectory.appendingPathComponent("ElliottTestHost-\(UUID().uuidString)", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return
        }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = support.appendingPathComponent("Elliott", isDirectory: true)
        // Data saved while the app was called Bastion moves over once.
        let legacy = support.appendingPathComponent("Bas" + "tion", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path), FileManager.default.fileExists(atPath: legacy.path) {
            try? FileManager.default.moveItem(at: legacy, to: dir)
        }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        load()

        filter.onEvents = { [weak self] in self?.ingest($0) }
        filter.onApproval = { [weak self] in self?.approvalArrived($0) }
        filter.onConnected = { [weak self] in self?.pushPolicy() }
        helper.onConnected = { [weak self] in self?.pushPolicy() }
        helper.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &bag)
        filter.$connected.removeDuplicates().sink { [weak self] connected in
            guard let self else { return }
            if connected { self.passive.stop() } else { self.startPassive(); self.pushPolicy() }
        }.store(in: &bag)
        filter.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &bag)

        Timer.publish(every: 1, on: .main, in: .common).autoconnect().sink { [weak self] now in
            // Only touch the published list when something expired: every change re-renders the window.
            guard let self, self.approvals.contains(where: { $0.deadline < now }) else { return }
            self.approvals.removeAll { $0.deadline < now }
        }.store(in: &bag)
        Timer.publish(every: 30, on: .main, in: .common).autoconnect().sink { [weak self] now in
            guard let self, self.rules.contains(where: { ($0.expires ?? .distantFuture) < now }) else { return }
            self.rules.removeAll { ($0.expires ?? .distantFuture) < now }
            self.rulesChanged(syncFirewall: false)
        }.store(in: &bag)

        startEDR()
        // Scheduled checks. NSBackgroundActivityScheduler runs them at good moments (power, idle) and catches up after
        // sleep; a wake observer adds a prompt catch-up once the network is back.
        jobs.every("intel", interval: Self.intelInterval) { [weak self] in await self?.refreshIntel(maxAge: Self.intelInterval) }
        jobs.every("exploits", interval: Self.exploitInterval) { [weak self] in await self?.refreshExploitSignals() }
        jobs.every("scan", interval: 3600) { [weak self] in self?.autoScanIfDue() }
        jobs.every("netscan", interval: 3600) { [weak self] in
            guard let self, self.netScanDue() else { return }
            await self.runNetworkScan()
        }
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didWakeNotification).sink { [weak self] _ in
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(30))
                await self?.runDueChecks()
            }
        }.store(in: &bag)
        Task { try? await Task.sleep(for: .seconds(20)); await runDueChecks() }
        startNameCapture()
        setUpMesh()

        if hasFilterExtension { Task { await filter.refresh() } }
        helper.start()
        analysisQueue = profiles.values.filter { $0.analysis == nil }.sorted { $0.lastSeen > $1.lastSeen }.map(\.id)
        pumpAnalysis()
    }

    private func startPassive() {
        passive.start { [weak self] events in
            Task { @MainActor in
                guard let self else { return }
                // Already reported (with its exact start) by connection capture.
                self.ingest(events.filter { self.wireSeen[Self.wireKey($0)] == nil })
            }
        }
    }

    // MARK: Connections

    func ingest(_ events: [FlowEvent]) {
        var ready: [FlowEvent] = []
        for var e in events {
            guard e.remoteHostname == nil, e.direction == .outbound, IPv4Set.isGlobal(e.remoteAddress) else { ready.append(e); continue }
            if annotate(&e) { ready.append(e); continue }
            // No name yet: a brand-new TLS connection's server name is usually a moment away.
            if nameCapture.active, e.outcome == .observed, e.proto == .tcp, e.preexisting != true,
               SNIAssembler.tlsPorts.contains(e.remotePort) {
                heldForName.append((e, Date().addingTimeInterval(4)))
            } else {
                ready.append(e)
            }
        }
        if !ready.isEmpty { commit(ready) }
    }

    /// Attaches a hostname only when the evidence belongs to this connection (see NameResolver). True if named.
    private func annotate(_ e: inout FlowEvent) -> Bool {
        e.nameChecked = names.coveredByCapture(observed: e.date, preexisting: e.preexisting == true) ? true : nil
        guard let m = names.resolve(remoteIP: e.remoteAddress, remotePort: e.remotePort, localPort: e.localPort,
                                    observed: e.date, preexisting: e.preexisting == true) else { return false }
        e.remoteHostname = m.name
        e.hostnameSource = m.source.rawValue
        e.alternativeNames = m.alternatives.isEmpty ? nil : m.alternatives
        return true
    }

    private func releaseHeld(force: Bool = false) {
        guard !heldForName.isEmpty else { return }
        let now = Date()
        var ready: [FlowEvent] = []
        heldForName.removeAll { item in
            var e = item.event
            if annotate(&e) || force || item.deadline <= now { ready.append(e); return true }
            return false
        }
        if !ready.isEmpty { commit(ready) }
    }

    private func startNameCapture() {
        nameTask?.cancel()
        nameTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollNames()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// Connections seen on the wire with their process (helper pktap capture): catches ones that start and finish
    /// between two nettop samples.
    private func pollConnections() async {
        guard let list = await helper.connections(since: wireCursor), !list.isEmpty else { return }
        wireCursor = list.map(\.received).max() ?? wireCursor
        scheduleSave()   // a restart must not re-ingest these
        var events: [FlowEvent] = []
        for c in list {
            // The sampler may have caught it first.
            if recent.prefix(400).contains(where: { $0.localPort == c.localPort && $0.remoteAddress == c.remoteIP
                && $0.remotePort == c.remotePort && abs($0.date.timeIntervalSince1970 - c.time) < 30 }) { continue }
            let path = c.path ?? c.name
            let (sid, team, apple) = await codeIdentity(path)
            var e = FlowEvent(pid: c.pid, processPath: path, signingID: sid, teamID: team, appleSigned: apple,
                              direction: c.outbound ? .outbound : .inbound, proto: c.tcp ? .tcp : .udp,
                              localAddress: c.localIP, localPort: c.localPort,
                              remoteAddress: c.remoteIP, remotePort: c.remotePort, remoteHostname: nil, outcome: .observed)
            e.date = Date(timeIntervalSince1970: c.time)
            events.append(e)
            wireSeen[Self.wireKey(e)] = Date()
        }
        if wireSeen.count > 20_000 { wireSeen = wireSeen.filter { Date().timeIntervalSince($0.value) < 600 } }
        if !events.isEmpty { ingest(events) }
    }

    nonisolated static func wireKey(_ e: FlowEvent) -> String {
        "\(e.proto.rawValue)|\(e.localPort ?? 0)|\(e.remoteAddress)|\(e.remotePort)"
    }

    /// Code-signing identity of a program (cached; checked off the main thread).
    private func codeIdentity(_ path: String) async -> (String?, String?, Bool) {
        if let hit = identityCache[path] { return hit }
        let id = await Task.detached { PassiveMonitor.staticIdentity(path) }.value
        identityCache[path] = id
        return id
    }

    private func pollNames() async {
        let want = settings.captureNames && helper.connected
        if want != helperCaptureOn || (want && !nameCapture.active) {
            helperCaptureOn = await helper.setNameCapture(want) && want
        }
        guard want, let batch = await helper.names(since: names.cursor) else {
            if nameCapture.active { nameCapture = (false, []) }
            releaseHeld(force: true)
            return
        }
        names.ingest(batch)
        if nameCapture.active != batch.capturing || nameCapture.interfaces != batch.interfaces {
            nameCapture = (batch.capturing, batch.interfaces)
        }
        if captureIsolation.unprivileged != batch.privilegesDropped || captureIsolation.sandboxed != batch.sandboxed {
            captureIsolation = (batch.privilegesDropped, batch.sandboxed)
        }
        await pollConnections()
        for s in batch.sni { checkNameMismatch(s) }
        if let u = batch.unsolicitedDNS, u != unsolicitedDNS { unsolicitedDNS = u; reportUnsolicitedDNS() }
        releaseHeld()
    }

    /// A connection labelled from DNS whose own TLS handshake names a different server: the DNS answer didn't
    /// describe this connection (spoofed, or another lookup for a shared IP). Revoke the IP from allow rules for the
    /// DNS name that the server name doesn't satisfy, and record a detection.
    private func checkNameMismatch(_ s: SNIObservation) {
        guard let e = recent.first(where: { $0.localPort == s.localPort && $0.remoteAddress == s.remoteIP && $0.remotePort == s.remotePort
                                              && abs($0.date.timeIntervalSince1970 - s.time) < 300 }),
              let dnsName = e.remoteHostname, dnsName != s.name,
              e.hostnameSource == NameSource.dns.rawValue || e.hostnameSource == NameSource.dnsAmbiguous.rawValue,
              !(e.alternativeNames ?? []).contains(s.name) else { return }
        var revoked: [String] = []
        for i in rules.indices where rules[i].verdict == .allow && rules[i].addresses.contains(s.remoteIP)
            && rules[i].host != "*" && !RiskHeuristics.isIPLiteral(rules[i].host)
            && !Rule.hostMatches(rules[i].host, addresses: [], hostname: s.name, address: "") {
            rules[i].addresses.removeAll { $0 == s.remoteIP }
            revoked.append(rules[i].host)
        }
        if !revoked.isEmpty { rulesChanged(syncFirewall: false) }
        let app = (e.processPath as NSString).lastPathComponent
        observe([Observation(
            key: "net.name-mismatch|\(e.processPath)|\(dnsName)|\(s.name)",
            draft: Draft(rule: "net.name-mismatch", title: "TLS server name didn't match the DNS name",
                         detail: "\(app) connected to \(s.remoteIP), which DNS said was \(dnsName), but the connection's own TLS handshake asked for \(s.name). Either the DNS answer was forged, or the address is shared and another lookup was mistaken for this one." + (revoked.isEmpty ? "" : " Elliott removed \(s.remoteIP) from the allow rule\(revoked.count == 1 ? "" : "s") for \(revoked.joined(separator: ", ")) so it isn't trusted on the strength of that DNS answer."),
                         severity: revoked.isEmpty ? .low : .medium, category: .network, mitre: ["T1557"],
                         evidence: ["DNS name: \(dnsName)", "TLS server name: \(s.name)", "remote \(s.remoteIP):\(s.remotePort), local port \(s.localPort)"]),
            path: e.processPath)])
    }

    private func reportUnsolicitedDNS() {
        guard unsolicitedDNS - reportedUnsolicited >= 20 else { return }
        reportedUnsolicited = unsolicitedDNS
        observe([Observation(
            key: "net.dns-unsolicited",
            draft: Draft(rule: "net.dns-unsolicited", title: "DNS answers that no query asked for",
                         detail: "\(unsolicitedDNS) DNS answers arrived that matched no query this Mac sent (wrong transaction ID, port, server or question). Elliott ignores them. A steady stream suggests someone on the network is trying to forge DNS answers.",
                         severity: .medium, category: .network, mitre: ["T1557.002"],
                         evidence: ["\(unsolicitedDNS) unsolicited answers since capture started", "interfaces: \(nameCapture.interfaces.joined(separator: ", "))"]))])
    }

    private func commit(_ events: [FlowEvent]) {
        let pfLockdown = backend == .packetFilter && settings.lockdown
        var events = events
        for i in events.indices where events[i].outcome == .pending && !pfLockdown && backend != .filter {
            events[i].outcome = .observed   // a handshake in progress, not one we're holding
        }
        var newIPs: Set<String> = []
        for e in events {
            let id = e.key.id
            if intel[e.remoteAddress] == nil { newIPs.insert(e.remoteAddress) }
            if profiles[id] == nil {
                profiles[id] = Profile(event: e)
                analysisQueue.append(id)
            } else {
                profiles[id]!.absorb(e)
            }
            if pfLockdown && e.outcome == .pending { heldByPacketFilter(e) }
        }
        if !newIPs.isEmpty { assess(newIPs) }
        recent.insert(contentsOf: events.reversed(), at: 0)
        if recent.count > 2000 { recent.removeLast(recent.count - 2000) }
        pumpAnalysis()
        scheduleSave()
    }

    /// pf lockdown is holding this handshake. Learn the IP for an existing allow rule, auto-allow trusted Apple
    /// software, or ask the user.
    private func heldByPacketFilter(_ e: FlowEvent) {
        if e.teamID == ElliottIDs.teamID && e.signingID == ElliottIDs.appBundleID {
            // Elliott's own traffic (threat feeds, firewall API): never ask about it.
            var r = Rule(key: e.key, appName: "Elliott", verdict: .allow, addresses: [e.remoteAddress])
            r.note = "Elliott's own traffic"
            rules.append(r)
            rulesChanged(syncFirewall: false)
            return
        }
        if let rule = RuleBook.decide(e, rules: rules) {
            guard rule.verdict == .allow, let i = rules.firstIndex(where: { $0.id == rule.id }),
                  !rules[i].addresses.contains(e.remoteAddress) else { return }
            rules[i].addresses.append(e.remoteAddress)
            rulesChanged(syncFirewall: false)
            return
        }
        if settings.trustAppleSigned && e.appleSigned {
            var r = Rule(key: e.key, appName: e.processName, verdict: .allow, addresses: [e.remoteAddress])
            r.note = "Automatically allowed: Apple-signed"
            rules.append(r)
            rulesChanged()
            return
        }
        guard !approvals.contains(where: { $0.id == e.key.id }) else { return }
        approvalArrived(ApprovalRequest(key: e.key, event: e, waiting: 1,
                                        deadline: Date().addingTimeInterval(settings.approvalTimeout)))
    }

    func decision(for p: Profile) -> Rule? { RuleBook.decide(p.sampleEvent, rules: rules) }

    var unclassifiedCount: Int { profiles.values.filter { decision(for: $0) == nil }.count }
    var analyzedCount: Int { profiles.values.filter { $0.analysis != nil }.count }

    // MARK: Classification

    func classify(_ p: Profile, _ verdict: Verdict, scope: RuleScope = .exact, expires: Date? = nil,
                  record source: Decision.Source? = .manual) {
        classify(p, verdict, target: scope.target, label: scope.label, expires: expires, record: source)
    }

    func classify(_ p: Profile, _ verdict: Verdict, target: RuleTarget, label: String? = nil, expires: Date? = nil,
                  record source: Decision.Source? = .manual) {
        if let source { record(Decision(profile: p, verdict: verdict, source: source, scope: label ?? target.label)) }
        let outbound = p.key.direction == .outbound
        // anyAppHost used to fall back to the IP when there was no hostname; keep that for "fqdn".
        let host: String = switch target.dest {
        case .exact: p.key.host
        case .fqdn: p.hostname ?? p.key.host
        case .ip: RuleTarget.ip(p)
        case .domain: "*.\(RuleScope.domain(of: p) ?? p.key.host)"
        case .everywhere: "*"
        }
        var rule = Rule(appKey: target.who == .app ? p.key.appKey : "*",
                        appName: target.who == .app ? p.appName : target.who == .signer ? p.signer.display : "any app",
                        direction: p.key.direction, proto: target.dest == .exact ? p.key.proto : nil, host: host,
                        port: target.dest == .exact || !outbound ? (target.dest == .everywhere ? nil : p.key.port) : nil,
                        verdict: verdict, addresses: target.dest == .everywhere || target.dest == .ip ? [] : p.addresses)
        if target.who == .signer, let key = p.signer.ruleKey { rule.signer = key }
        rule.note = p.analysis?.description
        rule.expires = expires
        if target.who == .app && target.dest == .everywhere && backend == .packetFilter { rule.addresses = p.addresses }   // pf needs addresses
        rules.removeAll { $0.appKey == rule.appKey && $0.signer == rule.signer && $0.direction == rule.direction
            && $0.proto == rule.proto && $0.host == rule.host && $0.port == rule.port }
        rules.append(rule)
        rulesChanged()
        resolveAddresses(for: rule)
    }

    /// "example.com" or "*.example.com" (the wildcard also covers example.com itself). Nil if it isn't a usable pattern.
    nonisolated static func normalizedDomainPattern(_ input: String) -> String? {
        let s = input.trimmingCharacters(in: .whitespaces).lowercased()
            .replacingOccurrences(of: #"^https?://"#, with: "", options: .regularExpression)
            .replacingOccurrences(of: #"/.*$"#, with: "", options: .regularExpression)
        let wildcard = s.hasPrefix("*.")
        let host = wildcard ? String(s.dropFirst(2)) : s
        guard host.range(of: #"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"#, options: .regularExpression) != nil else { return nil }
        // A wildcard over a bare public suffix ("*.com", "*.co.uk", shared hosting) would cover half the internet.
        // Narrower ones ("*.api.github.com") are fine.
        let labels = host.split(separator: ".")
        if wildcard, labels.count == 2, labels[0].count <= 3, labels[1].count == 2,
           ["co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"].contains(String(labels[0])) { return nil }
        if wildcard, ["co.uk", "com.au", "co.jp", "com.br", "co.nz", "github.io", "herokuapp.com", "cloudfront.net",
                      "amazonaws.com", "azurewebsites.net", "appspot.com", "blogspot.com"].contains(host) { return nil }
        return wildcard ? "*." + host : host
    }

    /// Allows (or blocks) a domain pattern for any app or one app, typed by the user in the rules view.
    @discardableResult
    func addDomainRule(_ input: String, verdict: Verdict, appKey: String = "*", appName: String = "any app") -> Bool {
        guard let pattern = Self.normalizedDomainPattern(input) else { return false }
        var rule = Rule(appKey: appKey, appName: appName, direction: .outbound, proto: nil, host: pattern, port: nil, verdict: verdict)
        rule.note = "Domain rule added by you"
        // Addresses this Mac already saw for names under the pattern (the packet filter needs IPs).
        rule.addresses = Array(Set(profiles.values.filter { p in
            p.key.direction == .outbound && Rule.hostMatches(pattern, addresses: [], hostname: p.hostname ?? p.key.host, address: "")
        }.flatMap(\.addresses)))
        rules.removeAll { $0.appKey == appKey && $0.direction == .outbound && $0.host == pattern && $0.port == nil && $0.proto == nil }
        rules.append(rule)
        record(Decision(rule: rule, verdict: verdict, source: .manual))
        rulesChanged()
        resolveAddresses(for: rule)
        return true
    }

    // MARK: LLM server identity

    @Published private(set) var llmServer: LLMServerIdentity?
    @Published private(set) var llmServerIssue: String?
    private var llmCheckedAt = Date.distantPast
    private var llmIssueNotified: LLMServerIdentity?

    /// True if the program on the LLM port is the one pinned on first use (or nothing is listening).
    func checkLLMServer(force: Bool = false) async -> Bool {
        if !force, Date().timeIntervalSince(llmCheckedAt) < 60 { return llmServerIssue == nil }
        llmCheckedAt = Date()
        let port = settings.llm.port
        let current = await Task.detached(priority: .utility) { LLMServerIdentity.listening(on: port) }.value
        llmServer = current
        guard let current else { llmServerIssue = nil; return true }   // nothing listening: requests just fail
        guard let pinned = settings.llm.pinnedServer else {
            settings.llm.pinnedServer = current                           // trust on first use
            llmServerIssue = nil
            return true
        }
        if pinned == current { llmServerIssue = nil; return true }
        llmServerIssue = "A different program is answering on the LLM port \(port): \(current.path) (\(current.signer)), not the one Elliott trusted (\(pinned.path)). LLM analysis is paused until you approve it in Settings → Local LLM."
        if llmIssueNotified != current {
            llmIssueNotified = current
            notify(id: "llm-\(current.cdhash)", title: "LLM server changed", body: llmServerIssue!, critical: true)
        }
        return false
    }

    func trustCurrentLLMServer() {
        guard let s = llmServer else { return }
        settings.llm.pinnedServer = s
        llmServerIssue = nil
        pumpAnalysis()
    }

    /// Removes the rule that currently decides this profile.
    /// Signer rules in force ("apple" or team ID → rule).
    func signerRule(_ key: String) -> Rule? { rules.first { $0.signer == key && $0.host == "*" && $0.direction == .outbound && $0.expires == nil } }

    /// Allows (or blocks) outbound connections for every app with a verified signature from this developer.
    /// Inbound stays per-app: trusting a developer shouldn't open listening ports.
    func setSignerTrust(_ s: SignerInfo, _ verdict: Verdict?) {
        guard let key = s.ruleKey else { return }
        rules.removeAll { $0.signer == key && $0.host == "*" }   // signer → specific destination rules stay
        if let verdict {
            let known = profiles.values.filter { $0.key.direction == .outbound && $0.signer.ruleKey == key }.flatMap(\.addresses)
            var r = Rule(appKey: "*", appName: s.display, direction: .outbound, proto: nil, host: "*", port: nil,
                         verdict: verdict, addresses: Array(Set(known)))
            r.signer = key
            r.note = verdict == .allow ? "Trusted signer\(s.teamID.map { " (team \($0))" } ?? "")" : "Blocked signer"
            rules.append(r)
            record(Decision(rule: r, verdict: verdict, source: .manual))
        }
        rulesChanged()
    }

    /// Accepts Elliott's suggestion for these profiles.
    func acceptSuggestions(_ ids: [String]) {
        for id in ids {
            guard let p = profiles[id], let s = p.suggestion else { continue }
            classify(p, s.verdict, record: .suggestion)
        }
    }

    func unclassify(_ p: Profile) {
        guard let r = decision(for: p) else { return }
        removeRules([r.id])
    }

    func removeRules(_ ids: Set<UUID>) {
        rules.removeAll { ids.contains($0.id) }
        rulesChanged()
    }

    /// Flips existing rules to `verdict` (a temporary "allow once" becomes permanent when changed).
    func setVerdict(_ ids: Set<UUID>, _ verdict: Verdict) {
        var changed = false
        for i in rules.indices where ids.contains(rules[i].id) && rules[i].verdict != verdict {
            let covered = profiles.values.first { decision(for: $0)?.id == rules[i].id }
            record(covered.map { Decision(profile: $0, verdict: verdict, source: .edit, scope: rules[i].scopeLabel) }
                   ?? Decision(rule: rules[i], verdict: verdict, source: .edit))
            rules[i].verdict = verdict
            rules[i].expires = nil
            changed = true
        }
        if changed { rulesChanged() }
    }

    /// The profiles each rule currently decides (a profile counts only for the rule that wins for it).
    func coverage() -> [UUID: [Profile]] {
        var out: [UUID: [Profile]] = [:]
        for p in profiles.values { if let r = decision(for: p) { out[r.id, default: []].append(p) } }
        return out
    }

    func allowUnclassified(maxRisk: Int) -> Int {
        let picks = profiles.values.filter { decision(for: $0) == nil && $0.riskScore <= maxRisk }
        for p in picks {
            rules.append(Rule(key: p.key, appName: p.appName, verdict: .allow, addresses: p.addresses))
        }
        if !picks.isEmpty { rulesChanged() }
        return picks.count
    }

    func forget(_ ids: Set<String>) {
        for id in ids { profiles[id] = nil }
        analysisQueue.removeAll { ids.contains($0) }
        suggestQueue.removeAll { ids.contains($0) }
        scheduleSave()
    }

    /// Erases the record of observed connections (profiles, their descriptions and suggestions, and the live log).
    /// Rules, the decision history, EDR detections, vulnerabilities and threat-intel caches are kept; connections that
    /// happen again are profiled from scratch.
    func clearConnections() {
        profiles.removeAll()
        recent.removeAll()
        analysisQueue.removeAll()
        suggestQueue.removeAll()
        heldForName.removeAll()
        notifiedBad.removeAll()
        scheduleSave()
    }

    func clearLiveLog() { recent.removeAll() }

    // MARK: Packet capture

    /// Starts recording an application's packets, a destination's, or an application's to a destination.
    /// `destination` is an IP, an FQDN or "*.domain"; names are resolved and refreshed while recording.
    func startCapture(_ t: CaptureTarget, minutes: Int = 60, maxMB: Int = 200) async -> String? {
        var spec = await captureSpec(t, id: UUID())
        spec.maxSeconds = max(1, minutes) * 60
        spec.maxBytes = max(1, maxMB) * 1024 * 1024
        if t.destination != nil && !spec.hasDestination {
            return "Elliott doesn't know any addresses for \(t.destination!) yet."
        }
        guard spec.isValid else { return "Choose an application, a destination, or both." }
        if let err = await helper.startPcap(spec) { return err }
        activeCaptures[spec.id] = (t, spec)
        await refreshCaptures()
        startCapturePolling()
        return nil
    }

    func stopCapture(_ id: UUID) async {
        _ = await helper.stopPcap(id)
        activeCaptures[id] = nil
        try? await Task.sleep(for: .seconds(1))
        await refreshCaptures()
    }

    func deleteCapture(_ c: PcapStatus) async {
        _ = await helper.deletePcap(c.file)
        await refreshCaptures()
    }

    func refreshCaptures() async {
        if let list = await helper.pcaps(), list != pcaps { pcaps = list }
        for id in activeCaptures.keys where pcaps.first(where: { $0.id == id })?.running != true { activeCaptures[id] = nil }
    }

    /// Captures running for a connection's app and/or destination (for the console's detail pane).
    func captures(for p: Profile) -> [PcapStatus] {
        let ids = activeCaptures.filter { $0.value.target.covers(p) }.keys
        return pcaps.filter { ids.contains($0.id) && $0.running }
    }

    private func startCapturePolling() {
        guard capturePoller == nil else { return }
        capturePoller = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled, let self, !self.activeCaptures.isEmpty {
                try? await Task.sleep(for: .seconds(2))
                await self.refreshCaptures()
                tick += 1
                if tick % 10 == 0 {   // every ~20 s: new IPs for the destination, new pids for the app
                    for (id, a) in self.activeCaptures {
                        let fresh = await self.captureSpec(a.target, id: id, limitsFrom: a.spec)
                        if fresh != a.spec, fresh.isValid, await self.helper.updatePcap(fresh) {
                            self.activeCaptures[id] = (a.target, fresh)
                        }
                    }
                }
            }
            self?.capturePoller = nil
        }
    }

    private func captureSpec(_ t: CaptureTarget, id: UUID, limitsFrom old: PcapSpec? = nil) async -> PcapSpec {
        var spec = old ?? PcapSpec(label: t.label)
        spec.id = id
        if let path = t.appPath {
            spec.processNames = [(path as NSString).lastPathComponent]
            spec.pids = await Task.detached { ProcessTable.snapshot(withArgs: false).filter { $0.path == path }.map(\.pid) }.value
        }
        if let d = t.destination {
            var ips: Set<String> = []
            if RiskHeuristics.isIPLiteral(d) {
                ips.insert(d)
            } else {
                for p in profiles.values where p.key.direction == .outbound {
                    if let h = p.hostname, Rule.hostMatches(d, addresses: [], hostname: h, address: "") { ips.formUnion(p.addresses) }
                }
                let name = d.hasPrefix("*.") ? String(d.dropFirst(2)) : d
                ips.formUnion(await Task.detached { Self.resolve(name) }.value)
            }
            spec.addresses = ips.sorted()
        }
        return spec
    }

    /// Removes every EDR detection. Ones marked benign stay silenced; anything still happening is detected afresh.
    func clearDetections() {
        suppressedFindingKeys.formUnion(findings.filter { $0.status == .benign }.map(\.key))
        findings.removeAll()
        triageQueue.removeAll()
        refreshProfileEDR()
        scheduleSave()
    }

    /// The filter often only sees an IP; record what a hostname currently resolves to.
    private func resolveAddresses(for rule: Rule) {
        guard rule.host != "*", !rule.host.hasPrefix("*."), !RiskHeuristics.isIPLiteral(rule.host) else { return }
        let host = rule.host
        Task.detached {
            let ips = Self.resolve(host)
            await MainActor.run {
                guard let i = self.rules.firstIndex(where: { $0.id == rule.id }) else { return }
                let merged = Array(Set(self.rules[i].addresses + ips)).sorted()
                if merged != self.rules[i].addresses.sorted() {
                    self.rules[i].addresses = merged
                    self.rulesChanged(syncFirewall: false)
                }
            }
        }
    }

    nonisolated static func resolve(_ host: String) -> [String] {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(res) }
        var out: Set<String> = []
        for ai in sequence(first: first, next: { $0.pointee.ai_next }) {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                out.insert(String(cString: buf))
            }
        }
        return Array(out)
    }

    private func rulesChanged(syncFirewall: Bool = true) {
        pushPolicy()
        scheduleSave()
        if syncFirewall { scheduleFirewallSync() }
        mesh?.publishLocal(rules: rules)
    }

    // MARK: Network vulnerability scanning

    @Published private(set) var scanHosts: [ScannedHost] = []
    @Published private(set) var netScanning = false
    @Published private(set) var netScanProgress: (String, Double) = ("", 0)

    /// The local IPv4 network this Mac is on, as a /24 suggestion ("192.168.1.0/24").
    var suggestedSubnet: String? {
        guard let ip = PolicyPlanner.primaryIPv4(), let v = IPv4Set.parse(ip) else { return nil }
        let net = v & 0xFFFFFF00
        return "\(net >> 24).\(net >> 16 & 0xFF).\(net >> 8 & 0xFF).0/24"
    }

    private func netScanDue() -> Bool {
        let s = settings.netscan
        guard s.enabled, !netScanning, s.targets.contains(where: \.enabled) else { return false }
        guard let last = s.lastScan else { return s.schedule != .manual }
        switch s.schedule {
        case .manual: return false
        case .daily: return Date().timeIntervalSince(last) > 86400
        case .weekly: return Date().timeIntervalSince(last) > 7 * 86400
        }
    }

    /// Scans the configured subnets: live hosts, open services, versions → CVEs, risky exposed services.
    func runNetworkScan() async {
        guard settings.netscan.enabled, !netScanning else { return }
        let targets = settings.netscan.targets.filter { $0.enabled && CIDR.check($0.cidr, ownedPublic: $0.ownedPublic) == nil }.map(\.cidr)
        guard !targets.isEmpty else { return }
        netScanning = true
        defer { netScanning = false }
        let ports = Array(Set(NetScanner.defaultPorts + settings.netscan.extraPorts.filter { (1...65535).contains($0) })).sorted()
        let rate = settings.netscan.rate, node = nodeName
        let hosts = await Task.detached(priority: .utility) { [weak self] in
            NetScanner.scan(targets: targets, ports: ports, rate: rate, node: node) { msg, frac in
                Task { @MainActor in self?.netScanProgress = (msg, frac) }
            }
        }.value

        netScanProgress = ("Matching services against NVD", 0.92)
        var found: [VulnFinding] = []
        var lookups: [String: [Vulnerability]] = [:]
        for host in hosts {
            for p in host.ports {
                let c = Component(kind: .remote, name: p.product ?? p.service, version: p.version ?? "", cpe: p.cpe,
                                  location: "\(host.label):\(p.port)", exposedPorts: [p.port])
                if let (what, score, why) = NetScanner.riskyServices[p.port] {
                    found.append(VulnFinding(component: c, vuln: Vulnerability(
                        id: "EXPOSED-NET-\(p.port)", summary: "\(what) reachable on \(host.label)",
                        details: why + " Found by \(node)'s network scan.", cvssScore: score, cvssVersion: "est.")))
                }
                guard let cpe = p.cpe, let v = p.version, !v.isEmpty else { continue }
                let key = "\(cpe)|\(v)"
                if lookups[key] == nil { lookups[key] = (try? await vulnDB.nvd(cpe: cpe, version: v)) ?? [] }
                found += (lookups[key] ?? []).map { VulnFinding(component: c, vuln: $0) }
            }
        }
        let kev = await vulnDB.kev()
        for i in found.indices { if let cve = found[i].vuln.cve { found[i].kev = kev.contains(cve) } }

        // Merge: keep the user's accept/reopen choices; network findings that disappeared were fixed.
        let old = Dictionary(vulnFindings.filter { $0.component.kind == .remote }.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var merged = found.map { f -> VulnFinding in
            var f = f
            if let prev = old[f.id] { f.firstSeen = prev.firstSeen; f.status = prev.status == .fixed ? .open : prev.status }
            return f
        }
        let current = Set(merged.map(\.id))
        for f in old.values where !current.contains(f.id) && f.status != .fixed { var g = f; g.status = .fixed; merged.append(g) }
        let fresh = merged.filter { old[$0.id] == nil && $0.status == .open }
        vulnFindings = vulnFindings.filter { $0.component.kind != .remote } + merged
        newVulnIDs.formUnion(fresh.map(\.id))
        scanHosts = hosts
        settings.netscan.lastScan = Date()
        netScanProgress = ("Found \(hosts.count) hosts, \(hosts.reduce(0) { $0 + $1.ports.count }) open services", 1)
        notifyVulns(new: old.isEmpty ? [] : fresh, exploited: fresh.filter(\.kev))
        mesh?.broadcastReport(force: true)
        scheduleSave()
    }

    // MARK: Multi-node

    @Published private(set) var mesh: MeshNode?
    @Published var scope: AppScope = .machine
    @Published private(set) var llmRunsOn: String = "this Mac"
    private var localModels: [String] = []
    private var meshBag: Set<AnyCancellable> = []
    private var savedMembership: Membership?
    private var savedSharedRules: [SharedRule] = []

    enum AppScope: String, CaseIterable, Identifiable { case machine = "This Machine", network = "Your Network"; var id: String { rawValue } }

    var nodeName: String { Host.current().localizedName ?? ProcessInfo.processInfo.hostName }

    /// Creates this Mac's node (identity from the Keychain) and starts it if multi-node is on.
    private func setUpMesh() {
        guard mesh == nil, let identity = try? NodeIdentity.loadOrCreate(name: nodeName) else { return }
        let node = MeshNode(identity: identity, membership: savedMembership, sharedRules: savedSharedRules)
        node.applyRemoteRules = { [weak self] in self?.applyShared($0) }
        node.localReport = { [weak self] in self?.localReport() ?? NodeReport(node: identity.info, hostname: "", os: "", enforcement: "", lockdown: false, profiles: [], findings: [], vulnFindings: [], componentCount: 0, decisionCount: 0) }
        node.localStatus = { [weak self] in self?.localStatus() ?? NodeStatus(node: identity.id, chip: "", memoryGB: 0, cpuCores: 0, cpuLoad: 0, llmModels: [], llmQueue: 0, acceptsLLMWork: false) }
        node.runLLM = { [weak self] system, user, schema in
            guard let self else { throw URLError(.cancelled) }
            return try await self.runLLMForPeer(system: system, user: user, schema: schema)
        }
        node.onChange = { [weak self] in
            self?.objectWillChange.send()
            self?.pushPolicy()
            self?.scheduleSave()
        }
        node.onMembershipEstablished = { [weak self] in
            guard let self else { return }
            self.mesh?.publishLocal(rules: self.rules)
        }
        node.onJoinRequest = { [weak self] who, code in
            self?.notify(id: "join-\(who.id)", title: "\(who.name) wants to join your Elliott network",
                         body: "Approve it in Elliott → Your Network → Devices only if it shows the code \(code).", critical: true)
        }
        node.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }.store(in: &meshBag)
        mesh = node
        if settings.mesh.enabled { node.start() }
        Task { [weak self] in
            while !Task.isCancelled {
                if let self, self.settings.llm.enabled {
                    self.localModels = (try? await LocalLLM(settings: self.settings.llm).models()) ?? []
                }
                try? await Task.sleep(for: .seconds(300))
            }
        }
    }

    func setMeshEnabled(_ on: Bool) {
        settings.mesh.enabled = on
        if on { mesh?.start() } else { mesh?.stop() }
        pushPolicy()
    }

    /// Shared rules from the network replace or remove local ones; local addresses learned for a rule are kept.
    private func applyShared(_ list: [SharedRule]) {
        for s in list {
            let local = rules.first { $0.id == s.rule.id }
            rules.removeAll { $0.id == s.rule.id }
            if !s.deleted {
                var r = s.rule
                r.addresses = Array(Set((local?.addresses ?? []) + s.rule.addresses))
                rules.append(r)
                resolveAddresses(for: r)
            }
        }
        pushPolicy()
        scheduleSave()
    }

    func localReport() -> NodeReport {
        let recentProfiles = profiles.values.sorted { $0.lastSeen > $1.lastSeen }.prefix(1500)
        let shownFindings = findings.filter { $0.status == .open } + findings.filter { $0.status != .open }.suffix(200)
        return NodeReport(node: mesh?.identity.info ?? NodeInfo(id: UUID(), name: nodeName, publicKey: Data()),
                          hostname: nodeName, os: ProcessInfo.processInfo.operatingSystemVersionString,
                          enforcement: backend == .filter ? "per-app filter" : backend == .packetFilter ? "packet filter" : "observe only",
                          lockdown: settings.lockdown, profiles: Array(recentProfiles), findings: shownFindings,
                          vulnFindings: openVulns, componentCount: components.count, decisionCount: decisions.count,
                          scanHosts: scanHosts)
    }

    private var statusCache: (NodeStatus, Date)?
    private var reportCache: (NodeReport, Date)?

    /// Cached for 15 s (it shells out to ioreg for GPU load).
    func localStatus() -> NodeStatus {
        if let (s, at) = statusCache, Date().timeIntervalSince(at) < 15 { return s }
        let s = freshLocalStatus()
        statusCache = (s, Date())
        return s
    }

    /// For views: rebuilt at most every 10 s.
    func displayedLocalReport() -> NodeReport {
        if let (r, at) = reportCache, Date().timeIntervalSince(at) < 10 { return r }
        let r = localReport()
        reportCache = (r, Date())
        return r
    }

    private func freshLocalStatus() -> NodeStatus {
        NodeStatus(node: mesh?.identity.id ?? UUID(), chip: Hardware.chip, memoryGB: Hardware.memoryGB, cpuCores: Hardware.cores,
                   cpuLoad: Hardware.loadPerCore, gpuUtilization: Hardware.gpuUtilization(),
                   llmModels: settings.llm.enabled && llmServerIssue == nil ? localModels : [],
                   llmQueue: analysisQueue.count + suggestQueue.count + triageQueue.count + reachQueue.count,
                   acceptsLLMWork: settings.mesh.shareLLM && settings.llm.enabled && llmServerIssue == nil)
    }

    /// A member asked this Mac to run an LLM job.
    private func runLLMForPeer(system: String, user: String, schema: Data) async throws -> String {
        guard settings.mesh.shareLLM, settings.llm.enabled else { throw MeshNode.RemoteLLMError.failed("this node isn't sharing its LLM") }
        guard await checkLLMServer() else { throw MeshNode.RemoteLLMError.failed("this node's LLM server isn't trusted right now") }
        let dict = (try? JSONSerialization.jsonObject(with: schema) as? [String: Any]) ?? [:]
        return try await LocalLLM(settings: settings.llm).completeLocally(system: system, user: user, schema: dict)
    }

    /// The LLM client for the next job: local, or the best-suited node on the network (falls back to local).
    func llmClient() -> LocalLLM {
        var client = LocalLLM(settings: settings.llm)
        guard let mesh, mesh.isMember else { llmRunsOn = "this Mac"; return client }
        let peers = mesh.statuses.values.filter { $0.node != mesh.identity.id && mesh.connected[$0.node] != nil }
        guard let target = LLMRouter.choose(local: localStatus(), peers: Array(peers), route: settings.mesh.llmRoute) else {
            llmRunsOn = "this Mac"
            return client
        }
        llmRunsOn = mesh.connected[target]?.name ?? "another node"
        let local = settings.llm
        client.remote = { [weak mesh] system, user, schema in
            do {
                guard let mesh else { throw URLError(.cancelled) }
                return try await mesh.remoteLLM(on: target, system: system, user: user, schema: schema)
            } catch {
                // The node went away or refused: do it here instead.
                let dict = (try? JSONSerialization.jsonObject(with: schema) as? [String: Any]) ?? [:]
                return try await LocalLLM(settings: local).completeLocally(system: system, user: user, schema: dict)
            }
        }
        return client
    }

    /// Whether the next job would run on this Mac (so the local server must be trusted).
    var llmRoutesLocally: Bool {
        guard let mesh, mesh.isMember else { return true }
        let peers = mesh.statuses.values.filter { $0.node != mesh.identity.id && mesh.connected[$0.node] != nil }
        return LLMRouter.choose(local: localStatus(), peers: Array(peers), route: settings.mesh.llmRoute) == nil
    }

    // MARK: Lockdown & approvals

    func setLockdown(_ on: Bool) { settings.lockdown = on }

    private func approvalArrived(_ r: ApprovalRequest) {
        if profiles[r.key.id] == nil { ingest([r.event]) }
        if let i = approvals.firstIndex(where: { $0.id == r.id }) { approvals[i] = r } else { approvals.append(r) }
        // Describe it first: the user is waiting.
        analysisQueue.removeAll { $0 == r.key.id }
        if profiles[r.key.id]?.analysis == nil { analysisQueue.insert(r.key.id, at: 0) }
        if canSuggest { suggestQueue.removeAll { $0 == r.key.id }; suggestQueue.insert(r.key.id, at: 0) }
        pumpAnalysis()
        ApprovalPanel.shared.show(model: self)
    }

    func answer(_ r: ApprovalRequest, allow: Bool, remember scope: RuleScope?) {
        let p = profiles[r.key.id] ?? Profile(event: r.event)
        record(Decision(profile: p, verdict: allow ? .allow : .deny, source: .approval, scope: scope?.label ?? "once"))
        if let scope {
            classify(p, allow ? .allow : .deny, scope: scope, record: nil)   // policy reaches the filter before the resume
        } else if allow && backend == .packetFilter {
            // pf has no "this connection only": open the destination briefly so the next SYN retry passes.
            classify(p, .allow, scope: .exact, expires: Date().addingTimeInterval(120), record: nil)
        }
        if backend == .filter { filter.resolve(r.key.id, allow: allow) }
        approvals.removeAll { $0.id == r.id }
    }

    private func pushPolicy() {
        let policy = FilterPolicy(rules: rules, lockdown: settings.lockdown,
                                  trustAppleSigned: settings.trustAppleSigned, approvalTimeout: settings.approvalTimeout,
                                  meshPort: settings.mesh.enabled ? mesh?.listeningPort.map(Int.init) : nil)
        passive.interval = backend == .packetFilter && settings.lockdown ? .seconds(1) : .seconds(3)
        if filter.connected {
            filter.push(policy)
            if helper.connected { Task { _ = await helper.clear() } }   // don't enforce twice
        } else if helper.connected {
            helper.push(policy)
        }
    }

    private func settingsChanged(_ old: AppSettings) {
        if settings.lockdown != old.lockdown || settings.trustAppleSigned != old.trustAppleSigned
            || settings.approvalTimeout != old.approvalTimeout { pushPolicy() }
        if settings.lockdown != old.lockdown && settings.pan.mirrorLockdown { scheduleFirewallSync() }
        if settings.llm != old.llm || settings.suggestionsEnabled != old.suggestionsEnabled {
            analysisFailures.removeAll(); pumpAnalysis()
        }
        // lastRefresh is written by refreshIntel itself; comparing it would re-trigger the refresh forever.
        var oldIntel = old.intel, newIntel = settings.intel
        oldIntel.lastRefresh = nil; newIntel.lastRefresh = nil
        if newIntel != oldIntel { Task { await refreshIntel() } }
        if settings.edr != old.edr {
            edr.minerDetection = settings.edr.minerDetection
            if settings.edr.enabled { edr.start() } else { edr.stop() }
        }
        scheduleSave()
    }

    // MARK: LLM

    func reanalyze(_ ids: [String]) {
        for id in ids { analysisFailures[id] = nil; analysisQueue.removeAll { $0 == id } }
        analysisQueue.insert(contentsOf: ids, at: 0)
        pumpAnalysis()
    }

    private enum Job { case analyze(String), suggest(String), triage(UUID), reach(String) }

    /// Analysis first (it feeds suggestions), then suggestions for unclassified connections.
    private func nextJob() -> Job? {
        // Serious detections first: someone may be waiting to decide whether to kill something.
        while let id = triageQueue.first {
            triageQueue.removeFirst()
            if let f = findings.first(where: { $0.id == id }), f.triage == nil, f.status == .open { return .triage(id) }
        }
        while let id = reachQueue.first {
            reachQueue.removeFirst()
            if let f = vulnFindings.first(where: { $0.id == id }), f.reachability.llmVerdict == nil, f.status == .open { return .reach(id) }
        }
        if !analysisQueue.isEmpty { return .analyze(analysisQueue.removeFirst()) }
        if suggestQueue.isEmpty { refillSuggestions() }
        while !suggestQueue.isEmpty {
            let id = suggestQueue.removeFirst()
            if let p = profiles[id], needsSuggestion(p) { return .suggest(id) }
        }
        return nil
    }

    private func pumpAnalysis() {
        guard analysisTask == nil, settings.llm.enabled else { return }
        analysisTask = Task { [weak self] in
            while let self, self.settings.llm.enabled {
                let serverOK = self.llmRoutesLocally ? await self.checkLLMServer() : true
                guard serverOK else {
                    self.llmStatus = "LLM paused: unrecognized server on the LLM port (Settings → Local LLM)"
                    try? await Task.sleep(for: .seconds(60))
                    continue
                }
                guard let job = self.nextJob() else { break }
                if case .triage(let fid) = job {
                    await self.runTriage(fid)
                    continue
                }
                if case .reach(let vid) = job {
                    await self.runReachJudge(vid)
                    continue
                }
                let id: String, failKey: String
                switch job {
                case .analyze(let i): id = i; failKey = i
                case .suggest(let i): id = i; failKey = "s:" + i
                case .triage, .reach: continue
                }
                guard let p = self.profiles[id] else { continue }
                do {
                    switch job {
                    case .analyze:
                        self.analyzingID = id
                        self.llmStatus = "Analyzing \(p.appName) → \(p.destination)"
                        let a = try await self.llmClient().analyze(p)
                        self.profiles[id]?.analysis = a
                        self.llmStatus = "\(self.analyzedCount) of \(self.profiles.count) connections analyzed"
                    case .triage, .reach: break
                    case .suggest:
                        self.suggestingID = id
                        self.llmStatus = "Predicting your call on \(p.appName) → \(p.destination)"
                        let s = try await Advisor.suggest(p, decisions: self.learnableDecisions,
                                                          llm: self.llmClient())
                        if self.decision(for: p) == nil { self.profiles[id]?.suggestion = s }
                        self.llmStatus = "\(self.suggestionCount) suggestions ready"
                    }
                    self.scheduleSave()
                } catch let e as LocalLLM.Failure {
                    // The model answered but not usefully: retry once later, then leave it.
                    let n = (self.analysisFailures[failKey] ?? 0) + 1
                    self.analysisFailures[failKey] = n
                    if n < 2 {
                        if case .analyze = job { self.analysisQueue.append(id) } else { self.suggestQueue.append(id) }
                    }
                    self.llmStatus = e.localizedDescription
                    if case .notLocal = e { break }
                } catch {
                    // Server not reachable: keep the work and try again in a bit.
                    if case .analyze = job { self.analysisQueue.insert(id, at: 0) } else { self.suggestQueue.insert(id, at: 0) }
                    self.llmStatus = "LLM unavailable (\(error.localizedDescription)); retrying in 30 s"
                    self.analyzingID = nil; self.suggestingID = nil
                    try? await Task.sleep(for: .seconds(30))
                }
                self.analyzingID = nil; self.suggestingID = nil
            }
            self?.analysisTask = nil
        }
    }

    // MARK: Learning from decisions

    /// Decisions suggestions learn from.
    var learnableDecisions: [Decision] { decisions }
    var canSuggest: Bool { settings.suggestionsEnabled && decisions.count >= Advisor.minimumDecisions }
    var suggestionCount: Int { profiles.values.filter { $0.suggestion != nil && decision(for: $0) == nil }.count }

    private func needsSuggestion(_ p: Profile) -> Bool {
        guard canSuggest, decision(for: p) == nil, analysisFailures["s:" + p.id, default: 0] < 2 else { return false }
        guard let s = p.suggestion else { return true }
        return decisions.count >= s.basedOn + Advisor.refreshEvery
    }

    private func refillSuggestions() {
        guard canSuggest else { return }
        // Riskiest and most recent first: those are the ones worth a second opinion.
        suggestQueue = profiles.values.filter(needsSuggestion)
            .sorted { ($0.riskScore, $0.lastSeen) > ($1.riskScore, $1.lastSeen) }.map(\.id)
    }

    private func record(_ d: Decision) {
        decisions.append(d)
        if decisions.count > 5000 { decisions.removeFirst(decisions.count - 5000) }
        // A decided profile no longer needs a suggestion.
        for id in profiles.keys where profiles[id]?.suggestion != nil && decision(for: profiles[id]!) != nil {
            profiles[id]?.suggestion = nil
        }
        scheduleSave()
        pumpAnalysis()
    }

    func forgetDecisions() {
        decisions.removeAll()
        for id in profiles.keys { profiles[id]?.suggestion = nil }
        scheduleSave()
    }

    // MARK: Threat intelligence

    var enabledFeeds: [Feed] {
        Feed.all.filter { !settings.intel.disabledFeeds.contains($0.id) }
            + settings.intel.customFeeds.filter(\.enabled).compactMap(\.feed)
    }
    /// Names of every list (built-in and custom), to tell list hits from online-lookup hits.
    private var feedNames: Set<String> { Set(Feed.all.map(\.name) + settings.intel.customFeeds.map(\.name)) }

    /// This Mac's DNS servers and gateway, plus Apple's 17.0.0.0/8: a poisoned feed listing them would break or
    /// discredit everything, so one source alone can't call them known-bad.
    private var protectedIPs: Set<String> = []
    private var protectedCheckedAt = Date.distantPast

    private func refreshProtected() {
        guard Date().timeIntervalSince(protectedCheckedAt) > 300 else { return }
        protectedCheckedAt = Date()
        var ips = Set<String>()
        let store = SCDynamicStoreCreate(nil, "Elliott" as CFString, nil, nil)
        if let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any] {
            (dns["ServerAddresses"] as? [String] ?? []).forEach { ips.insert($0) }
        }
        for key in ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] {
            if let v = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any], let r = v["Router"] as? String { ips.insert(r) }
        }
        protectedIPs = ips
    }

    func isProtected(_ ip: String) -> Bool {
        refreshProtected()
        return protectedIPs.contains(ip) || ip.hasPrefix("17.")
    }

    private func protect(_ ip: String, _ hits: [IntelHit]) -> [IntelHit] {
        let bad = Set(hits.filter { $0.severity == .knownBad }.map(\.source))
        guard isProtected(ip), bad.count == 1 else { return hits }
        return hits.map { h in
            var h = h
            if h.severity == .knownBad {
                h.severity = .suspicious
                h.detail += " (only one source, and this is your gateway/DNS server or Apple: needs corroboration)"
            }
            return h
        }
    }

    /// Anything overdue (after launch or wake): intel, exploit signals, the daily scan.
    func runDueChecks() async {
        let now = Date()
        if settings.intel.lastRefresh.map({ now.timeIntervalSince($0) > Self.intelInterval }) ?? true {
            await refreshIntel(maxAge: Self.intelInterval)
        }
        if settings.vuln.lastExploitCheck.map({ now.timeIntervalSince($0) > Self.exploitInterval }) ?? true {
            await refreshExploitSignals()
        }
        autoScanIfDue()
    }
    var knownBadCount: Int { profiles.values.filter { $0.intel?.reputation == .knownBad }.count }

    func refreshIntel(force: Bool = false, maxAge: TimeInterval = 12 * 3600) async {
        guard !intelRefreshing else { return }
        intelRefreshing = true
        for f in Feed.all where settings.intel.disabledFeeds.contains(f.id) { threatIntel.drop(f.id) }
        for c in settings.intel.customFeeds where !c.enabled { threatIntel.drop("custom-\(c.id)") }
        await threatIntel.refresh(enabledFeeds, maxAge: maxAge, force: force)
        settings.intel.lastRefresh = Date()
        intelRefreshing = false
        intelRevision += 1
        // Lists changed: re-check every IP we know about.
        assess(Set(intel.keys).union(profiles.values.flatMap(\.addresses)), recheck: true)
    }

    /// Matches IPs against the local lists now; queues opt-in online lookups.
    private func assess(_ ips: Set<String>, recheck: Bool = false) {
        let feeds = enabledFeeds
        var touched: Set<String> = []
        for ip in ips where IPv4Set.isGlobal(ip) {
            var entry = intel[ip] ?? IPIntel(ip: ip)
            let names = feedNames
            let online = entry.hits.filter { !names.contains($0.source) }
            entry.hits = protect(ip, threatIntel.hits(for: ip, feeds: feeds) + online)
            entry.checked = Date()
            if entry != intel[ip] { intel[ip] = entry; touched.insert(ip) }
            if !recheck && onlineLookupsEnabled && entry.onlineChecked == nil { onlineQueue.append(ip) }
        }
        if !touched.isEmpty { updateIntelSummaries(touched) }
        pumpOnline()
    }

    private func updateIntelSummaries(_ ips: Set<String>) {
        for (id, p) in profiles where p.addresses.contains(where: ips.contains) {
            let entries = p.addresses.compactMap { intel[$0] }
            guard !entries.isEmpty else { continue }
            var seen = Set<String>()
            let hits = entries.flatMap(\.hits).filter { seen.insert($0.source + $0.detail).inserted }
            let summary = IntelSummary(reputation: entries.map(\.reputation).max() ?? .clean, hits: hits,
                                       org: entries.compactMap(\.org).first)
            guard summary != p.intel else { continue }
            let wasBad = p.intel?.reputation == .knownBad
            profiles[id]?.intel = summary
            if summary.reputation == .knownBad && !wasBad {
                knownBadSeen(profiles[id]!)
                c2Finding(profiles[id]!)
            }
        }
        scheduleSave()
    }

    private func knownBadSeen(_ p: Profile) {
        // The analysis may predate the hit; redo it with the intel included.
        if p.analysis != nil { reanalyze([p.id]) }
        guard settings.intel.notifyKnownBad, notifiedBad.insert(p.id).inserted else { return }
        let content = UNMutableNotificationContent()
        content.title = "Known-bad destination: \(p.appName)"
        content.body = "\(p.destination) is on \(p.intel?.hits.filter { $0.severity == .knownBad }.map(\.source).joined(separator: ", ") ?? "a blocklist")."
        content.sound = .default
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            center.add(UNNotificationRequest(identifier: "bad-\(p.id)", content: content, trigger: nil))
        }
    }

    var onlineLookupsEnabled: Bool {
        (settings.intel.abuseIPDB && !(Keychain.get("abuseipdb-key") ?? "").isEmpty)
            || settings.intel.greyNoise
            || (settings.intel.virusTotal && !(Keychain.get("virustotal-key") ?? "").isEmpty)
    }

    /// One IP at a time, paced for free-tier rate limits (VirusTotal allows 4 lookups a minute).
    private func pumpOnline() {
        guard onlineTask == nil, !onlineQueue.isEmpty, onlineLookupsEnabled else { return }
        onlineTask = Task { [weak self] in
            while let self, !self.onlineQueue.isEmpty, self.onlineLookupsEnabled {
                let ip = self.onlineQueue.removeFirst()
                guard var entry = self.intel[ip], entry.onlineChecked == nil else { continue }
                let s = self.settings.intel
                var results: [OnlineIntel.Result] = []
                if s.abuseIPDB, let k = Keychain.get("abuseipdb-key"), !k.isEmpty,
                   let r = try? await OnlineIntel.abuseIPDB(ip, key: k) { results.append(r) }
                if s.greyNoise, let r = try? await OnlineIntel.greyNoise(ip, key: Keychain.get("greynoise-key")) { results.append(r) }
                if s.virusTotal, let k = Keychain.get("virustotal-key"), !k.isEmpty,
                   let r = try? await OnlineIntel.virusTotal(ip, key: k) { results.append(r) }
                entry.hits += results.flatMap(\.hits).filter { h in !entry.hits.contains(h) }
                entry.org = entry.org ?? results.compactMap(\.org).first
                entry.country = entry.country ?? results.compactMap(\.country).first
                entry.onlineChecked = Date()
                self.intel[ip] = entry
                self.updateIntelSummaries([ip])
                try? await Task.sleep(for: .seconds(s.virusTotal ? 16 : 2))
            }
            self?.onlineTask = nil
        }
    }

    // MARK: EDR

    var openFindings: [Finding] { findings.filter { $0.status == .open } }
    var openFindingCount: Int { openFindings.count }
    var openSeriousCount: Int { openFindings.filter { $0.severity >= .high }.count }

    func findings(forPath path: String) -> [Finding] {
        findings.filter { $0.path == path && $0.status != .benign }.sorted { $0.severity > $1.severity }
    }

    private func startEDR() {
        edr.baseline = Set(edrBaseline)
        edr.minerDetection = settings.edr.minerDetection
        edr.fetch = { [weak self] in
            // Root's view (complete command lines) when the helper is installed.
            if let procs = await self?.helper.processes(), !procs.isEmpty { return procs }
            return self?.processCache.snapshot(withArgs: true) ?? []
        }
        edr.onObservations = { [weak self] obs in Task { @MainActor in self?.observe(obs) } }
        // Publishing re-renders every view; only do it when the set of processes actually changed.
        edr.onProcesses = { [weak self] procs in
            Task { @MainActor in
                guard let self else { return }
                if procs.count != self.processes.count || zip(procs, self.processes).contains(where: { $0.pid != $1.pid || $0.start != $1.start }) {
                    self.processStore.list = procs
                }
            }
        }
        edr.onLaunchItems = { [weak self] items, baseline in
            Task { @MainActor in
                guard let self else { return }
                self.launchItems = items
                self.edrBaseline = baseline.sorted()
                self.scheduleSave()
            }
        }
        if settings.edr.enabled { edr.start() }
        // Anything left untriaged last time (e.g. the app quit mid-queue).
        triageQueue = findings.filter { $0.status == .open && $0.triage == nil && $0.severity >= .medium }
            .sorted { $0.severity > $1.severity }.map(\.id)
    }

    func observe(_ obs: [Observation]) {
        var touchedPaths: Set<String> = []
        for o in obs where !suppressedFindingKeys.contains(o.key) {
            if let i = findings.firstIndex(where: { $0.key == o.key }) {
                findings[i].lastSeen = Date()
                findings[i].count += 1
                if let p = o.process { findings[i].pid = p.pid; findings[i].processStart = p.start }
                continue
            }
            var f = Finding(key: o.key, rule: o.draft.rule, title: o.draft.title, detail: o.draft.detail,
                            severity: o.draft.severity, category: o.draft.category, mitre: o.draft.mitre,
                            path: o.path, pid: o.process?.pid, processStart: o.process?.start, commandLine: o.process?.commandLine,
                            user: o.process.map { ProcessTable.userName($0.uid) },
                            chain: o.chain.map { "\($0.displayName) (\($0.pid))" }, evidence: o.draft.evidence)
            if let p = o.process {
                f.evidence.insert("pid \(p.pid), started \(p.start.formatted(date: .abbreviated, time: .standard))", at: 0)
            }
            findings.append(f)
            if let path = f.path { touchedPaths.insert(path) }
            if f.severity >= .medium { triageQueue.append(f.id) }
            if f.severity >= settings.edr.notifyAt { notify(f) }
        }
        if findings.count > 3000 {
            findings.removeFirst(findings.count - 3000)
        }
        triageQueue.sort { a, b in
            (findings.first { $0.id == a }?.severity ?? .info) > (findings.first { $0.id == b }?.severity ?? .info)
        }
        refreshProfileEDR(touchedPaths)
        scheduleSave()
        pumpAnalysis()
    }

    /// A known-bad destination is also a process-level detection.
    private func c2Finding(_ p: Profile) {
        let hits = p.intel?.hits.filter { $0.severity == .knownBad }.map { "\($0.source): \($0.detail)" } ?? []
        observe([Observation(
            key: "net.c2|\(p.processPath)|\(p.key.host)",
            draft: Draft(rule: "net.c2", title: "Connection to a known-bad IP",
                         detail: "\(p.appName) connected to \(p.destination), which threat intelligence lists as malicious.",
                         severity: .critical, category: .network, mitre: ["T1071"], evidence: hits + p.addresses.prefix(4).map { "remote \($0)" }),
            path: p.processPath)])
    }

    /// Mirrors open findings onto the connections made by the same program.
    private func refreshProfileEDR(_ paths: Set<String>? = nil) {
        for (id, p) in profiles where paths == nil || paths!.contains(p.processPath) {
            let fs = findings.filter { $0.path == p.processPath && $0.status == .open && $0.severity >= .medium }
            let summary = fs.isEmpty ? nil : EDRSummary(severity: fs.map(\.severity).max()!, titles: fs.map(\.title))
            if summary != p.edr { profiles[id]?.edr = summary }
        }
    }

    private func runTriage(_ fid: UUID) async {
        guard let f = findings.first(where: { $0.id == fid }) else { return }
        triagingID = fid
        llmStatus = "Triaging: \(f.title)"
        let sig = f.path.map { edr.identity($0).label } ?? "n/a"
        let net = profiles.values.filter { $0.processPath == f.path }
            .map { "\($0.destination)\($0.intel.map { $0.reputation >= .suspicious ? " [\($0.reputation.label)]" : "" } ?? "")" }
        do {
            let t = try await TriageLLM.triage(f, signature: sig, network: net, llm: llmClient())
            if let i = findings.firstIndex(where: { $0.id == fid }) { findings[i].triage = t }
            llmStatus = "Triaged \(f.target): \(t.assessment)"
            scheduleSave()
        } catch {
            llmStatus = "Triage failed: \(error.localizedDescription)"
        }
        triagingID = nil
    }

    func retriage(_ ids: [UUID]) {
        for id in ids { if let i = findings.firstIndex(where: { $0.id == id }) { findings[i].triage = nil } }
        triageQueue.insert(contentsOf: ids, at: 0)
        pumpAnalysis()
    }

    func setStatus(_ ids: Set<UUID>, _ status: FindingStatus) {
        var paths: Set<String> = []
        for i in findings.indices where ids.contains(findings[i].id) {
            findings[i].status = status
            if let p = findings[i].path { paths.insert(p) }
        }
        refreshProfileEDR(paths)
        scheduleSave()
    }

    /// Kills the process behind a finding: directly for the user's own processes, through the helper otherwise.
    func kill(_ f: Finding) async -> String? {
        guard let pid = f.pid, pid > 1 else { return "No process id recorded." }
        guard let start = f.processStart else {
            return "This detection predates start-time tracking, so Elliott can't confirm pid \(pid) is still the same process. Not killing it."
        }
        // Process ids are reused: only kill if this pid is still the process that was detected.
        guard isRunning(f) else {
            return "Process \(pid) has exited. Its id now belongs to a different process (or none), so nothing was killed."
        }
        if Darwin.kill(pid, SIGKILL) == 0 { return nil }
        if helper.connected { return await helper.terminate(pid: pid, startedAt: start) }
        return "Permission denied. Install the packet filter helper to stop processes owned by other users."
    }

    /// The detected process is still alive (same pid *and* same start time).
    func isRunning(_ f: Finding) -> Bool {
        guard let pid = f.pid, let start = f.processStart else { return false }
        return ProcessTable.isSameProcess(pid, startedAt: start)
    }

    /// Denies all network access for the program behind a finding.
    func blockNetwork(_ f: Finding) {
        guard let path = f.path else { return }
        let id = edr.identity(path)
        let probe = FlowEvent(pid: 0, processPath: path, signingID: id.signingID, teamID: id.teamID, appleSigned: id.appleSigned,
                              direction: .outbound, proto: .tcp, remoteAddress: "", remotePort: 0, outcome: .observed)
        for dir in Direction.allCases {
            var r = Rule(appKey: probe.appKey, appName: (path as NSString).lastPathComponent, direction: dir, proto: nil,
                         host: "*", port: nil, verdict: .deny,
                         addresses: profiles.values.filter { $0.processPath == path && $0.key.direction == dir }.flatMap(\.addresses))
            r.note = "Blocked from EDR: \(f.title)"
            rules.removeAll { $0.appKey == r.appKey && $0.direction == dir && $0.host == "*" && $0.port == nil && $0.proto == nil }
            rules.append(r)
        }
        rulesChanged()
    }

    private func notify(_ f: Finding) {
        let content = UNMutableNotificationContent()
        content.title = "\(f.severity.label): \(f.title)"
        content.body = [f.target, f.detail].joined(separator: " — ")
        content.sound = f.severity >= .high ? .defaultCritical : .default
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            center.add(UNNotificationRequest(identifier: f.id.uuidString, content: content, trigger: nil))
        }
    }

    // MARK: Vulnerabilities

    var openVulns: [VulnFinding] { vulnFindings.filter { $0.status == .open } }
    var openSeriousVulnCount: Int { openVulns.filter { $0.severity >= .high }.count }

    private func autoScanIfDue() {
        guard settings.vuln.enabled, settings.vuln.autoScanDaily, !vulnScanning else { return }
        if let last = settings.vuln.lastScan, Date().timeIntervalSince(last) < 86400 { return }
        Task { await scanVulnerabilities() }
    }

    func scanVulnerabilities() async {
        guard !vulnScanning else { return }
        vulnScanning = true
        vulnDB.nvdKey = nvdKey.isEmpty ? nil : nvdKey
        let scanner = VulnScanner(db: vulnDB, settings: settings.vuln) { [weak self] msg, frac in
            Task { @MainActor in self?.vulnProgress = (msg, frac) }
        }
        let result = await Task.detached(priority: .utility) { await scanner.run() }.value
        mergeVulns(result)
        vulnScanning = false
        settings.vuln.lastScan = result.date
        if settings.remediation.mode == .automatic { await autoRemediate() }
    }

    /// Keeps the user's accept/reopen choices and LLM verdicts across rescans; what disappeared was fixed.
    private func mergeVulns(_ r: VulnScanResult) {
        let old = Dictionary(vulnFindings.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var merged: [VulnFinding] = r.findings.map { f in
            var f = f
            if let prev = old[f.id] {
                f.firstSeen = prev.firstSeen
                f.status = prev.status == .fixed ? .open : prev.status
                if prev.reachability.verdict == f.reachability.verdict {
                    f.reachability.llmVerdict = prev.reachability.llmVerdict
                    f.reachability.llmRationale = prev.reachability.llmRationale
                }
            }
            return f
        }
        let current = Set(merged.map(\.id))
        for f in vulnFindings where !current.contains(f.id) && f.status != .fixed && f.component.kind != .remote {
            var gone = f
            gone.status = .fixed   // no longer installed at that version
            merged.append(gone)
        }
        // What's new since the last scan (the first scan has nothing to compare against).
        let fresh = old.isEmpty ? [] : merged.filter { old[$0.id] == nil && $0.status == .open }
        newVulnIDs = Set(fresh.map(\.id))
        let nowExploited = merged.filter { f in f.kev && f.status == .open && old[f.id].map { !$0.kev } == true }
        vulnFindings = merged
        components = r.components
        vulnErrors = r.errors
        notifyVulns(new: fresh, exploited: nowExploited)
        reachQueue = merged.filter { $0.status == .open && $0.severity >= .medium && $0.reachability.llmVerdict == nil
            && [.imported, .reachable].contains($0.reachability.verdict) }
            .sorted { $0.priority > $1.priority }.map(\.id)
        refreshProfileVulns()
        scheduleSave()
        pumpAnalysis()
    }

    /// Every few hours: re-check CISA KEV (and daily EPSS) for the findings already known, without a full scan.
    func refreshExploitSignals() async {
        guard settings.vuln.enabled, !exploitChecking, !vulnFindings.isEmpty else { return }
        exploitChecking = true
        defer { exploitChecking = false }
        let kev = await vulnDB.kev(maxAge: Self.exploitInterval)
        guard !kev.isEmpty else { return }
        var flipped: [VulnFinding] = []
        for i in vulnFindings.indices {
            guard let cve = vulnFindings[i].vuln.cve else { continue }
            let isKEV = kev.contains(cve)
            if isKEV && !vulnFindings[i].kev && vulnFindings[i].status == .open { flipped.append(vulnFindings[i]) }
            vulnFindings[i].kev = isKEV
        }
        if settings.vuln.lastEPSS.map({ Date().timeIntervalSince($0) > 20 * 3600 }) ?? true {
            let cves = Array(Set(vulnFindings.filter { $0.status == .open }.compactMap(\.vuln.cve)))
            let epss = await vulnDB.epss(cves)
            if !epss.isEmpty {
                for i in vulnFindings.indices { if let c = vulnFindings[i].vuln.cve, let e = epss[c] { vulnFindings[i].epss = e } }
                settings.vuln.lastEPSS = Date()
            }
        }
        settings.vuln.lastExploitCheck = Date()
        notifyVulns(new: [], exploited: flipped)
        refreshProfileVulns()
        scheduleSave()
    }

    private func notifyVulns(new: [VulnFinding], exploited: [VulnFinding]) {
        guard settings.vuln.notify else { return }
        func list(_ fs: [VulnFinding]) -> String {
            let parts = fs.sorted { $0.priority > $1.priority }.prefix(4).map { "\($0.component.name) (\($0.vuln.cve ?? $0.vuln.id))" }
            return parts.joined(separator: ", ") + (fs.count > 4 ? " and \(fs.count - 4) more" : "")
        }
        if !exploited.isEmpty {
            notify(id: "kev-\(Date().timeIntervalSince1970)",
                   title: "Now exploited in the wild: \(exploited.count) vulnerabilit\(exploited.count == 1 ? "y" : "ies") on this Mac",
                   body: "CISA added \(list(exploited)) to its Known Exploited list. Patch these first.", critical: true)
        }
        let serious = new.filter { $0.severity >= settings.vuln.notifyAt && !exploited.contains($0) }
        if !serious.isEmpty {
            notify(id: "new-\(Date().timeIntervalSince1970)",
                   title: "\(serious.count) new \(settings.vuln.notifyAt.label.lowercased())+ vulnerabilit\(serious.count == 1 ? "y" : "ies")",
                   body: list(serious), critical: false)
        }
    }

    private func notify(id: String, title: String, body: String, critical: Bool) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = critical ? .defaultCritical : .default
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            if granted { center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil)) }
        }
    }

    // MARK: Remediation

    /// Plans for open findings (optionally only some components). Runs brew/git checks off the main thread.
    func remediationPlans(for componentIDs: Set<String>? = nil) async -> [RemediationPlan] {
        let findings = vulnFindings.filter { componentIDs == nil || componentIDs!.contains($0.component.id) }
        var cfg = settings.remediation
        if componentIDs != nil { cfg.minSeverity = .info }   // asked for specific components: cover all their vulns
        var plans = await Task.detached(priority: .userInitiated) { RemediationPlanner.plans(for: findings, settings: cfg) }.value
        await verifyReleases(&plans, cooldownDays: cfg.cooldownDays)
        return plans
    }

    /// Package upgrades must target a version the official registry actually publishes, old enough to be past the
    /// window in which hijacked releases usually get caught.
    private func verifyReleases(_ plans: inout [RemediationPlan], cooldownDays: Int) async {
        for i in plans.indices where plans[i].component.kind == .package && plans[i].blocked == nil {
            guard let target = plans[i].target, let eco = plans[i].component.ecosystem else { continue }
            switch await Registry.release(ecosystem: eco, name: plans[i].component.name, version: target) {
            case .published(let date):
                plans[i].registryVerified = true
                let age = Date().timeIntervalSince(date)
                if cooldownDays > 0, age < Double(cooldownDays) * 86400 {
                    let hours = Int(age / 3600)
                    plans[i].blocked = "\(plans[i].component.name) \(target) was published \(hours < 48 ? "\(hours) hours" : "\(hours / 24) days") ago. Waiting until it's \(cooldownDays) days old (Settings → Vulnerabilities → Remediation) in case it's a hijacked release."
                }
            case .notFound:
                plans[i].registryVerified = false
                plans[i].blocked = "\(target) isn't published in the official \(eco) registry. The advisory data may be wrong; not installing it."
            case .unknown(let why):
                plans[i].registryVerified = nil
                plans[i].warnings.append("Couldn't confirm \(target) with the \(eco) registry (\(why)). Automatic mode will skip it.")
            }
        }
    }

    func applyRemediation(_ plans: [RemediationPlan], automatic: Bool = false) async {
        guard !remediating else { return }
        remediating = true
        remediationLog = []
        let backups = dir.appendingPathComponent("remediation-backups", isDirectory: true)
        for plan in plans where plan.actionable || plan.steps.contains(where: { $0.kind == .firewallRule }) {
            remediationLog.append("── \(plan.component.display)\(plan.target.map { " → \($0)" } ?? "")")
            // Firewall steps go through Elliott's own rule engine.
            var ruleIDs: [UUID] = []
            for step in plan.steps where step.kind == .firewallRule {
                guard let port = step.port else { continue }
                var rule = Rule(appKey: "*", appName: plan.component.name, direction: .inbound, proto: .tcp, host: "*", port: port, verdict: .deny)
                rule.note = "Remediation: \(plan.component.name) was listening on the network"
                rules.append(rule)
                ruleIDs.append(rule.id)
                remediationLog.append("✓ \(step.summary)")
            }
            if !ruleIDs.isEmpty { rulesChanged() }
            var record = await Task.detached(priority: .userInitiated) { [weak self] in
                RemediationExecutor.execute(plan, backupDir: backups, automatic: automatic) { line in
                    Task { @MainActor in self?.remediationLog.append(line) }
                }
            }.value
            record.ruleIDs = ruleIDs
            if !ruleIDs.isEmpty && record.status == .succeeded { record.log.insert(contentsOf: plan.steps.filter { $0.kind == .firewallRule }.map { "✓ \($0.summary)" }, at: 0) }
            remediations.insert(record, at: 0)
            markRemediated(record)
        }
        remediating = false
        scheduleSave()
    }

    /// Findings count as fixed only when the verified version includes their fix (or the port is now blocked).
    private func markRemediated(_ r: RemediationRecord) {
        let cid = r.plan.component.id
        for i in vulnFindings.indices where vulnFindings[i].component.id == cid && vulnFindings[i].status == .open {
            let f = vulnFindings[i]
            if f.vuln.id.hasPrefix("EXPOSED-") {
                if !r.ruleIDs.isEmpty { vulnFindings[i].status = .fixed }
            } else if let v = r.verifiedVersion, let fix = Version.upgrades(f.vuln.fixedVersions, from: f.component.version).first,
                      Version.compare(v, fix) != .orderedAscending {
                vulnFindings[i].status = .fixed
            }
        }
        if let v = r.verifiedVersion, let i = components.firstIndex(where: { $0.id == cid }) { components[i].version = v }
        refreshProfileVulns()
    }

    func undoRemediation(_ id: UUID) async {
        guard let i = remediations.firstIndex(where: { $0.id == id }), remediations[i].status != .undone else { return }
        let record = remediations[i]
        remediationLog = ["── Undo \(record.plan.component.display)"]
        if !record.ruleIDs.isEmpty {
            removeRules(Set(record.ruleIDs))
            remediationLog.append("✓ Removed \(record.ruleIDs.count) firewall rule(s)")
        }
        let lines = await Task.detached { [weak self] in
            RemediationExecutor.undo(record) { line in Task { @MainActor in self?.remediationLog.append(line) } }
        }.value
        remediations[i].status = .undone
        remediations[i].log += ["── Undone \(Date().formatted())"] + lines
        // The vulnerabilities are back; reopen what this remediation closed.
        for j in vulnFindings.indices where vulnFindings[j].component.id == record.plan.component.id && vulnFindings[j].status == .fixed {
            vulnFindings[j].status = .open
        }
        refreshProfileVulns()
        scheduleSave()
    }

    private func autoRemediate() async {
        let cfg = settings.remediation
        let plans = await remediationPlans().filter { p in
            guard p.blocked == nil else { return false }
            if p.component.kind == .package && p.registryVerified != true { return false }   // never install unverified
            switch p.component.kind {
            case .homebrew: return cfg.homebrew
            case .package: return cfg.projects
            default: return cfg.exposuresInAutomatic && p.steps.contains { $0.kind == .firewallRule }
            }
        }
        guard !plans.isEmpty else { return }
        await applyRemediation(plans, automatic: true)
        let done = remediations.prefix(plans.count)
        let ok = done.filter { $0.status == .succeeded }.count
        let content = UNMutableNotificationContent()
        content.title = "Elliott auto-remediated \(ok) of \(plans.count) component\(plans.count == 1 ? "" : "s")"
        content.body = done.map { "\($0.plan.component.name): \($0.status.rawValue)" }.joined(separator: ", ")
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert]) { granted, _ in
            if granted { center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) }
        }
    }

    func setVulnStatus(_ ids: Set<String>, _ status: VulnFinding.Status) {
        for i in vulnFindings.indices where ids.contains(vulnFindings[i].id) { vulnFindings[i].status = status }
        refreshProfileVulns()
        scheduleSave()
    }

    func rejudgeReachability(_ ids: [String]) {
        for i in vulnFindings.indices where ids.contains(vulnFindings[i].id) {
            vulnFindings[i].reachability.llmVerdict = nil
            vulnFindings[i].reachability.llmRationale = nil
        }
        reachQueue.insert(contentsOf: ids, at: 0)
        pumpAnalysis()
    }

    private func runReachJudge(_ id: String) async {
        guard let f = vulnFindings.first(where: { $0.id == id }) else { return }
        reachJudgingID = id
        llmStatus = "Reachability: \(f.component.name) / \(f.vuln.id)"
        do {
            let (verdict, why) = try await ReachabilityLLM.judge(f, llm: llmClient())
            if let i = vulnFindings.firstIndex(where: { $0.id == id }) {
                vulnFindings[i].reachability.llmVerdict = verdict
                vulnFindings[i].reachability.llmRationale = why
            }
            scheduleSave()
        } catch {
            llmStatus = "Reachability check failed: \(error.localizedDescription)"
        }
        reachJudgingID = nil
    }

    /// Connections from an app with serious known vulnerabilities carry that into their risk.
    private func refreshProfileVulns() {
        let appVulns = Dictionary(grouping: openVulns.filter { $0.component.kind == .app || $0.component.kind == .homebrew },
                                  by: { $0.component.location })
        for (id, p) in profiles {
            let hits = appVulns.first { p.processPath.hasPrefix($0.key + "/") }?.value ?? []
            let summary = hits.isEmpty ? nil : VulnSummary(maxScore: hits.map(\.vuln.score).max()!, count: hits.count,
                                                          kev: hits.contains(where: \.kev))
            if summary != p.vuln { profiles[id]?.vuln = summary }
        }
    }

    // MARK: Palo Alto

    var panClient: PANClient { PANClient(settings: settings.pan, key: panKey) }

    func scheduleFirewallSync() {
        guard settings.pan.enabled, settings.pan.autoSync else { return }
        syncTask?.cancel()
        syncTask = Task {
            try? await Task.sleep(for: .seconds(3))
            if !Task.isCancelled { await syncFirewall() }
        }
    }

    func shadowPlan() -> ShadowPlan {
        var descriptions: [UUID: String] = [:]
        for r in rules {
            if let note = r.note { descriptions[r.id] = note; continue }
            if let p = profiles.values.first(where: { decision(for: $0)?.id == r.id }), let a = p.analysis {
                descriptions[r.id] = a.description
            }
        }
        let mac = settings.pan.macAddress.isEmpty ? (PolicyPlanner.primaryIPv4() ?? "0.0.0.0") : settings.pan.macAddress
        return PolicyPlanner.plan(rules: rules, descriptions: descriptions, macAddress: mac,
                                  lockdown: settings.lockdown, mirrorLockdown: settings.pan.mirrorLockdown)
    }

    func syncFirewall() async {
        guard settings.pan.enabled, !syncing else { return }
        syncing = true
        let report = await PolicySync.apply(shadowPlan(), client: panClient)
        syncReport = report
        syncing = false
    }

    // MARK: Persistence

    private struct Saved: Codable {
        var profiles: [Profile]
        var rules: [Rule]
        var settings: AppSettings
        var decisions: [Decision]?
        var intel: [IPIntel]?
        var findings: [Finding]?
        var edrBaseline: [String]?
        var vulnFindings: [VulnFinding]?
        var components: [Component]?
        var remediations: [RemediationRecord]?
        var newVulnIDs: [String]?
        var membership: Membership?
        var sharedRules: [SharedRule]?
        var scanHosts: [ScannedHost]?
        var suppressedFindingKeys: [String]? = nil
        var wireCursor: Double? = nil
    }

    private var stateURL: URL { dir.appendingPathComponent("state.json") }

    private var signingKey: SymmetricKey?
    /// Set when the saved state failed verification at launch.
    @Published var tamperAlert: String?

    private func load() {
        guard let file = try? Data(contentsOf: stateURL) else { signingKey = StateGuard.existingKey() ?? StateGuard.createKey(); return }
        let key = StateGuard.existingKey()
        let (data, sig) = StateGuard.open(file)
        switch StateGuard.check(data: data, signature: sig, key: key) {
        case .valid:
            signingKey = key
        case .firstUse:
            signingKey = StateGuard.createKey()   // adopt the existing file once; every save is signed from now on
        case .tampered(let why):
            recoverFromTampering(why)
            return
        }
        guard let s = try? JSONDecoder.elliott.decode(Saved.self, from: data) else { return }
        profiles = Dictionary(s.profiles.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        rules = s.rules
        settings = s.settings
        decisions = s.decisions ?? []
        findings = s.findings ?? []
        suppressedFindingKeys = Set(s.suppressedFindingKeys ?? [])
        wireCursor = s.wireCursor ?? 0
        edrBaseline = s.edrBaseline ?? []
        vulnFindings = s.vulnFindings ?? []
        components = s.components ?? []
        remediations = s.remediations ?? []
        newVulnIDs = Set(s.newVulnIDs ?? [])
        savedMembership = s.membership
        savedSharedRules = s.sharedRules ?? []
        scanHosts = s.scanHosts ?? []
        // Intel older than a week is re-checked from scratch.
        intel = Dictionary((s.intel ?? []).filter { Date().timeIntervalSince($0.checked) < 7 * 86400 }.map { ($0.ip, $0) },
                           uniquingKeysWith: { a, _ in a })
    }

    /// The file can't be trusted: set it aside for inspection, and take rules and lockdown from the helper's
    /// root-owned copy of the last policy Elliott pushed (if there is one).
    private func recoverFromTampering(_ why: String) {
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        try? FileManager.default.moveItem(at: stateURL, to: dir.appendingPathComponent("state.tampered-\(stamp).json"))
        // The file was altered, not the key: keep it, so a genuine copy can still be verified and restored.
        signingKey = StateGuard.existingKey() ?? StateGuard.createKey()
        var message = "Elliott's saved data failed its integrity check (\(why)). It was set aside as state.tampered-\(stamp).json"
        if let policy = StateGuard.helperPolicy() {
            rules = policy.rules
            settings.lockdown = policy.lockdown
            message += ". Rules and lockdown were restored from the helper's protected copy."
        } else {
            message += ". No protected copy of your rules exists (the helper isn't installed), so they start empty."
        }
        tamperAlert = message
        let content = UNMutableNotificationContent()
        content.title = "Elliott's data was tampered with"
        content.body = message
        content.sound = .defaultCritical
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { ok, _ in
            if ok { center.add(UNNotificationRequest(identifier: "tamper-\(stamp)", content: content, trigger: nil)) }
        }
        scheduleSave()
    }

    /// Copies set aside after failed integrity checks, newest first.
    var quarantinedStates: [URL] {
        ((try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.lastPathComponent.hasPrefix("state.tampered-") }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    /// Loads a quarantined copy the user has decided to trust (after a false alarm), then re-signs it. Its rules
    /// replace the current ones, so the user confirms first.
    func restoreQuarantined(_ url: URL) {
        guard let file = try? Data(contentsOf: url) else { return }
        let (json, _) = StateGuard.open(file)
        guard let s = try? JSONDecoder.elliott.decode(Saved.self, from: json) else {
            tamperAlert = "\(url.lastPathComponent) couldn't be read as Elliott data."
            return
        }
        let added = Set(s.rules.map(\.id)).subtracting(rules.map(\.id)).count
        guard Confirm.run(title: "Restore \(url.lastPathComponent)?",
                          message: "It contains \(s.rules.count) rules (\(added) not in your current set), \(s.profiles.count) connections and \(s.vulnFindings?.count ?? 0) vulnerability findings. Only restore it if you're sure nothing else edited it: its rules will be enforced.",
                          action: "Restore and Re-sign", destructive: true) else { return }
        profiles = Dictionary(s.profiles.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        rules = s.rules
        settings = s.settings
        decisions = s.decisions ?? []
        findings = s.findings ?? []
        edrBaseline = s.edrBaseline ?? []
        vulnFindings = s.vulnFindings ?? []
        components = s.components ?? []
        remediations = s.remediations ?? []
        newVulnIDs = Set(s.newVulnIDs ?? [])
        intel = Dictionary((s.intel ?? []).map { ($0.ip, $0) }, uniquingKeysWith: { a, _ in a })
        try? FileManager.default.removeItem(at: url)
        tamperAlert = nil
        rulesChanged()
    }

    private func scheduleSave() {
        guard !Self.isTestHost else { return }
        saveTask?.cancel()
        saveTask = Task {
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            let saved = Saved(profiles: Array(profiles.values), rules: rules, settings: settings,
                              decisions: decisions, intel: Array(intel.values),
                              findings: findings, edrBaseline: edrBaseline,
                              vulnFindings: vulnFindings, components: components, remediations: remediations,
                              newVulnIDs: Array(newVulnIDs),
                              membership: mesh?.membership ?? savedMembership, sharedRules: mesh?.allSharedRules ?? savedSharedRules,
                              scanHosts: scanHosts, suppressedFindingKeys: Array(suppressedFindingKeys),
                              wireCursor: wireCursor)
            guard let data = try? JSONEncoder.elliott.encode(saved) else { return }
            let key = signingKey ?? StateGuard.existingKey() ?? StateGuard.createKey()
            signingKey = key
            try? StateGuard.seal(data, key: key).write(to: stateURL, options: .atomic)   // one atomic write
            if !StateGuard.signingEstablished, helper.connected { _ = await helper.markStateSigned() }
        }
    }
}

/// The running-process list (see AppModel.processStore).
@MainActor
final class ProcessStore: ObservableObject {
    @Published var list: [ProcInfo] = []
}
