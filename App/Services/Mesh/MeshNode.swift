import Foundation
import Network
import os

private let log = Logger(subsystem: ElliottIDs.appBundleID, category: "mesh")

struct MeshSettings: Codable, Equatable {
    enum LLMRoute: Codable, Equatable, Hashable { case automatic, local, node(UUID) }
    var enabled = false
    var llmRoute: LLMRoute = .automatic
    /// Run LLM jobs for other nodes on this Mac.
    var shareLLM = true

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        llmRoute = try c.decodeIfPresent(LLMRoute.self, forKey: .llmRoute) ?? .automatic
        shareLLM = try c.decodeIfPresent(Bool.self, forKey: .shareLLM) ?? true
    }
}

/// Elliott's peer-to-peer layer: discovery (Bonjour), joining with human-confirmed codes, and replication of the
/// roster, shared rules, per-node reports and load status over post-quantum encrypted links.
@MainActor
final class MeshNode: ObservableObject {
    struct PendingJoin: Identifiable {
        var id: UUID { node.id }
        var node: NodeInfo
        var sas: String
        var peer: MeshPeer
        var since = Date()
    }
    struct DiscoveredNetwork: Identifiable, Hashable {
        var id: UUID          // network id
        var name: String
        var via: String       // node name advertising it
        var endpoint: NWEndpoint
        static func == (a: Self, b: Self) -> Bool { a.id == b.id && a.via == b.via }
        func hash(into h: inout Hasher) { h.combine(id); h.combine(via) }
    }
    enum JoinState: Equatable {
        case connecting(String)
        case waiting(sas: String, network: String)
        case approved(String)
        case rejected(String)
        case failed(String)
    }

    static let serviceType = "_elliott._tcp"

    let identity: NodeIdentity
    @Published private(set) var membership: Membership?
    @Published private(set) var connected: [UUID: NodeInfo] = [:]
    @Published private(set) var pendingJoins: [PendingJoin] = []
    @Published private(set) var discovered: [DiscoveredNetwork] = []
    @Published private(set) var joinState: JoinState?
    @Published private(set) var reports: [UUID: NodeReport] = [:]
    @Published private(set) var statuses: [UUID: NodeStatus] = [:]
    @Published private(set) var listeningPort: UInt16?
    private(set) var sharedRules: [UUID: SharedRule] = [:]

    // Hooks into the app.
    var applyRemoteRules: (([SharedRule]) -> Void)?
    var localReport: (() -> NodeReport)?
    var localStatus: (() -> NodeStatus)?
    var runLLM: ((String, String, Data) async throws -> String)?
    var onChange: (() -> Void)?
    var onJoinRequest: ((NodeInfo, String) -> Void)?
    /// This Mac just created or joined a network: time to publish its existing rules.
    var onMembershipEstablished: (() -> Void)?

    private var peers: [ObjectIdentifier: MeshPeer] = [:]
    private var memberPeers: [UUID: MeshPeer] = [:]
    private var listener: NWListener?
    private var browser: NWBrowser?
    private var timers: [Task<Void, Never>] = []
    private var llmWaiters: [UUID: CheckedContinuation<String, Error>] = [:]
    private var lastReportHash = 0
    private var joinPeer: MeshPeer?
    private var joinAttempts: [String: [Date]] = [:]

    var isMember: Bool { membership != nil }
    var members: [UUID: NodeInfo] { membership?.members ?? [:] }

    init(identity: NodeIdentity, membership: Membership?, sharedRules: [SharedRule]) {
        self.identity = identity
        self.membership = membership
        for r in sharedRules { self.sharedRules[r.rule.id] = r }
    }

    // MARK: Lifecycle

    /// `discovery: false` skips Bonjour (tests, manual setups): peers are then dialed by address.
    func start(discovery: Bool = true) {
        guard listener == nil else { return }
        do {
            let params = NWParameters.tcp
            params.includePeerToPeer = false
            let l = try NWListener(using: params)
            if discovery { l.service = advertisedService() }
            l.newConnectionHandler = { [weak self] c in Task { @MainActor in self?.accept(c) } }
            l.stateUpdateHandler = { [weak self] state in
                if case .ready = state { Task { @MainActor in self?.listeningPort = self?.listener?.port?.rawValue; self?.onChange?() } }
                if case .failed(let e) = state { log.error("listener: \(e.localizedDescription, privacy: .public)") }
            }
            l.start(queue: .main)
            listener = l
        } catch {
            log.error("listener failed: \(error.localizedDescription, privacy: .public)")
        }
        if discovery {
            let b = NWBrowser(for: .bonjourWithTXTRecord(type: Self.serviceType, domain: nil), using: .tcp)
            b.browseResultsChangedHandler = { [weak self] results, _ in Task { @MainActor in self?.browsed(results) } }
            b.start(queue: .main)
            browser = b
        }
        timers = [
            periodic(15) { [weak self] in self?.broadcastStatus() },
            periodic(60) { [weak self] in self?.broadcastReport(force: false) },
            periodic(30) { [weak self] in self?.expireJoins() },
        ]
    }

    func stop() {
        timers.forEach { $0.cancel() }
        timers = []
        listener?.cancel(); listener = nil
        browser?.cancel(); browser = nil
        for p in peers.values { p.close("stopped") }
        peers.removeAll(); memberPeers.removeAll(); connected.removeAll()
        listeningPort = nil
    }

    private func periodic(_ seconds: Double, _ work: @escaping @MainActor () -> Void) -> Task<Void, Never> {
        Task { @MainActor in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(seconds))
                work()
            }
        }
    }

    private func advertisedService() -> NWListener.Service {
        var txt = NWTXTRecord()
        txt["node"] = identity.id.uuidString
        txt["name"] = identity.name
        if let m = membership { txt["net"] = m.networkID.uuidString; txt["netname"] = m.name }
        return NWListener.Service(name: "Elliott \(identity.name) \(identity.id.uuidString.prefix(4))", type: Self.serviceType, txtRecord: txt)
    }

    private func readvertise() { if browser != nil { listener?.service = advertisedService() } }

    // MARK: Network membership

    func createNetwork(name: String) throws {
        membership = try Membership.found(name: name, by: identity)
        readvertise()
        onMembershipEstablished?()
        onChange?()
    }

    func leaveNetwork() {
        for p in memberPeers.values { p.close("left network") }
        memberPeers.removeAll(); connected.removeAll(); reports.removeAll(); statuses.removeAll()
        membership = nil
        readvertise()
        onChange?()
    }

    func remove(_ node: UUID) throws {
        guard var m = membership, let info = m.members[node], node != identity.id else { return }
        m.entries.append(try MemberEntry.signed(node: info, networkID: m.networkID, by: identity, removed: true))
        membership = m
        broadcast(.membership(m))
        memberPeers[node]?.close("removed from network")
        reports[node] = nil; statuses[node] = nil
        onChange?()
    }

    // MARK: Discovery

    private func browsed(_ results: Set<NWBrowser.Result>) {
        var found: [DiscoveredNetwork] = []
        for r in results {
            guard case .bonjour(let txt) = r.metadata, let nodeStr = txt["node"], let nodeID = UUID(uuidString: nodeStr),
                  nodeID != identity.id else { continue }
            if let netStr = txt["net"], let net = UUID(uuidString: netStr) {
                found.append(DiscoveredNetwork(id: net, name: txt["netname"] ?? "Elliott network", via: txt["name"] ?? "?", endpoint: r.endpoint))
                // Members connect to members; the lower id dials so each pair has one link.
                if let m = membership, net == m.networkID, m.members[nodeID] != nil, memberPeers[nodeID] == nil,
                   identity.id.uuidString < nodeID.uuidString {
                    dial(r.endpoint, expecting: nodeID)
                }
            }
        }
        if Set(found) != Set(discovered) { discovered = found.sorted { $0.name < $1.name } }
    }

    private func dial(_ endpoint: NWEndpoint, expecting node: UUID) {
        guard let m = membership else { return }
        let peer = MeshPeer(connection: NWConnection(to: endpoint, using: .tcp), role: .initiator)
        peer.admitReply = { reply in reply.node.id == node && m.isMember(reply.node) }
        wire(peer)
        peer.startInitiator(identity: identity, purpose: .member, networkID: m.networkID)
    }

    /// For tests and manual connections.
    func dial(host: String, port: UInt16, expecting node: UUID) {
        dial(.hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!), expecting: node)
    }

    // MARK: Joining (new node side)

    func join(_ network: DiscoveredNetwork) { join(endpoint: network.endpoint, networkID: network.id, name: network.name) }

    private var joinEndpoint: NWEndpoint?

    func join(endpoint: NWEndpoint, networkID: UUID, name: String) {
        guard membership == nil else { return }
        joinState = .connecting(name)
        joinEndpoint = endpoint
        let peer = MeshPeer(connection: NWConnection(to: endpoint, using: .tcp), role: .initiator)
        peer.admitReply = { _ in true }   // trust comes from the people comparing codes, not from this step
        joinPeer = peer
        wire(peer)
        peer.startInitiator(identity: identity, purpose: .join, networkID: networkID)
    }

    func cancelJoin() {
        joinPeer?.close("cancelled")
        joinPeer = nil
        joinState = nil
    }

    // MARK: Joining (member side)

    func approve(_ join: PendingJoin) throws {
        guard var m = membership else { return }
        m.entries.append(try MemberEntry.signed(node: join.node, networkID: m.networkID, by: identity))
        membership = m
        join.peer.send(.joinApproved(m))
        pendingJoins.removeAll { $0.id == join.id }
        broadcast(.membership(m))
        onChange?()
        // The new node reconnects as a member; this link was only for the request.
        Task { try? await Task.sleep(for: .seconds(2)); join.peer.close("joined") }
    }

    func reject(_ join: PendingJoin) {
        join.peer.send(.joinRejected("Not approved on \(identity.name)."))
        pendingJoins.removeAll { $0.id == join.id }
        Task { try? await Task.sleep(for: .seconds(1)); join.peer.close("rejected") }
    }

    private func expireJoins() {
        for j in pendingJoins where Date().timeIntervalSince(j.since) > 120 { reject(j) }
    }

    // MARK: Connections

    private func accept(_ c: NWConnection) {
        let peer = MeshPeer(connection: c, role: .responder)
        let host = peer.remoteHost ?? "?"
        // Rate-limit join attempts per address.
        let recent = (joinAttempts[host] ?? []).filter { Date().timeIntervalSince($0) < 300 }
        joinAttempts[host] = recent
        let m = membership
        let busy = pendingJoins.count >= 3
        peer.admitHello = { [weak self] hello in
            guard let m, hello.networkID == m.networkID else { return false }
            switch hello.purpose {
            case .member: return m.isMember(hello.node)
            case .join:
                guard !busy, recent.count < 5, !m.isMember(hello.node) else { return false }
                Task { @MainActor in self?.joinAttempts[host, default: []].append(Date()) }
                return true
            }
        }
        wire(peer)
        peer.startResponder(identity: identity)
    }

    private func wire(_ peer: MeshPeer) {
        peers[ObjectIdentifier(peer)] = peer
        peer.onReady = { [weak self] p in Task { @MainActor in self?.ready(p) } }
        peer.onMessage = { [weak self] p, m in Task { @MainActor in self?.handle(m, from: p) } }
        peer.onClose = { [weak self] p, reason in Task { @MainActor in self?.closed(p, reason: reason) } }
    }

    private func ready(_ peer: MeshPeer) {
        guard let remote = peer.remote else { return }
        switch (peer.role, peer.purpose) {
        case (.responder, .join):
            let sas = peer.keys?.sas ?? "?"
            pendingJoins.removeAll { $0.id == remote.id }
            pendingJoins.append(PendingJoin(node: remote, sas: sas, peer: peer))
            peer.send(.joinPending(sas: sas))
            onJoinRequest?(remote, sas)
            onChange?()
        case (.initiator, .join):
            break   // wait for joinPending
        default:
            if let old = memberPeers[remote.id], old !== peer { old.close("replaced") }
            memberPeers[remote.id] = peer
            connected[remote.id] = remote
            if let m = membership { peer.send(.membership(m)) }
            peer.send(.rules(Array(sharedRules.values)))
            if let s = localStatus?() { peer.send(.status(s)) }
            broadcastReport(force: true, to: peer)
            onChange?()
        }
    }

    private func closed(_ peer: MeshPeer, reason: String?) {
        peers[ObjectIdentifier(peer)] = nil
        if let r = peer.remote, memberPeers[r.id] === peer {
            memberPeers[r.id] = nil
            connected[r.id] = nil
            onChange?()
        }
        pendingJoins.removeAll { $0.peer === peer }
        if peer === joinPeer, case .waiting = joinState { joinState = .failed(reason ?? "connection closed") }
    }

    // MARK: Messages

    private func handle(_ message: MeshMessage, from peer: MeshPeer) {
        guard let remote = peer.remote else { return }
        // Join-flow messages only make sense on the joining node's request link.
        if peer === joinPeer {
            switch message {
            case .joinPending(let sas):
                // Show the code this Mac computed itself. The person approving compares it with the code on their
                // screen; an interceptor running two handshakes can't make those match.
                guard let mine = peer.keys?.sas else { return }
                if mine == sas { joinState = .waiting(sas: mine, network: discovered.first?.name ?? "network") }
                else { joinState = .failed("codes differ: possible interception"); peer.close("sas mismatch") }
            case .joinApproved(let m):
                // The roster must include us, admitted by the node we're talking to.
                if m.members[identity.id]?.publicKey == identity.info.publicKey, m.members[remote.id] != nil {
                    membership = m
                    joinState = .approved(m.name)
                    readvertise()
                    onMembershipEstablished?()
                    onChange?()
                    // Reconnect to the node that admitted us, now as a member.
                    if let ep = joinEndpoint {
                        let admitter = remote.id
                        Task { @MainActor in
                            try? await Task.sleep(for: .milliseconds(500))
                            self.dial(ep, expecting: admitter)
                        }
                    }
                } else {
                    joinState = .failed("the approval didn't include this Mac")
                }
                joinPeer = nil
                peer.close("joined")
            case .joinRejected(let why):
                joinState = .rejected(why)
                joinPeer = nil
            default: break
            }
            return
        }
        guard memberPeers[remote.id] === peer else { return }   // only full members past this point
        switch message {
        case .membership(let m):
            guard var mine = membership else { return }
            if mine.merge(m) {
                membership = mine
                if mine.members[identity.id] == nil { leaveNetwork(); return }   // we were removed
                for (id, p) in memberPeers where mine.members[id] == nil { p.close("removed") }
                broadcast(.membership(mine), except: peer)
                onChange?()
            }
        case .rules(let list):
            let accepted = merge(list)
            if !accepted.isEmpty {
                applyRemoteRules?(accepted)
                broadcast(.rules(accepted), except: peer)
                onChange?()
            }
        case .report(let blob):
            guard let json = MeshCodec.decompress(blob), let r = try? MeshCodec.decode(NodeReport.self, json),
                  r.node.id == remote.id else { return }
            reports[remote.id] = r
            onChange?()
        case .status(let s):
            guard s.node == remote.id else { return }
            statuses[remote.id] = s
        case .llmRequest(let id, let system, let user, let schema):
            Task { @MainActor in
                do {
                    guard let run = self.runLLM else { throw URLError(.unsupportedURL) }
                    let content = try await run(system, user, schema)
                    peer.send(.llmResponse(id: id, content: content, error: nil))
                } catch {
                    peer.send(.llmResponse(id: id, content: nil, error: error.localizedDescription))
                }
            }
        case .llmResponse(let id, let content, let error):
            guard let waiter = llmWaiters.removeValue(forKey: id) else { return }
            if let content { waiter.resume(returning: content) } else { waiter.resume(throwing: RemoteLLMError.failed(error ?? "remote error")) }
        case .ping: peer.send(.pong)
        default: break
        }
    }

    private func broadcast(_ m: MeshMessage, except: MeshPeer? = nil) {
        for p in memberPeers.values where p !== except { p.send(m) }
    }

    // MARK: Shared rules

    /// Accepts rules signed by current members that are newer than what we have. Returns the ones applied.
    @discardableResult
    func merge(_ incoming: [SharedRule]) -> [SharedRule] {
        let members = self.members
        var applied: [SharedRule] = []
        for s in incoming {
            guard let origin = members[s.origin], origin.verify(s.signature, over: s.signedBytes) else { continue }
            if let mine = sharedRules[s.rule.id], !s.isNewer(than: mine) { continue }
            sharedRules[s.rule.id] = s
            applied.append(s)
        }
        return applied   // the caller applies them, then announces the change (never the other way round)
    }

    /// Diffs the local rule set against what the network has and publishes signed changes.
    func publishLocal(rules local: [Rule]) {
        guard isMember else { return }
        var changed: [SharedRule] = []
        let shareable = local.filter { $0.expires == nil }   // "allow once" stays local
        let ids = Set(shareable.map(\.id))
        for r in shareable {
            let canonical = SharedRule.canonical(r)
            if let s = sharedRules[r.id], !s.deleted, s.rule == canonical { continue }
            if let s = try? SharedRule.make(r, by: identity) { sharedRules[r.id] = s; changed.append(s) }
        }
        for (id, s) in sharedRules where !s.deleted && !ids.contains(id) {
            if let t = try? SharedRule.make(s.rule, deleted: true, by: identity) { sharedRules[id] = t; changed.append(t) }
        }
        if !changed.isEmpty { publish(rules: changed) }
    }

    private func publish(rules: [SharedRule]) { broadcast(.rules(rules)) }

    var allSharedRules: [SharedRule] { Array(sharedRules.values) }

    // MARK: Reports & status

    func broadcastStatus() {
        guard let s = localStatus?() else { return }
        statuses[identity.id] = s
        broadcast(.status(s))
    }

    func broadcastReport(force: Bool, to only: MeshPeer? = nil) {
        guard isMember, let r = localReport?(), let json = try? MeshCodec.encode(r) else { return }
        let h = json.hashValue
        guard force || h != lastReportHash else { return }
        lastReportHash = h
        reports[identity.id] = r
        let blob = MeshCodec.compress(json)
        if let only { only.send(.report(blob)) } else { broadcast(.report(blob)) }
    }

    // MARK: Remote LLM

    enum RemoteLLMError: LocalizedError {
        case notConnected, timeout, failed(String)
        var errorDescription: String? {
            switch self {
            case .notConnected: "that node isn't connected"
            case .timeout: "the node didn't answer in time"
            case .failed(let s): "remote LLM: \(s)"
            }
        }
    }

    func remoteLLM(on node: UUID, system: String, user: String, schema: Data) async throws -> String {
        guard let peer = memberPeers[node] else { throw RemoteLLMError.notConnected }
        let id = UUID()
        return try await withCheckedThrowingContinuation { cont in
            llmWaiters[id] = cont
            peer.send(.llmRequest(id: id, system: system, user: user, schema: schema))
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(180))
                if let w = self.llmWaiters.removeValue(forKey: id) { w.resume(throwing: RemoteLLMError.timeout) }
            }
        }
    }

    var connectedPeerHosts: [String] { memberPeers.values.compactMap(\.remoteHost) }
}
