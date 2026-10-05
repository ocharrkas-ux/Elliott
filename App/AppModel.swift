import AppKit
import Combine
import Foundation
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
    }
}

enum RuleScope: String, CaseIterable, Identifiable {
    case exact = "This destination and port"
    case host = "This destination, any port"
    case app = "Everything this app does"
    var id: String { rawValue }
    var label: String {
        switch self {
        case .exact: "dest + port"
        case .host: "any port"
        case .app: "everything"
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
    @Published private(set) var processes: [ProcInfo] = []
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
    private var reachQueue: [String] = []
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

    init() {
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
            self?.approvals.removeAll { $0.deadline < now }
        }.store(in: &bag)
        Timer.publish(every: 30, on: .main, in: .common).autoconnect().sink { [weak self] now in
            guard let self, self.rules.contains(where: { ($0.expires ?? .distantFuture) < now }) else { return }
            self.rules.removeAll { ($0.expires ?? .distantFuture) < now }
            self.rulesChanged(syncFirewall: false)
        }.store(in: &bag)

        Timer.publish(every: 6 * 3600, on: .main, in: .common).autoconnect().sink { [weak self] _ in
            Task { await self?.refreshIntel() }
        }.store(in: &bag)
        Task { await refreshIntel() }
        startEDR()
        Timer.publish(every: 3600, on: .main, in: .common).autoconnect().sink { [weak self] _ in self?.autoScanIfDue() }
            .store(in: &bag)
        Task { try? await Task.sleep(for: .seconds(20)); autoScanIfDue() }

        if hasFilterExtension { Task { await filter.refresh() } }
        helper.start()
        analysisQueue = profiles.values.filter { $0.analysis == nil }.sorted { $0.lastSeen > $1.lastSeen }.map(\.id)
        pumpAnalysis()
    }

    private func startPassive() {
        passive.start { [weak self] events in Task { @MainActor in self?.ingest(events) } }
    }

    // MARK: Connections

    func ingest(_ events: [FlowEvent]) {
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
        if let source { record(Decision(profile: p, verdict: verdict, source: source, scope: scope.label)) }
        var rule: Rule
        switch scope {
        case .exact: rule = Rule(key: p.key, appName: p.appName, verdict: verdict, addresses: p.addresses)
        case .host: rule = Rule(appKey: p.key.appKey, appName: p.appName, direction: p.key.direction, proto: nil,
                                host: p.key.host, port: p.key.direction == .inbound ? p.key.port : nil,
                                verdict: verdict, addresses: p.addresses)
        case .app: rule = Rule(appKey: p.key.appKey, appName: p.appName, direction: p.key.direction, proto: nil,
                               host: "*", port: nil, verdict: verdict)
        }
        rule.note = p.analysis?.description
        rule.expires = expires
        if scope == .app && backend == .packetFilter { rule.addresses = p.addresses }   // pf needs addresses
        rules.removeAll { $0.appKey == rule.appKey && $0.direction == rule.direction && $0.proto == rule.proto
            && $0.host == rule.host && $0.port == rule.port }
        rules.append(rule)
        rulesChanged()
        resolveAddresses(for: rule)
    }

    /// Removes the rule that currently decides this profile.
    /// Signer rules in force ("apple" or team ID → rule).
    func signerRule(_ key: String) -> Rule? { rules.first { $0.signer == key && $0.direction == .outbound && $0.expires == nil } }

    /// Allows (or blocks) outbound connections for every app with a verified signature from this developer.
    /// Inbound stays per-app: trusting a developer shouldn't open listening ports.
    func setSignerTrust(_ s: SignerInfo, _ verdict: Verdict?) {
        guard let key = s.ruleKey else { return }
        rules.removeAll { $0.signer == key }
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
                                  trustAppleSigned: settings.trustAppleSigned, approvalTimeout: settings.approvalTimeout)
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
        if settings.intel != old.intel { Task { await refreshIntel() } }
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
            while let self, self.settings.llm.enabled, let job = self.nextJob() {
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
                        let a = try await LocalLLM(settings: self.settings.llm).analyze(p)
                        self.profiles[id]?.analysis = a
                        self.llmStatus = "\(self.analyzedCount) of \(self.profiles.count) connections analyzed"
                    case .triage, .reach: break
                    case .suggest:
                        self.suggestingID = id
                        self.llmStatus = "Predicting your call on \(p.appName) → \(p.destination)"
                        let s = try await Advisor.suggest(p, decisions: self.learnableDecisions,
                                                          llm: LocalLLM(settings: self.settings.llm))
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

    var enabledFeeds: [Feed] { Feed.all.filter { !settings.intel.disabledFeeds.contains($0.id) } }
    var knownBadCount: Int { profiles.values.filter { $0.intel?.reputation == .knownBad }.count }

    func refreshIntel(force: Bool = false) async {
        guard !intelRefreshing else { return }
        intelRefreshing = true
        for f in Feed.all where settings.intel.disabledFeeds.contains(f.id) { threatIntel.drop(f.id) }
        await threatIntel.refresh(enabledFeeds, force: force)
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
            let online = entry.hits.filter { h in !Feed.all.contains { $0.name == h.source } }
            entry.hits = threatIntel.hits(for: ip, feeds: feeds) + online
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
            return ProcessTable.snapshot(withArgs: true)
        }
        edr.onObservations = { [weak self] obs in Task { @MainActor in self?.observe(obs) } }
        edr.onProcesses = { [weak self] procs in Task { @MainActor in self?.processes = procs } }
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

    private func observe(_ obs: [Observation]) {
        var touchedPaths: Set<String> = []
        for o in obs {
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
            let t = try await TriageLLM.triage(f, signature: sig, network: net, llm: LocalLLM(settings: settings.llm))
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
        for f in vulnFindings where !current.contains(f.id) && f.status != .fixed {
            var gone = f
            gone.status = .fixed   // no longer installed at that version
            merged.append(gone)
        }
        vulnFindings = merged
        components = r.components
        vulnErrors = r.errors
        reachQueue = merged.filter { $0.status == .open && $0.severity >= .medium && $0.reachability.llmVerdict == nil
            && [.imported, .reachable].contains($0.reachability.verdict) }
            .sorted { $0.priority > $1.priority }.map(\.id)
        refreshProfileVulns()
        scheduleSave()
        pumpAnalysis()
    }

    // MARK: Remediation

    /// Plans for open findings (optionally only some components). Runs brew/git checks off the main thread.
    func remediationPlans(for componentIDs: Set<String>? = nil) async -> [RemediationPlan] {
        let findings = vulnFindings.filter { componentIDs == nil || componentIDs!.contains($0.component.id) }
        var cfg = settings.remediation
        if componentIDs != nil { cfg.minSeverity = .info }   // asked for specific components: cover all their vulns
        return await Task.detached(priority: .userInitiated) { RemediationPlanner.plans(for: findings, settings: cfg) }.value
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
            let (verdict, why) = try await ReachabilityLLM.judge(f, llm: LocalLLM(settings: settings.llm))
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
    }

    private var stateURL: URL { dir.appendingPathComponent("state.json") }

    private func load() {
        guard let data = try? Data(contentsOf: stateURL),
              let s = try? JSONDecoder.elliott.decode(Saved.self, from: data) else { return }
        profiles = Dictionary(s.profiles.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        rules = s.rules
        settings = s.settings
        decisions = s.decisions ?? []
        findings = s.findings ?? []
        edrBaseline = s.edrBaseline ?? []
        vulnFindings = s.vulnFindings ?? []
        components = s.components ?? []
        remediations = s.remediations ?? []
        // Intel older than a week is re-checked from scratch.
        intel = Dictionary((s.intel ?? []).filter { Date().timeIntervalSince($0.checked) < 7 * 86400 }.map { ($0.ip, $0) },
                           uniquingKeysWith: { a, _ in a })
    }

    private func scheduleSave() {
        saveTask?.cancel()
        saveTask = Task {
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            let saved = Saved(profiles: Array(profiles.values), rules: rules, settings: settings,
                              decisions: decisions, intel: Array(intel.values),
                              findings: findings, edrBaseline: edrBaseline,
                              vulnFindings: vulnFindings, components: components, remediations: remediations)
            if let data = try? JSONEncoder.elliott.encode(saved) { try? data.write(to: stateURL, options: .atomic) }
        }
    }
}
