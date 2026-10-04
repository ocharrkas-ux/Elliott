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
    @Published private(set) var intelRevision = 0   // bumps when feeds reload, for the settings view
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
    private var analysisTask: Task<Void, Never>?
    private var saveTask: Task<Void, Never>?
    private var syncTask: Task<Void, Never>?
    private var bag: Set<AnyCancellable> = []
    private let dir: URL

    enum Backend { case filter, packetFilter, none }
    /// The Network Extension filter (per-app, if this build has it) wins; else the pf helper; else observe only.
    var backend: Backend { filter.connected ? .filter : helper.connected ? .packetFilter : .none }
    var enforcing: Bool { backend != .none }
    /// Only the BastionNE build (paid developer team) is entitled to run the content-filter system extension.
    let hasFilterExtension: Bool = {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        let value = SecTaskCopyValueForEntitlement(task, "com.apple.developer.networking.networkextension" as CFString, nil)
        return (value as? [String])?.isEmpty == false
    }()

    init() {
        dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Bastion", isDirectory: true)
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
        if e.teamID == BastionIDs.teamID && e.signingID == BastionIDs.appBundleID {
            // Bastion's own traffic (threat feeds, firewall API): never ask about it.
            var r = Rule(key: e.key, appName: "Bastion", verdict: .allow, addresses: [e.remoteAddress])
            r.note = "Bastion's own traffic"
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
    /// Accepts Bastion's suggestion for these profiles.
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
        scheduleSave()
    }

    // MARK: LLM

    func reanalyze(_ ids: [String]) {
        for id in ids { analysisFailures[id] = nil; analysisQueue.removeAll { $0 == id } }
        analysisQueue.insert(contentsOf: ids, at: 0)
        pumpAnalysis()
    }

    private enum Job { case analyze(String), suggest(String) }

    /// Analysis first (it feeds suggestions), then suggestions for unclassified connections.
    private func nextJob() -> Job? {
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
                let id: String, failKey: String
                switch job {
                case .analyze(let i): id = i; failKey = i
                case .suggest(let i): id = i; failKey = "s:" + i
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
            if summary.reputation == .knownBad && !wasBad { knownBadSeen(profiles[id]!) }
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
    }

    private var stateURL: URL { dir.appendingPathComponent("state.json") }

    private func load() {
        guard let data = try? Data(contentsOf: stateURL),
              let s = try? JSONDecoder.bastion.decode(Saved.self, from: data) else { return }
        profiles = Dictionary(s.profiles.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        rules = s.rules
        settings = s.settings
        decisions = s.decisions ?? []
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
                              decisions: decisions, intel: Array(intel.values))
            if let data = try? JSONEncoder.bastion.encode(saved) { try? data.write(to: stateURL, options: .atomic) }
        }
    }
}
