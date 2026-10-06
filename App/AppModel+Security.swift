import AppKit
import CryptoKit
import Foundation

/// State for the behavioral detections, posture audit, event log and integrations, observed by their own views
/// (kept off AppModel's published properties so it doesn't re-render the whole window).
@MainActor
final class SecurityStore: ObservableObject {
    @Published var posture: PostureReport?
    @Published var postureRunning = false
    @Published var correlations: [Correlator.Signal] = []
    @Published var integrationStatus: [UUID: Integrations.Status] = [:]
    @Published var tlsFeedCount = 0
    @Published var malwareHashCount = 0
    @Published var lastFileScan: Date?
    @Published var fileScanning = false
}

/// Mutable detector state (lives on the main actor with AppModel).
@MainActor
final class SecurityState {
    var beacons = BeaconDetector()
    var dns = DNSAnalytics()
    var volume = VolumeBaseline()
    var lanKnown: Set<String> = []
    var lanBaselined = false
    var tls = TLSFingerprintList()
    let files = FileScanner()
    let domainAge = DomainAge()
    var checkedDomains: Set<String> = []
    var pendingTLS: [String: (ja3: String?, ja4: String?, time: Date)] = [:]
    var reportedCorrelations: Set<String> = []
    var log: EventLog?
    var integrations = Integrations(build: AppModel.appBuild)
}

extension AppModel {
    // MARK: Setup

    func setUpSecurity() {
        guard !Self.isTestHost else { return }
        // The event log's MAC key is derived from the state-signing key (Keychain), not stored anywhere else.
        let base = StateGuard.existingKey() ?? StateGuard.createKey()
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: base, info: Data("elliott-eventlog-v1".utf8), outputByteCount: 32)
        sec.log = EventLog(path: dir.appendingPathComponent("events.sqlite"), key: key)
        Task { await sec.integrations.configure(settings.integrations) }

        passive.onBytesSent = { [weak self] perApp in Task { @MainActor in self?.volumeSample(perApp) } }

        jobs.every("feeds-detect", interval: 6 * 3600) { [weak self] in await self?.refreshDetectionFeeds() }
        jobs.every("lan-watch", interval: 300) { [weak self] in await self?.lanWatch() }
        jobs.every("correlate", interval: 300) { [weak self] in self?.correlate() }
        jobs.every("file-scan", interval: 600) { [weak self] in await self?.scanFiles() }
        jobs.every("posture", interval: 6 * 3600) { [weak self] in await self?.runPostureAudit() }
        jobs.every("log-prune", interval: 86400) { [weak self] in
            guard let self else { return }
            self.sec.log?.prune(olderThan: self.settings.logging.retentionDays)
        }
        // Independent, so one waiting step (the file scan can sit on macOS's folder-access prompt for Desktop or
        // Downloads until the user answers) doesn't hold up the rest.
        Task { try? await Task.sleep(for: .seconds(30)); await refreshDetectionFeeds() }
        Task { try? await Task.sleep(for: .seconds(40)); await lanWatch() }
        Task {
            try? await Task.sleep(for: .seconds(50))
            if securityStore.posture == nil || Date().timeIntervalSince(securityStore.posture!.date) > 6 * 3600 { await runPostureAudit() }
        }
        Task { try? await Task.sleep(for: .seconds(90)); await scanFiles() }
        Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(10))
                let s = await sec.integrations.statuses()
                if s != securityStore.integrationStatus { securityStore.integrationStatus = s }
            }
        }
        logEvent(.system, .info, "Elliott started (build \(Self.appBuild))")
        if let t = tamperAlert { logEvent(.alert, .critical, "Elliott's saved data failed its integrity check", detail: ["detail": t]) }
    }

    func integrationsChanged() {
        let s = settings.integrations
        Task { await sec.integrations.configure(s) }
    }

    // MARK: Events

    /// Records an event in the local history and hands it to SIEM forwarders and alert channels.
    func logEvent(_ kind: SecurityEvent.Kind, _ severity: Severity, _ summary: String, app: String? = nil,
                  detail: [String: String] = [:], actor: String? = nil) {
        let e = SecurityEvent(time: Date(), kind: kind, severity: severity, node: nodeName, app: app,
                              summary: summary, detail: detail, actor: actor)
        if settings.logging.enabled && (kind != .connection || settings.logging.logConnections) { sec.log?.append(e) }
        Task { await sec.integrations.submit([e]) }
    }

    func findingEvent(_ f: Finding) {
        var d: [String: String] = ["rule": f.rule, "category": f.category.rawValue]
        if let p = f.path { d["path"] = p }
        if let c = f.commandLine { d["command"] = String(c.prefix(500)) }
        if !f.mitre.isEmpty { d["mitre"] = f.mitre.joined(separator: ",") }
        if !f.evidence.isEmpty { d["evidence"] = f.evidence.prefix(4).joined(separator: " | ") }
        logEvent(.detection, f.severity, f.title, app: f.path.map { ($0 as NSString).lastPathComponent }, detail: d)
    }

    func auditDecision(_ d: Decision) {
        let actor: String = switch d.source {
        case .manual: "you (console)"
        case .approval: "you (lockdown prompt)"
        case .edit: "you (rules)"
        case .suggestion: "you (accepted LLM suggestion)"
        }
        logEvent(.decision, .info, "\(d.verdict == .allow ? "Allowed" : "Denied") \(d.appName) → \(d.host)\(d.port.map { ":\($0)" } ?? "") (\(d.scope))",
                 app: d.appName, detail: ["verdict": d.verdict.rawValue, "scope": d.scope, "signer": d.signer], actor: actor)
    }

    func auditRules(_ changed: [Rule], removed: Bool, actor: String) {
        for r in changed.prefix(50) {
            logEvent(.rule, .info, (removed ? "Removed rule: " : "Rule: ") + r.sentence, app: r.appName,
                     detail: ["rule": r.id.uuidString], actor: actor)
        }
    }

    // MARK: Connections → beaconing, TLS fingerprints, domain age

    func securityIngest(_ events: [FlowEvent]) {
        for e in events {
            if settings.logging.logConnections && e.preexisting != true {
                logEvent(.connection, .info, "\(e.processName) → \(e.remoteHostname ?? e.remoteAddress):\(e.remotePort)",
                         app: e.processName,
                         detail: ["direction": e.direction.rawValue, "proto": e.proto.rawValue, "remote": e.remoteAddress,
                                  "path": e.processPath])
            }
            guard e.direction == .outbound, e.preexisting != true else { continue }
            attachTLS(e)
            if settings.detect.beaconing, !e.appleSigned, IPv4Set.isGlobal(e.remoteAddress) || e.remoteAddress.contains(":") {
                let dest = e.remoteHostname.map(Advisor.registrableDomain) ?? e.remoteAddress
                if let b = sec.beacons.record(app: e.processPath, destination: dest, at: e.date.timeIntervalSince1970) {
                    beaconFound(e, dest: dest, b)
                }
            }
        }
        for e in events where e.direction == .outbound {
            if let h = e.remoteHostname { checkDomain(h, event: e) }
        }
    }

    private func beaconFound(_ e: FlowEvent, dest: String, _ b: BeaconDetector.Beacon) {
        let unsigned = e.teamID == nil
        let bad = (intel[e.remoteAddress]?.reputation ?? .unknown) >= .suspicious
        let sev: Severity = bad ? .critical : unsigned ? .high : .low
        let every = b.interval >= 120 ? "\(Int((b.interval / 60).rounded())) min" : "\(Int(b.interval.rounded())) s"
        observe([Observation(
            key: "net.beacon|\(e.processPath)|\(dest)",
            draft: Draft(rule: "net.beacon", title: "Regular check-ins to \(dest)",
                         detail: "\(e.processName) connected to \(dest) every \(every) (±\(Int(b.jitter * 100))%) across \(b.count) connections. Malware checks in with its controller on a timer like this; so do some legitimate updaters and sync clients.",
                         severity: sev, category: .network, mitre: ["T1071", "T1573"],
                         evidence: ["interval \(Int(b.interval)) s, jitter \(String(format: "%.0f", b.jitter * 100))%", "\(unsigned ? "not signed by a developer" : "signed: team \(e.teamID ?? "?")")"]),
            path: e.processPath)])
    }

    /// SNI observations carry the ClientHello fingerprints; they're matched to their connection by local port.
    func securityNames(_ batch: NameBatch) {
        for s in batch.sni where s.ja3 != nil || s.ja4 != nil {
            sec.pendingTLS["\(s.localPort)|\(s.remoteIP)"] = (s.ja3, s.ja4, Date())
            if let e = recent.prefix(300).first(where: { $0.localPort == s.localPort && $0.remoteAddress == s.remoteIP }) { attachTLS(e) }
        }
        sec.pendingTLS = sec.pendingTLS.filter { Date().timeIntervalSince($0.value.time) < 120 }
        guard settings.detect.dnsAnalytics else { return }
        for q in batch.queries ?? [] {
            switch sec.dns.feed(q) {
            case .generatedDomains(let n, let examples)?:
                observe([Observation(key: "dns.dga|\(Int(q.time / 3600))",
                                     draft: Draft(rule: "dns.dga", title: "Bursts of lookups for random-looking domains",
                                                  detail: "\(n) different random-looking domains failed to resolve within 10 minutes (e.g. \(examples.joined(separator: ", "))). Malware with a domain-generation algorithm does this while hunting for its controller.",
                                                  severity: .high, category: .network, mitre: ["T1568.002"], evidence: examples),
                                     path: nil)])
            case .tunnelling(let domain, let subs, let avg, let txt)?:
                observe([Observation(key: "dns.tunnel|\(domain)",
                                     draft: Draft(rule: "dns.tunnel", title: "Possible DNS tunnelling via \(domain)",
                                                  detail: "\(subs) unique subdomains of \(domain) (average name length \(avg))\(txt > 0 ? " and \(txt) TXT/NULL lookups" : "") in 10 minutes. Data can be smuggled out inside DNS names this way.",
                                                  severity: .high, category: .network, mitre: ["T1071.004", "T1048"],
                                                  evidence: ["\(subs) subdomains", "avg length \(avg)", "\(txt) TXT/NULL"]),
                                     path: nil)])
            case nil: break
            }
        }
    }

    private func attachTLS(_ e: FlowEvent) {
        guard let fp = sec.pendingTLS.removeValue(forKey: "\(e.localPort ?? 0)|\(e.remoteAddress)") else { return }
        let id = e.key.id
        var tags = profiles[id]?.tlsFingerprints ?? []
        for t in [fp.ja4.map { "JA4 " + $0 }, fp.ja3.map { "JA3 " + $0 }].compactMap({ $0 }) where !tags.contains(t) { tags.append(t) }
        setTLSFingerprints(id, Array(tags.suffix(6)))
        guard settings.detect.tlsFingerprints,
              let why = sec.tls.reason(ja3: fp.ja3, ja4: fp.ja4, custom: settings.detect.customTLSFingerprints) else { return }
        observe([Observation(key: "tls.fingerprint|\(e.processPath)|\(fp.ja3 ?? fp.ja4 ?? "")",
                             draft: Draft(rule: "tls.fingerprint", title: "Malware TLS fingerprint",
                                          detail: "\(e.processName)'s TLS handshake to \(e.remoteHostname ?? e.remoteAddress) matches a known-malicious client: \(why).",
                                          severity: .critical, category: .network, mitre: ["T1071.001", "T1573"],
                                          evidence: [fp.ja3.map { "JA3 \($0)" }, fp.ja4.map { "JA4 \($0)" }].compactMap { $0 }),
                             path: e.processPath)])
    }

    /// Random-looking or brand-new domains contacted by non-Apple software.
    private func checkDomain(_ host: String, event e: FlowEvent) {
        let domain = Advisor.registrableDomain(host)
        guard !e.appleSigned, domain.contains("."), !sec.checkedDomains.contains(domain) else { return }
        sec.checkedDomains.insert(domain)
        if sec.checkedDomains.count > 50_000 { sec.checkedDomains.removeAll() }
        if settings.detect.dnsAnalytics, let label = DomainShape.registeredLabel(domain), DomainShape.randomness(label) >= 0.75 {
            observe([Observation(key: "dns.random|\(e.processPath)|\(domain)",
                                 draft: Draft(rule: "dns.random", title: "Connection to a random-looking domain",
                                              detail: "\(e.processName) connected to \(host), whose registered name looks machine-generated.",
                                              severity: e.teamID == nil ? .medium : .low, category: .network, mitre: ["T1568.002"],
                                              evidence: [domain]), path: e.processPath)])
        }
        guard settings.detect.domainAge else { return }
        let app = e.processName, path = e.processPath
        Task {
            guard let reg = await sec.domainAge.registered(domain) else { return }
            let days = Int(Date().timeIntervalSince(reg) / 86400)
            guard days < 30 else { return }
            observe([Observation(key: "dns.newdomain|\(path)|\(domain)",
                                 draft: Draft(rule: "dns.newdomain", title: "Connection to a newly registered domain",
                                              detail: "\(app) connected to \(domain), registered \(days) day\(days == 1 ? "" : "s") ago. Phishing and malware infrastructure is usually brand new.",
                                              severity: days < 7 ? .high : .medium, category: .network, mitre: ["T1583.001"],
                                              evidence: ["registered \(reg.formatted(date: .abbreviated, time: .omitted))"]),
                                 path: path)])
        }
    }

    // MARK: Outbound volume

    private func volumeSample(_ perApp: [String: Double]) {
        guard settings.detect.volumeAnomalies else { return }
        let now = Date().timeIntervalSince1970
        for (path, bytes) in perApp {
            guard let spike = sec.volume.add(app: path, bytes: bytes, at: now) else { continue }
            let mb = Int(spike.bytes / 1_000_000)
            let usual = spike.usual.map { "\(Int($0 / 1_000_000)) MB" } ?? "no history yet"
            let name = (path as NSString).lastPathComponent
            let signer = Signers.shared.info(path: path, teamID: nil, appleSigned: false)
            observe([Observation(key: "net.volume|\(path)|\(Int(now / 3600))",
                                 draft: Draft(rule: "net.volume", title: "Unusually large upload from \(name)",
                                              detail: "\(name) sent \(mb) MB in the last hour; its usual busiest hour is \(usual). A sudden upload can be data being stolen (or a backup or sync catching up).",
                                              severity: signer.ruleKey == nil ? .high : .medium, category: .network, mitre: ["T1041", "T1048"],
                                              evidence: ["\(mb) MB this hour", "usual: \(usual)"]),
                                 path: path)])
        }
    }

    // MARK: LAN devices

    func lanWatch() async {
        guard settings.detect.newLANDevices else { return }
        var table = await helper.arpTable() ?? [:]
        if table.isEmpty { table = await Task.detached { NetScanner.arpTable() }.value }
        guard !table.isEmpty else { return }
        let fresh = LANWatch.newDevices(current: table, known: sec.lanKnown)
        sec.lanKnown.formUnion(fresh.map(\.mac))
        defer { sec.lanBaselined = true; scheduleSave() }
        // The first look only learns what's already there.
        guard sec.lanBaselined else {
            logEvent(.system, .info, "Learned \(fresh.count) devices on the local network (new ones will be flagged)")
            return
        }
        for d in fresh {
            let name = await Task.detached { NetScanner.reverseName(d.ip) }.value
            observe([Observation(key: "lan.new|\(d.mac)",
                                 draft: Draft(rule: "lan.new", title: "New device on your network: \(name ?? d.ip)",
                                              detail: "A device with hardware address \(d.mac) appeared at \(d.ip)\(name.map { " (\($0))" } ?? "").\(LANWatch.isRandomized(d.mac) ? " It uses a private (randomized) address, typical of phones and tablets." : "") If you don't recognize it, check your Wi-Fi password and router.",
                                              severity: .low, category: .network, mitre: ["T1200"], evidence: [d.ip, d.mac]),
                                 path: nil)])
        }
    }

    // MARK: Cross-device correlation

    func correlate() {
        guard settings.detect.correlation, mesh?.isMember == true else { return }
        let reports = networkReports
        var addresses: [UUID: [String]] = [:]
        for r in reports { addresses[r.node.id] = r.addresses ?? [] }
        let signals = Correlator.signals(reports, addresses: addresses)
        if signals != securityStore.correlations { securityStore.correlations = signals }
        for s in signals where !sec.reportedCorrelations.contains(s.key) {
            sec.reportedCorrelations.insert(s.key)
            logEvent(.detection, s.severity, s.title, detail: ["devices": s.devices.joined(separator: ", "), "detail": s.detail, "rule": "correlation"])
            notify(id: s.key, title: s.title, body: s.detail, critical: s.severity >= .critical)
        }
        scheduleSave()
    }

    // MARK: Files

    func scanFiles() async {
        guard settings.detect.fileScanning, !securityStore.fileScanning else { return }
        securityStore.fileScanning = true
        defer { securityStore.fileScanning = false; securityStore.lastFileScan = Date() }
        var o = FileScanner.Options()
        o.extraPaths = Array(Set(launchItems.map(\.program).filter { $0.hasPrefix("/") }))
        if settings.detect.virusTotalFiles { o.virusTotalKey = Keychain.get("virustotal-key") }
        if settings.detect.malwareBazaar { o.malwareBazaarKey = Keychain.get("malwarebazaar-key") }
        o.yaraRules = settings.detect.yaraRulesFolder
        let scanner = sec.files
        let verdicts = await scanner.scan(o)
        for v in verdicts {
            guard let sev = v.severity else { continue }
            let name = (v.path as NSString).lastPathComponent
            var evidence = ["SHA-256 \(v.sha256)", "signature: \(v.signer)"]
            if let o = v.origin { evidence.append("downloaded from \(o)") }
            evidence += v.hits
            observe([Observation(key: "file|\(v.sha256)",
                                 draft: Draft(rule: v.hits.contains { $0.hasPrefix("YARA") } ? "file.yara" : "file.reputation",
                                              title: sev >= .high ? "Malicious file: \(name)" : "Suspicious file: \(name)",
                                              detail: "\(v.path): \(v.hits.joined(separator: "; ")).",
                                              severity: sev, category: .file, mitre: ["T1204.002", "T1105"], evidence: evidence),
                                 path: v.path)])
        }
    }

    // MARK: Feeds

    func refreshDetectionFeeds() async {
        if settings.detect.tlsFingerprints,
           let (data, resp) = try? await LimitedDownload.fetch(URLRequest(url: TLSFingerprintList.feedURL, timeoutInterval: 30), maxBytes: 4 * 1024 * 1024),
           resp.statusCode == 200 {
            var list = TLSFingerprintList()
            list.load(csv: String(decoding: data, as: UTF8.self))
            if list.count > 0 { sec.tls = list; securityStore.tlsFeedCount = list.count }
        }
        if settings.detect.fileScanning,
           let (data, resp) = try? await LimitedDownload.fetch(URLRequest(url: FileScanner.recentMalwareURL, timeoutInterval: 30), maxBytes: 8 * 1024 * 1024),
           resp.statusCode == 200 {
            sec.files.loadRecentMalware(String(decoding: data, as: UTF8.self))
            securityStore.malwareHashCount = sec.files.knownBadCount
        }
    }

    // MARK: Posture

    func runPostureAudit() async {
        guard !securityStore.postureRunning else { return }
        securityStore.postureRunning = true
        let covered = backend == .packetFilter || backend == .filter
        let report = await Task.detached { PostureAudit.run(appFirewallCovered: covered) }.value
        let previous = securityStore.posture
        securityStore.posture = report
        securityStore.postureRunning = false
        // Changes for the worse are events; risky privacy grants are detections.
        let before = Dictionary((previous?.checks ?? []).map { ($0.id, $0.status) }, uniquingKeysWith: { a, _ in a })
        for c in report.checks where c.status == .fail && before[c.id] != .fail {
            logEvent(.posture, c.weight >= 3 ? .high : .medium, "Posture: \(c.title) — failing", detail: ["detail": c.detail, "check": c.id])
        }
        for g in report.grants where g.risky {
            observe([Observation(key: "privacy.risky|\(g.service)|\(g.client)",
                                 draft: Draft(rule: "privacy.risky", title: "\(g.label) granted to an unverified program",
                                              detail: "\(g.path ?? g.client) holds \(g.label) but is \(g.signer == "missing" ? "missing from disk" : g.signer). Malware asks for these permissions to read files, record the screen or log keystrokes.",
                                              severity: g.service == "kTCCServiceListenEvent" || g.service == "kTCCServiceScreenCapture" ? .high : .medium,
                                              category: .posture, mitre: ["T1548", "T1113", "T1056.001"],
                                              evidence: ["\(g.systemWide ? "system" : "user") privacy database", g.client]),
                                 path: g.path)])
        }
        scheduleSave()
    }

    // MARK: This Mac's addresses (for cross-device correlation)

    nonisolated static func localAddresses() -> [String] {
        var out: [String] = []
        var ifa: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifa) == 0, let first = ifa else { return [] }
        defer { freeifaddrs(ifa) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) || sa.pointee.sa_family == UInt8(AF_INET6) else { continue }
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(sa.pointee.sa_family == UInt8(AF_INET) ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            if getnameinfo(sa, len, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = String(cString: buf)
                if !s.hasPrefix("127.") && s != "::1" && !s.hasPrefix("fe80") { out.append(s) }
            }
        }
        return out
    }
}
