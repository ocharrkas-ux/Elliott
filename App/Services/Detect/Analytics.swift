import Foundation

// Behavioral network detections built on what Elliott already observes: connection starts (beaconing), DNS lookups
// (generated domains, tunnelling), per-app outbound volume (exfiltration), the LAN's ARP table (new devices), TLS
// fingerprints (known-malware JA3) and the other nodes' reports (the same threat on several devices).
// Everything here is pure logic over observations, so it's unit-tested without a network.

struct DetectSettings: Codable, Equatable {
    var beaconing = true
    var dnsAnalytics = true
    /// Look up registration dates of contacted domains (RDAP). Sends domain names to the registries: opt-in.
    var domainAge = false
    var volumeAnomalies = true
    var tlsFingerprints = true
    var newLANDevices = true
    var correlation = true
    var fileScanning = true
    /// Hash lookups of suspicious files (only the SHA-256 leaves the Mac).
    var virusTotalFiles = false
    var malwareBazaar = false
    var yaraRulesFolder: String?
    /// Extra fingerprints (JA3 MD5 or JA4) to treat as malicious.
    var customTLSFingerprints: [String] = []

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = DetectSettings()
        beaconing = try c.decodeIfPresent(Bool.self, forKey: .beaconing) ?? d.beaconing
        dnsAnalytics = try c.decodeIfPresent(Bool.self, forKey: .dnsAnalytics) ?? d.dnsAnalytics
        domainAge = try c.decodeIfPresent(Bool.self, forKey: .domainAge) ?? d.domainAge
        volumeAnomalies = try c.decodeIfPresent(Bool.self, forKey: .volumeAnomalies) ?? d.volumeAnomalies
        tlsFingerprints = try c.decodeIfPresent(Bool.self, forKey: .tlsFingerprints) ?? d.tlsFingerprints
        newLANDevices = try c.decodeIfPresent(Bool.self, forKey: .newLANDevices) ?? d.newLANDevices
        correlation = try c.decodeIfPresent(Bool.self, forKey: .correlation) ?? d.correlation
        fileScanning = try c.decodeIfPresent(Bool.self, forKey: .fileScanning) ?? d.fileScanning
        virusTotalFiles = try c.decodeIfPresent(Bool.self, forKey: .virusTotalFiles) ?? d.virusTotalFiles
        malwareBazaar = try c.decodeIfPresent(Bool.self, forKey: .malwareBazaar) ?? d.malwareBazaar
        yaraRulesFolder = try c.decodeIfPresent(String.self, forKey: .yaraRulesFolder)
        customTLSFingerprints = try c.decodeIfPresent([String].self, forKey: .customTLSFingerprints) ?? []
    }
}

// MARK: - Beaconing

/// Malware checks in with its controller on a timer. A process that connects to the same destination at a
/// steady interval (low jitter), many times, is flagged. Apple's own software is skipped (it polls constantly).
struct BeaconDetector {
    struct Series { var times: [Double] = []; var reported: Double? }
    private(set) var series: [String: Series] = [:]
    static let minEvents = 8, maxEvents = 24
    static let minInterval = 10.0, maxInterval = 6 * 3600.0
    static let maxJitter = 0.15

    struct Beacon: Equatable { var interval: Double; var jitter: Double; var count: Int }

    /// Records a new connection start; returns a beacon when this series newly qualifies (or again after a day).
    mutating func record(app: String, destination: String, at t: Double) -> Beacon? {
        let key = app + "|" + destination
        var s = series[key] ?? Series()
        if let last = s.times.last, t - last < 1 { return nil }   // the same burst
        s.times.append(t)
        if s.times.count > Self.maxEvents { s.times.removeFirst(s.times.count - Self.maxEvents) }
        defer { series[key] = s; if series.count > 20_000 { prune(now: t) } }
        guard let b = Self.analyze(s.times), s.reported.map({ t - $0 > 86_400 }) ?? true else { return nil }
        s.reported = t
        return b
    }

    static func analyze(_ times: [Double]) -> Beacon? {
        guard times.count >= minEvents else { return nil }
        let deltas = zip(times.dropFirst(), times).map { $0 - $1 }
        let mean = deltas.reduce(0, +) / Double(deltas.count)
        guard mean >= minInterval, mean <= maxInterval else { return nil }
        let sd = (deltas.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(deltas.count)).squareRoot()
        let jitter = sd / mean
        return jitter <= maxJitter ? Beacon(interval: mean, jitter: jitter, count: times.count) : nil
    }

    private mutating func prune(now: Double) {
        series = series.filter { now - ($0.value.times.last ?? 0) < 2 * 86_400 }
    }
}

// MARK: - DNS

enum DomainShape {
    /// The label a domain was registered under ("xkqjzvbw" for "a.xkqjzvbw.com"): what generated names randomize.
    static func registeredLabel(_ name: String) -> String? {
        let reg = Advisor.registrableDomain(name)
        return reg.split(separator: ".").first.map(String.init)
    }

    static func entropy(_ s: String) -> Double {
        let chars = Array(s)
        guard !chars.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for c in chars { counts[c, default: 0] += 1 }
        return counts.values.reduce(0) { acc, n in
            let p = Double(n) / Double(chars.count)
            return acc - p * log2(p)
        }
    }

    /// 0…1: how machine-generated a registered label looks (long, high entropy, few vowels, digits mixed in,
    /// long consonant runs). Human-chosen names score low.
    static func randomness(_ label: String) -> Double {
        let l = label.lowercased()
        guard l.count >= 8, !l.contains("-") || l.count >= 16 else { return 0 }
        let letters = l.filter(\.isLetter)
        let vowels = letters.filter { "aeiouy".contains($0) }.count
        let digits = l.filter(\.isNumber).count
        var run = 0, maxRun = 0
        for c in l {
            if c.isLetter && !"aeiouy".contains(c) { run += 1; maxRun = max(maxRun, run) } else { run = 0 }
        }
        var score = 0.0
        if entropy(l) >= 3.3 { score += 0.35 }
        if letters.count > 0 && Double(vowels) / Double(letters.count) < 0.22 { score += 0.25 }
        if maxRun >= 5 { score += 0.2 }
        if digits >= 2 && letters.count >= 4 { score += 0.15 }
        if l.count >= 14 { score += 0.1 }
        return min(score, 1)
    }
}

/// Watches this Mac's DNS lookups (seen on the wire) for two malware habits:
/// - domain generation: bursts of failed lookups (NXDOMAIN) for random-looking domains;
/// - DNS tunnelling: many unique, long subdomains (or TXT/NULL records) under one domain.
struct DNSAnalytics {
    private var nx: [(t: Double, domain: String)] = []
    private var perDomain: [String: (first: Double, subs: Set<String>, totalLen: Int, txt: Int)] = [:]
    private var reported: [String: Double] = [:]
    private var seen: Set<String> = []
    static let window = 600.0
    static let nxThreshold = 8
    static let tunnelSubdomains = 60, tunnelAvgLength = 40, tunnelTXT = 30

    enum Alert: Equatable {
        case generatedDomains(count: Int, examples: [String])
        case tunnelling(domain: String, subdomains: Int, avgLength: Int, txt: Int)
    }

    mutating func feed(_ q: DNSQueryObservation) -> Alert? {
        let key = "\(q.name)|\(q.type)|\(q.time)"
        guard !seen.contains(key) else { return nil }      // batches overlap
        seen.insert(key)
        if seen.count > 50_000 { seen.removeAll() }
        let t = q.time
        let name = q.name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard name.contains("."), !name.hasSuffix(".local"), !name.hasSuffix(".arpa") else { return nil }
        let domain = Advisor.registrableDomain(name)

        if q.rcode == 3, let label = DomainShape.registeredLabel(name), DomainShape.randomness(label) >= 0.6 {
            nx.append((t, domain))
            nx.removeAll { t - $0.t > Self.window }
            let distinct = Array(Set(nx.map(\.domain)))
            if distinct.count >= Self.nxThreshold, reported["dga"].map({ t - $0 > 3600 }) ?? true {
                reported["dga"] = t
                return .generatedDomains(count: distinct.count, examples: Array(distinct.sorted().prefix(5)))
            }
        }

        let sub = name == domain ? "" : String(name.dropLast(domain.count + 1))
        var d = perDomain[domain] ?? (t, [], 0, 0)
        if t - d.first > Self.window { d = (t, [], 0, 0) }
        if !sub.isEmpty, d.subs.count < 10_000 { if d.subs.insert(sub).inserted { d.totalLen += name.count } }
        if q.type == 16 || q.type == 10 { d.txt += 1 }
        perDomain[domain] = d
        if perDomain.count > 5000 { perDomain = perDomain.filter { t - $0.value.first < Self.window } }
        let avg = d.subs.isEmpty ? 0 : d.totalLen / d.subs.count
        let tunnel = (d.subs.count >= Self.tunnelSubdomains && avg >= Self.tunnelAvgLength) || d.txt >= Self.tunnelTXT
        if tunnel, reported["tun|" + domain].map({ t - $0 > 3600 }) ?? true {
            reported["tun|" + domain] = t
            return .tunnelling(domain: domain, subdomains: d.subs.count, avgLength: avg, txt: d.txt)
        }
        return nil
    }
}

// MARK: - Outbound volume

/// Per-app outbound bytes per hour against that app's own history. An app suddenly sending far more than it ever
/// has (and a lot in absolute terms) may be exfiltrating data.
struct VolumeBaseline: Codable {
    var history: [String: [Double]] = [:]      // app → bytes out in each past hour (most recent last)
    var current: [String: Double] = [:]
    var hour: Int = 0
    private var reported: [String: Int] = [:]
    static let keepHours = 14 * 24, minHistory = 24
    static let minBytes = 250.0 * 1_000_000, factor = 8.0, newAppBytes = 1_000.0 * 1_000_000

    struct Spike: Equatable { var bytes: Double; var usual: Double?; var hours: Int }

    mutating func add(app: String, bytes: Double, at t: Double) -> Spike? {
        let h = Int(t / 3600)
        if h != hour { roll(to: h) }
        current[app, default: 0] += max(0, bytes)
        let now = current[app]!
        guard reported[app] != h else { return nil }
        let past = history[app] ?? []
        if past.count >= Self.minHistory {
            let usual = Self.percentile(past, 0.95)
            guard now >= Self.minBytes, now >= usual * Self.factor else { return nil }
            reported[app] = h
            return Spike(bytes: now, usual: usual, hours: past.count)
        }
        guard past.count < 2, now >= Self.newAppBytes else { return nil }   // no history yet: only very large
        reported[app] = h
        return Spike(bytes: now, usual: nil, hours: past.count)
    }

    private mutating func roll(to h: Int) {
        if hour != 0 {
            for (app, v) in current {
                var past = history[app] ?? []
                past.append(v)
                if past.count > Self.keepHours { past.removeFirst(past.count - Self.keepHours) }
                history[app] = past
            }
            // Hours with no traffic count as zero for apps we know.
            for app in history.keys where current[app] == nil {
                history[app]!.append(0)
                if history[app]!.count > Self.keepHours { history[app]!.removeFirst() }
            }
        }
        if history.count > 500 { history = history.filter { $0.value.contains { $0 > 0 } } }
        current.removeAll()
        hour = h
    }

    static func percentile(_ v: [Double], _ p: Double) -> Double {
        let s = v.sorted()
        return s[min(s.count - 1, Int(Double(s.count - 1) * p))]
    }

    enum CodingKeys: String, CodingKey { case history }
}

// MARK: - LAN devices

enum LANWatch {
    /// Devices in `current` (ip → MAC) not seen before. Broadcast/multicast/incomplete entries are ignored.
    static func newDevices(current: [String: String], known: Set<String>) -> [(ip: String, mac: String)] {
        current.compactMap { ip, mac in
            let m = mac.lowercased()
            guard m.count >= 11, m != "ff:ff:ff:ff:ff:ff", !m.hasPrefix("1:0:5e"), !m.hasPrefix("01:00:5e"),
                  !m.hasPrefix("33:33"), !known.contains(m) else { return nil }
            return (ip, m)
        }.sorted { $0.ip < $1.ip }
    }

    /// Phones and newer OSes use a random ("private") MAC per network: the locally administered bit is set.
    static func isRandomized(_ mac: String) -> Bool {
        let first = mac.split(separator: ":").first.flatMap { UInt8($0, radix: 16) } ?? 0
        return first & 0x02 != 0
    }
}

// MARK: - Cross-device correlation

/// Signals that only show up when several devices are looked at together.
enum Correlator {
    struct Signal: Equatable {
        var key: String
        var title: String
        var detail: String
        var severity: Severity
        var devices: [String]
    }

    /// `addresses`: each device's own IPs (to recognize one device connecting to another).
    static func signals(_ reports: [NodeReport], addresses: [UUID: [String]]) -> [Signal] {
        var out: [Signal] = []
        // 1. The same known-bad destination on several devices.
        var bad: [String: Set<String>] = [:]
        for r in reports {
            for p in r.profiles where p.intel?.reputation == .knownBad { bad[p.key.host, default: []].insert(r.node.name) }
        }
        for (host, devices) in bad where devices.count >= 2 {
            out.append(Signal(key: "corr.bad|\(host)", title: "Known-malicious destination on \(devices.count) devices",
                              detail: "\(host) is on a threat-intel blocklist and was contacted from \(devices.sorted().joined(separator: ", ")).",
                              severity: .critical, devices: devices.sorted()))
        }
        // 2. The same open detection on several devices (spreading, or a shared compromise).
        var same: [String: (title: String, devices: Set<String>, sev: Severity)] = [:]
        for r in reports {
            for f in r.findings where f.status == .open && f.severity >= .medium && !f.rule.hasPrefix("posture.") {
                let k = f.rule + "|" + f.target
                same[k, default: (f.title, [], f.severity)].devices.insert(r.node.name)
            }
        }
        for (k, v) in same where v.devices.count >= 2 {
            out.append(Signal(key: "corr.same|\(k)", title: "\(v.title) — on \(v.devices.count) devices",
                              detail: "The same detection (\(k.replacingOccurrences(of: "|", with: ", "))) is open on \(v.devices.sorted().joined(separator: ", ")). Malware spreading between devices often looks like this.",
                              severity: max(v.sev, .high), devices: v.devices.sorted()))
        }
        // 3. One device probing another: connections to many different ports on a peer.
        var owner: [String: String] = [:]
        for r in reports { for ip in addresses[r.node.id] ?? [] { owner[ip] = r.node.name } }
        for r in reports {
            var ports: [String: Set<Int>] = [:]
            for p in r.profiles where p.key.direction == .outbound {
                if let peer = owner[p.key.host], peer != r.node.name { ports[peer, default: []].insert(p.key.port) }
            }
            for (peer, ps) in ports where ps.count >= 10 {
                out.append(Signal(key: "corr.scan|\(r.node.name)|\(peer)", title: "\(r.node.name) probed \(peer)",
                                  detail: "\(r.node.name) connected to \(ps.count) different ports on \(peer) (\(ps.sorted().prefix(12).map(String.init).joined(separator: ", "))…). Unless that was Elliott's network scan, this looks like lateral movement.",
                                  severity: .high, devices: [r.node.name, peer]))
            }
        }
        return out.sorted { $0.severity > $1.severity }
    }
}

// MARK: - TLS fingerprints

/// JA3 fingerprints of known malware clients (abuse.ch SSLBL), plus the user's own list.
struct TLSFingerprintList {
    private(set) var bad: [String: String] = [:]        // fingerprint → reason

    static let feedURL = URL(string: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv")!

    /// "md5,firstseen,lastseen,reason" lines.
    mutating func load(csv: String) {
        for line in csv.split(separator: "\n") where !line.hasPrefix("#") {
            let cols = line.split(separator: ",", omittingEmptySubsequences: false)
            guard cols.count >= 4, cols[0].count == 32, cols[0].allSatisfy(\.isHexDigit) else { continue }
            bad[String(cols[0]).lowercased()] = String(cols[3])
        }
    }

    func reason(ja3: String?, ja4: String?, custom: [String]) -> String? {
        let mine = Set(custom.map { $0.lowercased().trimmingCharacters(in: .whitespaces) })
        if let j = ja3?.lowercased() {
            if let r = bad[j] { return "JA3 \(j) belongs to \(r) (abuse.ch SSLBL)" }
            if mine.contains(j) { return "JA3 \(j) is on your fingerprint list" }
        }
        if let j = ja4?.lowercased(), mine.contains(j) { return "JA4 \(j) is on your fingerprint list" }
        return nil
    }

    var count: Int { bad.count }
}
