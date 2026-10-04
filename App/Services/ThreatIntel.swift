import Foundation

// OSINT reputation for remote IPs. Public blocklists are downloaded and matched on this Mac, so checking them
// reveals nothing about where this Mac connects. Per-IP lookups (AbuseIPDB, GreyNoise, VirusTotal) do send the
// IP to that service and are off unless the user turns them on.

enum Reputation: Int, Codable, Comparable, CaseIterable {
    case unknown, clean, suspicious, knownBad
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    var label: String {
        switch self {
        case .unknown: "unchecked"
        case .clean: "clean"
        case .suspicious: "suspicious"
        case .knownBad: "KNOWN BAD"
        }
    }
}

struct IntelHit: Codable, Hashable {
    var source: String      // "Feodo Tracker", "AbuseIPDB", ...
    var detail: String      // "botnet C2", "confidence 87%, 312 reports"
    var severity: Reputation
}

struct IPIntel: Codable, Hashable {
    var ip: String
    var hits: [IntelHit] = []
    var org: String?
    var country: String?
    var checked = Date()
    var onlineChecked: Date?
    var reputation: Reputation { hits.map(\.severity).max() ?? .clean }
}

/// What a profile's remote IPs add up to.
struct IntelSummary: Codable, Hashable {
    var reputation: Reputation
    var hits: [IntelHit]
    var org: String?
}

struct IntelSettings: Codable, Equatable {
    var disabledFeeds: [String] = []
    var abuseIPDB = false
    var greyNoise = false
    var virusTotal = false
    var notifyKnownBad = true
}

struct Feed: Identifiable, Hashable {
    var id: String
    var name: String
    var url: URL
    var detail: String
    var severity: Reputation
    var about: String

    static let all: [Feed] = [
        Feed(id: "feodo", name: "Feodo Tracker", url: URL(string: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt")!,
             detail: "botnet command-and-control server", severity: .knownBad,
             about: "abuse.ch: active botnet C2 servers (Dridex, Emotet, QakBot…)."),
        Feed(id: "spamhaus-drop", name: "Spamhaus DROP", url: URL(string: "https://www.spamhaus.org/drop/drop_v4.json")!,
             detail: "hijacked or criminal-operated netblock", severity: .knownBad,
             about: "Netblocks run by or hijacked for cybercrime. Never legitimate."),
        Feed(id: "et-compromised", name: "ET Compromised", url: URL(string: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt")!,
             detail: "known compromised host", severity: .knownBad,
             about: "Proofpoint Emerging Threats: hosts known to be compromised."),
        Feed(id: "ipsum3", name: "IPsum (3+ lists)", url: URL(string: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt")!,
             detail: "listed on 3 or more public blocklists", severity: .knownBad,
             about: "Aggregates 30+ blocklists; level 3 = IPs on at least three of them."),
        Feed(id: "firehol1", name: "FireHOL Level 1", url: URL(string: "https://iplists.firehol.org/files/firehol_level1.netset")!,
             detail: "on FireHOL's high-confidence blocklist", severity: .knownBad,
             about: "Conservative aggregate of attack and malware sources (bogons ignored here)."),
        Feed(id: "cins", name: "CINS Army", url: URL(string: "https://cinsscore.com/list/ci-badguys.txt")!,
             detail: "seen attacking (CINS Army)", severity: .suspicious,
             about: "IPs with poor reputation from Sentinel IPS sensors."),
        Feed(id: "blocklist-de", name: "blocklist.de", url: URL(string: "https://lists.blocklist.de/lists/all.txt")!,
             detail: "reported for attacks in the last 48h", severity: .suspicious,
             about: "IPs reported for SSH, mail, web and other attacks."),
        Feed(id: "tor-exit", name: "Tor exit nodes", url: URL(string: "https://check.torproject.org/torbulkexitlist")!,
             detail: "Tor exit node", severity: .suspicious,
             about: "Current Tor exit relays. Anonymised, not necessarily malicious."),
    ]
}

/// Sorted, merged IPv4 ranges with binary-search lookup.
struct IPv4Set {
    private(set) var ranges: [(UInt32, UInt32)] = []
    var count: Int { ranges.count }

    init(lines: some Sequence<Substring>) {
        var raw: [(UInt32, UInt32)] = []
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.hasPrefix("#") || t.hasPrefix(";") { continue }
            guard let (start, end) = IPv4Set.firstRange(in: t) else { continue }
            raw.append((start, end))
        }
        raw.sort { $0.0 < $1.0 }
        for r in raw {
            if let last = ranges.last, r.0 <= last.1 &+ 1, last.1 != .max {
                ranges[ranges.count - 1].1 = max(last.1, r.1)
            } else {
                ranges.append(r)
            }
        }
    }

    func contains(_ ip: String) -> Bool {
        guard let v = IPv4Set.parse(ip) else { return false }
        var lo = 0, hi = ranges.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if v < ranges[mid].0 { hi = mid - 1 } else if v > ranges[mid].1 { lo = mid + 1 } else { return true }
        }
        return false
    }

    /// First "a.b.c.d" or "a.b.c.d/nn" in a line (plain lists, netsets, Spamhaus JSON lines, IPsum "ip<TAB>n").
    static func firstRange(in line: String) -> (UInt32, UInt32)? {
        guard let m = line.firstMatch(of: /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2}))?/),
              let base = parse(String(m.1)) else { return nil }
        let bits = m.2.flatMap { Int($0) } ?? 32
        guard (0...32).contains(bits) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
        return (base & mask, (base & mask) | ~mask)
    }

    static func parse(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard let n = UInt32(p), n < 256 else { return nil }
            v = v << 8 | n
        }
        return v
    }

    /// Public, routable unicast: the only addresses worth checking (blocklists like FireHOL include bogons such
    /// as 10/8 and 100.64/10, which would otherwise flag LAN and Tailscale peers).
    static func isGlobal(_ ip: String) -> Bool {
        if ip.contains(":") {
            let a = ip.lowercased()
            return a.hasPrefix("2") || a.hasPrefix("3")   // 2000::/3
        }
        guard let v = parse(ip) else { return false }
        let reserved: [(UInt32, Int)] = [
            (0x00000000, 8), (0x0A000000, 8), (0x64400000, 10), (0x7F000000, 8), (0xA9FE0000, 16), (0xAC100000, 12),
            (0xC0000000, 24), (0xC0000200, 24), (0xC0A80000, 16), (0xC6120000, 15), (0xC6336400, 24), (0xCB007100, 24),
            (0xE0000000, 3),
        ]
        for (net, bits) in reserved where v & (~UInt32(0) << (32 - bits)) == net { return false }
        return true
    }
}

/// Downloads, caches and matches the blocklists.
final class ThreatIntel: @unchecked Sendable {
    struct FeedStatus: Hashable { var entries: Int; var updated: Date?; var error: String? }

    private let dir: URL
    private let lock = NSLock()
    private var sets: [String: IPv4Set] = [:]
    private(set) var status: [String: FeedStatus] = [:]

    init(directory: URL) {
        dir = directory.appendingPathComponent("intel", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    /// Loads cached lists, then refreshes any older than `maxAge` (or all, if forced).
    func refresh(_ feeds: [Feed], maxAge: TimeInterval = 12 * 3600, force: Bool = false) async {
        await withTaskGroup(of: Void.self) { group in
            for feed in feeds {
                group.addTask { await self.refresh(feed, maxAge: maxAge, force: force) }
            }
        }
    }

    private func refresh(_ feed: Feed, maxAge: TimeInterval, force: Bool) async {
        let file = dir.appendingPathComponent("\(feed.id).txt")
        let modified = (try? file.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        var error: String?
        if force || modified == nil || Date().timeIntervalSince(modified!) > maxAge {
            do {
                var req = URLRequest(url: feed.url, timeoutInterval: 60)
                req.setValue("Bastion/1.0 (macOS firewall)", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await URLSession.shared.data(for: req)
                guard (response as? HTTPURLResponse)?.statusCode == 200, !data.isEmpty else {
                    throw URLError(.badServerResponse)
                }
                try data.write(to: file, options: .atomic)
            } catch let e {
                error = e.localizedDescription   // keep using the cached copy, if any
            }
        }
        guard let text = try? String(contentsOf: file, encoding: .utf8) else {
            lock.withLock { status[feed.id] = FeedStatus(entries: 0, updated: nil, error: error ?? "not downloaded") }
            return
        }
        let set = IPv4Set(lines: text.split(separator: "\n"))
        let updated = (try? file.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        lock.withLock {
            sets[feed.id] = set
            status[feed.id] = FeedStatus(entries: set.count, updated: updated, error: error)
        }
    }

    func drop(_ feedID: String) { lock.withLock { sets[feedID] = nil; status[feedID] = nil } }

    func hits(for ip: String, feeds: [Feed]) -> [IntelHit] {
        guard IPv4Set.isGlobal(ip) else { return [] }
        let snapshot = lock.withLock { sets }
        return feeds.compactMap { f in
            snapshot[f.id]?.contains(ip) == true ? IntelHit(source: f.name, detail: f.detail, severity: f.severity) : nil
        }
    }

    var totalEntries: Int { lock.withLock { status.values.reduce(0) { $0 + $1.entries } } }
    var loadedFeeds: Int { lock.withLock { sets.count } }
    var lastUpdated: Date? { lock.withLock { status.values.compactMap(\.updated).max() } }
}

/// Opt-in per-IP reputation APIs. Each sends the IP to that service.
enum OnlineIntel {
    struct Result { var hits: [IntelHit] = []; var org: String?; var country: String? }

    static func abuseIPDB(_ ip: String, key: String) async throws -> Result {
        var c = URLComponents(string: "https://api.abuseipdb.com/api/v2/check")!
        c.queryItems = [.init(name: "ipAddress", value: ip), .init(name: "maxAgeInDays", value: "90")]
        var req = URLRequest(url: c.url!, timeoutInterval: 20)
        req.setValue(key, forHTTPHeaderField: "Key")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let obj = try await json(req)
        let d = obj["data"] as? [String: Any] ?? [:]
        let score = d["abuseConfidenceScore"] as? Int ?? 0
        let reports = d["totalReports"] as? Int ?? 0
        var r = Result(org: d["isp"] as? String, country: d["countryCode"] as? String)
        if score >= 25 || reports >= 5 {
            r.hits.append(IntelHit(source: "AbuseIPDB", detail: "abuse confidence \(score)%, \(reports) reports",
                                   severity: score >= 75 ? .knownBad : .suspicious))
        }
        return r
    }

    static func greyNoise(_ ip: String, key: String?) async throws -> Result {
        var req = URLRequest(url: URL(string: "https://api.greynoise.io/v3/community/\(ip)")!, timeoutInterval: 20)
        if let key, !key.isEmpty { req.setValue(key, forHTTPHeaderField: "key") }
        let (data, response) = try await URLSession.shared.data(for: req)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        if code == 404 { return Result() }   // not observed scanning the internet
        guard code == 200, let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }
        var r = Result(org: obj["name"] as? String)
        switch obj["classification"] as? String {
        case "malicious": r.hits.append(IntelHit(source: "GreyNoise", detail: "classified malicious (internet scanner)", severity: .knownBad))
        case "suspicious": r.hits.append(IntelHit(source: "GreyNoise", detail: "classified suspicious", severity: .suspicious))
        default: break
        }
        return r
    }

    static func virusTotal(_ ip: String, key: String) async throws -> Result {
        var req = URLRequest(url: URL(string: "https://www.virustotal.com/api/v3/ip_addresses/\(ip)")!, timeoutInterval: 20)
        req.setValue(key, forHTTPHeaderField: "x-apikey")
        let obj = try await json(req)
        let a = (obj["data"] as? [String: Any])?["attributes"] as? [String: Any] ?? [:]
        let stats = a["last_analysis_stats"] as? [String: Any] ?? [:]
        let mal = stats["malicious"] as? Int ?? 0, sus = stats["suspicious"] as? Int ?? 0
        var r = Result(org: a["as_owner"] as? String, country: a["country"] as? String)
        if mal + sus > 0 {
            r.hits.append(IntelHit(source: "VirusTotal", detail: "\(mal) engines malicious, \(sus) suspicious",
                                   severity: mal >= 3 ? .knownBad : .suspicious))
        }
        return r
    }

    private static func json(_ req: URLRequest) async throws -> [String: Any] {
        let (data, response) = try await URLSession.shared.data(for: req)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw URLError(code == 401 || code == 403 ? .userAuthenticationRequired : .badServerResponse) }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
}
