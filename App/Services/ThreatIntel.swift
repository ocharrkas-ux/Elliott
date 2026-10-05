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

/// A blocklist the user added: one IP or CIDR per line (comments with # or ;), like the built-in feeds.
struct CustomFeed: Codable, Equatable, Identifiable, Hashable {
    var id = UUID().uuidString
    var name: String
    var url: String
    var severity: Reputation = .suspicious
    var enabled = true

    var feed: Feed? {
        guard let u = URL(string: url), u.scheme == "https" else { return nil }
        return Feed(id: "custom-\(id)", name: name, url: u, detail: "listed on \(name)", severity: severity, about: url)
    }
}

struct IntelSettings: Codable, Equatable {
    var disabledFeeds: [String] = []
    var abuseIPDB = false
    var greyNoise = false
    var virusTotal = false
    var notifyKnownBad = true
    var customFeeds: [CustomFeed] = []
    var lastRefresh: Date?

    init() {}

    // Older saves lack newer keys: default them instead of failing the whole load.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        disabledFeeds = try c.decodeIfPresent([String].self, forKey: .disabledFeeds) ?? []
        abuseIPDB = try c.decodeIfPresent(Bool.self, forKey: .abuseIPDB) ?? false
        greyNoise = try c.decodeIfPresent(Bool.self, forKey: .greyNoise) ?? false
        virusTotal = try c.decodeIfPresent(Bool.self, forKey: .virusTotal) ?? false
        notifyKnownBad = try c.decodeIfPresent(Bool.self, forKey: .notifyKnownBad) ?? true
        customFeeds = try c.decodeIfPresent([CustomFeed].self, forKey: .customFeeds) ?? []
        lastRefresh = try c.decodeIfPresent(Date.self, forKey: .lastRefresh)
    }
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
    /// Number of addresses covered (to spot a poisoned list claiming a large part of the internet).
    var coverage: UInt64 { ranges.reduce(0) { $0 + UInt64($1.1 - $1.0) + 1 } }
    /// Entries ignored for being implausibly broad.
    private(set) var dropped = 0

    /// Ranges broader than a /8 are never a legitimate blocklist entry (FireHOL's bogon /3 is one); they're skipped.
    init(lines: some Sequence<Substring>) {
        var raw: [(UInt32, UInt32)] = []
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.hasPrefix("#") || t.hasPrefix(";") { continue }
            guard let (start, end) = IPv4Set.firstRange(in: t) else { continue }
            if UInt64(end - start) + 1 > (1 << 24) { dropped += 1; continue }
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
    /// Hand-rolled (lists run to hundreds of thousands of lines; a regex per line is far slower).
    static func firstRange(in line: String) -> (UInt32, UInt32)? {
        let b = Array(line.utf8)
        func isDigit(_ i: Int) -> Bool { i < b.count && b[i] >= 48 && b[i] <= 57 }
        var i = 0
        while i < b.count {
            guard isDigit(i), i == 0 || !isDigit(i - 1) else { i += 1; continue }
            // Try "a.b.c.d" starting here: four 1–3 digit octets.
            var j = i, octets: [UInt32] = []
            while octets.count < 4 {
                let start = j
                var v: UInt32 = 0
                while isDigit(j) && j - start < 3 { v = v * 10 + UInt32(b[j] - 48); j += 1 }
                guard j > start, v < 256, !isDigit(j) else { break }
                octets.append(v)
                if octets.count < 4 { guard j < b.count, b[j] == 46 else { break }; j += 1 }   // "."
            }
            guard octets.count == 4 else { i += 1; continue }
            let base = octets.reduce(0) { $0 << 8 | $1 }
            var bits = 32
            if j + 1 < b.count, b[j] == 47, isDigit(j + 1) {   // "/nn"
                var k = j + 1, n = 0
                while isDigit(k) && k - j <= 2 { n = n * 10 + Int(b[k] - 48); k += 1 }
                bits = n
            }
            return range(base: base, bits: bits)
        }
        return nil
    }

    private static func range(base: UInt32, bits: Int) -> (UInt32, UInt32)? {
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
    struct FeedStatus: Hashable {
        var entries: Int
        var updated: Date?
        var error: String?
        var stale: Bool { updated.map { Date().timeIntervalSince($0) > 24 * 3600 } ?? true }
    }

    /// Limits a downloaded list must pass before it replaces the cached copy.
    static let maxDownload = 50 * 1024 * 1024
    static let maxCoverage: UInt64 = 1 << 28          // ~6% of IPv4: no real blocklist is that broad

    private let dir: URL
    private let lock = NSLock()
    private var sets: [String: IPv4Set] = [:]
    private var parsedAt: [String: Date] = [:]   // file modification date each loaded set came from
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
                req.setValue("Elliott/1.0 (macOS firewall)", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await LimitedDownload.fetch(req, maxBytes: Self.maxDownload)
                guard response.statusCode == 200, !data.isEmpty else { throw URLError(.badServerResponse) }
                let previous = (try? String(contentsOf: file, encoding: .utf8)).map { IPv4Set(lines: $0.split(separator: "\n")).count }
                if let problem = Self.validate(String(decoding: data, as: UTF8.self), previousCount: previous) {
                    error = "held back: \(problem)"   // keep the last good copy
                } else {
                    try data.write(to: file, options: .atomic)
                }
            } catch let e {
                error = e.localizedDescription   // keep using the cached copy, if any
            }
        }
        let current = (try? file.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        // Unchanged file already loaded: nothing to parse.
        if let current, lock.withLock({ parsedAt[feed.id] == current && sets[feed.id] != nil }) {
            if let error { lock.withLock { status[feed.id]?.error = error } }
            return
        }
        guard let text = try? String(contentsOf: file, encoding: .utf8) else {
            lock.withLock { status[feed.id] = FeedStatus(entries: 0, updated: nil, error: error ?? "not downloaded") }
            return
        }
        let set = IPv4Set(lines: text.split(separator: "\n"))
        let updated = (try? file.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        lock.withLock {
            sets[feed.id] = set
            parsedAt[feed.id] = updated
            status[feed.id] = FeedStatus(entries: set.count, updated: updated, error: error)
        }
    }

    /// Why a freshly downloaded list shouldn't be trusted, or nil if it looks sane.
    static func validate(_ text: String, previousCount: Int?) -> String? {
        let set = IPv4Set(lines: text.split(separator: "\n"))
        if set.coverage > maxCoverage {
            return "it would cover \(set.coverage.formatted()) addresses, far more than any real blocklist"
        }
        if let p = previousCount, p >= 100 {
            if set.count == 0 { return "it came back empty (was \(p.formatted()) ranges)" }
            if set.count * 10 < p || set.count > p * 10 {
                return "its size jumped from \(p.formatted()) to \(set.count.formatted()) ranges"
            }
        }
        return nil
    }

    var staleFeeds: [String] { lock.withLock { status.filter { $0.value.stale }.map(\.key).sorted() } }

    func drop(_ feedID: String) { lock.withLock { sets[feedID] = nil; status[feedID] = nil; parsedAt[feedID] = nil } }

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
        let (data, response) = try await LimitedDownload.fetch(req, maxBytes: 2 * 1024 * 1024)
        let code = response.statusCode
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
        let (data, response) = try await LimitedDownload.fetch(req, maxBytes: 2 * 1024 * 1024)
        let code = response.statusCode
        guard code == 200 else { throw URLError(code == 401 || code == 403 ? .userAuthenticationRequired : .badServerResponse) }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
}
