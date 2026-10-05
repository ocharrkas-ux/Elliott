import Foundation

/// A piece of installed software Elliott checks for known vulnerabilities.
struct Component: Codable, Hashable, Identifiable {
    enum Kind: String, Codable, CaseIterable {
        case os = "macOS", app = "app", homebrew = "Homebrew", package = "package", service = "service"
    }
    var kind: Kind
    /// OSV ecosystem (npm, PyPI, Go, crates.io, RubyGems, Packagist, SwiftURL) for packages; nil for NVD-matched software.
    var ecosystem: String?
    var name: String
    var version: String
    /// NVD CPE "vendor:product" for apps, Homebrew formulae, services and macOS.
    var cpe: String?
    /// Where it was found: app bundle, project lockfile, listening port.
    var location: String
    /// For project packages: declared directly in the manifest (vs. pulled in transitively).
    var direct: Bool?
    /// Project root, for reachability analysis.
    var project: String?
    /// Listening on a non-loopback address (reachable from the network).
    var exposedPorts: [Int] = []
    /// Packages this one depends on (normalized names), where the lockfile or virtualenv records it.
    var requires: [String]?

    var id: String { "\(kind.rawValue)|\(ecosystem ?? "")|\(name)|\(version)|\(location)" }
    var display: String { "\(name) \(version)" }
}

struct Vulnerability: Codable, Hashable, Identifiable {
    var id: String                 // GHSA-…, CVE-…, PYSEC-…
    var aliases: [String] = []
    var summary: String
    var details: String = ""
    var cvssVector: String?
    var cvssScore: Double?
    var cvssVersion: String?
    var severityLabel: String?     // from the database when there's no usable vector
    var fixedVersions: [String] = []
    var references: [String] = []
    /// Functions/symbols the advisory names as vulnerable (Go advisories list them; others sometimes do).
    var symbols: [String] = []
    var published: Date?

    var cve: String? { ([id] + aliases).first { $0.hasPrefix("CVE-") } }

    /// CVSS base score, or an estimate from the database's severity label.
    var score: Double {
        if let cvssScore { return cvssScore }
        switch severityLabel?.uppercased() {
        case "CRITICAL": return 9.0
        case "HIGH": return 7.5
        case "MODERATE", "MEDIUM": return 5.5
        case "LOW": return 2.5
        default: return 5.0
        }
    }
}

enum Reachability: String, Codable, Comparable, CaseIterable {
    case notApplicable = "n/a"        // apps, OS, services: no source code to analyze
    case unknown = "unknown"
    case notImported = "not imported" // only a transitive dependency; the project's code never imports it
    case imported = "imported"        // the project imports the package; the vulnerable function isn't known/seen
    case reachable = "reachable"      // the project calls a function the advisory names as vulnerable

    private var rank: Int { [.notApplicable: 0, .notImported: 1, .unknown: 2, .imported: 3, .reachable: 4][self]! }
    static func < (a: Self, b: Self) -> Bool { a.rank < b.rank }
}

struct ReachabilityResult: Codable, Hashable {
    var verdict: Reachability
    var evidence: [String] = []       // "src/app.js:12: _.template(userInput)"
    var llmVerdict: String?           // "reachable" | "not reachable" | "unclear"
    var llmRationale: String?
}

struct VulnFinding: Codable, Hashable, Identifiable {
    enum Status: String, Codable, CaseIterable { case open, accepted, fixed }

    var component: Component
    var vuln: Vulnerability
    var kev = false                   // on CISA's Known Exploited Vulnerabilities list
    var epss: Double?                 // probability of exploitation in the next 30 days
    var reachability = ReachabilityResult(verdict: .notApplicable)
    var status: Status = .open
    var firstSeen = Date()

    var id: String { "\(component.id)|\(vuln.id)" }

    /// 0-100 priority: CVSS, raised by active exploitation, exploit likelihood, network exposure and reachability,
    /// lowered when the vulnerable package isn't used.
    var priority: Int {
        var p = vuln.score * 10
        if kev { p += 25 }
        if let epss { p += min(15, epss * 30) }
        if !component.exposedPorts.isEmpty && (vuln.cvssVector?.contains("AV:N") ?? true) { p += 10 }
        switch reachability.verdict {
        case .reachable: p += 15
        case .imported: p += 5
        case .notImported: p -= 30
        default: break
        }
        if reachability.llmVerdict == "not reachable" { p -= 10 }
        return Int(min(100, max(0, p)).rounded())
    }

    var severity: Severity {
        switch vuln.score {
        case 9...: .critical
        case 7..<9: .high
        case 4..<7: .medium
        case 0.1..<4: .low
        default: .info
        }
    }
}

/// CVSS v3.0/3.1 base score from a vector string (OSV publishes vectors, not scores).
enum CVSS3 {
    static func score(_ vector: String) -> Double? {
        guard vector.hasPrefix("CVSS:3") else { return nil }
        var m: [String: String] = [:]
        for part in vector.split(separator: "/").dropFirst() {
            let kv = part.split(separator: ":")
            if kv.count == 2 { m[String(kv[0])] = String(kv[1]) }
        }
        guard let av = ["N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2][m["AV"] ?? ""],
              let ac = ["L": 0.77, "H": 0.44][m["AC"] ?? ""],
              let ui = ["N": 0.85, "R": 0.62][m["UI"] ?? ""],
              let s = m["S"], ["U", "C"].contains(s),
              let c = ["H": 0.56, "L": 0.22, "N": 0.0][m["C"] ?? ""],
              let i = ["H": 0.56, "L": 0.22, "N": 0.0][m["I"] ?? ""],
              let a = ["H": 0.56, "L": 0.22, "N": 0.0][m["A"] ?? ""],
              let prRaw = m["PR"] else { return nil }
        let changed = s == "C"
        let pr: Double
        switch prRaw {
        case "N": pr = 0.85
        case "L": pr = changed ? 0.68 : 0.62
        case "H": pr = changed ? 0.5 : 0.27
        default: return nil
        }
        let iss = 1 - (1 - c) * (1 - i) * (1 - a)
        let impact = changed ? 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15) : 6.42 * iss
        let exploitability = 8.22 * av * ac * pr * ui
        guard impact > 0 else { return 0 }
        let base = changed ? min(1.08 * (impact + exploitability), 10) : min(impact + exploitability, 10)
        return roundUp(base)
    }

    /// CVSS 3.1 "round up to one decimal" (Appendix A), avoiding floating-point artifacts.
    static func roundUp(_ x: Double) -> Double {
        let i = Int((x * 100_000).rounded())
        return i % 10_000 == 0 ? Double(i) / 100_000 : (Double(i / 10_000) + 1) / 10
    }
}

/// Version ordering for NVD ranges: numeric parts compare as numbers, letter suffixes ("1.1.1ze") by length then
/// alphabetically (OpenSSL's scheme), and a missing part sorts first ("2" < "2a" < "2.1").
enum Version {
    static func tokens(_ v: String) -> [Either] {
        var out: [Either] = []
        var cur = "", digits = false
        func flush() {
            guard !cur.isEmpty else { return }
            out.append(digits ? .num(Int(cur.prefix(18)) ?? 0) : .text(cur.lowercased()))
            cur = ""
        }
        for ch in v {
            if ch.isNumber {
                if !digits { flush(); digits = true }
                cur.append(ch)
            } else if ch.isLetter {
                if digits { flush(); digits = false }
                cur.append(ch)
            } else {
                flush()
            }
        }
        flush()
        return out
    }

    enum Either: Equatable { case num(Int), text(String) }

    /// Fixed versions that are actually upgrades from `installed` (drops other release lines and date-stamped
    /// snapshots), lowest first.
    static func upgrades(_ fixes: [String], from installed: String) -> [String] {
        fixes.filter { $0.firstMatch(of: /^\d{4}-\d{2}-\d{2}/) == nil && compare($0, installed) == .orderedDescending }
            .sorted { compare($0, $1) == .orderedAscending }
    }

    static func compare(_ a: String, _ b: String) -> ComparisonResult {
        let x = tokens(a), y = tokens(b)
        for i in 0..<max(x.count, y.count) {
            guard i < x.count else { return .orderedAscending }
            guard i < y.count else { return .orderedDescending }
            switch (x[i], y[i]) {
            case let (.num(p), .num(q)) where p != q: return p < q ? .orderedAscending : .orderedDescending
            case let (.text(p), .text(q)) where p != q:
                if p.count != q.count { return p.count < q.count ? .orderedAscending : .orderedDescending }
                return p < q ? .orderedAscending : .orderedDescending
            case (.num, .text): return .orderedDescending   // 1.0 > 1.beta
            case (.text, .num): return .orderedAscending
            default: continue
            }
        }
        return .orderedSame
    }
}
