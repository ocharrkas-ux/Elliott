import Foundation

/// Public vulnerability data: OSV (open-source packages), NVD (CVE records with CVSS, matched by CPE for apps,
/// Homebrew, services and macOS), CISA KEV (exploited in the wild) and FIRST EPSS (exploit likelihood).
/// Responses are cached on disk so rescans are cheap and polite to the APIs.
final class VulnDB: @unchecked Sendable {
    private let dir: URL
    var nvdKey: String?
    private var lastNVD = Date.distantPast

    init(directory: URL) {
        dir = directory.appendingPathComponent("vulndb", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    // MARK: Cache

    private func cached(_ name: String, maxAge: TimeInterval) -> Data? {
        let url = dir.appendingPathComponent(name)
        guard let mod = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate,
              Date().timeIntervalSince(mod) < maxAge else { return nil }
        return try? Data(contentsOf: url)
    }

    private func store(_ name: String, _ data: Data) { try? data.write(to: dir.appendingPathComponent(name), options: .atomic) }

    private func safe(_ s: String) -> String {
        String(s.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." ? $0 : "_" }).prefix(180).description
    }

    private func get(_ url: URL, headers: [String: String] = [:]) async throws -> Data {
        var req = URLRequest(url: url, timeoutInterval: 60)
        req.setValue("Elliott/1.0 (macOS vulnerability scanner)", forHTTPHeaderField: "User-Agent")
        headers.forEach { req.setValue($1, forHTTPHeaderField: $0) }
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw URLError(code == 403 || code == 429 ? .resourceUnavailable : .badServerResponse) }
        return data
    }

    // MARK: OSV

    /// Vulnerability ids per package component (same order as `components`).
    func osvQuery(_ components: [Component]) async throws -> [[String]] {
        var out: [[String]] = []
        for chunk in stride(from: 0, to: components.count, by: 500).map({ Array(components[$0..<min($0 + 500, components.count)]) }) {
            let queries = chunk.map { ["package": ["name": $0.name, "ecosystem": $0.ecosystem ?? ""], "version": $0.version] }
            var req = URLRequest(url: URL(string: "https://api.osv.dev/v1/querybatch")!, timeoutInterval: 90)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: ["queries": queries])
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard (resp as? HTTPURLResponse)?.statusCode == 200,
                  let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let results = obj["results"] as? [[String: Any]] else { throw URLError(.badServerResponse) }
            out += results.map { (($0["vulns"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String } }
        }
        return out
    }

    /// Full OSV record (cached for 3 days).
    func osvVuln(_ id: String) async throws -> [String: Any] {
        let name = "osv-\(safe(id)).json"
        let data: Data
        if let c = cached(name, maxAge: 3 * 86400) { data = c } else {
            data = try await get(URL(string: "https://api.osv.dev/v1/vulns/\(id)")!)
            store(name, data)
        }
        return (try JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }

    /// An OSV record as it applies to one component.
    static func parseOSV(_ o: [String: Any], for c: Component) -> Vulnerability {
        var v = Vulnerability(id: o["id"] as? String ?? "?",
                              aliases: o["aliases"] as? [String] ?? [],
                              summary: (o["summary"] as? String) ?? String((o["details"] as? String ?? "").prefix(160)),
                              details: o["details"] as? String ?? "")
        for sev in o["severity"] as? [[String: Any]] ?? [] {
            guard let vec = sev["score"] as? String else { continue }
            if (sev["type"] as? String)?.hasPrefix("CVSS_V3") == true, let s = CVSS3.score(vec) {
                v.cvssVector = vec; v.cvssScore = s; v.cvssVersion = "3.1"
            } else if v.cvssVector == nil {
                v.cvssVector = vec; v.cvssVersion = (sev["type"] as? String)?.replacingOccurrences(of: "CVSS_V", with: "")
            }
        }
        v.severityLabel = (o["database_specific"] as? [String: Any])?["severity"] as? String
        let norm = Inventory.normalize(c.name, c.ecosystem ?? "")
        for a in o["affected"] as? [[String: Any]] ?? [] {
            let pkg = a["package"] as? [String: Any] ?? [:]
            guard Inventory.normalize(pkg["name"] as? String ?? "", c.ecosystem ?? "") == norm else { continue }
            for r in a["ranges"] as? [[String: Any]] ?? [] {
                for e in r["events"] as? [[String: Any]] ?? [] { if let f = e["fixed"] as? String { v.fixedVersions.append(f) } }
            }
            // Go advisories name the vulnerable functions.
            let eco = a["ecosystem_specific"] as? [String: Any] ?? [:]
            for imp in eco["imports"] as? [[String: Any]] ?? [] { v.symbols += imp["symbols"] as? [String] ?? [] }
            if v.severityLabel == nil { v.severityLabel = eco["severity"] as? String }
        }
        v.fixedVersions = Version.upgrades(Array(Set(v.fixedVersions)), from: c.version)
        v.references = (o["references"] as? [[String: Any]] ?? []).compactMap { $0["url"] as? String }.prefix(8).map { $0 }
        if let p = o["published"] as? String { v.published = ISO8601DateFormatter().date(from: p) }
        return v
    }

    // MARK: NVD

    /// CVEs whose NVD configurations cover this product version. NVD allows 5 requests / 30 s without a key.
    func nvd(cpe: String, version: String) async throws -> [Vulnerability] {
        let match = "cpe:2.3:\(cpe):\(version)"
        let name = "nvd-\(safe(match)).json"
        let data: Data
        if let c = cached(name, maxAge: 86400) { data = c } else {
            let gap: TimeInterval = (nvdKey?.isEmpty == false) ? 0.7 : 6.5
            let wait = gap - Date().timeIntervalSince(lastNVD)
            if wait > 0 { try await Task.sleep(for: .seconds(wait)) }
            lastNVD = Date()
            var c = URLComponents(string: "https://services.nvd.nist.gov/rest/json/cves/2.0")!
            c.queryItems = [.init(name: "virtualMatchString", value: match), .init(name: "resultsPerPage", value: "2000")]
            data = try await get(c.url!, headers: nvdKey.map { ["apiKey": $0] } ?? [:])
            store(name, data)
        }
        let obj = (try JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        let product = cpe.split(separator: ":").suffix(2).joined(separator: ":")
        return (obj["vulnerabilities"] as? [[String: Any]] ?? []).compactMap { $0["cve"] as? [String: Any] }
            .filter { ($0["vulnStatus"] as? String) != "Rejected" && Self.affects($0, product: product, version: version) }
            .map { cve in
                var v = Self.parseNVD(cve, product: product)
                v.fixedVersions = Version.upgrades(v.fixedVersions, from: version)
                return v
            }
    }

    /// NVD's version filter is loose (it returns CVEs where the product only appears as a platform, or other version
    /// ranges). Keep a CVE only if a *vulnerable* match entry for this exact product covers the installed version.
    static func affects(_ cve: [String: Any], product: String, version: String) -> Bool {
        for conf in cve["configurations"] as? [[String: Any]] ?? [] {
            for node in conf["nodes"] as? [[String: Any]] ?? [] {
                for m in node["cpeMatch"] as? [[String: Any]] ?? [] where m["vulnerable"] as? Bool == true {
                    let parts = (m["criteria"] as? String ?? "").split(separator: ":", omittingEmptySubsequences: false).map(String.init)
                    guard parts.count > 5, "\(parts[3]):\(parts[4])" == product else { continue }
                    let exact = parts[5]
                    if exact != "*" && exact != "-" {
                        if Version.compare(exact, version) == .orderedSame { return true }
                        continue
                    }
                    var ok = true
                    if let s = m["versionStartIncluding"] as? String { ok = ok && Version.compare(version, s) != .orderedAscending }
                    if let s = m["versionStartExcluding"] as? String { ok = ok && Version.compare(version, s) == .orderedDescending }
                    if let e = m["versionEndExcluding"] as? String { ok = ok && Version.compare(version, e) == .orderedAscending }
                    if let e = m["versionEndIncluding"] as? String { ok = ok && Version.compare(version, e) != .orderedDescending }
                    let bounded = ["versionStartIncluding", "versionStartExcluding", "versionEndExcluding", "versionEndIncluding"]
                        .contains { m[$0] != nil }
                    // "every version" with no bounds is too vague to report against a specific install.
                    if ok && bounded { return true }
                }
            }
        }
        return false
    }

    static func parseNVD(_ cve: [String: Any], product: String) -> Vulnerability {
        let desc = (cve["descriptions"] as? [[String: Any]] ?? []).first { $0["lang"] as? String == "en" }?["value"] as? String ?? ""
        var v = Vulnerability(id: cve["id"] as? String ?? "?", summary: String(desc.prefix(200)), details: desc)
        let metrics = cve["metrics"] as? [String: Any] ?? [:]
        for (key, ver) in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")] {
            guard let m = (metrics[key] as? [[String: Any]])?.first, let d = m["cvssData"] as? [String: Any] else { continue }
            v.cvssScore = d["baseScore"] as? Double
            v.cvssVector = d["vectorString"] as? String
            v.cvssVersion = ver
            v.severityLabel = (d["baseSeverity"] as? String) ?? (m["baseSeverity"] as? String)
            break
        }
        // Fixed version = the first version past a vulnerable range for this product.
        for conf in cve["configurations"] as? [[String: Any]] ?? [] {
            for node in conf["nodes"] as? [[String: Any]] ?? [] {
                for m in node["cpeMatch"] as? [[String: Any]] ?? [] where (m["criteria"] as? String ?? "").contains(product) {
                    if let f = m["versionEndExcluding"] as? String { v.fixedVersions.append(f) }
                }
            }
        }
        v.fixedVersions = Array(Set(v.fixedVersions)).sorted { $0.compare($1, options: .numeric) == .orderedAscending }
        v.references = (cve["references"] as? [[String: Any]] ?? []).compactMap { $0["url"] as? String }.prefix(8).map { $0 }
        if let p = cve["published"] as? String { v.published = ISO8601DateFormatter().date(from: p + "Z") }
        return v
    }

    // MARK: KEV & EPSS

    func kev() async -> Set<String> {
        let name = "kev.json"
        var data = cached(name, maxAge: 86400)
        if data == nil, let fresh = try? await get(URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!) {
            store(name, fresh); data = fresh
        }
        data = data ?? (try? Data(contentsOf: dir.appendingPathComponent(name)))   // stale beats nothing
        guard let data, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        return Set((obj["vulnerabilities"] as? [[String: Any]] ?? []).compactMap { $0["cveID"] as? String })
    }

    func epss(_ cves: [String]) async -> [String: Double] {
        var out: [String: Double] = [:]
        for chunk in stride(from: 0, to: cves.count, by: 80).map({ Array(cves[$0..<min($0 + 80, cves.count)]) }) {
            var c = URLComponents(string: "https://api.first.org/data/v1/epss")!
            c.queryItems = [.init(name: "cve", value: chunk.joined(separator: ","))]
            guard let data = try? await get(c.url!),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            for row in obj["data"] as? [[String: Any]] ?? [] {
                if let cve = row["cve"] as? String, let e = Double(row["epss"] as? String ?? "") { out[cve] = e }
            }
        }
        return out
    }
}
