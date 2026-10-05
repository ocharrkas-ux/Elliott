import Foundation

/// Asks the package's official registry whether a version exists and when it was published. Used before any
/// automatic upgrade: the version must be real, and (by default) at least a few days old, since most malicious
/// releases of hijacked packages are found and pulled within days.
enum Registry {
    enum Answer: Equatable { case published(Date), notFound, unknown(String) }

    static func release(ecosystem: String, name: String, version: String) async -> Answer {
        guard let enc = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
              let ver = version.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return .unknown("bad name") }
        let url: String
        switch ecosystem {
        case "PyPI": url = "https://pypi.org/pypi/\(enc)/\(ver)/json"
        case "npm": url = "https://registry.npmjs.org/\(name.replacingOccurrences(of: "/", with: "%2F"))"
        case "crates.io": url = "https://crates.io/api/v1/crates/\(enc)/\(ver)"
        case "Go": url = "https://proxy.golang.org/\(goEscape(name))/@v/v\(ver).info"
        case "RubyGems": url = "https://rubygems.org/api/v1/versions/\(enc).json"
        case "Packagist": url = "https://repo.packagist.org/p2/\(enc).json"
        default: return .unknown("no registry check for \(ecosystem)")
        }
        var req = URLRequest(url: URL(string: url)!, timeoutInterval: 20)
        req.setValue("Elliott/1.0 (macOS vulnerability remediation)", forHTTPHeaderField: "User-Agent")
        do {
            let (data, resp) = try await LimitedDownload.fetch(req, maxBytes: 50 * 1024 * 1024)
            if resp.statusCode == 404 || resp.statusCode == 410 { return .notFound }
            guard resp.statusCode == 200 else { return .unknown("HTTP \(resp.statusCode)") }
            return parse(ecosystem: ecosystem, version: version, data: data)
        } catch {
            return .unknown(error.localizedDescription)
        }
    }

    static func parse(ecosystem: String, version: String, data: Data) -> Answer {
        let obj = (try? JSONSerialization.jsonObject(with: data)) ?? [:]
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        func date(_ s: String?) -> Date? {
            guard let s else { return nil }
            return iso.date(from: s) ?? ISO8601DateFormatter().date(from: s)
                ?? ISO8601DateFormatter().date(from: s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression))
        }
        switch ecosystem {
        case "PyPI":
            let urls = (obj as? [String: Any])?["urls"] as? [[String: Any]] ?? []
            let dates = urls.compactMap { date($0["upload_time_iso_8601"] as? String) }
            return dates.min().map(Answer.published) ?? .unknown("no files published")
        case "npm":
            let times = (obj as? [String: Any])?["time"] as? [String: String] ?? [:]
            return times[version].flatMap(date).map(Answer.published) ?? .notFound
        case "crates.io":
            return date(((obj as? [String: Any])?["version"] as? [String: Any])?["created_at"] as? String).map(Answer.published) ?? .notFound
        case "Go":
            return date((obj as? [String: Any])?["Time"] as? String).map(Answer.published) ?? .notFound
        case "RubyGems":
            let versions = obj as? [[String: Any]] ?? []
            return versions.first { $0["number"] as? String == version }.flatMap { date($0["created_at"] as? String) }.map(Answer.published) ?? .notFound
        case "Packagist":
            let packages = ((obj as? [String: Any])?["packages"] as? [String: Any])?.values.first as? [[String: Any]] ?? []
            let match = packages.first { ($0["version"] as? String).map { $0 == version || $0 == "v" + version } ?? false }
            return match.flatMap { date($0["time"] as? String) }.map(Answer.published) ?? .notFound
        default:
            return .unknown("unsupported")
        }
    }

    /// Go module proxy escapes capitals as "!lowercase".
    static func goEscape(_ module: String) -> String {
        module.map { $0.isUppercase ? "!" + $0.lowercased() : String($0) }.joined()
    }
}
