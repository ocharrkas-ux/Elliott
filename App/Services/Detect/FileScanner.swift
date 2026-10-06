import CryptoKit
import Foundation
import Security

/// Looks at new executable files where malware usually lands (Downloads, Desktop, temp folders, shared folders,
/// and the programs launch items point at). Each new file is hashed, its code signature and download origin
/// read, and it's checked against: MalwareBazaar's recent-malware hashes (downloaded list, no lookup), optional
/// per-hash lookups (VirusTotal / MalwareBazaar, only the SHA-256 is sent), and YARA rules if `yara` is installed.
final class FileScanner: @unchecked Sendable {
    struct FileVerdict: Codable, Hashable {
        var path: String
        var sha256: String
        var signer: String          // "Developer ID: …", "ad-hoc", "unsigned", "Apple", "invalid signature"
        var origin: String?         // where it was downloaded from
        var quarantined: Bool
        var hits: [String] = []     // reputation / YARA findings
        var severity: Severity?     // nil = nothing notable
        var scanned = Date()
    }

    static let roots: [String] = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return ["\(home)/Downloads", "\(home)/Desktop", "/private/tmp", "/private/var/tmp", "/Users/Shared"]
    }()
    static let maxSize = 300 * 1024 * 1024
    static let recentMalwareURL = URL(string: "https://bazaar.abuse.ch/export/txt/sha256/recent/")!

    private let lock = NSLock()
    private var seen: [String: (inode: UInt64, mtime: Double)] = [:]
    private var knownBad: Set<String> = []
    private var lookups: [Date] = []          // rate limit for online lookups
    private(set) var lastScan: Date?

    // MARK: Known-bad hashes

    func loadRecentMalware(_ text: String) {
        let hashes = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { $0.count == 64 && $0.allSatisfy(\.isHexDigit) }
        lock.withLock { knownBad = Set(hashes) }
    }
    var knownBadCount: Int { lock.withLock { knownBad.count } }

    // MARK: Scanning

    struct Options {
        var extraPaths: [String] = []        // e.g. programs launch items run
        var roots: [String] = FileScanner.roots
        var virusTotalKey: String?
        var malwareBazaarKey: String?
        var yaraRules: String?
    }

    /// New or changed candidate files since the last scan, judged. The first scan only records what's there
    /// (old files aren't alerted on), except launch-item programs and known-bad hashes.
    func scan(_ o: Options) async -> [FileVerdict] {
        let first = lock.withLock { lastScan == nil }
        var candidates: [String] = []
        for root in o.roots { candidates += Self.walk(root, depth: 3) }
        candidates += o.extraPaths
        var out: [FileVerdict] = []
        for path in Set(candidates) {
            guard let st = Self.stat(path) else { continue }
            let changed: Bool = lock.withLock {
                if let s = seen[path], s.inode == st.inode, s.mtime == st.mtime { return false }
                seen[path] = (st.inode, st.mtime)
                return true
            }
            guard changed, st.size > 0, st.size <= Self.maxSize else { continue }
            // The first pass only learns what's already there (hashing a full Downloads folder of disk images
            // would cost minutes of CPU); launch-item programs are always checked.
            if first && !o.extraPaths.contains(path) { continue }
            guard Self.isCandidate(path) || o.extraPaths.contains(path) else { continue }
            var v = Self.inspect(path)
            if lock.withLock({ knownBad.contains(v.sha256) }) {
                v.hits.append("SHA-256 is on MalwareBazaar's list of recent malware samples")
                v.severity = .critical
            }
            await enrich(&v, o)
            if v.severity != nil { out.append(v) }
        }
        lock.withLock {
            lastScan = Date()
            if seen.count > 100_000 { seen.removeAll() }
        }
        return out
    }

    private func enrich(_ v: inout FileVerdict, _ o: Options) async {
        let suspicious = v.signer == "unsigned" || v.signer == "ad-hoc" || v.signer == "invalid signature"
        // Online lookups only for files that aren't properly signed (and not too often: free API limits).
        if suspicious, allowLookup() {
            if let key = o.virusTotalKey, let r = try? await Self.virusTotal(v.sha256, key: key), r.malicious + r.suspicious > 0 {
                v.hits.append("VirusTotal: \(r.malicious) engines malicious, \(r.suspicious) suspicious")
                v.severity = max(v.severity ?? .info, r.malicious >= 3 ? .critical : .high)
            }
            if let key = o.malwareBazaarKey, let family = try? await Self.malwareBazaar(v.sha256, key: key) {
                v.hits.append("MalwareBazaar: known sample (\(family))")
                v.severity = .critical
            }
        }
        if let rules = o.yaraRules, let yara = Self.yaraPath, suspicious || v.severity != nil {
            let matches = Self.yara(yara, rules: rules, file: v.path)
            if !matches.isEmpty {
                v.hits.append("YARA: \(matches.joined(separator: ", "))")
                v.severity = max(v.severity ?? .info, .high)
            }
        }
        if v.severity == nil && suspicious && v.quarantined && Self.isMachO(v.path) {
            v.hits.append("A downloaded program without a valid Developer ID signature")
            v.severity = .medium
        }
    }

    private func allowLookup() -> Bool {
        lock.withLock {
            lookups.removeAll { Date().timeIntervalSince($0) > 60 }
            guard lookups.count < 4 else { return false }
            lookups.append(Date())
            return true
        }
    }

    // MARK: File facts

    static func walk(_ root: String, depth: Int) -> [String] {
        guard depth >= 0, let items = try? FileManager.default.contentsOfDirectory(atPath: root) else { return [] }
        var out: [String] = []
        for name in items.prefix(2000) where !name.hasPrefix(".") {
            let p = root + "/" + name
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: p, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                if name.hasSuffix(".app") {
                    if let exe = Bundle(path: p)?.executablePath { out.append(exe) }
                } else if !name.hasSuffix(".photoslibrary") && !name.hasSuffix(".git") {
                    out += walk(p, depth: depth - 1)
                }
            } else {
                out.append(p)
            }
        }
        return out
    }

    static func stat(_ path: String) -> (inode: UInt64, mtime: Double, size: Int)? {
        var st = Darwin.stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        return (UInt64(st.st_ino), Double(st.st_mtimespec.tv_sec), Int(st.st_size))
    }

    static let installerExtensions: Set<String> = ["pkg", "mpkg", "dmg", "command", "tool", "sh", "py", "scpt", "jar", "zsh"]

    static func isCandidate(_ path: String) -> Bool {
        if installerExtensions.contains((path as NSString).pathExtension.lowercased()) { return true }
        if isMachO(path) { return true }
        // Executable scripts.
        return FileManager.default.isExecutableFile(atPath: path) && firstBytes(path, 2) == [0x23, 0x21]   // "#!"
    }

    static func firstBytes(_ path: String, _ n: Int) -> [UInt8] {
        guard let h = FileHandle(forReadingAtPath: path) else { return [] }
        defer { try? h.close() }
        return Array((try? h.read(upToCount: n)) ?? Data())
    }

    static func isMachO(_ path: String) -> Bool {
        let b = firstBytes(path, 4)
        guard b.count == 4 else { return false }
        let magic = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        return [0xFEEDFACF, 0xCFFAEDFE, 0xFEEDFACE, 0xCEFAEDFE, 0xCAFEBABE, 0xBEBAFECA].contains(magic)
    }

    static func sha256(_ path: String) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        while let chunk = try? h.read(upToCount: 1 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func inspect(_ path: String) -> FileVerdict {
        let (origin, quarantined) = downloadOrigin(path)
        return FileVerdict(path: path, sha256: sha256(path) ?? "", signer: signer(path), origin: origin, quarantined: quarantined)
    }

    static func signer(_ path: String) -> String {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return "unsigned" }
        let status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
        if status == errSecCSUnsigned { return "unsigned" }
        guard status == errSecSuccess else { return "invalid signature" }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return "unsigned" }
        if let flags = dict[kSecCodeInfoFlags as String] as? UInt32, flags & 0x2 != 0 { return "ad-hoc" }   // kSecCodeSignatureAdhoc
        if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first {
            let name = SecCertificateCopySubjectSummary(leaf) as String? ?? "unknown"
            // Apple's own leaf: "Software Signing", "macOS Software Signing", "Apple Mac OS Application Signing".
            return name.hasSuffix("Software Signing") || name.hasPrefix("Apple Mac OS") ? "Apple" : name
        }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String ?? "signed"
    }

    /// The URL a file was downloaded from (Finder's "Where from") and whether it carries the quarantine flag.
    static func downloadOrigin(_ path: String) -> (String?, Bool) {
        let quarantined = getxattr(path, "com.apple.quarantine", nil, 0, 0, 0) > 0
        let size = getxattr(path, "com.apple.metadata:kMDItemWhereFroms", nil, 0, 0, 0)
        guard size > 0 else { return (nil, quarantined) }
        var buf = [UInt8](repeating: 0, count: size)
        guard getxattr(path, "com.apple.metadata:kMDItemWhereFroms", &buf, size, 0, 0) == size,
              let list = try? PropertyListSerialization.propertyList(from: Data(buf), format: nil) as? [String] else { return (nil, quarantined) }
        return (list.first, quarantined)
    }

    // MARK: Lookups

    static func virusTotal(_ sha: String, key: String) async throws -> (malicious: Int, suspicious: Int) {
        var req = URLRequest(url: URL(string: "https://www.virustotal.com/api/v3/files/\(sha)")!, timeoutInterval: 20)
        req.setValue(key, forHTTPHeaderField: "x-apikey")
        let (data, resp) = try await LimitedDownload.fetch(req, maxBytes: 4 * 1024 * 1024)
        if resp.statusCode == 404 { return (0, 0) }   // never seen: not evidence either way
        guard resp.statusCode == 200, let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw URLError(.badServerResponse) }
        let stats = ((obj["data"] as? [String: Any])?["attributes"] as? [String: Any])?["last_analysis_stats"] as? [String: Any] ?? [:]
        return (stats["malicious"] as? Int ?? 0, stats["suspicious"] as? Int ?? 0)
    }

    static func malwareBazaar(_ sha: String, key: String) async throws -> String? {
        var req = URLRequest(url: URL(string: "https://mb-api.abuse.ch/api/v1/")!, timeoutInterval: 20)
        req.httpMethod = "POST"
        req.setValue(key, forHTTPHeaderField: "Auth-Key")
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data("query=get_info&hash=\(sha)".utf8)
        let (data, resp) = try await LimitedDownload.fetch(req, maxBytes: 2 * 1024 * 1024)
        guard resp.statusCode == 200, let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["query_status"] as? String == "ok" else { return nil }
        let first = (obj["data"] as? [[String: Any]])?.first
        return first?["signature"] as? String ?? "malware"
    }

    // MARK: YARA

    static var yaraPath: String? { ["/opt/homebrew/bin/yara", "/usr/local/bin/yara"].first(where: FileManager.default.isExecutableFile) }

    /// Rule names matching the file. `rules` is a .yar file or a folder of them.
    static func yara(_ tool: String, rules: String, file: String) -> [String] {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: rules, isDirectory: &isDir) else { return [] }
        let ruleFiles = isDir.boolValue
            ? ((try? FileManager.default.contentsOfDirectory(atPath: rules)) ?? []).filter { $0.hasSuffix(".yar") || $0.hasSuffix(".yara") }.map { rules + "/" + $0 }
            : [rules]
        var hits: [String] = []
        for r in ruleFiles.prefix(200) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: tool)
            p.arguments = ["-w", "-a", "20", r, file]
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = FileHandle.nullDevice
            guard (try? p.run()) != nil else { continue }
            let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            p.waitUntilExit()
            hits += out.split(separator: "\n").compactMap { $0.split(separator: " ").first.map(String.init) }
        }
        return Array(Set(hits)).sorted()
    }
}

/// Registration dates of domains (RDAP), cached. A connection to a domain registered days ago is a common
/// phishing/malware sign. Opt-in: the domain name is sent to the registry.
actor DomainAge {
    private var cache: [String: Date?] = [:]
    private var lookups: [Date] = []

    func registered(_ domain: String) async -> Date? {
        if let c = cache[domain] { return c }
        lookups.removeAll { Date().timeIntervalSince($0) > 3600 }
        guard lookups.count < 60 else { return nil }   // at most 60 lookups an hour
        lookups.append(Date())
        var date: Date?
        var req = URLRequest(url: URL(string: "https://rdap.org/domain/\(domain)")!, timeoutInterval: 15)
        req.setValue("application/rdap+json", forHTTPHeaderField: "Accept")
        if let (data, resp) = try? await LimitedDownload.fetch(req, maxBytes: 512 * 1024), resp.statusCode == 200 {
            date = Self.registrationDate(data)
        }
        cache[domain] = date
        if cache.count > 20_000 { cache.removeAll() }
        return date
    }

    static func registrationDate(_ data: Data) -> Date? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let events = obj["events"] as? [[String: Any]] else { return nil }
        let f = ISO8601DateFormatter()
        for e in events where (e["eventAction"] as? String) == "registration" {
            if let s = e["eventDate"] as? String {
                if let d = f.date(from: s) { return d }
                f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                if let d = f.date(from: s) { return d }
            }
        }
        return nil
    }
}
