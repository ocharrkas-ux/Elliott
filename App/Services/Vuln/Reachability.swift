import Foundation

/// SCA reachability: does a project's own code actually use the vulnerable package, and the vulnerable function?
/// Static and best-effort (no call graph): it finds import sites, then calls to the functions an advisory names.
enum ReachabilityAnalyzer {
    struct SourceFile { var path: String; var lines: [String] }

    static let extensions: [String: Set<String>] = [
        "npm": ["js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte"], "PyPI": ["py"], "Go": ["go"],
        "crates.io": ["rs"], "RubyGems": ["rb"], "Packagist": ["php"], "SwiftURL": ["swift"],
    ]

    /// Distribution name → import name, where they differ.
    static let pythonImports: [String: String] = [
        "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "scikit-learn": "sklearn", "python-dateutil": "dateutil",
        "protobuf": "google.protobuf", "opencv-python": "cv2", "opencv-python-headless": "cv2", "pyjwt": "jwt",
        "python-jose": "jose", "pycryptodome": "Crypto", "pymysql": "pymysql", "psycopg2-binary": "psycopg2",
        "python-multipart": "multipart", "attrs": "attr", "msgpack-python": "msgpack", "pyopenssl": "OpenSSL",
        "setuptools": "setuptools", "tensorflow-cpu": "tensorflow", "faiss-cpu": "faiss", "python-dotenv": "dotenv",
    ]

    /// Reads a project's source files for one ecosystem (dependency folders skipped; bounded in size).
    static func index(project: String, ecosystem: String) -> [SourceFile] {
        guard let exts = extensions[ecosystem] else { return [] }
        var out: [SourceFile] = []
        var bytes = 0
        func walk(_ dir: String, _ depth: Int) {
            guard depth < 12, out.count < 6000, bytes < 80_000_000,
                  let items = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
            for item in items where !item.hasPrefix(".") || item == ".github" {
                let path = "\(dir)/\(item)"
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { continue }
                if isDir.boolValue {
                    if !Inventory.skipDirs.contains(item) && !item.hasSuffix(".app") { walk(path, depth + 1) }
                } else if exts.contains((item as NSString).pathExtension.lowercased()),
                          let text = try? String(contentsOfFile: path, encoding: .utf8), text.utf8.count < 1_000_000 {
                    bytes += text.utf8.count
                    out.append(SourceFile(path: path, lines: text.components(separatedBy: "\n")))
                }
            }
        }
        walk(project, 0)
        return out
    }

    static func importPattern(for c: Component) -> NSRegularExpression? {
        let name = NSRegularExpression.escapedPattern(for: c.name)
        let p: String
        switch c.ecosystem {
        case "npm":
            p = #"(?:from\s+|require\(\s*|import\(\s*|import\s+)['"]"# + name + #"(?:/[^'"]*)?['"]"#
        case "PyPI":
            let mod = pythonImports[Inventory.normalize(c.name, "PyPI")]
                ?? c.name.lowercased().replacingOccurrences(of: "-", with: "_").replacingOccurrences(of: ".", with: "_")
            let m = NSRegularExpression.escapedPattern(for: mod)
            p = #"^\s*(?:import\s+(?:[\w.]+\s*,\s*)*"# + m + #"(?:[\s.,]|$)|from\s+"# + m + #"(?:\.[\w.]+)?\s+import\b)"#
        case "Go":
            p = #""\#(name)(?:/[^"]*)?""#
        case "crates.io":
            let crate = NSRegularExpression.escapedPattern(for: c.name.replacingOccurrences(of: "-", with: "_"))
            p = #"\b(?:use\s+|extern\s+crate\s+)?"# + crate + #"::|\bextern\s+crate\s+"# + crate + #"\b"#
        case "RubyGems":
            p = #"require(?:_relative)?\s*\(?\s*['"]"# + name + #"(?:/[^'"]*)?['"]"#
        case "SwiftURL":
            let repo = (c.name as NSString).lastPathComponent.replacingOccurrences(of: "swift-", with: "").replacingOccurrences(of: "-", with: "")
            p = #"^\s*(?:@testable\s+)?import\s+(?i:"# + NSRegularExpression.escapedPattern(for: repo) + #")\w*\s*$"#
        default:
            return nil
        }
        return try? NSRegularExpression(pattern: p, options: [.anchorsMatchLines])
    }

    /// Function names worth looking for: the advisory's own list, else identifiers it mentions in `code` or as calls().
    static func candidateSymbols(_ v: Vulnerability, package: String) -> (symbols: [String], authoritative: Bool) {
        if !v.symbols.isEmpty {
            return (Array(Set(v.symbols.map { String($0.split(separator: ".").last ?? Substring($0)) })), true)
        }
        let text = v.summary + "\n" + v.details
        var found: [String] = []
        for m in text.matches(of: /`([A-Za-z_$][\w.$]*)(?:\(\))?`|\b([A-Za-z_$][\w.$]{2,})\(\)/) {
            let raw = String(m.1 ?? m.2 ?? "")
            let last = String(raw.split(separator: ".").last ?? Substring(raw))
            found.append(last)
        }
        let stop: Set<String> = ["true", "false", "null", "undefined", "none", "this", "self", "string", "object", "function",
                                 "the", "and", "for", "with", "from", "import", "require", "version", "versions", "npm", "pip",
                                 "constructor", "prototype", "__proto__", "length", "value", "data", "input", "options", "config",
                                 "json", "yaml", "http", "https", "url", "utf", "html", "xml", "api", "true", "pickle"]
        let pkg = package.lowercased()
        let symbols = found.filter { $0.count >= 3 && !stop.contains($0.lowercased()) && $0.lowercased() != pkg }
        return (Array(Set(symbols)).sorted().prefix(10).map { $0 }, false)
    }

    /// API names nearly every user of a library calls; an advisory mentioning one doesn't make it reachable on its own.
    static let genericCalls: Set<String> = ["from_pretrained", "save_pretrained", "load", "loads", "dump", "dumps", "open", "read",
                                            "write", "get", "post", "put", "request", "run", "parse", "render", "compile", "create",
                                            "send", "fetch", "call", "init", "__init__", "close", "connect", "execute", "update"]

    /// Packages (normalized names) the project's code imports, out of `components`.
    static func importedPackages(_ components: [Component], files: [SourceFile]) -> Set<String> {
        var out = Set<String>()
        for c in components {
            guard let rx = importPattern(for: c) else { continue }
            if files.contains(where: { f in f.lines.contains { rx.firstMatch(in: $0, range: NSRange($0.startIndex..., in: $0)) != nil } }) {
                out.insert(Inventory.normalize(c.name, c.ecosystem ?? ""))
            }
        }
        return out
    }

    /// Shortest chain from a package the code imports to `target`, through recorded dependencies.
    static func path(to target: String, from imported: Set<String>, graph: [String: [String]]) -> [String]? {
        var queue = imported.sorted().map { [$0] }
        var seen = imported
        while !queue.isEmpty {
            let p = queue.removeFirst()
            for next in graph[p.last!] ?? [] where !seen.contains(next) {
                if next == target { return p + [next] }
                seen.insert(next)
                queue.append(p + [next])
            }
        }
        return nil
    }

    static func analyze(_ c: Component, _ v: Vulnerability, files: [SourceFile], via: [String]? = nil) -> ReachabilityResult {
        guard let project = c.project, let importRx = importPattern(for: c) else {
            return ReachabilityResult(verdict: .unknown, evidence: ["No reachability support for \(c.ecosystem ?? "this ecosystem") yet."])
        }
        func rel(_ p: String) -> String { p.hasPrefix(project + "/") ? String(p.dropFirst(project.count + 1)) : p }

        var importing: [SourceFile] = []
        var importLines: [String] = []
        for f in files {
            var hit = false
            for (i, line) in f.lines.enumerated() where importRx.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
                hit = true
                if importLines.count < 6 { importLines.append("\(rel(f.path)):\(i + 1): \(line.trimmingCharacters(in: .whitespaces).prefix(160))") }
            }
            if hit { importing.append(f) }
        }
        if importing.isEmpty, let via, via.count > 1 {
            return ReachabilityResult(verdict: .imported,
                                      evidence: ["Your code doesn't import \(c.name) itself but uses it through \(via.dropLast().joined(separator: " → ")) → \(c.name), which your code imports (\(via[0]))."])
        }
        guard !importing.isEmpty else {
            let why = c.direct == true ? "\(c.name) is declared in the manifest but no source file imports it."
                : c.direct == false ? "\(c.name) is only a transitive dependency and no source file imports it directly."
                : "No source file in the project imports \(c.name)."
            return ReachabilityResult(verdict: .notImported,
                                      evidence: [why + " It can still be reached through another dependency that uses it."])
        }

        let (symbols, authoritative) = candidateSymbols(v, package: c.name)
        var calls: [String] = []
        for s in symbols {
            let e = NSRegularExpression.escapedPattern(for: s)
            guard let rx = try? NSRegularExpression(pattern: #"(?<![\w$])"# + e + #"\s*\(|\.\#(e)\b|\{[^}]*\b\#(e)\b[^}]*\}\s*from|import\s+[^;\n]*\b\#(e)\b"#) else { continue }
            for f in importing {
                for (i, line) in f.lines.enumerated() where rx.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
                    if calls.count < 8 { calls.append("\(rel(f.path)):\(i + 1): \(line.trimmingCharacters(in: .whitespaces).prefix(160))") }
                }
            }
        }
        let specific = symbols.filter { !genericCalls.contains($0.lowercased()) }
        let specificCalls = calls.filter { line in specific.contains { line.contains($0) } }
        if !calls.isEmpty && (authoritative || !specificCalls.isEmpty) {
            return ReachabilityResult(verdict: .reachable,
                                      evidence: ["Calls to \(authoritative ? "functions the advisory lists as vulnerable" : "functions named in the advisory") (\(symbols.joined(separator: ", "))):"] + calls)
        }
        var ev = ["\(importing.count) file(s) import \(c.name):"] + importLines
        if !calls.isEmpty {
            ev.append("Calls common APIs the advisory mentions (\(symbols.filter { genericCalls.contains($0.lowercased()) }.joined(separator: ", "))), but not the specific vulnerable code path:")
            ev += calls.prefix(4)
        }
        if !symbols.isEmpty && calls.isEmpty {
            ev.append("None of the \(authoritative ? "vulnerable functions listed by the advisory" : "functions mentioned in the advisory") (\(symbols.joined(separator: ", "))) appear to be called.")
        }
        return ReachabilityResult(verdict: .imported, evidence: ev)
    }

    /// Lines around each evidence location, for the LLM judge.
    static func snippets(_ r: ReachabilityResult, project: String, limit: Int = 6) -> [String] {
        r.evidence.compactMap { e -> String? in
            guard let m = e.firstMatch(of: /^(.+?):(\d+):\s/), let n = Int(m.2) else { return nil }
            let path = project + "/" + String(m.1)
            guard let lines = try? String(contentsOfFile: path, encoding: .utf8).components(separatedBy: "\n") else { return nil }
            let lo = max(0, n - 4), hi = min(lines.count, n + 3)
            return "// \(m.1):\(n)\n" + lines[lo..<hi].joined(separator: "\n")
        }.prefix(limit).map { $0 }
    }
}

/// Asks the local model whether the project's use of a vulnerable package plausibly reaches the vulnerability.
enum ReachabilityLLM {
    private static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "verdict": ["type": "string", "enum": ["reachable", "not reachable", "unclear"]],
            "rationale": ["type": "string"],
        ],
        "required": ["verdict", "rationale"],
    ]

    private static let system = """
    You are an application-security engineer doing reachability analysis. You get a vulnerability advisory for a \
    dependency and the places where a project uses that dependency. Decide whether the project's code plausibly \
    exercises the vulnerable functionality (e.g. calls the affected function, with attacker-influenced input where \
    that matters). Use only what is shown. Reply with JSON:
    - "verdict": "reachable", "not reachable", or "unclear" (when the snippets don't show enough)
    - "rationale": 1-2 sentences naming the specific call or the reason it isn't reached
    """

    static func judge(_ f: VulnFinding, llm: LocalLLM) async throws -> (String, String) {
        guard let project = f.component.project else { return ("unclear", "Not a project dependency.") }
        var user = "Dependency: \(f.component.name) \(f.component.version) (\(f.component.ecosystem ?? ""))\n"
        user += "Advisory \(f.vuln.id): \(f.vuln.summary)\n"
        if !f.vuln.details.isEmpty { user += "Details: \(String(f.vuln.details.prefix(1500)))\n" }
        if !f.vuln.symbols.isEmpty { user += "Vulnerable functions per advisory: \(f.vuln.symbols.joined(separator: ", "))\n" }
        user += "Static analysis: \(f.reachability.verdict.rawValue)\n"
        let snips = ReachabilityAnalyzer.snippets(f.reachability, project: project)
        user += snips.isEmpty ? "No code snippets available.\n" : "Project code using it:\n" + snips.joined(separator: "\n\n")

        let content = try await llm.complete(system: system, user: user, schema: schema)
        guard let obj = LocalLLM.jsonObject(content), let verdict = obj["verdict"] as? String else {
            throw LocalLLM.Failure.badResponse(String(content.prefix(200)))
        }
        return (verdict.lowercased(), TriageLLM.firstSentences(obj["rationale"] as? String ?? "", 2))
    }
}
