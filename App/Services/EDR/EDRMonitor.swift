import Foundation
import Security

struct EDRSettings: Codable, Equatable {
    var enabled = true
    var notifyAt: Severity = .high
    var minerDetection = true
}

/// A finding as produced by the monitor, with the context it was found in.
struct Observation {
    var key: String
    var draft: Draft
    var process: ProcInfo?
    var path: String?
    var chain: [ProcInfo] = []
}

/// A launchd job definition on disk.
struct LaunchItem: Codable, Hashable {
    var plist: String
    var label: String
    var program: String
    var arguments: [String]
    var modified: Date
}

/// User-space EDR sensor. Endpoint Security (real-time exec events) needs an Apple-granted entitlement, so this
/// polls: new processes every couple of seconds (very short-lived ones can slip between polls), persistence and
/// posture every few minutes.
final class EDRMonitor: @unchecked Sendable {
    /// Supplies the process table (from the root helper when available, so arguments are complete).
    var fetch: @Sendable () async -> [ProcInfo] = { ProcessTable.snapshot(withArgs: true) }
    var onObservations: @Sendable ([Observation]) -> Void = { _ in }
    var onProcesses: @Sendable ([ProcInfo]) -> Void = { _ in }
    var onLaunchItems: @Sendable ([LaunchItem], Set<String>) -> Void = { _, _ in }
    var minerDetection = true
    /// Launch items already known, so only new ones count as "newly installed".
    var baseline: Set<String> = []

    private var task: Task<Void, Never>?
    private var known: [Int32: ProcInfo] = [:]
    private var history: [Int32: ProcInfo] = [:]          // recently exited, for ancestry
    private var identities: [String: CodeID] = [:]
    private var cpu: [Int32: (Date, Double, Int)] = [:]   // last sample, cpu seconds, consecutive hot samples
    private var lastSlowScan = Date.distantPast
    private var firstPoll = true

    func start() {
        guard task == nil else { return }
        task = Task.detached(priority: .utility) { [self] in
            while !Task.isCancelled {
                await self.poll()
                if Date().timeIntervalSince(self.lastSlowScan) > 300 {
                    self.lastSlowScan = Date()
                    self.slowScan()
                }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    func rescanNow() { lastSlowScan = .distantPast }

    // MARK: Processes

    private func poll() async {
        let procs = await fetch()
        guard !procs.isEmpty else { return }
        var byPID: [Int32: ProcInfo] = [:]
        for p in procs { byPID[p.pid] = p }
        var out: [Observation] = []

        for p in procs {
            // A pid is "new" if unseen or reused by a different process.
            if let old = known[p.pid], old.start == p.start { continue }
            out += evaluate(p, table: byPID)
        }
        for (pid, p) in known where byPID[pid] == nil { history[pid] = p }
        if history.count > 4000 { history = history.filter { byPID[$0.key] == nil }.suffix(2000).reduce(into: [:]) { $0[$1.key] = $1.value } }
        known = byPID
        if minerDetection { out += sampleCPU(procs) }
        firstPoll = false
        onProcesses(procs)
        if !out.isEmpty { onObservations(out) }
    }

    func identity(_ path: String) -> CodeID {
        if let hit = identities[path] { return hit }
        let (sid, team, apple) = PassiveMonitor.staticIdentity(path)
        let id = CodeID(signingID: sid, teamID: team, appleSigned: apple)
        identities[path] = id
        return id
    }

    func ancestors(of p: ProcInfo, table: [Int32: ProcInfo]) -> [ProcInfo] {
        var chain: [ProcInfo] = []
        var cur = p.ppid
        while cur > 1, chain.count < 8, let parent = table[cur] ?? history[cur] {
            chain.append(parent)
            cur = parent.ppid
        }
        return chain
    }

    private func evaluate(_ p: ProcInfo, table: [Int32: ProcInfo]) -> [Observation] {
        guard !p.path.isEmpty else { return [] }
        let id = identity(p.path)
        // Apple's own binaries only get command-line checks (that's where living-off-the-land shows up).
        let chain = ancestors(of: p, table: table)
        let exists = FileManager.default.fileExists(atPath: p.path)
        var drafts = Detections.evaluate(p, id: id, ancestors: chain, exists: exists)
        if id.appleSigned { drafts = drafts.filter { $0.category == .commandLine || $0.rule.hasPrefix("chain.") } }
        return drafts.map { d in
            var key = "\(d.rule)|\(p.path)"
            if d.category == .commandLine, let cmd = p.commandLine { key += "|\(Detections.stableHash(cmd))" }
            return Observation(key: key, draft: d, process: p, path: p.path, chain: chain)
        }
    }

    /// Untrusted processes that keep a core busy for 3+ minutes look like cryptominers.
    private func sampleCPU(_ procs: [ProcInfo]) -> [Observation] {
        var out: [Observation] = []
        let now = Date()
        var next: [Int32: (Date, Double, Int)] = [:]
        for p in procs where !p.path.isEmpty && identity(p.path).untrusted {
            guard let secs = ProcessTable.cpuSeconds(p.pid) else { continue }
            var hot = 0
            if let (t, prev, n) = cpu[p.pid] {
                let usage = (secs - prev) / max(now.timeIntervalSince(t), 0.5)
                hot = usage > 0.8 ? n + 1 : 0
                if hot == 90 {   // ~3 minutes of 2 s samples
                    out.append(Observation(
                        key: "res.cpu|\(p.path)",
                        draft: Draft(rule: "res.cpu", title: "Unsigned process pinning the CPU",
                                     detail: "\(p.displayName) (\(identity(p.path).label)) has used over 80% of a core for 3 minutes. Sustained load from an unsigned binary is typical of cryptominers.",
                                     severity: .medium, category: .resource, mitre: ["T1496"],
                                     evidence: [String(format: "%.0f%% CPU", usage * 100)]),
                        process: p, path: p.path))
                }
            }
            next[p.pid] = (now, secs, hot)
        }
        cpu = next
        return out
    }

    // MARK: Persistence & posture

    private func slowScan() {
        var out: [Observation] = []
        let items = launchItems()
        let isBaselineRun = baseline.isEmpty
        for item in items {
            out += assess(item, isNew: !isBaselineRun && !baseline.contains(item.plist))
            baseline.insert(item.plist)
        }
        onLaunchItems(items, baseline)   // after the baseline is complete
        out += shellProfiles() + cron() + loginHook() + posture()
        if !out.isEmpty { onObservations(out) }
    }

    func launchItems() -> [LaunchItem] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = ["\(home)/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
        var out: [LaunchItem] = []
        for dir in dirs {
            for file in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] where file.hasSuffix(".plist") {
                let path = "\(dir)/\(file)"
                guard let data = FileManager.default.contents(atPath: path),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { continue }
                let args = plist["ProgramArguments"] as? [String] ?? []
                var program = plist["Program"] as? String ?? args.first ?? ""
                if program.isEmpty, let bundled = plist["BundleProgram"] as? String {
                    // Relative to the app bundle that registered it (SMAppService); resolve when possible.
                    program = bundled
                }
                let modified = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date) ?? Date()
                out.append(LaunchItem(plist: path, label: plist["Label"] as? String ?? file, program: program,
                                      arguments: args, modified: modified))
            }
        }
        return out
    }

    func assess(_ item: LaunchItem, isNew: Bool) -> [Observation] {
        var drafts: [Draft] = []
        let daemon = item.plist.hasPrefix("/Library/LaunchDaemons")
        let mitre = [daemon ? "T1543.004" : "T1543.001"]
        let kind = daemon ? "launch daemon (runs as root)" : "launch agent"
        let id = item.program.hasPrefix("/") ? identity(item.program) : CodeID(appleSigned: false)
        let cmd = item.arguments.isEmpty ? item.program : item.arguments.joined(separator: " ")
        var evidence = ["plist: \(item.plist)", "label: \(item.label)", "runs: \(cmd)", "program signature: \(id.label)"]

        if Detections.isTemp(item.program) || Detections.hiddenComponent(item.program) {
            drafts.append(Draft(rule: "persist.risky-path", title: "Persistence runs a program from a temporary or hidden folder",
                                detail: "The \(kind) \(item.label) starts \(item.program), which lives somewhere malware typically hides.",
                                severity: .high, category: .persistence, mitre: mitre))
        }
        let interp = Detections.base((item.program as NSString).lastPathComponent)
        if ["sh", "bash", "zsh", "python", "perl", "ruby", "osascript"].contains(interp),
           item.arguments.contains(where: { ["-c", "-e"].contains($0) }) {
            drafts.append(Draft(rule: "persist.inline-script", title: "Persistence runs an inline script",
                                detail: "The \(kind) \(item.label) runs code written directly into its definition rather than an installed program.",
                                severity: .medium, category: .persistence, mitre: mitre + ["T1059"]))
        }
        if item.program.hasPrefix("/"), !FileManager.default.fileExists(atPath: item.program) {
            evidence.append("program file is missing")
        }
        for r in Detections.scriptRules(cmd) {
            drafts.append(Draft(rule: "persist.\(r.id)", title: "Persistence: \(r.title)", detail: r.why,
                                severity: r.severity, category: .persistence, mitre: mitre + r.mitre))
        }
        if isNew {
            let risky = !drafts.isEmpty || (item.program.hasPrefix("/") && id.untrusted)
            drafts.append(Draft(rule: "persist.new", title: "New \(kind) installed: \(item.label)",
                                detail: "Something added \(item.plist) since Bastion started watching. It will start \(item.program) automatically.",
                                severity: risky ? .high : .low, category: .persistence, mitre: mitre))
        }
        return drafts.map { d in
            var d = d
            d.evidence = evidence
            return Observation(key: "\(d.rule)|\(item.plist)", draft: d, path: item.program.isEmpty ? item.plist : item.program)
        }
    }

    private func shellProfiles() -> [Observation] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var out: [Observation] = []
        for f in [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"] {
            let path = "\(home)/\(f)"
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for (n, line) in text.split(separator: "\n").enumerated() {
                let l = line.trimmingCharacters(in: .whitespaces)
                guard !l.isEmpty, !l.hasPrefix("#") else { continue }
                for r in Detections.scriptRules(l) {
                    out.append(Observation(
                        key: "shell.\(r.id)|\(path)|\(Detections.stableHash(l))",
                        draft: Draft(rule: "shell.\(r.id)", title: "Shell startup file: \(r.title)",
                                     detail: "\(f) runs this every time a terminal opens. \(r.why)",
                                     severity: max(r.severity, .medium), category: .persistence, mitre: ["T1546.004"] + r.mitre,
                                     evidence: ["\(path):\(n + 1)", String(l.prefix(300))]),
                        path: path))
                }
            }
        }
        return out
    }

    private func cron() -> [Observation] {
        let text = run("/usr/bin/crontab", ["-l"])
        return text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { l in l.first.map { $0.isNumber || $0 == "*" || $0 == "@" } ?? false }   // schedule lines only
            .map { line in
                let rules = Detections.scriptRules(line)
                return Observation(
                    key: "persist.cron|\(Detections.stableHash(line))",
                    draft: Draft(rule: "persist.cron", title: rules.first.map { "Cron job: \($0.title)" } ?? "Cron job scheduled",
                                 detail: "A cron job runs on a schedule. Rarely used by normal Mac apps; a classic persistence spot.",
                                 severity: rules.map(\.severity).max().map { max($0, .medium) } ?? .low,
                                 category: .persistence, mitre: ["T1053.003"] + rules.flatMap(\.mitre),
                                 evidence: [line]),
                    path: "/usr/lib/cron/tabs")
            }
    }

    private func loginHook() -> [Observation] {
        let hook = run("/usr/bin/defaults", ["read", "com.apple.loginwindow", "LoginHook"]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !hook.isEmpty, !hook.contains("does not exist"), !hook.hasPrefix("Error") else { return [] }
        return [Observation(key: "persist.loginhook|\(hook)",
                            draft: Draft(rule: "persist.loginhook", title: "Login hook set",
                                         detail: "A deprecated mechanism that runs \(hook) as root at every login.",
                                         severity: .high, category: .persistence, mitre: ["T1037.002"], evidence: [hook]),
                            path: hook)]
    }

    private func posture() -> [Observation] {
        var out: [Observation] = []
        func add(_ rule: String, _ title: String, _ detail: String, _ sev: Severity, _ mitre: [String], _ ev: String) {
            out.append(Observation(key: rule, draft: Draft(rule: rule, title: title, detail: detail, severity: sev,
                                                           category: .posture, mitre: mitre, evidence: [ev])))
        }
        let sip = run("/usr/bin/csrutil", ["status"])
        if sip.contains("disabled") {
            add("posture.sip", "System Integrity Protection is off", "SIP protects system files and processes from tampering, even by root.",
                .high, ["T1562.001"], sip.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let gk = run("/usr/sbin/spctl", ["--status"])
        if gk.contains("disabled") {
            add("posture.gatekeeper", "Gatekeeper is off", "Apps from anywhere can run without a signature or notarization check.",
                .high, ["T1553.001"], gk.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let fv = run("/usr/bin/fdesetup", ["status"])
        if fv.contains("FileVault is Off") {
            add("posture.filevault", "FileVault disk encryption is off", "Anyone with physical access to this Mac can read its disk.",
                .low, ["T1005"], fv.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return out
    }

    private func run(_ exe: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
