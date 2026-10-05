import Foundation

struct RemediationSettings: Codable, Equatable {
    enum Mode: String, Codable, CaseIterable, Identifiable {
        case off = "Off", preview = "Preview & confirm", automatic = "Automatic after each scan"
        var id: String { rawValue }
    }
    var mode: Mode = .preview
    var minSeverity: Severity = .high
    var allowMajorUpgrades = false
    var homebrew = true
    var projects = true
    /// Block network-exposed services with an inbound firewall rule. Off for automatic mode by default: it can
    /// break things the user shares on purpose.
    var exposuresInAutomatic = false
    var installIntoVirtualenv = true
    var requireCleanGit = true
    /// Don't install a release younger than this many days (0 = no cooldown).
    var cooldownDays = 3

    init() {}

    // Older saves lack newer keys: default them instead of failing the whole load.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = RemediationSettings()
        mode = try c.decodeIfPresent(Mode.self, forKey: .mode) ?? d.mode
        minSeverity = try c.decodeIfPresent(Severity.self, forKey: .minSeverity) ?? d.minSeverity
        allowMajorUpgrades = try c.decodeIfPresent(Bool.self, forKey: .allowMajorUpgrades) ?? d.allowMajorUpgrades
        homebrew = try c.decodeIfPresent(Bool.self, forKey: .homebrew) ?? d.homebrew
        projects = try c.decodeIfPresent(Bool.self, forKey: .projects) ?? d.projects
        exposuresInAutomatic = try c.decodeIfPresent(Bool.self, forKey: .exposuresInAutomatic) ?? d.exposuresInAutomatic
        installIntoVirtualenv = try c.decodeIfPresent(Bool.self, forKey: .installIntoVirtualenv) ?? d.installIntoVirtualenv
        requireCleanGit = try c.decodeIfPresent(Bool.self, forKey: .requireCleanGit) ?? d.requireCleanGit
        cooldownDays = try c.decodeIfPresent(Int.self, forKey: .cooldownDays) ?? d.cooldownDays
    }
}

struct RemediationStep: Codable, Hashable {
    enum Kind: String, Codable { case command, edit, firewallRule, manual }
    var kind: Kind
    var summary: String
    var command: [String]?
    var cwd: String?
    var file: String?
    var before: String?
    var after: String?
    var port: Int?
    /// For undo: the command that reverses this one, when there is one (pip can reinstall the old version).
    var undoCommand: [String]?

    /// "- old / + new" for the lines an edit changes.
    var diff: [String] {
        guard let b = before?.components(separatedBy: "\n"), let a = after?.components(separatedBy: "\n") else { return [] }
        var out: [String] = []
        for i in 0..<max(a.count, b.count) {
            let x = i < b.count ? b[i] : nil, y = i < a.count ? a[i] : nil
            if x != y {
                if let x { out.append("- \(x)") }
                if let y { out.append("+ \(y)") }
            }
        }
        return out
    }
}

struct RemediationPlan: Identifiable, Codable, Hashable {
    var component: Component
    var target: String?
    var fixes: [String]              // vulnerability ids the target version fixes
    var unfixable: [String] = []     // no fixed release listed
    var steps: [RemediationStep] = []
    var warnings: [String] = []
    var blocked: String?             // why it can't run automatically
    var majorUpgrade = false
    var severity: Severity
    /// The target version was confirmed in the package's official registry (nil = not checked / not applicable).
    var registryVerified: Bool?
    var id: String { component.id }

    /// Steps that actually change something (not just advice).
    var actionable: Bool { blocked == nil && steps.contains { $0.kind != .manual } }
}

struct RemediationRecord: Codable, Identifiable, Hashable {
    enum Status: String, Codable { case running, succeeded, partial, failed, undone }
    var id = UUID()
    var date = Date()
    var plan: RemediationPlan
    var status: Status = .running
    var log: [String] = []
    var backups: [String: String] = [:]   // edited file → backup copy
    var ruleIDs: [UUID] = []
    var completedSteps: [Int] = []
    var verifiedVersion: String?
    var automatic = false
}

/// Builds remediation plans from open findings. Everything here runs off the main thread (it calls brew/git).
enum RemediationPlanner {
    static let env: [String: String] = {
        var e = ProcessInfo.processInfo.environment
        e["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        e["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        e["HOMEBREW_NO_ENV_HINTS"] = "1"
        // `brew cleanup`/`uninstall` otherwise also remove every dependency no formula needs any more: fixing one
        // formula must never uninstall others.
        e["HOMEBREW_NO_AUTOREMOVE"] = "1"
        return e
    }()

    static func tool(_ name: String) -> String? {
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"].map { "\($0)/\(name)" }.first(where: FileManager.default.isExecutableFile)
    }

    /// Names reach command arguments; allow only what package registries allow.
    static func validName(_ s: String) -> Bool { s.range(of: #"^[A-Za-z0-9@._+/\-]{1,214}$"#, options: .regularExpression) != nil }
    static func validVersion(_ s: String) -> Bool { s.range(of: #"^[A-Za-z0-9._+\-]{1,64}$"#, options: .regularExpression) != nil }

    /// Major-version change (for 0.x, a minor change counts as major, per semver convention).
    static func isMajor(from: String, to: String) -> Bool {
        let a = Version.tokens(from), b = Version.tokens(to)
        guard case .num(let a0)? = a.first, case .num(let b0)? = b.first else { return false }
        if a0 != b0 { return true }
        if a0 == 0, a.count > 1, b.count > 1, case .num(let a1) = a[1], case .num(let b1) = b[1] { return a1 != b1 }
        return false
    }

    static func plans(for findings: [VulnFinding], settings: RemediationSettings) -> [RemediationPlan] {
        let open = findings.filter { $0.status == .open && $0.severity >= settings.minSeverity }
        return Dictionary(grouping: open, by: { $0.component.id }).values.compactMap { group in
            plan(group, settings: settings)
        }.sorted { ($0.severity, $0.fixes.count) > ($1.severity, $1.fixes.count) }
    }

    static func plan(_ group: [VulnFinding], settings: RemediationSettings) -> RemediationPlan? {
        guard let c = group.first?.component else { return nil }
        let severity = group.map(\.severity).max() ?? .info

        // Network exposure: block inbound connections to the port.
        if group.allSatisfy({ $0.vuln.id.hasPrefix("EXPOSED-") }) {
            var p = RemediationPlan(component: c, target: nil, fixes: group.map(\.vuln.id), severity: severity)
            for f in group {
                let port = Int(f.vuln.id.split(separator: "-").last ?? "") ?? 0
                p.steps.append(RemediationStep(kind: .firewallRule, summary: "Deny inbound connections to port \(port) (\(c.name))", port: port))
            }
            p.warnings.append("Other devices will no longer reach this service. If you share it on purpose, don't apply this.")
            return p
        }

        // Lowest version that fixes every open vulnerability that has a fix.
        var target: String?
        var fixes: [String] = [], unfixable: [String] = []
        for f in group {
            if let first = Version.upgrades(f.vuln.fixedVersions, from: c.version).first {
                fixes.append(f.vuln.id)
                if target == nil || Version.compare(first, target!) == .orderedDescending { target = first }
            } else {
                unfixable.append(f.vuln.id)
            }
        }
        var p = RemediationPlan(component: c, target: target, fixes: fixes, unfixable: unfixable, severity: severity)
        if !unfixable.isEmpty {
            p.warnings.append("\(unfixable.count) vulnerabilit\(unfixable.count == 1 ? "y has" : "ies have") no fixed release yet and will remain.")
        }

        switch c.kind {
        case .homebrew: planHomebrew(&p)
        case .package: planPackage(&p, settings: settings)
        case .app:
            p.steps.append(RemediationStep(kind: .manual, summary: "Update \(c.name)\(target.map { " to \($0) or later" } ?? "") with its built-in updater, the App Store, or the vendor's site."))
            p.blocked = "Apps update through their own updater."
        case .os:
            p.steps.append(RemediationStep(kind: .manual, summary: "Install the latest macOS update in System Settings → General → Software Update."))
            p.blocked = "macOS updates need your password and usually a restart."
        case .remote:
            p.steps.append(RemediationStep(kind: .manual, summary: "Update or reconfigure the device at \(c.location) (\(c.name)); Elliott can't change other machines."))
            p.blocked = "This is another device on your network."
        case .service:
            p.steps.append(RemediationStep(kind: .manual, summary: "Update \(c.name)\(target.map { " to \($0) or later" } ?? "") (it's provided by \(c.location))."))
            p.blocked = "Elliott can't tell how this service was installed."
        }
        if let t = target, isMajor(from: c.version, to: t) {
            p.majorUpgrade = true
            p.warnings.append("\(c.version) → \(t) is a major-version upgrade and may contain breaking changes.")
            if !settings.allowMajorUpgrades && p.blocked == nil {
                p.blocked = "Major-version upgrade (allow it in Settings → Vulnerabilities → Remediation, or apply it yourself)."
            }
        }
        if target == nil && p.blocked == nil && !p.steps.contains(where: { $0.kind == .firewallRule }) {
            p.blocked = "No fixed release is available yet."
        }
        return p
    }

    // MARK: Homebrew

    static func planHomebrew(_ p: inout RemediationPlan) {
        let name = p.component.name
        guard validName(name), let brew = tool("brew") else { p.blocked = "Homebrew not found."; return }
        if p.component.staleKeg == true {
            // A leftover from an earlier upgrade: nothing to upgrade, just delete the old copy.
            p.target = nil
            p.steps.append(RemediationStep(kind: .command,
                                           summary: "brew cleanup \(name) (removes the old \(p.component.version) copy; a newer version is the one in use)",
                                           command: [brew, "cleanup", name]))
            return
        }
        // Does Homebrew have the fixed version yet?
        let info = run([brew, "info", "--json=v2", name]).output
        if let obj = try? JSONSerialization.jsonObject(with: Data(info.utf8)) as? [String: Any],
           let stable = (((obj["formulae"] as? [[String: Any]])?.first?["versions"]) as? [String: Any])?["stable"] as? String {
            if let t = p.target, Version.compare(stable, t) == .orderedAscending {
                p.blocked = "Homebrew's newest \(name) is \(stable), which doesn't include the fix (\(t)) yet."
                return
            }
            if Version.compare(stable, p.component.version) != .orderedDescending {
                p.blocked = "\(name) \(p.component.version) is already Homebrew's newest version."
                return
            }
            p.warnings.append("Homebrew installs its newest \(name) (\(stable)) and may also upgrade formulae that depend on it.")
        }
        p.steps.append(RemediationStep(kind: .command, summary: "brew upgrade \(name)", command: [brew, "upgrade", name]))
    }

    // MARK: Project packages

    static func planPackage(_ p: inout RemediationPlan, settings: RemediationSettings) {
        let c = p.component
        guard let project = c.project, let eco = c.ecosystem else { p.blocked = "Unknown project."; return }
        guard let target = p.target else { return }
        guard validName(c.name), validVersion(target) else { p.blocked = "Unexpected package name or version."; return }
        var edited: [String] = []

        switch eco {
        case "PyPI":
            // Raise the pin/floor in every requirements file that names the package.
            let norm = Inventory.normalize(c.name, "PyPI")
            for file in ((try? FileManager.default.contentsOfDirectory(atPath: project)) ?? []).sorted()
            where file.hasPrefix("requirements") && file.hasSuffix(".txt") {
                let path = "\(project)/\(file)"
                guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
                let updated = repin(requirements: text, package: norm, to: target)
                if updated != text {
                    p.steps.append(RemediationStep(kind: .edit, summary: "\(file): require \(c.name) \(target)", file: path, before: text, after: updated))
                    edited.append(path)
                }
            }
            if settings.installIntoVirtualenv, let py = virtualenvPython(project) {
                p.steps.append(RemediationStep(kind: .command, summary: "pip install \(c.name)==\(target) into \(((py as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent.split(separator: "/").last ?? "venv")",
                                               // Wheels only: a source distribution would run the package's own setup code.
                                               command: [py, "-m", "pip", "install", "--disable-pip-version-check", "--only-binary", ":all:", "\(c.name)==\(target)"], cwd: project,
                                               undoCommand: [py, "-m", "pip", "install", "--disable-pip-version-check", "--only-binary", ":all:", "\(c.name)==\(c.version)"]))
            }
            if p.steps.isEmpty {
                p.steps.append(RemediationStep(kind: .manual, summary: "Upgrade \(c.name) to \(target) where this environment is defined."))
                p.blocked = "No requirements file or virtualenv to update."
            }
        case "npm":
            guard let npm = tool("npm") else {
                p.steps.append(RemediationStep(kind: .manual, summary: "npm install \(c.name)@\(target)  (in \(project))"))
                p.blocked = "npm isn't installed on this Mac."
                break
            }
            if c.direct == true {
                p.steps.append(RemediationStep(kind: .command, summary: "npm install \(c.name)@\(target)", command: [npm, "install", "\(c.name)@\(target)"], cwd: project))
            } else if let edit = npmOverride(project: project, package: c.name, version: target) {
                p.steps.append(edit)
                edited.append(edit.file!)
                p.steps.append(RemediationStep(kind: .command, summary: "npm install (apply the override)", command: [npm, "install"], cwd: project))
            }
        case "crates.io":
            command(&p, tool: "cargo", args: ["update", "-p", c.name, "--precise", target], cwd: project)
        case "Go":
            command(&p, tool: "go", args: ["get", "\(c.name)@v\(target)"], cwd: project)
            command(&p, tool: "go", args: ["mod", "tidy"], cwd: project)
        case "RubyGems":
            command(&p, tool: "bundle", args: ["update", c.name, "--conservative"], cwd: project)
        case "Packagist":
            command(&p, tool: "composer", args: ["update", c.name, "--with-dependencies"], cwd: project)
        default:
            p.steps.append(RemediationStep(kind: .manual, summary: "Upgrade \(c.name) to \(target) in \(project)."))
            p.blocked = "No automatic upgrade for \(eco) packages."
        }

        // Lockfiles a command rewrites count as edits too.
        let lock = c.location.hasSuffix("pyvenv.cfg") ? nil : c.location
        let touched = edited + (p.steps.contains { $0.kind == .command } ? [lock].compactMap { $0 } : [])
        if settings.requireCleanGit, p.blocked == nil, let dirty = uncommitted(touched, in: project), !dirty.isEmpty {
            p.blocked = "Uncommitted changes in \(dirty.joined(separator: ", ")). Commit or stash them first so the upgrade is easy to review and revert."
        }
    }

    static func command(_ p: inout RemediationPlan, tool name: String, args: [String], cwd: String) {
        if let t = tool(name) {
            p.steps.append(RemediationStep(kind: .command, summary: "\(name) \(args.joined(separator: " "))", command: [t] + args, cwd: cwd))
        } else {
            p.steps.append(RemediationStep(kind: .manual, summary: "\(name) \(args.joined(separator: " "))  (in \(cwd))"))
            if p.blocked == nil { p.blocked = "\(name) isn't installed on this Mac." }
        }
    }

    /// `pkg==1.0` → `pkg==target`; `pkg>=1.0` → `pkg>=target`; other lines untouched (comments and extras kept).
    static func repin(requirements text: String, package norm: String, to target: String) -> String {
        text.components(separatedBy: "\n").map { line -> String in
            guard let m = line.firstMatch(of: /^(\s*)([A-Za-z0-9_.\-]+)(\[[^\]]*\])?(\s*)(==|>=|~=)(\s*)([A-Za-z0-9_.\-+!]+)(.*)$/),
                  Inventory.normalize(String(m.2), "PyPI") == norm else { return line }
            let op = m.5 == "~=" ? ">=" : String(m.5)
            return "\(m.1)\(m.2)\(m.3 ?? "")\(m.4)\(op)\(m.6)\(target)\(m.8)"
        }.joined(separator: "\n")
    }

    static func virtualenvPython(_ project: String) -> String? {
        for v in [".venv", "venv", "env"] {
            let py = "\(project)/\(v)/bin/python"
            if FileManager.default.isExecutableFile(atPath: py) { return py }
        }
        return nil
    }

    /// Adds `"overrides": {pkg: version}` to package.json, for a transitive dependency.
    static func npmOverride(project: String, package: String, version: String) -> RemediationStep? {
        let path = "\(project)/package.json"
        guard let text = try? String(contentsOfFile: path, encoding: .utf8),
              var obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return nil }
        var overrides = obj["overrides"] as? [String: Any] ?? [:]
        overrides[package] = version
        obj["overrides"] = overrides
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else { return nil }
        return RemediationStep(kind: .edit, summary: "package.json: override \(package) to \(version)", file: path, before: text,
                               after: String(decoding: data, as: UTF8.self) + "\n")
    }

    /// Files (relative) with uncommitted changes, or nil when the project isn't a git repository.
    static func uncommitted(_ files: [String], in project: String) -> [String]? {
        guard !files.isEmpty, let git = tool("git") else { return nil }
        let top = run([git, "-C", project, "rev-parse", "--show-toplevel"])
        guard top.status == 0 else { return nil }
        let status = run([git, "-C", project, "status", "--porcelain", "--"] + files)
        return status.output.split(separator: "\n").map { String($0.dropFirst(3)) }
    }

    @discardableResult
    static func run(_ args: [String], cwd: String? = nil, timeout: TimeInterval = 900) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: args[0])
        p.arguments = Array(args.dropFirst())
        p.environment = env
        if let cwd { p.currentDirectoryURL = URL(fileURLWithPath: cwd) }
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (-1, error.localizedDescription) }
        let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        killer.cancel()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

/// Runs a plan: backs up and edits files, runs commands, then re-reads the installed version to verify.
/// Firewall-rule steps are applied by the caller (they go through Elliott's rule engine).
enum RemediationExecutor {
    static func execute(_ plan: RemediationPlan, backupDir: URL, automatic: Bool,
                        log: @Sendable (String) -> Void) -> RemediationRecord {
        var r = RemediationRecord(plan: plan, automatic: automatic)
        func say(_ s: String) { r.log.append(s); log(s) }
        let dir = backupDir.appendingPathComponent(r.id.uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var failed = false

        for (i, step) in plan.steps.enumerated() {
            switch step.kind {
            case .manual, .firewallRule:
                continue
            case .edit:
                guard let file = step.file, let before = step.before, let after = step.after else { continue }
                guard let current = try? String(contentsOfFile: file, encoding: .utf8), current == before else {
                    say("✗ \(file) changed since the plan was made; not editing it.")
                    failed = true
                    break
                }
                let backup = dir.appendingPathComponent("\(i)-\((file as NSString).lastPathComponent)")
                do {
                    try FileManager.default.copyItem(at: URL(fileURLWithPath: file), to: backup)
                    r.backups[file] = backup.path
                    try after.write(toFile: file, atomically: true, encoding: .utf8)
                    r.completedSteps.append(i)
                    say("✓ \(step.summary)")
                } catch {
                    say("✗ \(step.summary): \(error.localizedDescription)")
                    failed = true
                }
            case .command:
                guard let cmd = step.command else { continue }
                say("$ \(cmd.map { ($0 as NSString).lastPathComponent == $0 ? $0 : ($0 as NSString).lastPathComponent }.joined(separator: " "))")
                let res = RemediationPlanner.run(cmd, cwd: step.cwd)
                let tail = res.output.split(separator: "\n").suffix(12).joined(separator: "\n")
                if !tail.isEmpty { say(tail) }
                if res.status == 0 {
                    r.completedSteps.append(i)
                    say("✓ \(step.summary)")
                } else {
                    say("✗ \(step.summary) exited with status \(res.status)")
                    failed = true
                }
            }
            if failed { break }
        }

        if plan.component.staleKeg == true {
            let gone = !FileManager.default.fileExists(atPath: plan.component.location)
            say(gone ? "✓ Verified: the old \(plan.component.name) \(plan.component.version) copy is gone."
                     : "✗ The old copy is still at \(plan.component.location).")
            r.status = gone ? (failed ? .partial : .succeeded) : .failed
            return r
        }
        r.verifiedVersion = installedVersion(plan.component)
        if let v = r.verifiedVersion, let t = plan.target {
            let ok = Version.compare(v, t) != .orderedAscending
            say(ok ? "✓ Verified: \(plan.component.name) is now \(v)." : "✗ \(plan.component.name) is still \(v) (needed \(t)).")
            r.status = ok ? (failed ? .partial : .succeeded) : .failed
        } else {
            r.status = failed ? (r.completedSteps.isEmpty ? .failed : .partial) : .succeeded
        }
        return r
    }

    /// The version installed now, read the same way the scan reads it.
    static func installedVersion(_ c: Component) -> String? {
        switch c.kind {
        case .homebrew:
            guard let brew = RemediationPlanner.tool("brew") else { return nil }
            let out = RemediationPlanner.run([brew, "list", "--versions", c.name]).output
            let kegs = out.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ").dropFirst().map(String.init)
            let prefix = ((brew as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
            return Inventory.activeKeg(c.name, kegs: kegs, prefix: prefix).map(Inventory.brewVersion)
        case .package:
            let norm = Inventory.normalize(c.name, c.ecosystem ?? "")
            // Prefer what's actually installed (virtualenv) over what's declared.
            var sources = [c.location]
            if c.ecosystem == "PyPI", let project = c.project, let py = RemediationPlanner.virtualenvPython(project) {
                sources.insert(((py as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent + "/pyvenv.cfg", at: 0)
            }
            for s in sources {
                let found = Inventory.packages(lockfile: s).filter { Inventory.normalize($0.name, $0.ecosystem ?? "") == norm }
                if let best = found.map(\.version).max(by: { Version.compare($0, $1) == .orderedAscending }) { return best }
            }
            return nil
        default:
            return nil
        }
    }

    /// Restores edited files and reverses commands that can be reversed (pip). Homebrew upgrades stay.
    static func undo(_ r: RemediationRecord, log: @Sendable (String) -> Void) -> [String] {
        var out: [String] = []
        func say(_ s: String) { out.append(s); log(s) }
        for (file, backup) in r.backups {
            do {
                _ = try FileManager.default.replaceItemAt(URL(fileURLWithPath: file), withItemAt: URL(fileURLWithPath: backup),
                                                          backupItemName: nil, options: [.usingNewMetadataOnly])
                say("✓ Restored \((file as NSString).lastPathComponent)")
            } catch {
                say("✗ Couldn't restore \(file): \(error.localizedDescription)")
            }
        }
        for i in r.completedSteps.reversed() {
            let step = r.plan.steps[i]
            if let undo = step.undoCommand {
                let res = RemediationPlanner.run(undo, cwd: step.cwd)
                say(res.status == 0 ? "✓ Reverted: \(step.summary)" : "✗ Couldn't revert \(step.summary) (status \(res.status))")
            } else if step.kind == .command {
                say("• \(step.summary) can't be reverted automatically")
            }
        }
        return out
    }
}
