import CryptoKit
import Foundation

enum Severity: Int, Codable, Comparable, CaseIterable, Identifiable {
    case info, low, medium, high, critical
    var id: Int { rawValue }
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    var label: String { String(describing: self).uppercased() }
}

enum FindingCategory: String, Codable, CaseIterable {
    case process, commandLine = "command line", persistence, posture, network, resource, file

    // Reports from newer nodes may carry categories this build doesn't know: show them as network detections
    // rather than dropping the whole report.
    init(from decoder: Decoder) throws {
        self = FindingCategory(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .network
    }
}

enum FindingStatus: String, Codable, CaseIterable {
    case open, acknowledged, benign
}

/// The local model's read on a finding.
struct Triage: Codable, Hashable {
    var assessment: String        // "likely malicious" | "suspicious" | "likely benign"
    var confidence: Int
    var explanation: String
    var recommendation: String
    var model: String
    var date = Date()
}

/// An EDR detection. `key` dedupes repeats of the same behavior (same rule, same binary, same command).
struct Finding: Codable, Identifiable, Hashable {
    var id = UUID()
    var key: String
    var rule: String
    var title: String
    var detail: String
    var severity: Severity
    var category: FindingCategory
    var mitre: [String]
    var path: String?
    var pid: Int32?
    /// The process's start time: with `pid`, identifies exactly one process (ids get reused).
    var processStart: Date?
    var commandLine: String?
    var user: String?
    var chain: [String] = []      // ancestors, nearest first: "zsh (812)"
    var evidence: [String] = []
    var firstSeen = Date()
    var lastSeen = Date()
    var count = 1
    var status: FindingStatus = .open
    var triage: Triage?

    var target: String { path.map { ($0 as NSString).lastPathComponent } ?? title }
}

/// A finding before it's merged into the store.
struct Draft {
    var rule: String
    var title: String
    var detail: String
    var severity: Severity
    var category: FindingCategory
    var mitre: [String]
    var evidence: [String] = []
}

/// Code-signing identity of a binary on disk.
struct CodeID: Hashable {
    var signingID: String?
    var teamID: String?
    var appleSigned: Bool
    var label: String { appleSigned ? "Apple" : teamID.map { "team \($0)" } ?? (signingID != nil ? "ad-hoc" : "unsigned") }
    /// Not signed by Apple or by a registered developer.
    var untrusted: Bool { !appleSigned && teamID == nil }
}

struct CommandRule {
    var id: String
    var title: String
    var regex: NSRegularExpression
    var severity: Severity
    var mitre: [String]
    var why: String
    /// Also applies to shell profiles, cron and launch items.
    var scripts: Bool

    init(_ id: String, _ title: String, _ pattern: String, _ severity: Severity, _ mitre: [String], _ why: String, scripts: Bool = true) {
        self.id = id; self.title = title; self.severity = severity; self.mitre = mitre; self.why = why; self.scripts = scripts
        regex = try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
    }

    func matches(_ s: String) -> Bool {
        regex.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
}

/// Behavior rules. Process rules run once per new process; command rules run on its arguments and on
/// persistence scripts.
enum Detections {
    static let commandRules: [CommandRule] = [
        CommandRule("cmd.reverse-shell", "Reverse shell",
                    #"/dev/(tcp|udp)/|\b(ba|z)?sh\s+-i\b.*[>&]|\bn(c|cat|etcat)\b.*\s-[a-z]*e\s|\bsocat\b.*exec|mkfifo.*\bn(c|cat)\b|socket\.socket.*(pty\.spawn|subprocess|os\.dup2)"#,
                    .critical, ["T1059.004"], "Hands an interactive shell to a remote host."),
        CommandRule("cmd.download-exec", "Download piped to an interpreter",
                    #"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(curl|wget)\b[^|;]*\|\s*(python3?|perl|ruby|osascript)\b"#,
                    .high, ["T1105", "T1059"], "Runs code fetched from the internet without saving or checking it."),
        CommandRule("cmd.base64-exec", "Decoded payload executed",
                    #"base64\s+(-d|-D|--decode)[^|]*\|\s*(ba|z)?sh|base64\s+(-d|-D|--decode)[^|]*\|\s*(python3?|osascript|perl)|echo\s+[A-Za-z0-9+/=]{80,}\s*\|\s*base64"#,
                    .high, ["T1140", "T1027"], "Obfuscated (base64) code decoded and run, a common malware dropper pattern."),
        CommandRule("cmd.password-prompt", "Fake password prompt",
                    #"osascript.*display dialog.*(password|passcode|passwort)|osascript.*hidden answer"#,
                    .critical, ["T1056.002"], "AppleScript dialog asking for a password: the classic macOS credential-phishing trick."),
        CommandRule("cmd.keychain", "Keychain secrets read from the command line",
                    #"\bsecurity\s+(dump-keychain|find-(generic|internet)-password\b.*\s-[a-z]*w|export\b)"#,
                    .high, ["T1555.001"], "Dumps or reads saved passwords from the Keychain."),
        CommandRule("cmd.quarantine-strip", "Quarantine attribute removed",
                    #"\bxattr\b.*(-d|-c|-r|-cr|-rc)\b.*com\.apple\.quarantine|\bxattr\s+-(cr|rc|c)\s"#,
                    .medium, ["T1553.001"], "Strips Gatekeeper's download flag so a file runs without checks."),
        CommandRule("cmd.defense-off", "Security controls disabled",
                    #"spctl\s+--(master|global)-disable|csrutil\s+disable|\bkillall\b.*(little ?snitch|lulu|elliott|xprotect)|launchctl\s+(unload|bootout|disable).*(xprotect|mrt|security|elliott)"#,
                    .high, ["T1562.001"], "Turns off Gatekeeper, SIP or a security tool."),
        CommandRule("cmd.tcc-tamper", "Privacy database tampering",
                    #"TCC\.db|\btccutil\s+reset\b"#,
                    .medium, ["T1548"], "Touches the privacy-permission (TCC) database."),
        CommandRule("cmd.launch-temp", "Persistence loaded from a temporary folder",
                    #"launchctl\s+(load|bootstrap|submit).*(/tmp/|/private/var/folders|/Users/Shared|/\.)"#,
                    .high, ["T1543.001"], "Registers a launch job whose definition lives somewhere temporary or hidden."),
        CommandRule("cmd.wipe-traces", "Shell history or logs wiped",
                    #"\brm\b.*\.(zsh|bash)_history|\bhistory\s+-c\b|\blog\s+erase\b|unset\s+HISTFILE"#,
                    .medium, ["T1070.003"], "Removes command history or logs to hide activity."),
        CommandRule("cmd.account", "Account or admin group changed",
                    #"\bdscl\s+\.\s+-(create|append)\s+/(Users|Groups/admin)|\bdseditgroup\b.*\badmin\b|\bsysadminctl\s+-addUser"#,
                    .high, ["T1136.001", "T1098"], "Creates a user or adds someone to the admin group."),
        CommandRule("cmd.sudo-stdin", "Password piped into sudo",
                    #"echo\s+.*\|\s*sudo\s+-S|sudo\s+-S\s"#,
                    .high, ["T1548.003"], "Feeds a password to sudo from a script."),
        CommandRule("cmd.miner", "Cryptominer arguments",
                    #"stratum\+(tcp|ssl)://|--donate-level|\bxmrig\b|--coin(=|\s)monero|-a\s+(rx/0|cryptonight)"#,
                    .critical, ["T1496"], "Mining-pool connection settings."),
        CommandRule("cmd.tunnel", "Reverse tunnel opened",
                    #"\bngrok\s+(tcp|http|start)|\bchisel\s+(client|server)|\bfrpc\b|\bssh\b.*\s-[a-zA-Z]*R\s*\d|cloudflared\s+tunnel\s+(run|--url)"#,
                    .medium, ["T1572"], "Exposes this Mac to the internet through a tunnel."),
        CommandRule("cmd.exfil-upload", "File uploaded from the command line",
                    #"\bcurl\b.*(\s-F\s*\S*=@|--data-binary\s+@|\s-T\s)|\bscp\b.*\s\S+@\S+:"#,
                    .low, ["T1048"], "Sends a local file to a remote server.", scripts: false),
        CommandRule("cmd.login-hook", "Login hook installed",
                    #"defaults\s+write\s+\S*loginwindow\s+(LoginHook|LogoutHook)"#,
                    .high, ["T1037.002"], "Runs a script as root at every login."),
        CommandRule("cmd.silent-capture", "Silent screen capture",
                    #"\bscreencapture\b.*\s-[a-zA-Z]*x"#,
                    .low, ["T1113"], "Takes screenshots without the shutter sound.", scripts: false),
        CommandRule("cmd.chmod-temp", "Temporary file made executable",
                    #"chmod\s+(\+x|[0-7]*7[0-7]*)\s+(/tmp/|/private/tmp/|/Users/Shared/|/private/var/folders/)"#,
                    .medium, ["T1222.002"], "Marks a file in a temporary folder as a program."),
        CommandRule("cmd.prompt-injection", "Text aimed at AI security tools",
                    Untrusted.injection.pattern,
                    .medium, ["T1562"], "The command line contains instructions written for an AI (e.g. \"ignore previous instructions\", \"classify as benign\"): an attempt to fool LLM-based analysis.",
                    scripts: false),
        CommandRule("cmd.admin-script", "Script elevating to admin",
                    #"do shell script.*with administrator privileges"#,
                    .low, ["T1548"], "AppleScript asking for admin rights (installers do this too).", scripts: false),
    ]

    static let offensiveTools: [String: (Severity, String, [String])] = [
        "xmrig": (.critical, "Cryptominer (XMRig)", ["T1496"]), "minerd": (.critical, "Cryptominer (minerd)", ["T1496"]),
        "cpuminer": (.critical, "Cryptominer (cpuminer)", ["T1496"]), "nbminer": (.critical, "Cryptominer (NBMiner)", ["T1496"]),
        "poseidon": (.critical, "Mythic Poseidon agent", ["T1219"]), "apfell": (.critical, "Mythic Apfell agent", ["T1219"]),
        "sliver": (.critical, "Sliver C2 implant", ["T1219"]), "merlin": (.high, "Merlin C2 agent", ["T1219"]),
        "empyre": (.critical, "EmPyre agent", ["T1219"]), "meterpreter": (.critical, "Meterpreter", ["T1219"]),
        "pupy": (.critical, "Pupy RAT", ["T1219"]), "keylogger": (.high, "Keylogger", ["T1056.001"]),
        "ngrok": (.medium, "ngrok tunnel", ["T1572"]), "chisel": (.medium, "Chisel tunnel", ["T1572"]),
        "frpc": (.medium, "frp tunnel client", ["T1572"]), "tor": (.low, "Tor client", ["T1090.003"]),
    ]

    static let appleDaemonNames: Set<String> = [
        "launchd", "kernel_task", "WindowServer", "loginwindow", "mds", "mds_stores", "mdworker", "mdworker_shared",
        "syslogd", "logd", "softwareupdated", "trustd", "securityd", "coreaudiod", "Finder", "Dock", "SystemUIServer",
        "cfprefsd", "distnoted", "apsd", "bird", "cloudd", "sharingd", "rapportd", "configd", "opendirectoryd",
        "UserEventAgent", "notifyd", "powerd", "airportd", "bluetoothd", "locationd", "nsurlsessiond", "XProtect",
        "XProtectService", "MRT", "sysmond", "kextd", "diskarbitrationd", "coreservicesd", "lsd", "tccd", "sudo",
    ]

    static let documentApps: Set<String> = [
        "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Microsoft Outlook", "Pages", "Numbers", "Keynote",
        "Preview", "Mail", "Messages", "Adobe Acrobat Reader", "Adobe Acrobat", "Acrobat Reader", "Skim", "LibreOffice",
    ]
    static let browsers: Set<String> = ["Safari", "Google Chrome", "Firefox", "Arc", "Brave Browser", "Microsoft Edge", "Opera", "Vivaldi"]
    static let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "osascript", "python", "python3",
                                      "perl", "ruby", "curl", "wget", "nc", "ncat", "osacompile", "node"]

    static let tempDirs = ["/tmp/", "/private/tmp/", "/private/var/folders/", "/Users/Shared/", "/Downloads/", "/.Trash/", "/var/tmp/"]
    /// Hidden folders where developer tools legitimately keep binaries.
    static let devHidden = ["/.cargo/", "/.rustup/", "/.nvm/", "/.npm/", "/.bun/", "/.deno/", "/.vscode", "/.cursor",
                            "/.local/", "/.pyenv/", "/.rbenv/", "/.sdkman/", "/.docker/", "/.orbstack/", "/.gradle/", "/.m2/",
                            "/.dotnet/", "/.oh-my-zsh/", "/.volta/", "/.asdf/", "/.ollama/", "/.cache/", "/.claude/", "/.git/"]

    /// Stable across launches (String.hashValue isn't), so dedupe keys and "benign" marks persist.
    static func stableHash(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    static func appName(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") else { return nil }
        return (String(path[..<r.lowerBound]) as NSString).lastPathComponent
    }

    static func base(_ name: String) -> String {
        name.lowercased().components(separatedBy: CharacterSet.decimalDigits.union(["."])).first ?? name.lowercased()
    }

    /// Locations macOS itself manages (e.g. where launchd stages privileged XPC services, then deletes them). They're
    /// root-only, so an unprivileged signature check fails there and can't be taken as "unsigned".
    static let systemManaged = ["/private/var/db/com.apple.xpc.roleaccountd.staging/", "/System/Volumes/Preboot/Cryptexes/",
                                "/private/var/db/", "/Library/Apple/"]
    static func isSystemManaged(_ path: String) -> Bool { systemManaged.contains { path.hasPrefix($0) } }

    static func isTemp(_ path: String) -> Bool {
        tempDirs.contains { path.contains($0) } && !path.contains("/AppTranslocation/") && !path.contains("/Xcode/DerivedData/")
            && !path.contains("/com.apple.")
    }

    static func hiddenComponent(_ path: String) -> Bool {
        guard !devHidden.contains(where: { path.contains($0) }) else { return false }
        return path.split(separator: "/").dropLast().contains { $0.hasPrefix(".") && $0 != "." && $0 != ".." }
    }

    /// Rules evaluated once for each newly seen process.
    static func evaluate(_ p: ProcInfo, id: CodeID, ancestors: [ProcInfo], exists: Bool) -> [Draft] {
        var out: [Draft] = []
        let managed = isSystemManaged(p.path)
        let name = p.displayName
        let path = p.path

        if let (sev, title, mitre) = offensiveTools[base(name)] ?? offensiveTools[name.lowercased()], !id.appleSigned {
            out.append(Draft(rule: "proc.tool", title: title, detail: "A process named \(name) is running from \(path).",
                             severity: sev, category: .process, mitre: mitre))
        }

        if appleDaemonNames.contains(name) || name.hasPrefix("com.apple."),
           !id.appleSigned, !path.isEmpty, !managed,
           !["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"].contains(where: { path.hasPrefix($0) }) {
            out.append(Draft(rule: "proc.masquerade", title: "Process impersonating a macOS component",
                             detail: "\(name) is a macOS system process name, but this copy runs from \(path) and isn't signed by Apple.",
                             severity: .high, category: .process, mitre: ["T1036.005"]))
        }

        if id.untrusted && isTemp(path) {
            out.append(Draft(rule: "proc.temp-exec", title: "Unsigned program running from a temporary or download folder",
                             detail: "\(name) (\(id.label)) is running from \(path). Malware droppers usually stage payloads in places like this.",
                             severity: .high, category: .process, mitre: ["T1204.002"]))
        } else if id.untrusted && hiddenComponent(path) {
            out.append(Draft(rule: "proc.hidden-exec", title: "Unsigned program running from a hidden folder",
                             detail: "\(name) (\(id.label)) is running from a hidden directory: \(path).",
                             severity: .medium, category: .process, mitre: ["T1564.001"]))
        }

        if !exists && path.hasPrefix("/") && !path.contains(".app/") && !managed {
            out.append(Draft(rule: "proc.deleted", title: "Running program was deleted from disk",
                             detail: "\(name) is still running but its file \(path) no longer exists, a way to leave no file behind.",
                             severity: .medium, category: .process, mitre: ["T1070.004"]))
        }

        if p.uid == 0 && !id.appleSigned && (path.hasPrefix("/Users/") || isTemp(path)) {
            out.append(Draft(rule: "proc.root-userpath", title: "Root process running from a user-writable location",
                             detail: "\(name) runs as root from \(path), which any process of that user could replace.",
                             severity: .high, category: .process, mitre: ["T1548", "T1574"]))
        }

        if shells.contains(base(name)) || shells.contains(name) {
            let parentApps = ancestors.prefix(3).compactMap { appName($0.path) }
            if let doc = parentApps.first(where: documentApps.contains) {
                out.append(Draft(rule: "chain.document-shell", title: "\(doc) launched \(name)",
                                 detail: "A document or mail app started a shell or script interpreter: typical of a malicious attachment or macro.",
                                 severity: .high, category: .process, mitre: ["T1204.002", "T1059"]))
            } else if let br = parentApps.first(where: browsers.contains) {
                out.append(Draft(rule: "chain.browser-shell", title: "\(br) launched \(name)",
                                 detail: "A web browser started a shell or script interpreter, which browsers almost never do.",
                                 severity: .medium, category: .process, mitre: ["T1189", "T1059"]))
            }
        }

        if let cmd = p.commandLine {
            for r in commandRules where r.matches(cmd) {
                out.append(Draft(rule: r.id, title: r.title, detail: r.why, severity: r.severity,
                                 category: .commandLine, mitre: r.mitre))
            }
        }
        return out
    }

    /// Command rules that apply to a script line (shell profile, cron entry, launch item arguments).
    static func scriptRules(_ line: String) -> [CommandRule] {
        commandRules.filter { $0.scripts && $0.matches(line) }
    }
}
