import AppKit
import Foundation
import SQLite3

/// How well this Mac is configured, CIS-benchmark style: each check passes or fails with a reason and a fix, and
/// they roll up into a score. Read-only: nothing is changed; fixes open the right System Settings pane.
struct PostureCheck: Codable, Hashable, Identifiable {
    enum Status: String, Codable { case pass, warn, fail, unknown }
    var id: String
    var title: String
    var area: String
    var status: Status
    var detail: String
    var fix: String?
    var settings: String?         // x-apple.systempreferences: URL
    var weight: Int

    var points: Double { switch status { case .pass: 1; case .warn: 0.5; case .fail: 0; case .unknown: 0 } }
}

/// One privacy permission (TCC) an app holds.
struct PrivacyGrant: Codable, Hashable, Identifiable {
    var service: String           // kTCCService…
    var client: String            // bundle id or path
    var path: String?
    var signer: String
    var allowed: Bool
    var systemWide: Bool          // from the system database (vs this user's)
    var modified: Date?
    var id: String { "\(service)|\(client)|\(systemWide)" }

    var label: String { PrivacyGrant.serviceNames[service] ?? service.replacingOccurrences(of: "kTCCService", with: "") }
    var sensitive: Bool { PrivacyGrant.sensitive.contains(service) }
    /// Sensitive access held by something that isn't a properly signed, existing app.
    var risky: Bool {
        allowed && sensitive && (path == nil || signer == "unsigned" || signer == "ad-hoc" || signer == "invalid signature")
    }

    static let serviceNames: [String: String] = [
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access", "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceAccessibility": "Accessibility (control the Mac)", "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServicePostEvent": "Send keystrokes", "kTCCServiceCamera": "Camera", "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceAppleEvents": "Automation (control other apps)", "kTCCServiceSystemPolicyDocumentsFolder": "Documents folder",
        "kTCCServiceSystemPolicyDesktopFolder": "Desktop folder", "kTCCServiceSystemPolicyDownloadsFolder": "Downloads folder",
        "kTCCServiceAddressBook": "Contacts", "kTCCServiceCalendar": "Calendars", "kTCCServicePhotos": "Photos",
        "kTCCServiceLocation": "Location", "kTCCServiceDeveloperTool": "Developer Tools", "kTCCServiceEndpointSecurityClient": "Endpoint Security",
        "kTCCServiceSystemPolicyNetworkVolumes": "Network volumes", "kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
        "kTCCServiceSystemPolicySysAdminFiles": "Administer the system", "kTCCServiceBluetoothAlways": "Bluetooth",
    ]
    static let sensitive: Set<String> = [
        "kTCCServiceSystemPolicyAllFiles", "kTCCServiceScreenCapture", "kTCCServiceAccessibility", "kTCCServiceListenEvent",
        "kTCCServicePostEvent", "kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceSystemPolicySysAdminFiles",
        "kTCCServiceEndpointSecurityClient", "kTCCServiceDeveloperTool",
    ]
}

/// A browser extension with what it's allowed to do.
struct BrowserExtension: Codable, Hashable, Identifiable {
    var browser: String
    var id: String
    var name: String
    var version: String
    var permissions: [String]
    var fromStore: Bool
    var risky: [String] { permissions.filter { BrowserExtension.riskyPermissions.contains($0) } }
    static let riskyPermissions: Set<String> = [
        "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "webRequest", "webRequestBlocking", "debugger", "nativeMessaging",
        "cookies", "proxy", "management", "history", "clipboardRead", "privacy", "declarativeNetRequestWithHostAccess",
    ]
}

struct PostureReport: Codable, Equatable {
    var date = Date()
    var checks: [PostureCheck] = []
    var grants: [PrivacyGrant] = []
    var grantsReadable = false            // false = Elliott needs Full Disk Access to read them
    var extensions: [BrowserExtension] = []

    var score: Int {
        let scored = checks.filter { $0.status != .unknown }
        let total = scored.reduce(0) { $0 + $1.weight }
        guard total > 0 else { return 0 }
        return Int((scored.reduce(0.0) { $0 + $1.points * Double($1.weight) } / Double(total) * 100).rounded())
    }
}

enum PostureAudit {
    static func pane(_ id: String) -> String { "x-apple.systempreferences:\(id)" }

    static func run(appFirewallCovered: Bool) -> PostureReport {
        var r = PostureReport()
        r.checks = checks(appFirewallCovered: appFirewallCovered)
        (r.grants, r.grantsReadable) = privacyGrants()
        r.extensions = browserExtensions()
        // Privacy permissions and extensions roll into the score too.
        let risky = r.grants.filter(\.risky)
        r.checks.append(PostureCheck(id: "privacy.unsigned", title: "Sensitive privacy permissions held only by signed apps", area: "Privacy",
                                     status: !r.grantsReadable ? .unknown : risky.isEmpty ? .pass : .fail,
                                     detail: !r.grantsReadable ? "Elliott needs Full Disk Access to read the privacy database."
                                        : risky.isEmpty ? "No unsigned, ad-hoc or missing program holds Full Disk Access, Screen Recording, Accessibility, Input Monitoring, camera or microphone."
                                        : "\(risky.count) sensitive permission(s) held by unsigned, ad-hoc or missing programs: \(risky.prefix(4).map { "\($0.label) → \(($0.path ?? $0.client) as NSString).lastPathComponent" }.joined(separator: "; ")).",
                                     fix: "Remove permissions you don't recognize in Privacy & Security.",
                                     settings: pane("com.apple.settings.PrivacySecurity.extension"), weight: 3))
        let riskyExt = r.extensions.filter { !$0.risky.isEmpty && !$0.fromStore }
        r.checks.append(PostureCheck(id: "browser.extensions", title: "No powerful browser extensions from outside the stores", area: "Browsers",
                                     status: riskyExt.isEmpty ? .pass : .warn,
                                     detail: riskyExt.isEmpty ? "\(r.extensions.count) extension(s) found; none sideloaded with broad access."
                                        : "Sideloaded with broad access: \(riskyExt.prefix(4).map { "\($0.name) (\($0.browser))" }.joined(separator: ", ")).",
                                     fix: "Remove extensions you didn't install on purpose.", settings: nil, weight: 2))
        return r
    }

    // MARK: System checks

    static func checks(appFirewallCovered: Bool) -> [PostureCheck] {
        var c: [PostureCheck] = []
        func add(_ id: String, _ title: String, _ area: String, _ status: PostureCheck.Status, _ detail: String,
                 fix: String? = nil, settings: String? = nil, weight: Int = 2) {
            c.append(PostureCheck(id: id, title: title, area: area, status: status, detail: detail, fix: fix, settings: settings, weight: weight))
        }
        let su = UserDefaults(suiteName: "/Library/Preferences/com.apple.SoftwareUpdate")
        let pending = (su?.array(forKey: "RecommendedUpdates") ?? []).compactMap { ($0 as? [String: Any])?["Display Name"] as? String }
        let lastCheck = su?.object(forKey: "LastSuccessfulDate") as? Date
        // macOS, security and Safari updates matter most; developer tools and the like are worth a nudge only.
        let critical = pending.filter { n in ["macos", "security", "safari", "rapid security"].contains { n.lowercased().contains($0) } }
        add("os.updates", "macOS is up to date", "Updates",
            !critical.isEmpty ? .fail : !pending.isEmpty ? .warn
                : lastCheck.map { Date().timeIntervalSince($0) > 14 * 86400 } == true ? .warn : lastCheck == nil ? .unknown : .pass,
            !pending.isEmpty ? "Pending: \(pending.joined(separator: ", "))."
                : lastCheck.map { "Last checked \($0.formatted(.relative(presentation: .named)))." } ?? "No update check recorded.",
            fix: "Install pending updates.", settings: pane("com.apple.Software-Update-Settings.extension"), weight: 4)
        let auto = (su?.object(forKey: "AutomaticCheckEnabled") as? Bool ?? true) && (su?.object(forKey: "CriticalUpdateInstall") as? Bool ?? true)
        add("os.autoupdate", "Security updates install automatically", "Updates", auto ? .pass : .fail,
            auto ? "Automatic checks and security responses are on." : "Automatic update checks or security responses are off.",
            fix: "Turn on automatic updates, including Security Responses and system files.",
            settings: pane("com.apple.Software-Update-Settings.extension"), weight: 3)
        let xp = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        let xpDate = (try? FileManager.default.attributesOfItem(atPath: xp + "/Contents/Info.plist"))?[.modificationDate] as? Date
        add("os.xprotect", "Malware definitions (XProtect) are current", "Updates",
            xpDate.map { Date().timeIntervalSince($0) > 60 * 86400 ? .warn : .pass } ?? .unknown,
            xpDate.map { "XProtect updated \($0.formatted(.relative(presentation: .named)))." } ?? "XProtect not found.", weight: 2)

        let fv = run("/usr/bin/fdesetup", ["status"])
        add("disk.filevault", "FileVault disk encryption is on", "Protection", fv.contains("is On") ? .pass : fv.isEmpty ? .unknown : .fail,
            fv.trimmingCharacters(in: .whitespacesAndNewlines), fix: "Turn on FileVault.", settings: pane("com.apple.settings.PrivacySecurity.extension"), weight: 4)
        let sip = run("/usr/bin/csrutil", ["status"])
        add("os.sip", "System Integrity Protection is on", "Protection", sip.contains("enabled") ? .pass : sip.isEmpty ? .unknown : .fail,
            sip.trimmingCharacters(in: .whitespacesAndNewlines), fix: "Re-enable SIP from Recovery (csrutil enable).", weight: 4)
        let gk = run("/usr/sbin/spctl", ["--status"])
        add("os.gatekeeper", "Gatekeeper checks apps", "Protection", gk.contains("enabled") ? .pass : gk.isEmpty ? .unknown : .fail,
            gk.trimmingCharacters(in: .whitespacesAndNewlines), fix: "sudo spctl --global-enable", settings: pane("com.apple.settings.PrivacySecurity.extension"), weight: 3)
        let fw = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"])
        let fwOn = fw.contains("enabled")
        add("net.appfirewall", "Inbound connections are filtered", "Network",
            fwOn || appFirewallCovered ? .pass : .warn,
            fwOn ? "macOS's application firewall is on." : appFirewallCovered ? "macOS's application firewall is off, but Elliott's packet filter is enforcing your rules." : "Neither macOS's firewall nor Elliott's packet filter is filtering incoming connections.",
            fix: "Turn on the firewall, or install Elliott's helper.", settings: pane("com.apple.Network-Settings.extension"), weight: 2)

        let lock = run("/usr/sbin/sysadminctl", ["-screenLock", "status"])
        let lockStatus: PostureCheck.Status
        if lock.contains("immediate") { lockStatus = .pass }
        else if let n = lock.firstMatch(of: /(\d+) seconds/).flatMap({ Int($0.1) }) { lockStatus = n <= 300 ? .pass : .warn }
        else if lock.lowercased().contains("off") { lockStatus = .fail } else { lockStatus = .unknown }
        add("login.screenlock", "Password required soon after sleep or screen saver", "Login", lockStatus,
            lock.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Couldn't read the screen lock setting." : lock.trimmingCharacters(in: .whitespacesAndNewlines),
            fix: "Require a password immediately (or within 5 minutes).", settings: pane("com.apple.Lock-Screen-Settings.extension"), weight: 3)
        let lw = UserDefaults(suiteName: "/Library/Preferences/com.apple.loginwindow")
        let autoLogin = lw?.string(forKey: "autoLoginUser")
        add("login.autologin", "Automatic login is off", "Login", autoLogin == nil ? .pass : .fail,
            autoLogin.map { "Logs in as \($0) without a password at startup." } ?? "A password is needed at startup.",
            fix: "Turn off automatic login.", settings: pane("com.apple.Users-Groups-Settings.extension"), weight: 3)
        let guest = lw?.bool(forKey: "GuestEnabled") ?? false
        add("login.guest", "Guest account is off", "Login", guest ? .warn : .pass,
            guest ? "Anyone can log in as Guest." : "No guest login.", settings: pane("com.apple.Users-Groups-Settings.extension"), weight: 1)

        let disabled = run("/bin/launchctl", ["print-disabled", "system"])
        func serviceOn(_ label: String) -> Bool? {
            guard let line = disabled.split(separator: "\n").first(where: { $0.contains("\"\(label)\"") }) else { return nil }
            return line.contains("enabled") || line.contains("=> false")
        }
        let sshOn = serviceOn("com.openssh.sshd") ?? false
        let sshdConfig = ((try? String(contentsOfFile: "/etc/ssh/sshd_config", encoding: .utf8)) ?? "")
            + (((try? FileManager.default.contentsOfDirectory(atPath: "/etc/ssh/sshd_config.d")) ?? [])
                .compactMap { try? String(contentsOfFile: "/etc/ssh/sshd_config.d/" + $0, encoding: .utf8) }.joined(separator: "\n"))
        let passwordsOff = sshdConfig.split(separator: "\n").contains { $0.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("passwordauthentication no") }
        add("share.ssh", "Remote Login (SSH) is off, or keys only", "Sharing",
            !sshOn ? .pass : passwordsOff ? .warn : .fail,
            !sshOn ? "SSH is off." : passwordsOff ? "SSH is on, with password logins disabled." : "SSH is on and accepts passwords (open to password guessing).",
            fix: "Turn off Remote Login, or set PasswordAuthentication no.", settings: pane("com.apple.Sharing-Settings.extension"), weight: 3)
        let screen = serviceOn("com.apple.screensharing") ?? false
        add("share.screen", "Screen Sharing is off", "Sharing", screen ? .warn : .pass,
            screen ? "Screen Sharing is on." : "Screen Sharing is off.", settings: pane("com.apple.Sharing-Settings.extension"), weight: 2)
        let smb = serviceOn("com.apple.smbd") ?? false
        add("share.files", "File Sharing is off", "Sharing", smb ? .warn : .pass,
            smb ? "File Sharing (SMB) is on." : "File Sharing is off.", settings: pane("com.apple.Sharing-Settings.extension"), weight: 1)
        let ae = serviceOn("com.apple.AEServer") ?? false
        add("share.appleevents", "Remote Apple Events are off", "Sharing", ae ? .fail : .pass,
            ae ? "Other computers can send Apple Events (control apps) to this Mac." : "Remote Apple Events are off.",
            settings: pane("com.apple.Sharing-Settings.extension"), weight: 2)
        let nat = NSDictionary(contentsOfFile: "/Library/Preferences/SystemConfiguration/com.apple.nat.plist")?["NAT"] as? [String: Any]
        let internetSharing = (nat?["Enabled"] as? Int ?? 0) == 1
        add("share.internet", "Internet Sharing is off", "Sharing", internetSharing ? .warn : .pass,
            internetSharing ? "This Mac shares its internet connection." : "Internet Sharing is off.", settings: pane("com.apple.Sharing-Settings.extension"), weight: 1)
        let cups = run("/usr/sbin/cupsctl", [])
        let printerSharing = cups.contains("_share_printers=1")
        add("share.printers", "Printer Sharing is off", "Sharing", printerSharing ? .warn : .pass,
            printerSharing ? "Printers are shared to the network." : "Printers aren't shared.", settings: pane("com.apple.Sharing-Settings.extension"), weight: 1)

        let admins = run("/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"])
            .replacingOccurrences(of: "GroupMembership:", with: "").split(separator: " ").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && $0 != "root" && !$0.hasPrefix("_") }   // _mbsetupuser etc. are system accounts
        add("accounts.admins", "Few administrator accounts", "Accounts", admins.count <= 2 ? .pass : .warn,
            "Administrators: \(admins.joined(separator: ", ")).", fix: "Use a standard account day to day; keep admin accounts to a minimum.",
            settings: pane("com.apple.Users-Groups-Settings.extension"), weight: 1)
        let rootAuth = run("/usr/bin/dscl", [".", "-read", "/Users/root", "AuthenticationAuthority"])
        let rootEnabled = rootAuth.contains("ShadowHash") || rootAuth.contains("Kerberos")
        add("accounts.root", "The root account is disabled", "Accounts", rootEnabled ? .fail : .pass,
            rootEnabled ? "root has a password and can log in." : "root can't log in.", fix: "dsenableroot -d", weight: 3)

        let profiles = configurationProfiles()
        add("mdm.profiles", "No unexpected configuration profiles", "Management", profiles.isEmpty ? .pass : .warn,
            profiles.isEmpty ? "No configuration profiles installed." : "Installed: \(profiles.joined(separator: ", ")). Profiles can add trusted certificates, proxies and VPNs.",
            fix: "Remove profiles you don't recognize.", settings: pane("com.apple.Profiles-Settings.extension"), weight: 2)
        let trust = run("/usr/bin/security", ["dump-trust-settings", "-d"])
        let addedRoots = trust.split(separator: "\n").filter { $0.contains("Cert ") && $0.contains(":") }.count
        add("tls.roots", "No extra trusted root certificates", "Network", addedRoots == 0 ? .pass : .warn,
            addedRoots == 0 ? "Only Apple's built-in roots are trusted." : "\(addedRoots) certificate(s) were added to the system trust settings. A trusted root can intercept every HTTPS connection.",
            fix: "In Keychain Access, remove trust from certificates you don't recognize.", weight: 3)
        let proxy = run("/usr/sbin/scutil", ["--proxy"])
        let proxied = proxy.contains("HTTPEnable : 1") || proxy.contains("HTTPSEnable : 1") || proxy.contains("ProxyAutoConfigEnable : 1")
        add("net.proxy", "No system web proxy", "Network", proxied ? .warn : .pass,
            proxied ? "Web traffic goes through a proxy (check it's one you set up)." : "No web proxy configured.",
            settings: pane("com.apple.Network-Settings.extension"), weight: 2)
        let tm = run("/usr/bin/tmutil", ["latestbackup"])
        let tmDate = tm.firstMatch(of: /(\d{4}-\d{2}-\d{2})-\d{6}/).flatMap { m -> Date? in
            let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; return f.date(from: String(m.1))
        }
        add("backup.timemachine", "Backed up in the last week", "Recovery",
            tmDate.map { Date().timeIntervalSince($0) <= 7 * 86400 ? .pass : .warn } ?? (tm.isEmpty ? .unknown : .warn),
            tmDate.map { "Latest Time Machine backup: \($0.formatted(date: .abbreviated, time: .omitted))." } ?? "No recent Time Machine backup found (or not readable).",
            fix: "Set up Time Machine or another backup: it's the cure for ransomware.", settings: pane("com.apple.Time-Machine-Settings.extension"), weight: 2)
        return c
    }

    static func configurationProfiles() -> [String] {
        let out = run("/usr/sbin/system_profiler", ["SPConfigurationProfileDataType", "-json"])
        guard let obj = try? JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any],
              let items = obj["SPConfigurationProfileDataType"] as? [[String: Any]] else { return [] }
        func names(_ list: [[String: Any]]) -> [String] {
            list.flatMap { item -> [String] in
                let own = (item["_name"] as? String).map { [$0] } ?? []
                return item["_items"] is [[String: Any]] ? names(item["_items"] as! [[String: Any]]) : own
            }
        }
        // Xcode's provisioning profiles show up here too; they're developer signing artifacts, not device configuration.
        return names(items).filter { n in
            let l = n.lowercased()
            return !l.contains("computer level") && !l.contains("user level") && !l.contains("provisioning profile")
        }
    }

    // MARK: Privacy permissions (TCC)

    /// Both privacy databases. Reading them needs Full Disk Access; without it, `readable` is false.
    static func privacyGrants() -> ([PrivacyGrant], Bool) {
        let user = FileManager.default.homeDirectoryForCurrentUser.path + "/Library/Application Support/com.apple.TCC/TCC.db"
        let system = "/Library/Application Support/com.apple.TCC/TCC.db"
        var out: [PrivacyGrant] = []
        var readable = false
        for (db, systemWide) in [(system, true), (user, false)] {
            guard let rows = tccRows(db) else { continue }
            readable = true
            for r in rows {
                let path: String? = r.clientType == 1
                    ? (FileManager.default.fileExists(atPath: r.client) ? r.client : nil)
                    : NSWorkspace.shared.urlForApplication(withBundleIdentifier: r.client)?.path
                let exe = path.flatMap { p in p.hasSuffix(".app") ? Bundle(path: p)?.executablePath : p }
                out.append(PrivacyGrant(service: r.service, client: r.client, path: path,
                                        signer: exe.map(FileScanner.signer) ?? "missing", allowed: r.allowed,
                                        systemWide: systemWide, modified: r.modified))
            }
        }
        return (out.sorted { ($0.risky ? 0 : 1, $0.label, $0.client) < ($1.risky ? 0 : 1, $1.label, $1.client) }, readable)
    }

    static func tccRows(_ path: String) -> [(service: String, client: String, clientType: Int, allowed: Bool, modified: Date?)]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { sqlite3_close(db); return nil }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT service, client, client_type, auth_value, last_modified FROM access", -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        var rows: [(String, String, Int, Bool, Date?)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let s = sqlite3_column_text(stmt, 0), let c = sqlite3_column_text(stmt, 1) else { continue }
            let modified = sqlite3_column_int64(stmt, 4)
            rows.append((String(cString: s), String(cString: c), Int(sqlite3_column_int(stmt, 2)),
                         sqlite3_column_int(stmt, 3) >= 2, modified > 0 ? Date(timeIntervalSince1970: Double(modified)) : nil))
        }
        return rows
    }

    // MARK: Browser extensions

    static func browserExtensions() -> [BrowserExtension] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var out: [BrowserExtension] = []
        let chromium: [(String, String)] = [
            ("Chrome", "\(home)/Library/Application Support/Google/Chrome"), ("Brave", "\(home)/Library/Application Support/BraveSoftware/Brave-Browser"),
            ("Edge", "\(home)/Library/Application Support/Microsoft Edge"), ("Arc", "\(home)/Library/Application Support/Arc/User Data"),
            ("Vivaldi", "\(home)/Library/Application Support/Vivaldi"), ("Chromium", "\(home)/Library/Application Support/Chromium"),
        ]
        for (browser, root) in chromium {
            let profiles = ((try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []).filter { $0 == "Default" || $0.hasPrefix("Profile ") }
            for profile in profiles {
                let extDir = "\(root)/\(profile)/Extensions"
                let prefs = (try? Data(contentsOf: URL(fileURLWithPath: "\(root)/\(profile)/Secure Preferences")))
                    .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                let settings = ((prefs?["extensions"] as? [String: Any])?["settings"] as? [String: Any]) ?? [:]
                for id in (try? FileManager.default.contentsOfDirectory(atPath: extDir)) ?? [] where id.count == 32 {
                    guard let ver = ((try? FileManager.default.contentsOfDirectory(atPath: "\(extDir)/\(id)")) ?? []).sorted().last,
                          let m = (try? Data(contentsOf: URL(fileURLWithPath: "\(extDir)/\(id)/\(ver)/manifest.json")))
                            .flatMap({ try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }) else { continue }
                    var name = m["name"] as? String ?? id
                    if name.hasPrefix("__MSG_") { name = id }
                    let perms = ((m["permissions"] as? [Any]) ?? []).compactMap { $0 as? String }
                        + ((m["host_permissions"] as? [Any]) ?? []).compactMap { $0 as? String }
                    let s = settings[id] as? [String: Any]
                    let fromStore = (s?["from_webstore"] as? Bool) ?? ((m["update_url"] as? String)?.contains("google.com") == true || (m["update_url"] as? String)?.contains("microsoft.com") == true)
                    out.append(BrowserExtension(browser: profiles.count > 1 ? "\(browser) (\(profile))" : browser, id: id, name: name,
                                                version: m["version"] as? String ?? ver, permissions: perms, fromStore: fromStore))
                }
            }
        }
        // Firefox: every profile's extensions.json.
        let ff = "\(home)/Library/Application Support/Firefox/Profiles"
        for profile in (try? FileManager.default.contentsOfDirectory(atPath: ff)) ?? [] {
            guard let obj = (try? Data(contentsOf: URL(fileURLWithPath: "\(ff)/\(profile)/extensions.json")))
                    .flatMap({ try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }),
                  let addons = obj["addons"] as? [[String: Any]] else { continue }
            for a in addons where (a["type"] as? String) == "extension" && (a["location"] as? String) != "app-builtin" && (a["location"] as? String) != "app-system-defaults" {
                let perms = ((a["userPermissions"] as? [String: Any])?["permissions"] as? [String] ?? [])
                    + ((a["userPermissions"] as? [String: Any])?["origins"] as? [String] ?? [])
                let name = ((a["defaultLocale"] as? [String: Any])?["name"] as? String) ?? (a["id"] as? String ?? "?")
                out.append(BrowserExtension(browser: "Firefox", id: a["id"] as? String ?? "?", name: name,
                                            version: a["version"] as? String ?? "", permissions: perms,
                                            fromStore: (a["sourceURI"] as? String)?.contains("addons.mozilla.org") == true))
            }
        }
        // Safari: web extensions are app extensions, listed by pluginkit (permissions aren't exposed).
        for line in run("/usr/bin/pluginkit", ["-mAv", "-p", "com.apple.Safari.web-extension"]).split(separator: "\n") {
            let parts = line.trimmingCharacters(in: .whitespaces).split(separator: "\t").map(String.init)
            guard let idv = parts.first, !idv.isEmpty else { continue }
            let id = idv.components(separatedBy: "(").first ?? idv
            let path = parts.last ?? ""
            out.append(BrowserExtension(browser: "Safari", id: id, name: (path as NSString).lastPathComponent.replacingOccurrences(of: ".appex", with: ""),
                                        version: idv.firstMatch(of: /\(([^)]*)\)/).map { String($0.1) } ?? "", permissions: [],
                                        fromStore: path.hasPrefix("/Applications") || path.contains("/Applications/")))
        }
        return out.sorted { ($0.risky.isEmpty ? 1 : 0, $0.browser, $0.name) < ($1.risky.isEmpty ? 1 : 0, $1.browser, $1.name) }
    }

    // MARK: Helpers

    static func run(_ tool: String, _ args: [String], timeout: Double = 20) -> String {
        guard FileManager.default.isExecutableFile(atPath: tool) else { return "" }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return "" }
        let deadline = DispatchTime.now() + timeout
        DispatchQueue.global().asyncAfter(deadline: deadline) { if p.isRunning { p.terminate() } }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
