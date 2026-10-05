import Foundation

/// Builds the software inventory: macOS, apps, Homebrew, this Mac's listening services, and the packages locked
/// in the user's project folders.
enum Inventory {
    // MARK: CPE mappings (NVD "part:vendor:product")

    static let appCPE: [String: String] = [
        "com.google.Chrome": "a:google:chrome", "org.mozilla.firefox": "a:mozilla:firefox",
        "com.apple.Safari": "a:apple:safari", "com.brave.Browser": "a:brave:brave", "com.microsoft.edgemac": "a:microsoft:edge_chromium",
        "com.operasoftware.Opera": "a:opera:opera_browser", "com.microsoft.VSCode": "a:microsoft:visual_studio_code",
        "com.apple.dt.Xcode": "a:apple:xcode", "com.google.android.studio": "a:google:android_studio",
        "org.virtualbox.app.VirtualBox": "a:oracle:vm_virtualbox", "com.vmware.fusion": "a:vmware:fusion",
        "com.parallels.desktop.console": "a:parallels:parallels_desktop", "com.docker.docker": "a:docker:desktop",
        "us.zoom.xos": "a:zoom:zoom", "com.tinyspeck.slackmacgap": "a:slack:slack", "com.microsoft.teams2": "a:microsoft:teams",
        "org.whispersystems.signal-desktop": "a:signal:signal-desktop", "com.hnc.Discord": "a:discord:discord",
        "org.videolan.vlc": "a:videolan:vlc_media_player", "com.obsproject.obs-studio": "a:obsproject:obs_studio",
        "org.wireshark.Wireshark": "a:wireshark:wireshark", "com.googlecode.iterm2": "a:iterm2:iterm2",
        "md.obsidian": "a:obsidian:obsidian", "com.agilebits.onepassword7": "a:agilebits:1password",
        "com.1password.1password": "a:agilebits:1password", "com.cockos.reaper": "a:cockos:reaper",
        "io.tailscale.ipn.macos": "a:tailscale:tailscale", "com.anydesk.anydeskmacos": "a:anydesk:anydesk",
        "com.teamviewer.TeamViewer": "a:teamviewer:teamviewer", "org.libreoffice.script": "a:libreoffice:libreoffice",
        "org.gimp.gimp-2.10": "a:gimp:gimp", "com.jetbrains.intellij": "a:jetbrains:intellij_idea",
        "com.jetbrains.pycharm": "a:jetbrains:pycharm", "com.adobe.Reader": "a:adobe:acrobat_reader_dc",
        "com.electron.ollama": "a:ollama:ollama", "com.getpostman.postman": "a:postman:postman",
        "com.microsoft.Word": "a:microsoft:word", "com.microsoft.Excel": "a:microsoft:excel",
        "com.microsoft.Powerpoint": "a:microsoft:powerpoint", "com.microsoft.Outlook": "a:microsoft:outlook",
        "com.github.GitHubClient": "a:github:desktop", "org.keepassxc.keepassxc": "a:keepassxc:keepassxc",
        "com.transmissionbt.Transmission": "a:transmissionbt:transmission", "com.spotify.client": "a:spotify:spotify",
    ]

    static let brewCPE: [String: String] = [
        "openssl": "a:openssl:openssl", "curl": "a:haxx:curl", "git": "a:git-scm:git", "python": "a:python:python",
        "node": "a:nodejs:node.js", "sqlite": "a:sqlite:sqlite", "libxml2": "a:xmlsoft:libxml2", "ffmpeg": "a:ffmpeg:ffmpeg",
        "openssh": "a:openbsd:openssh", "wget": "a:gnu:wget", "gnutls": "a:gnu:gnutls", "glib": "a:gnome:glib",
        "libpng": "a:libpng:libpng", "jpeg-turbo": "a:libjpeg-turbo:libjpeg-turbo", "zlib": "a:zlib:zlib",
        "xz": "a:tukaani:xz", "vim": "a:vim:vim", "nginx": "a:f5:nginx", "postgresql": "a:postgresql:postgresql",
        "mysql": "a:oracle:mysql", "redis": "a:redis:redis", "go": "a:golang:go", "rust": "a:rust-lang:rust",
        "ruby": "a:ruby-lang:ruby", "php": "a:php:php", "imagemagick": "a:imagemagick:imagemagick", "ollama": "a:ollama:ollama",
        "libtiff": "a:libtiff:libtiff", "freetype": "a:freetype:freetype", "expat": "a:libexpat_project:libexpat",
        "pcre2": "a:pcre:pcre2", "gnupg": "a:gnupg:gnupg", "libssh2": "a:libssh2:libssh2", "krb5": "a:mit:kerberos_5",
        "cairo": "a:cairographics:cairo", "webp": "a:webmproject:libwebp", "ghostscript": "a:artifex:ghostscript",
        "nghttp2": "a:nghttp2:nghttp2", "tmux": "a:tmux_project:tmux", "bash": "a:gnu:bash", "zsh": "a:zsh:zsh",
        "openjdk": "a:oracle:openjdk", "mongodb-community": "a:mongodb:mongodb", "httpd": "a:apache:http_server",
        "libarchive": "a:libarchive:libarchive", "dav1d": "a:videolan:dav1d", "flac": "a:flac_project:flac",
        "gmp": "a:gmplib:gmp", "libsndfile": "a:libsndfile_project:libsndfile", "giflib": "a:giflib_project:giflib",
        "libheif": "a:struktur:libheif", "openexr": "a:openexr:openexr", "jasper": "a:jasper_project:jasper",
        "c-ares": "a:c-ares:c-ares", "libuv": "a:libuv:libuv", "protobuf": "a:google:protobuf",
    ]

    /// Server banners → CPE, for version detection of this Mac's own listening services.
    static let bannerCPE: [(prefix: String, cpe: String, name: String)] = [
        ("OpenSSH_", "a:openbsd:openssh", "OpenSSH"), ("nginx/", "a:f5:nginx", "nginx"),
        ("Apache/", "a:apache:http_server", "Apache httpd"), ("lighttpd/", "a:lighttpd:lighttpd", "lighttpd"),
        ("Jetty(", "a:eclipse:jetty", "Jetty"), ("Werkzeug/", "a:palletsprojects:werkzeug", "Werkzeug"),
        ("gunicorn/", "a:gunicorn:gunicorn", "gunicorn"), ("Caddy", "a:caddyserver:caddy", "Caddy"),
    ]

    // MARK: System software

    static func macOS() -> Component {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let version = v.patchVersion > 0 ? "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)" : "\(v.majorVersion).\(v.minorVersion)"
        return Component(kind: .os, name: "macOS", version: version, cpe: "o:apple:macos", location: "/System")
    }

    static func apps() -> [Component] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var roots = ["/Applications", "/Applications/Utilities", "\(home)/Applications"]
        // One level of vendor folders (/Applications/Native Instruments/…)
        for r in ["/Applications"] {
            for d in (try? FileManager.default.contentsOfDirectory(atPath: r)) ?? [] where !d.hasSuffix(".app") && !d.hasPrefix(".") {
                roots.append("\(r)/\(d)")
            }
        }
        var out: [Component] = []
        var seen = Set<String>()
        for root in roots {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? [] where name.hasSuffix(".app") {
                let path = "\(root)/\(name)"
                guard seen.insert(path).inserted,
                      let info = NSDictionary(contentsOfFile: "\(path)/Contents/Info.plist") as? [String: Any],
                      let bid = info["CFBundleIdentifier"] as? String else { continue }
                let version = (info["CFBundleShortVersionString"] as? String) ?? (info["CFBundleVersion"] as? String) ?? "?"
                out.append(Component(kind: .app, name: (name as NSString).deletingPathExtension, version: version,
                                     cpe: appCPE[bid], location: path))
            }
        }
        return out
    }

    static func homebrew() -> [Component] {
        guard let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first(where: FileManager.default.isExecutableFile) else { return [] }
        let prefix = (brew as NSString).deletingLastPathComponent.replacingOccurrences(of: "/bin", with: "")
        return run(brew, ["list", "--formula", "--versions"]).split(separator: "\n").flatMap { line -> [Component] in
            let parts = line.split(separator: " ").map(String.init)
            guard parts.count >= 2 else { return [] }
            let formula = parts[0], kegs = Array(parts.dropFirst())
            let active = activeKeg(formula, kegs: kegs, prefix: prefix)
            let base = formula.replacingOccurrences(of: #"@[\d.]+$"#, with: "", options: .regularExpression)
            // The keg in use, plus older ones Homebrew left behind (still on disk, so still worth flagging).
            return kegs.map { keg in
                var c = Component(kind: .homebrew, name: formula, version: brewVersion(keg), cpe: brewCPE[base],
                                  location: "\(prefix)/Cellar/\(formula)/\(keg)")
                if keg != active { c.staleKeg = true }
                return c
            }
        }
    }

    /// "ffmpeg 7.1.1_3" → 7.1.1 (drop Homebrew's revision suffix).
    static func brewVersion(_ keg: String) -> String {
        keg.replacingOccurrences(of: #"_\d+$"#, with: "", options: .regularExpression)
    }

    /// The installed version in use: what opt/<formula> links to (`brew list --versions` order isn't by version),
    /// else the newest.
    static func activeKeg(_ formula: String, kegs: [String], prefix: String) -> String? {
        if let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: "\(prefix)/opt/\(formula)") {
            let keg = (dest as NSString).lastPathComponent
            if kegs.contains(keg) { return keg }
        }
        return kegs.max { Version.compare(brewVersion($0), brewVersion($1)) == .orderedAscending }
    }

    // MARK: Listening services (this Mac only)

    struct Listener: Hashable { var process: String; var pid: Int32; var port: Int; var exposed: Bool; var proto: String }

    /// Every listening socket on this Mac, from nettop (sees all processes without root).
    static func listeners() -> [Listener] {
        let text = run("/usr/bin/nettop", ["-L", "1", "-n", "-x", "-J", "state"])
        var out: Set<Listener> = []
        var name = "", pid: Int32 = 0
        for line in text.split(separator: "\n").dropFirst() {
            let cols = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard let first = cols.first, !first.isEmpty else { continue }
            if first.hasPrefix("tcp") || first.hasPrefix("udp") {
                let parts = first.split(separator: " ", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let ends = parts[1].components(separatedBy: "<->")
                let isTCP = first.hasPrefix("tcp")
                guard ends.count == 2, let l = PassiveMonitor.endpoint(ends[0]), let r = PassiveMonitor.endpoint(ends[1]),
                      (isTCP && cols.count > 1 && cols[1] == "Listen") || (!isTCP && r.addr == "*"), l.port > 0 else { continue }
                let loopback = l.addr.hasPrefix("127.") || l.addr == "::1"
                out.insert(Listener(process: name, pid: pid, port: l.port, exposed: !loopback, proto: isTCP ? "tcp" : "udp"))
            } else if let dot = first.lastIndex(of: "."), let p = Int32(first[first.index(after: dot)...]) {
                name = String(first[..<dot]); pid = p
            }
        }
        // A socket bound to both 127.0.0.1 and * shows twice; exposed wins.
        var merged: [String: Listener] = [:]
        for l in out {
            let k = "\(l.pid)|\(l.port)|\(l.proto)"
            if merged[k] == nil || l.exposed { merged[k] = l }
        }
        return Array(merged.values).sorted { $0.port < $1.port }
    }

    /// Reads the version banner of one of this Mac's own TCP services over loopback (SSH and SMTP announce
    /// themselves; HTTP servers answer a HEAD request with a Server header).
    static func banner(port: Int) -> String? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard ok == 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: 512)
        var n = recv(fd, &buf, buf.count, 0)
        if n <= 0 {
            let req = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
            _ = req.withCString { send(fd, $0, strlen($0), 0) }
            n = recv(fd, &buf, buf.count, 0)
        }
        guard n > 0 else { return nil }
        let text = String(decoding: buf[0..<n], as: UTF8.self)
        if let server = text.split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("server:") }) {
            return server.dropFirst(7).trimmingCharacters(in: .whitespaces)
        }
        return text.split(separator: "\r\n").first.map(String.init)
    }

    /// "SSH-2.0-OpenSSH_9.8" → (OpenSSH, 9.8, cpe)
    static func identify(banner: String) -> (name: String, version: String, cpe: String)? {
        for b in bannerCPE {
            guard let r = banner.range(of: b.prefix) else { continue }
            let rest = banner[r.upperBound...]
            let version = rest.prefix { $0.isNumber || $0 == "." }
            guard !version.isEmpty else { return nil }
            return (b.name, String(version), b.cpe)
        }
        return nil
    }

    /// Network-level checks on this Mac's own exposure (not CVEs): sensitive services listening on every interface.
    static let sensitivePorts: [Int: (String, Double)] = [
        22: ("SSH (Remote Login)", 5.3), 5900: ("Screen Sharing / VNC", 7.5), 3283: ("Apple Remote Desktop", 6.5),
        445: ("SMB file sharing", 5.3), 548: ("AFP file sharing", 5.3), 3306: ("MySQL database", 7.5),
        5432: ("PostgreSQL database", 7.5), 6379: ("Redis (often no password)", 9.1), 27017: ("MongoDB database", 9.1),
        9200: ("Elasticsearch", 9.1), 11211: ("Memcached", 7.5), 11434: ("Ollama LLM API (no authentication)", 7.5),
        2375: ("Docker API (unauthenticated)", 9.8), 8888: ("Jupyter", 8.1), 5000: ("Development web server", 5.3),
        3000: ("Development web server", 5.3), 8000: ("Development web server", 5.3), 8080: ("Web server", 5.3),
    ]

    // MARK: Projects

    static let skipDirs: Set<String> = ["node_modules", ".git", ".venv", "venv", "env", "vendor", "build", "DerivedData",
                                        "Pods", ".build", "target", "dist", ".next", "__pycache__", ".tox", "Library",
                                        ".cache", ".gradle", "bower_components", "site-packages", ".Trash"]
    static let lockfiles: Set<String> = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock",
                                         "uv.lock", "Pipfile.lock", "Cargo.lock", "go.mod", "Gemfile.lock", "composer.lock",
                                         "Package.resolved"]

    static func findLockfiles(under root: String, maxDepth: Int = 6) -> [String] {
        var out: [String] = []
        func walk(_ dir: String, _ depth: Int) {
            guard depth <= maxDepth, out.count < 500,
                  let items = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
            for item in items {
                let path = "\(dir)/\(item)"
                if lockfiles.contains(item) || (item.hasPrefix("requirements") && item.hasSuffix(".txt")) {
                    out.append(path)
                    continue
                }
                // A Python virtualenv records exactly what's installed, even when requirements only give ranges.
                if [".venv", "venv", "env", ".env"].contains(item), FileManager.default.fileExists(atPath: "\(path)/pyvenv.cfg") {
                    out.append("\(path)/pyvenv.cfg")
                    continue
                }
                var isDir: ObjCBool = false
                if !skipDirs.contains(item), !item.hasSuffix(".app"),
                   FileManager.default.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
                    walk(path, depth + 1)
                }
            }
        }
        walk(root, 0)
        return out
    }

    /// Packages from one lockfile, with "direct" from the neighboring manifest when one exists.
    static func packages(lockfile path: String) -> [Component] {
        let file = (path as NSString).lastPathComponent
        let project = (path as NSString).deletingLastPathComponent
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        var pkgs: [(String, String, String)] = []   // ecosystem, name, version
        var requires: [String: [String]] = [:]      // normalized name → dependencies
        switch file {
        case "package-lock.json":
            guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { break }
            if let packages = obj["packages"] as? [String: [String: Any]] {
                for (key, v) in packages where key.contains("node_modules/") {
                    guard let ver = v["version"] as? String else { continue }
                    let name = key.components(separatedBy: "node_modules/").last!
                    pkgs.append(("npm", name, ver))
                    let deps = ["dependencies", "optionalDependencies", "peerDependencies"].flatMap { ((v[$0] as? [String: Any]) ?? [:]).keys }
                    requires[name.lowercased(), default: []] += deps.map { $0.lowercased() }
                }
            } else if let deps = obj["dependencies"] as? [String: [String: Any]] {
                func walk(_ d: [String: [String: Any]]) {
                    for (name, v) in d {
                        if let ver = v["version"] as? String { pkgs.append(("npm", name, ver)) }
                        if let sub = v["dependencies"] as? [String: [String: Any]] { walk(sub) }
                    }
                }
                walk(deps)
            }
        case "yarn.lock":
            var current: [String] = []
            for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
                if !line.hasPrefix(" "), line.hasSuffix(":"), !line.hasPrefix("#") {
                    current = line.dropLast().split(separator: ",").map { spec in
                        var s = spec.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                        if let at = s.dropFirst().firstIndex(of: "@") { s = String(s[..<at]) }
                        return s
                    }
                } else if let m = line.firstMatch(of: /^\s+version:?\s+"?([^"\s]+)"?/), let name = current.first {
                    pkgs.append(("npm", name, String(m.1)))
                    current = []
                }
            }
        case "pnpm-lock.yaml":
            var inPackages = false
            for line in text.split(separator: "\n") {
                if line.hasPrefix("packages:") || line.hasPrefix("snapshots:") { inPackages = true; continue }
                if !line.hasPrefix(" ") { inPackages = false }
                guard inPackages, let m = line.firstMatch(of: /^\s{2}'?\/?(@?[^@\s']+)@([0-9][^:('\s]*)/) else { continue }
                pkgs.append(("npm", String(m.1), String(m.2)))
            }
        case let f where f.hasPrefix("requirements"):
            for line in text.split(separator: "\n") {
                if let m = line.firstMatch(of: /^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)/) {
                    pkgs.append(("PyPI", String(m.1), String(m.2)))
                }
            }
        case "poetry.lock", "uv.lock", "Cargo.lock":
            let eco = file == "Cargo.lock" ? "crates.io" : "PyPI"
            for block in text.components(separatedBy: "[[package]]").dropFirst() {
                guard let n = block.firstMatch(of: /\nname = "([^"]+)"/), let v = block.firstMatch(of: /\nversion = "([^"]+)"/) else { continue }
                if eco == "crates.io" && !block.contains("source = ") { continue }   // the project's own crates
                pkgs.append((eco, String(n.1), String(v.1)))
            }
        case "Pipfile.lock":
            guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { break }
            for section in ["default", "develop"] {
                for (name, v) in obj[section] as? [String: [String: Any]] ?? [:] {
                    if let ver = (v["version"] as? String)?.replacingOccurrences(of: "==", with: "") { pkgs.append(("PyPI", name, ver)) }
                }
            }
        case "go.mod":
            for m in text.matches(of: /(?m)^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}\/[^\s]+)\s+v([0-9][^\s]*)/) {
                pkgs.append(("Go", String(m.1), String(m.2)))
            }
        case "Gemfile.lock":
            var inSpecs = false
            for line in text.split(separator: "\n") {
                if line.trimmingCharacters(in: .whitespaces) == "specs:" { inSpecs = true; continue }
                if !line.hasPrefix(" ") { inSpecs = false }
                if inSpecs, let m = line.firstMatch(of: /^ {4}([A-Za-z0-9_.\-]+) \(([^)\s]+)\)/) {
                    pkgs.append(("RubyGems", String(m.1), String(m.2)))
                }
            }
        case "composer.lock":
            guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { break }
            for section in ["packages", "packages-dev"] {
                for p in obj[section] as? [[String: Any]] ?? [] {
                    if let n = p["name"] as? String, let v = p["version"] as? String {
                        pkgs.append(("Packagist", n, v.hasPrefix("v") ? String(v.dropFirst()) : v))
                    }
                }
            }
        case "pyvenv.cfg":
            let venv = (path as NSString).deletingLastPathComponent
            let lib = "\(venv)/lib"
            for py in (try? FileManager.default.contentsOfDirectory(atPath: lib)) ?? [] where py.hasPrefix("python") {
                let site = "\(lib)/\(py)/site-packages"
                for d in (try? FileManager.default.contentsOfDirectory(atPath: site)) ?? [] where d.hasSuffix(".dist-info") {
                    guard let meta = try? String(contentsOfFile: "\(site)/\(d)/METADATA", encoding: .utf8),
                          let n = meta.firstMatch(of: /(?m)^Name:\s*(\S+)/), let v = meta.firstMatch(of: /(?m)^Version:\s*(\S+)/) else { continue }
                    pkgs.append(("PyPI", String(n.1), String(v.1)))
                    // Includes optional extras: a framework uses them whenever they're installed (FastAPI → python-multipart).
                    requires[normalize(String(n.1), "PyPI")] = meta.matches(of: /(?m)^Requires-Dist:\s*([A-Za-z0-9_.\-]+)/)
                        .map { normalize(String($0.1), "PyPI") }
                }
            }
        case "Package.resolved":
            guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { break }
            let pins = (obj["pins"] as? [[String: Any]]) ?? ((obj["object"] as? [String: Any])?["pins"] as? [[String: Any]]) ?? []
            for pin in pins {
                guard let url = (pin["location"] as? String) ?? (pin["repositoryURL"] as? String),
                      let ver = (pin["state"] as? [String: Any])?["version"] as? String else { continue }
                let name = url.replacingOccurrences(of: #"^https?://"#, with: "", options: .regularExpression)
                    .replacingOccurrences(of: #"\.git$"#, with: "", options: .regularExpression)
                pkgs.append(("SwiftURL", name, ver))
            }
        default: break
        }
        let isVenv = file == "pyvenv.cfg"
        let projectDir = isVenv ? (project as NSString).deletingLastPathComponent : project
        let direct = directDependencies(project: projectDir, lockfile: file, text: text)
        var seen = Set<String>()
        return pkgs.compactMap { eco, name, version in
            guard seen.insert("\(eco)|\(name)|\(version)").inserted else { return nil }
            let isDirect: Bool? = direct.map { $0.contains(normalize(name, eco)) }
            var c = Component(kind: .package, ecosystem: eco, name: name, version: version, location: path,
                              direct: isDirect, project: projectDir)
            c.requires = requires[normalize(name, eco)]
            return c
        }
    }

    static func normalize(_ name: String, _ eco: String) -> String {
        eco == "PyPI" ? name.lowercased().replacingOccurrences(of: "_", with: "-").replacingOccurrences(of: ".", with: "-")
                      : name.lowercased()
    }

    /// Names declared in the project's manifest; nil when there's no manifest to tell.
    static func directDependencies(project: String, lockfile: String, text: String) -> Set<String>? {
        func read(_ f: String) -> String? { try? String(contentsOfFile: "\(project)/\(f)", encoding: .utf8) }
        switch lockfile {
        case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
            guard let s = read("package.json"),
                  let obj = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: Any] else { return nil }
            var names = Set<String>()
            for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
                (obj[k] as? [String: Any])?.keys.forEach { names.insert($0.lowercased()) }
            }
            return names
        case let f where f.hasPrefix("requirements"):
            return Set(text.split(separator: "\n").compactMap { $0.firstMatch(of: /^\s*([A-Za-z0-9_.\-]+)/).map { normalize(String($0.1), "PyPI") } })
        case "pyvenv.cfg":
            // Direct = named in the project's requirements files or pyproject.toml.
            var names = Set<String>()
            for f in ((try? FileManager.default.contentsOfDirectory(atPath: project)) ?? []) where f.hasPrefix("requirements") && f.hasSuffix(".txt") {
                for line in (read(f) ?? "").split(separator: "\n") {
                    if let m = line.firstMatch(of: /^\s*([A-Za-z0-9_.\-]+)/) { names.insert(normalize(String(m.1), "PyPI")) }
                }
            }
            if let s = read("pyproject.toml") {
                s.matches(of: /(?m)^\s*"([A-Za-z0-9_.\-]+)/).forEach { names.insert(normalize(String($0.1), "PyPI")) }
            }
            return names.isEmpty ? nil : names
        case "poetry.lock", "uv.lock", "Pipfile.lock":
            guard let s = read("pyproject.toml") ?? read("Pipfile") else { return nil }
            return Set(s.matches(of: /(?m)^\s*"?([A-Za-z0-9_.\-]+)\s*(?:[=<>~!\[;"]|$)/).map { normalize(String($0.1), "PyPI") })
        case "Cargo.lock":
            guard let s = read("Cargo.toml") else { return nil }
            return Set(s.matches(of: /(?m)^\s*([A-Za-z0-9_\-]+)\s*=/).map { String($0.1).lowercased() })
        case "go.mod":
            return Set(text.split(separator: "\n").filter { !$0.contains("// indirect") }
                .compactMap { $0.firstMatch(of: /([a-z0-9.\-]+\.[a-z]{2,}\/[^\s]+)\s+v[0-9]/).map { String($0.1).lowercased() } })
        case "Gemfile.lock":
            guard let s = read("Gemfile") else { return nil }
            return Set(s.matches(of: /gem\s+['"]([^'"]+)['"]/).map { String($0.1).lowercased() })
        case "composer.lock":
            guard let s = read("composer.json"),
                  let obj = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: Any] else { return nil }
            return Set(["require", "require-dev"].flatMap { ((obj[$0] as? [String: Any]) ?? [:]).keys.map { $0.lowercased() } })
        default:
            return nil
        }
    }

    static func run(_ exe: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
