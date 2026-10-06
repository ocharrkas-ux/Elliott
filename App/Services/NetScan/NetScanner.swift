import Foundation

/// A subnet the user asked Elliott to scan.
struct ScanTarget: Codable, Hashable, Identifiable {
    var id = UUID()
    var cidr: String
    var label: String = ""
    var enabled = true
    /// Set after the user confirms they own/administer a public range.
    var ownedPublic = false
}

struct NetScanSettings: Codable, Equatable {
    enum Schedule: String, Codable, CaseIterable, Identifiable { case manual = "Manually", daily = "Daily", weekly = "Weekly"; var id: String { rawValue } }
    var enabled = false
    var targets: [ScanTarget] = []
    var extraPorts: [Int] = []
    var schedule: Schedule = .manual
    /// New connection attempts per second (keeps scans gentle on home routers and IoT devices).
    var rate = 150
    var lastScan: Date?

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = NetScanSettings()
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        targets = try c.decodeIfPresent([ScanTarget].self, forKey: .targets) ?? d.targets
        extraPorts = try c.decodeIfPresent([Int].self, forKey: .extraPorts) ?? d.extraPorts
        schedule = try c.decodeIfPresent(Schedule.self, forKey: .schedule) ?? d.schedule
        rate = try c.decodeIfPresent(Int.self, forKey: .rate) ?? d.rate
        lastScan = try c.decodeIfPresent(Date.self, forKey: .lastScan)
    }
}

struct OpenPort: Codable, Hashable {
    var port: Int
    var service: String
    var banner: String?
    var product: String?
    var version: String?
    var cpe: String?
}

struct ScannedHost: Codable, Hashable, Identifiable {
    var ip: String
    var hostname: String?
    var mac: String?
    var ports: [OpenPort]
    var lastSeen = Date()
    var scannedBy: String = ""
    var id: String { ip }
    var label: String { hostname.map { "\($0) (\(ip))" } ?? ip }
}

enum CIDR {
    /// IPv4 CIDR → (first, last) host addresses; nil if it isn't valid.
    static func parse(_ s: String) -> (UInt32, UInt32, Int)? {
        let parts = s.trimmingCharacters(in: .whitespaces).split(separator: "/")
        guard let base = IPv4Set.parse(String(parts[0])) else { return nil }
        let bits = parts.count > 1 ? Int(parts[1]) ?? -1 : 32
        guard (0...32).contains(bits) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
        let net = base & mask, bcast = net | ~mask
        if bits >= 31 { return (net, bcast, bits) }
        return (net + 1, bcast - 1, bits)   // skip network and broadcast addresses
    }

    static func hosts(_ s: String) -> [String] {
        guard let (lo, hi, _) = parse(s) else { return [] }
        return (lo...hi).map { v in "\(v >> 24).\(v >> 16 & 0xFF).\(v >> 8 & 0xFF).\(v & 0xFF)" }
    }

    static func count(_ s: String) -> Int { parse(s).map { Int($0.1 - $0.0) + 1 } ?? 0 }

    /// RFC 1918, CGNAT, link-local: networks nobody else owns.
    static func isPrivate(_ s: String) -> Bool {
        guard let (lo, hi, _) = parse(s) else { return false }
        let ranges: [(UInt32, Int)] = [(0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16), (0x64400000, 10), (0xA9FE0000, 16)]
        return ranges.contains { net, bits in
            let mask: UInt32 = ~UInt32(0) << (32 - bits)
            return lo & mask == net && hi & mask == net
        }
    }

    enum Problem: Equatable { case invalid, tooLarge, publicRange }

    /// Elliott scans at most a /16, and public ranges only after explicit confirmation.
    static func check(_ s: String, ownedPublic: Bool) -> Problem? {
        guard let (_, _, bits) = parse(s) else { return .invalid }
        if bits < 16 { return .tooLarge }
        if !isPrivate(s) && !ownedPublic { return .publicRange }
        return nil
    }
}

/// TCP connect scanning: no raw packets, no root, nothing sent except an HTTP HEAD to web ports. Detection only.
enum NetScanner {
    static let defaultPorts: [Int] = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 515, 548,
                                      554, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3306, 3389,
                                      5000, 5060, 5432, 5900, 5985, 6379, 7000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
                                      9100, 9200, 10000, 11211, 27017, 32400, 49152, 62078]
    static let discoveryPorts: [Int] = [22, 80, 443, 445, 554, 3389, 5000, 7000, 8080, 9100, 49152, 62078]
    static let httpPorts: Set<Int> = [80, 81, 3000, 5000, 7000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200, 10000, 32400, 2375]

    static let serviceNames: [Int: String] = [
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC",
        135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 515: "LPD", 548: "AFP", 554: "RTSP",
        587: "SMTP submission", 631: "IPP printing", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MS SQL", 1521: "Oracle DB",
        1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2375: "Docker API", 2376: "Docker API (TLS)", 3306: "MySQL", 3389: "RDP",
        5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis", 7000: "AirPlay", 8443: "HTTPS alt",
        9100: "Raw printing", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 49152: "UPnP",
        62078: "iOS sync",
    ]

    /// Services that are a risk merely by being reachable (CVSS-like estimate).
    static let riskyServices: [Int: (String, Double, String)] = [
        23: ("Telnet", 9.0, "Logins and everything typed travel unencrypted."),
        21: ("FTP", 6.5, "Credentials and files travel unencrypted; anonymous access is common on devices."),
        2375: ("Docker API without TLS", 9.8, "Anyone who can reach it can run containers as root on that host."),
        6379: ("Redis", 9.1, "Redis often has no password; reachable instances get taken over for cryptomining."),
        27017: ("MongoDB", 9.1, "Unauthenticated MongoDB instances are routinely wiped or ransomed."),
        9200: ("Elasticsearch", 9.1, "Often unauthenticated; data can be read or deleted."),
        11211: ("Memcached", 7.5, "No authentication; can leak cached data."),
        3389: ("Remote Desktop", 7.5, "A frequent target for password guessing and RDP vulnerabilities."),
        5900: ("VNC", 7.5, "Remote screen control; often weak or no passwords."),
        1883: ("MQTT", 6.5, "IoT message broker; frequently without authentication."),
        445: ("SMB file sharing", 5.3, "File sharing; keep it patched and off untrusted networks."),
        5985: ("WinRM", 6.5, "Remote management endpoint."),
        1433: ("MS SQL", 6.5, "Database exposed to the network."),
        3306: ("MySQL", 6.5, "Database exposed to the network."),
        5432: ("PostgreSQL", 6.5, "Database exposed to the network."),
        2049: ("NFS", 6.5, "Network file system exports can expose data."),
    ]

    /// Banner → (product, version, CPE). Extends the local-service table with common embedded/server software.
    static let banners: [(pattern: String, name: String, cpe: String)] = Inventory.bannerCPE.map { ($0.prefix, $0.name, $0.cpe) } + [
        ("dropbear_", "Dropbear SSH", "a:dropbear_ssh_project:dropbear_ssh"), ("vsFTPd ", "vsftpd", "a:beasts:vsftpd"),
        ("ProFTPD ", "ProFTPD", "a:proftpd:proftpd"), ("Exim ", "Exim", "a:exim:exim"),
        ("Microsoft-IIS/", "IIS", "a:microsoft:internet_information_services"), ("MiniUPnPd/", "MiniUPnPd", "a:miniupnp_project:miniupnpd"),
        ("mini_httpd/", "mini_httpd", "a:acme:mini_httpd"), ("Boa/", "Boa", "a:boa:boa"), ("Pure-FTPd", "Pure-FTPd", "a:pureftpd:pure-ftpd"),
        ("OpenResty/", "OpenResty", "a:openresty:openresty"), ("Tengine/", "Tengine", "a:alibaba:tengine"),
    ]

    static func identify(_ banner: String, port: Int) -> (String, String, String)? {
        // MySQL/MariaDB greeting: protocol 10, then a NUL-terminated version string.
        if port == 3306, let v = banner.firstMatch(of: /(\d+\.\d+\.\d+)(-\d+\.\d+\.\d+-MariaDB|-MariaDB)?/) {
            if banner.contains("MariaDB") {
                let ver = banner.firstMatch(of: /(\d+\.\d+\.\d+)-MariaDB/).map { String($0.1) } ?? String(v.1)
                return ("MariaDB", ver, "a:mariadb:mariadb")
            }
            return ("MySQL", String(v.1), "a:oracle:mysql")
        }
        for b in banners {
            guard let r = banner.range(of: b.pattern) else { continue }
            let version = banner[r.upperBound...].prefix { $0.isNumber || $0 == "." }
            guard !version.isEmpty, version.contains(".") || Int(version) != nil else { continue }
            return (b.name, String(version.trimmingCharacters(in: CharacterSet(charactersIn: "."))), b.cpe)
        }
        return nil
    }

    // MARK: Probing

    /// Opens a TCP connection with a timeout; optionally reads a banner (sending HTTP HEAD on web ports).
    static func probe(_ ip: String, _ port: Int, timeout: Double, banner: Bool) -> (open: Bool, banner: String?) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return (false, nil) }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return (false, nil) }
        let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        if r != 0 && errno != EINPROGRESS { return (false, nil) }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, Int32(timeout * 1000)) == 1 else { return (false, nil) }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
        guard err == 0 else { return (false, nil) }
        guard banner else { return (true, nil) }

        if httpPorts.contains(port) {
            let req = "HEAD / HTTP/1.0\r\nHost: \(ip)\r\nUser-Agent: Elliott-scanner\r\n\r\n"
            _ = req.withCString { send(fd, $0, strlen($0), 0) }
        }
        var rfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&rfd, 1, 1500) == 1 else { return (true, nil) }
        var buf = [UInt8](repeating: 0, count: 1024)
        let n = recv(fd, &buf, buf.count, 0)
        guard n > 0 else { return (true, nil) }
        var text = String(decoding: buf[0..<n].map { $0 == 0 ? 0x20 : $0 }, as: UTF8.self)
        if let server = text.split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("server:") }) {
            text = String(server.dropFirst(7)).trimmingCharacters(in: .whitespaces)
        } else {
            text = text.split(separator: "\r\n").first.map(String.init) ?? text
        }
        return (true, String(text.filter { !$0.isNewline }.prefix(200)))
    }

    /// IP → MAC from the ARP cache (hosts this Mac has recently talked to).
    /// IP → MAC for the local network, read from the kernel's routing table (what `arp -an` prints); falls back
    /// to running arp.
    static func arpTable() -> [String: String] {
        let direct = ARPTable.read()
        if !direct.isEmpty { return direct }
        var out: [String: String] = [:]
        for line in Inventory.run("/usr/sbin/arp", ["-an"]).split(separator: "\n") {
            if let m = line.firstMatch(of: /\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{11,17})/) { out[String(m.1)] = String(m.2) }
        }
        return out
    }

    static func reverseName(_ ip: String) -> String? {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) } }
        return r == 0 ? String(cString: host) : nil
    }

    // MARK: Scanning

    /// Paces new connections to `rate` per second and caps concurrency.
    final class Throttle: @unchecked Sendable {
        private let lock = NSLock()
        private var next = Date()
        private let gap: Double
        let slots: DispatchSemaphore
        init(rate: Int, concurrency: Int) { gap = 1 / Double(max(1, rate)); slots = DispatchSemaphore(value: concurrency) }
        func wait() {
            slots.wait()
            let delay: Double = lock.withLock {
                let now = Date()
                let at = max(now, next)
                next = at.addingTimeInterval(gap)
                return at.timeIntervalSince(now)
            }
            if delay > 0 { Thread.sleep(forTimeInterval: delay) }
        }
        func done() { slots.signal() }
    }

    /// Scans targets: discovery on a few ports (+ ARP), then the full port list on live hosts.
    static func scan(targets: [String], ports: [Int], rate: Int, node: String, arp known: [String: String]? = nil,
                     progress: @escaping @Sendable (String, Double) -> Void) -> [ScannedHost] {
        let throttle = Throttle(rate: rate, concurrency: 64)
        // The helper's (root) view of the ARP table when available: macOS hides it from apps.
        let arp = known.flatMap { $0.isEmpty ? nil : $0 } ?? arpTable()
        let all = Array(Set(targets.flatMap(CIDR.hosts)))
        let lock = NSLock()
        var live = Set(all.filter { arp[$0] != nil })
        let workers = OperationQueue()
        workers.maxConcurrentOperationCount = 32   // bounded threads; the throttle paces connections on top
        var done = 0

        // Phase 1: who's there?
        for ip in all where !live.contains(ip) {
            workers.addOperation {
                for p in discoveryPorts {
                    throttle.wait()
                    let open = probe(ip, p, timeout: 0.6, banner: false).open
                    throttle.done()
                    if open { lock.withLock { _ = live.insert(ip) }; break }
                }
                let n = lock.withLock { done += 1; return done }
                if n % 16 == 0 { progress("Finding hosts (\(n)/\(all.count))", 0.4 * Double(n) / Double(max(1, all.count))) }
            }
        }
        workers.waitUntilAllOperationsAreFinished()

        // Phase 2: services on live hosts.
        let hosts = Array(live).sorted { (IPv4Set.parse($0) ?? 0) < (IPv4Set.parse($1) ?? 0) }
        var results: [ScannedHost] = []
        done = 0
        for ip in hosts {
            workers.addOperation {
                var open: [OpenPort] = []
                for p in ports {
                    throttle.wait()
                    let r = probe(ip, p, timeout: 0.8, banner: true)
                    throttle.done()
                    guard r.open else { continue }
                    let id = r.banner.flatMap { identify($0, port: p) }
                    open.append(OpenPort(port: p, service: serviceNames[p] ?? "tcp/\(p)", banner: r.banner,
                                         product: id?.0, version: id?.1, cpe: id?.2))
                }
                let host = ScannedHost(ip: ip, hostname: reverseName(ip), mac: arp[ip], ports: open, scannedBy: node)
                let n = lock.withLock { results.append(host); done += 1; return done }
                progress("Probing services on \(ip) (\(n)/\(hosts.count))", 0.4 + 0.5 * Double(n) / Double(max(1, hosts.count)))
            }
        }
        workers.waitUntilAllOperationsAreFinished()
        return results.sorted { (IPv4Set.parse($0.ip) ?? 0) < (IPv4Set.parse($1.ip) ?? 0) }
    }
}
