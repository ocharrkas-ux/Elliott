import Foundation

struct Heuristic: Hashable {
    var score: Int
    var flags: [String]
}

/// Deterministic risk signals. They give every connection a score before (or without) the LLM and keep the
/// model honest about things it can't see, like the code signature.
enum RiskHeuristics {
    static let wellKnownPorts: [Int: String] = [
        53: "DNS", 80: "HTTP", 123: "NTP", 443: "HTTPS", 853: "DNS over TLS", 993: "IMAPS", 995: "POP3S",
        465: "SMTPS", 587: "SMTP submission", 5223: "Apple Push", 5228: "Google Push", 3478: "STUN/TURN",
        19302: "Google STUN", 22: "SSH", 5353: "mDNS/Bonjour", 1900: "SSDP/UPnP", 7000: "AirPlay",
        5000: "AirPlay/UPnP", 8080: "HTTP alt", 8443: "HTTPS alt", 3389: "RDP", 5900: "VNC", 445: "SMB", 548: "AFP",
    ]
    static let suspiciousPorts: Set<Int> = [23, 21, 69, 135, 139, 1337, 4444, 5555, 6666, 6667, 6697, 9001, 9050, 31337, 12345]
    static let interpreters: Set<String> = ["python", "python3", "perl", "ruby", "node", "bash", "sh", "zsh", "osascript",
                                            "curl", "wget", "ssh", "scp", "java", "php", "deno", "bun"]
    static let rawSocketTools: Set<String> = ["nc", "ncat", "netcat", "socat", "telnet"]
    static let riskyDirs = ["/tmp/", "/private/tmp/", "/private/var/folders/", "/Users/Shared/", "/Downloads/", "/.Trash/"]

    static func assess(_ p: Profile) -> Heuristic {
        var score = 30
        var flags: [String] = []
        func add(_ n: Int, _ why: String) { score += n; flags.append(why) }

        if p.appleSigned { add(-25, "Signed by Apple") }
        else if p.teamID != nil { add(-10, "Signed by a registered developer (team \(p.teamID!))") }
        else { add(25, "Unsigned or ad-hoc signed binary") }

        if riskyDirs.contains(where: { p.processPath.contains($0) }) { add(25, "Runs from a temporary or download folder") }
        let name = p.processName.lowercased()
        let base = name.components(separatedBy: CharacterSet.decimalDigits.union(["."])).first ?? name
        if rawSocketTools.contains(base) { add(35, "Raw socket tool (\(p.processName))") }
        else if interpreters.contains(base) { add(15, "Script interpreter or transfer tool (\(p.processName))") }

        let port = p.key.port
        if suspiciousPorts.contains(port) { add(30, "Port \(port) is commonly used by backdoors, IRC, Tor or plaintext logins") }
        else if wellKnownPorts[port] == nil && port < 49152 { add(10, "Uncommon port \(port)") }
        if port == 80 || port == 21 || port == 23 { add(5, "Plaintext protocol") }

        if let intel = p.intel {
            for hit in intel.hits {
                switch hit.severity {
                case .knownBad: add(45, "Threat intel: \(hit.source) lists this IP (\(hit.detail))")
                case .suspicious: add(15, "Threat intel: \(hit.source): \(hit.detail)")
                default: break
                }
            }
        }

        if let v = p.vuln, v.maxScore >= 7 {
            add(v.kev ? 20 : v.maxScore >= 9 ? 15 : 8,
                "The app has \(v.count) known vulnerabilit\(v.count == 1 ? "y" : "ies") (CVSS up to \(String(format: "%.1f", v.maxScore))\(v.kev ? ", actively exploited" : ""))")
        }

        if let edr = p.edr {
            let bump = [Severity.critical: 40, .high: 25, .medium: 10][edr.severity] ?? 0
            if bump > 0 { add(bump, "EDR: the program behind it is flagged (\(edr.titles.prefix(2).joined(separator: "; ")))") }
        }

        if p.key.direction == .inbound {
            add(15, "Accepts inbound connections on port \(port)")
            if p.addresses.contains(where: { !isPrivate($0) }) { add(15, "Inbound peers from the public internet") }
        } else {
            // Only meaningful when Elliott could see DNS/TLS names for this connection; otherwise "no hostname" just
            // means "not observable", not that the app connected to a bare IP.
            let destIsIP = p.hostname == nil && isIPLiteral(p.key.host)
            if destIsIP && !isPrivate(p.key.host) && p.nameChecked == true {
                add(10, "Connects to a raw public IP: no DNS lookup or TLS server name preceded it")
            }
            if isPrivate(p.key.host) { add(-10, "Destination is on the local network") }
        }
        // A destination on a known-bad list is critical no matter how reputable the app is.
        if p.intel?.reputation == .knownBad { score = max(score, 75) }
        return Heuristic(score: min(100, max(0, score)), flags: flags)
    }

    static func isIPLiteral(_ s: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s.components(separatedBy: "%")[0], &v6) == 1
    }

    static func isPrivate(_ s: String) -> Bool {
        let a = s.lowercased()
        if a.hasPrefix("10.") || a.hasPrefix("192.168.") || a.hasPrefix("169.254.") || a.hasPrefix("127.") { return true }
        if a.hasPrefix("172."), let second = Int(a.split(separator: ".").dropFirst().first ?? ""), (16...31).contains(second) { return true }
        if a.hasPrefix("fe80:") || a.hasPrefix("fd") || a.hasPrefix("fc") || a == "::1" { return true }
        if a.hasPrefix("224.") || a.hasPrefix("239.") || a.hasPrefix("ff0") || a == "255.255.255.255" { return true }
        return a.hasSuffix(".local")
    }
}
