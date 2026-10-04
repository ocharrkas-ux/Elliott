import CryptoKit
import Foundation

/// Turns Bastion's rules into Palo Alto "shadow" security rules: the same allow/deny connectivity, expressed
/// the way a network firewall can (it can't see which app opened a connection, so rules are per destination).
struct ShadowPlan: Equatable {
    struct Object: Equatable { var kind: Kind; var name: String; var element: String
        enum Kind: String { case address, service }
    }
    struct SecurityRule: Equatable {
        var name: String
        var action: Verdict
        var source: [String]
        var destination: [String]
        var service: [String]
        var description: String
    }
    var objects: [Object] = []
    var rules: [SecurityRule] = []      // in rulebase order
    var notes: [String] = []            // conflicts and rules that couldn't be expressed
}

enum PolicyPlanner {
    static let tag = "bastion-shadow"
    static let macObject = "bastion-this-mac"

    static func plan(rules: [Rule], descriptions: [UUID: String], macAddress: String,
                     lockdown: Bool, mirrorLockdown: Bool) -> ShadowPlan {
        var plan = ShadowPlan()
        var objects: [String: ShadowPlan.Object] = [:]
        plan.objects.append(.init(kind: .address, name: macObject, element: "<ip-netmask>\(xmlEscape(macAddress))</ip-netmask><tag><member>\(tag)</member></tag>"))

        struct Group { var direction: Direction; var remote: [String]; var services: [String]
            var apps: [Verdict: [String]] = [:]; var notes: [Verdict: [String]] = [:] }
        var groups: [String: Group] = [:]
        var order: [String] = []

        for rule in rules {
            if rule.proto == .other { plan.notes.append("\(rule.appName) → \(rule.host): non-TCP/UDP rules aren't mirrored"); continue }
            // Services
            var services: [String] = []
            if let port = rule.port {
                for p in rule.proto.map({ [$0] }) ?? [.tcp, .udp] {
                    let name = "bastion-\(p.rawValue)-\(port)"
                    objects[name] = .init(kind: .service, name: name,
                                          element: "<protocol><\(p.rawValue)><port>\(port)</port></\(p.rawValue)></protocol><tag><member>\(tag)</member></tag>")
                    services.append(name)
                }
            } else {
                services = ["any"]
            }
            // Remote side
            var remote: [String] = []
            if rule.host == "*" {
                remote = ["any"]
            } else if RiskHeuristics.isIPLiteral(rule.host) {
                remote = [addressObject(ip: rule.host, into: &objects)]
            } else if rule.host.hasPrefix("*.") {
                remote = rule.addresses.filter(RiskHeuristics.isIPLiteral).map { addressObject(ip: $0, into: &objects) }
                if remote.isEmpty { plan.notes.append("\(rule.appName) → \(rule.host): wildcard with no known IPs, skipped"); continue }
            } else {
                let name = objectName("bastion-fqdn-", rule.host)
                objects[name] = .init(kind: .address, name: name, element: "<fqdn>\(xmlEscape(rule.host))</fqdn><tag><member>\(tag)</member></tag>")
                remote = [name]
            }
            remote = Array(Set(remote)).sorted()
            let gk = "\(rule.direction.rawValue)|\(remote.joined(separator: ","))|\(services.sorted().joined(separator: ","))"
            if groups[gk] == nil {
                groups[gk] = Group(direction: rule.direction, remote: remote, services: services.sorted())
                order.append(gk)
            }
            groups[gk]!.apps[rule.verdict, default: []].append(rule.appName)
            if let d = descriptions[rule.id] { groups[gk]!.notes[rule.verdict, default: []].append(d) }
        }

        var allows: [ShadowPlan.SecurityRule] = [], denies: [ShadowPlan.SecurityRule] = []
        for gk in order {
            let g = groups[gk]!
            for verdict in [Verdict.deny, .allow] {
                guard let apps = g.apps[verdict] else { continue }
                if verdict == .deny, let allowed = g.apps[.allow] {
                    // The firewall can't tell apps apart; denying here would also block the allowed app.
                    plan.notes.append("\(g.remote.joined(separator: ",")) \(g.services.joined(separator: ",")): denied for \(Set(apps).sorted().joined(separator: ", ")) but allowed for \(Set(allowed).sorted().joined(separator: ", ")); mirrored as allow")
                    continue
                }
                let appList = Set(apps).sorted().joined(separator: ", ")
                var desc = "Bastion shadow (\(verdict.rawValue)) for \(appList)."
                if let n = g.notes[verdict]?.first { desc += " " + n }
                let r = ShadowPlan.SecurityRule(
                    name: "bastion-\(verdict.rawValue)-\(shortHash(gk))", action: verdict,
                    source: g.direction == .outbound ? [macObject] : g.remote,
                    destination: g.direction == .outbound ? g.remote : [macObject],
                    service: g.services, description: String(desc.prefix(1000)))
                if verdict == .allow { allows.append(r) } else { denies.append(r) }
            }
        }
        plan.rules = denies + allows
        if lockdown && mirrorLockdown {
            plan.rules.append(.init(name: "bastion-lockdown-outbound", action: .deny, source: [macObject], destination: ["any"],
                                    service: ["any"], description: "Bastion lockdown: this Mac may only reach approved destinations."))
            plan.rules.append(.init(name: "bastion-lockdown-inbound", action: .deny, source: ["any"], destination: [macObject],
                                    service: ["any"], description: "Bastion lockdown: no unapproved inbound connections to this Mac."))
        }
        plan.objects += objects.values.sorted { $0.name < $1.name }
        return plan
    }

    static func ruleElement(_ r: ShadowPlan.SecurityRule, disabled: Bool) -> String {
        func members(_ xs: [String]) -> String { xs.map { "<member>\(xmlEscape($0))</member>" }.joined() }
        return "<from><member>any</member></from><to><member>any</member></to>"
            + "<source>\(members(r.source))</source><destination>\(members(r.destination))</destination>"
            + "<source-user><member>any</member></source-user><category><member>any</member></category>"
            + "<application><member>any</member></application><service>\(members(r.service))</service>"
            + "<action>\(r.action.rawValue)</action><description>\(xmlEscape(r.description))</description>"
            + "<tag><member>\(tag)</member></tag><log-end>yes</log-end><disabled>\(disabled ? "yes" : "no")</disabled>"
    }

    private static func addressObject(ip: String, into objects: inout [String: ShadowPlan.Object]) -> String {
        let name = objectName("bastion-ip-", ip)
        objects[name] = .init(kind: .address, name: name, element: "<ip-netmask>\(xmlEscape(ip))</ip-netmask><tag><member>\(tag)</member></tag>")
        return name
    }

    /// PAN-OS names: ≤63 chars of letters, digits, '.', '_', '-'.
    static func objectName(_ prefix: String, _ value: String) -> String {
        let clean = String(value.lowercased().map { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" ? $0 : "_" })
        let name = prefix + clean
        return name.count <= 63 ? name : String(name.prefix(54)) + "-" + shortHash(value)
    }

    static func shortHash(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    /// First IPv4 address on a non-loopback interface that's up.
    static func primaryIPv4() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var candidates: [(String, String)] = []
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            guard let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET),
                  ifa.ifa_flags & UInt32(IFF_UP) != 0, ifa.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                candidates.append((String(cString: ifa.ifa_name), String(cString: host)))
            }
        }
        return (candidates.first { $0.0.hasPrefix("en") } ?? candidates.first)?.1
    }
}

struct SyncReport {
    var date = Date()
    var lines: [String] = []
    var error: String?
}

enum PolicySync {
    /// Makes the firewall's Bastion-tagged rules match `plan`: creates/updates objects and rules, removes stale
    /// rules, orders them (denies, allows, lockdown) at the top of the rulebase, and optionally commits.
    static func apply(_ plan: ShadowPlan, client: PANClient) async -> SyncReport {
        var report = SyncReport()
        func say(_ s: String) { report.lines.append(s) }
        do {
            say(try await client.systemInfo())
            try await client.set("\(client.base)/tag/entry[@name='\(PolicyPlanner.tag)']",
                                 "<color>color3</color><comments>Managed by Bastion</comments>")
            for o in plan.objects {
                try await client.set("\(client.base)/\(o.kind.rawValue)/entry[@name='\(o.name)']", o.element)
            }
            say("\(plan.objects.count) address/service objects up to date")

            let existing = Set(try await client.ruleNames(tagged: PolicyPlanner.tag))
            let desired = Set(plan.rules.map(\.name))
            for stale in existing.subtracting(desired).sorted() {
                try await client.delete("\(client.rulesXPath)/entry[@name='\(stale)']")
                say("removed \(stale)")
            }
            for r in plan.rules {
                let body = PolicyPlanner.ruleElement(r, disabled: client.settings.createDisabled)
                let xpath = "\(client.rulesXPath)/entry[@name='\(r.name)']"
                if existing.contains(r.name) {
                    try await client.edit(xpath, "<entry name=\"\(r.name)\">\(body)</entry>")
                } else {
                    try await client.set(xpath, body)
                    say("created \(r.name) (\(r.action.rawValue) \(r.destination.joined(separator: ",")) \(r.service.joined(separator: ",")))")
                }
            }
            for r in plan.rules.reversed() { try await client.moveTop(rule: r.name) }
            say("\(plan.rules.count) shadow rules in place at the top of the rulebase")
            plan.notes.forEach { say("note: \($0)") }

            if client.settings.commit {
                let job = try await client.commit(description: "Bastion shadow policy sync")
                say("commit job \(job)")
            } else {
                say("changes are in the candidate config (auto-commit is off)")
            }
        } catch {
            report.error = error.localizedDescription
        }
        return report
    }
}
