import Foundation

// Types shared by the app and the filter extension. Everything crosses XPC as JSON.

enum Direction: String, Codable, CaseIterable, Sendable { case outbound, inbound }
enum Proto: String, Codable, CaseIterable, Sendable { case tcp, udp, other }
enum Verdict: String, Codable, Sendable { case allow, deny }

/// What happened to a flow.
enum Outcome: String, Codable, Sendable {
    case observed   // seen by the passive monitor (no enforcement)
    case allowed    // allowed by a rule or by learning mode
    case denied     // denied by a rule, by the user, or by lockdown timing out
    case pending    // waiting for the user to approve (lockdown)
}

/// One connection as seen by the filter extension or the passive monitor.
struct FlowEvent: Codable, Identifiable, Hashable, Sendable {
    var id = UUID()
    var date = Date()
    var pid: Int32
    var processPath: String
    var signingID: String?
    var teamID: String?
    var appleSigned: Bool = false
    var direction: Direction
    var proto: Proto
    var localAddress: String?
    var localPort: Int?
    var remoteAddress: String
    var remotePort: Int
    var remoteHostname: String?
    var outcome: Outcome
    /// Id of the rule that decided this flow, if any.
    var ruleID: UUID?

    var processName: String { (processPath as NSString).lastPathComponent }

    /// Rules and profiles key an app by its verified signer + identifier, else by its path. The signer is part of
    /// the key so an ad-hoc-signed binary can't borrow another app's identifier (and its rules).
    var appKey: String {
        if let s = signingID {
            if appleSigned { return "apple:\(s)" }
            if let t = teamID { return "\(t):\(s)" }
        }
        return processPath
    }

    var key: ConnectionKey { ConnectionKey(event: self) }
}

/// A connection "profile": every flow from one app to one destination (outbound) or to one local
/// service port (inbound) aggregates under one key. The console, the LLM and the rules work per key.
struct ConnectionKey: Codable, Hashable, Sendable, Identifiable {
    var appKey: String
    var direction: Direction
    var proto: Proto
    /// Outbound: hostname if known, else the remote IP. Inbound: "*" (any peer).
    var host: String
    /// Outbound: remote port. Inbound: the local (listening) port.
    var port: Int

    var id: String { "\(appKey)|\(direction.rawValue)|\(proto.rawValue)|\(host)|\(port)" }

    init(appKey: String, direction: Direction, proto: Proto, host: String, port: Int) {
        self.appKey = appKey; self.direction = direction; self.proto = proto; self.host = host; self.port = port
    }

    init(event e: FlowEvent) {
        appKey = e.appKey
        direction = e.direction
        proto = e.proto
        if e.direction == .inbound {
            host = "*"
            port = e.localPort ?? 0
        } else {
            host = (e.remoteHostname?.isEmpty == false ? e.remoteHostname! : e.remoteAddress).lowercased()
            port = e.remotePort
        }
    }
}

/// An allow/deny decision. `nil` fields and "*" mean "any".
struct Rule: Codable, Identifiable, Hashable, Sendable {
    var id = UUID()
    var appKey: String            // signing id, path, or "*"
    var appName: String
    var direction: Direction
    var proto: Proto?
    var host: String              // hostname, IP, "*.example.com", or "*"
    var port: Int?
    var verdict: Verdict
    /// IPs the host resolved to (the filter often only sees an IP; also used for firewall objects).
    var addresses: [String] = []
    var created = Date()
    var note: String?
    /// "Allow once" under the packet-filter backend: a short-lived rule.
    var expires: Date?

    init(key: ConnectionKey, appName: String, verdict: Verdict, addresses: [String] = []) {
        appKey = key.appKey
        self.appName = appName
        direction = key.direction
        proto = key.proto
        host = key.host
        port = key.port
        self.verdict = verdict
        self.addresses = addresses
    }

    init(appKey: String, appName: String, direction: Direction, proto: Proto?, host: String, port: Int?,
         verdict: Verdict, addresses: [String] = []) {
        self.appKey = appKey; self.appName = appName; self.direction = direction; self.proto = proto
        self.host = host; self.port = port; self.verdict = verdict; self.addresses = addresses
    }

    var specificity: Int {
        var s = 0
        if appKey != "*" { s += 8 }
        if host != "*" { s += host.hasPrefix("*.") ? 2 : 4 }
        if port != nil { s += 2 }
        if proto != nil { s += 1 }
        return s
    }

    func matches(_ e: FlowEvent) -> Bool {
        if let expires, expires < Date() { return false }
        if appKey != "*" && appKey != e.appKey { return false }
        if direction != e.direction { return false }
        if let proto, proto != e.proto { return false }
        if e.direction == .inbound {
            if let port, port != e.localPort { return false }
            return host == "*" || host == e.remoteAddress || addresses.contains(e.remoteAddress)
        }
        if let port, port != e.remotePort { return false }
        return Rule.hostMatches(host, addresses: addresses, hostname: e.remoteHostname, address: e.remoteAddress)
    }

    static func hostMatches(_ pattern: String, addresses: [String], hostname: String?, address: String) -> Bool {
        if pattern == "*" { return true }
        if pattern == address || addresses.contains(address) { return true }
        guard let name = hostname?.lowercased(), !name.isEmpty else { return false }
        let p = pattern.lowercased()
        if p.hasPrefix("*.") {
            let suffix = String(p.dropFirst(1)) // ".example.com"
            return name.hasSuffix(suffix) || name == String(p.dropFirst(2))
        }
        return name == p
    }
}

enum RuleBook {
    /// Most specific matching rule wins; on a tie, deny wins.
    static func decide(_ e: FlowEvent, rules: [Rule]) -> Rule? {
        rules.filter { $0.matches(e) }.max { a, b in
            if a.specificity != b.specificity { return a.specificity < b.specificity }
            return a.verdict == .allow && b.verdict == .deny
        }
    }
}

/// Everything the filter needs to enforce. The app pushes it; the filter persists it so enforcement survives
/// reboots and the app not running.
struct FilterPolicy: Codable, Sendable {
    var rules: [Rule] = []
    var lockdown = false
    /// In lockdown, let Apple-signed system software through without asking.
    var trustAppleSigned = true
    /// Seconds a paused connection waits for the user before it's denied.
    var approvalTimeout: Double = 60
}

/// Sent from the filter to the app when lockdown pauses a connection.
struct ApprovalRequest: Codable, Identifiable, Sendable {
    var id: String { key.id }
    var key: ConnectionKey
    var event: FlowEvent
    var waiting: Int          // flows paused on this key
    var deadline: Date
}

enum BastionIDs {
    static let appBundleID = "com.omarcharrkas.bastion"
    static let filterBundleID = "com.omarcharrkas.bastion.filter"
    static let teamID = "3JG68S88LM"
    static let machService = "\(teamID).com.omarcharrkas.bastion.xpc"
    static func requirement(for id: String) -> String {
        "anchor apple generic and identifier \"\(id)\" and certificate leaf[subject.OU] = \"\(teamID)\""
    }
}

extension JSONEncoder {
    static let bastion: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }()
}
extension JSONDecoder {
    static let bastion: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()
}
