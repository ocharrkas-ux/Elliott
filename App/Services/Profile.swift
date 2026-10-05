import Foundation

/// Everything known about one ConnectionKey (an app talking to one destination, or serving one port).
struct Profile: Codable, Identifiable, Hashable {
    var key: ConnectionKey
    var id: String { key.id }
    var processPath: String
    var signingID: String?
    var teamID: String?
    var appleSigned: Bool
    var hostname: String?
    var addresses: [String] = []        // remote IPs (outbound) or a sample of peers (inbound)
    var firstSeen: Date
    var lastSeen: Date
    var count = 0
    var lastOutcome: Outcome
    var analysis: Analysis?
    /// OSINT verdict on the remote IPs (outbound) or peers (inbound).
    var intel: IntelSummary?
    /// What Elliott thinks the user would decide, once it has learned enough.
    var suggestion: Suggestion?
    /// Open EDR findings on the program behind this connection.
    var edr: EDRSummary?
    /// Known vulnerabilities in the app behind this connection.
    var vuln: VulnSummary?
    /// How the hostname was established, and other names a shared IP also served (NameSource raw value).
    var hostnameSource: String?
    var alternativeNames: [String]?
    /// Hostname capture was running since before a connection in this profile started.
    var nameChecked: Bool?

    var processName: String { (processPath as NSString).lastPathComponent }
    /// The app bundle name for helpers inside an .app ("Google Chrome" for "Google Chrome Helper").
    var appName: String {
        if let r = processPath.range(of: ".app/") {
            return ((String(processPath[..<r.lowerBound]) as NSString).lastPathComponent)
        }
        return processName
    }
    var destination: String {
        key.direction == .inbound ? "listening :\(key.port)" : "\(key.host):\(key.port)"
    }

    init(event e: FlowEvent) {
        key = e.key
        processPath = e.processPath
        signingID = e.signingID
        teamID = e.teamID
        appleSigned = e.appleSigned
        hostname = e.remoteHostname
        hostnameSource = e.hostnameSource
        alternativeNames = e.alternativeNames
        firstSeen = e.date
        lastSeen = e.date
        lastOutcome = e.outcome
        absorb(e)
    }

    mutating func absorb(_ e: FlowEvent) {
        count += 1
        lastSeen = max(lastSeen, e.date)
        lastOutcome = e.outcome
        if hostname == nil, let h = e.remoteHostname { hostname = h; hostnameSource = e.hostnameSource; alternativeNames = e.alternativeNames }
        if e.nameChecked == true { nameChecked = true }
        if !addresses.contains(e.remoteAddress), addresses.count < 32 { addresses.append(e.remoteAddress) }
    }

    /// A representative flow, for running this profile through the rule book.
    var sampleEvent: FlowEvent {
        FlowEvent(pid: 0, processPath: processPath, signingID: signingID, teamID: teamID, appleSigned: appleSigned,
                  direction: key.direction, proto: key.proto,
                  localAddress: nil, localPort: key.direction == .inbound ? key.port : nil,
                  remoteAddress: addresses.first ?? key.host,
                  remotePort: key.direction == .inbound ? 0 : key.port,
                  remoteHostname: key.direction == .inbound ? nil : hostname, outcome: .observed)
    }
}

struct VulnSummary: Codable, Hashable {
    var maxScore: Double
    var count: Int
    var kev: Bool
}

struct EDRSummary: Codable, Hashable {
    var severity: Severity
    var titles: [String]
}

struct Analysis: Codable, Hashable {
    var description: String
    var category: String
    var risk: Int              // 0-100 from the LLM
    var reasons: [String]
    var model: String
    var date = Date()
}

enum RiskLevel: String, CaseIterable, Comparable {
    case low, medium, high, critical
    init(score: Int) {
        switch score {
        case ..<25: self = .low
        case ..<50: self = .medium
        case ..<75: self = .high
        default: self = .critical
        }
    }
    static func < (a: Self, b: Self) -> Bool { allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)! }
}

extension Profile {
    var heuristic: Heuristic { RiskHeuristics.assess(self) }

    /// LLM and heuristics blended; strong heuristic signals can't be talked down by the model.
    var riskScore: Int {
        let h = heuristic.score
        guard let a = analysis else { return h }
        let blended = Int((0.6 * Double(a.risk) + 0.4 * Double(h)).rounded())
        return h >= 70 ? max(blended, h) : blended
    }
    var riskLevel: RiskLevel { RiskLevel(score: riskScore) }
}
