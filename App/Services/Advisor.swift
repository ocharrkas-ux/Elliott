import Foundation

/// One allow/deny choice the user made, kept as a training example for suggestions.
struct Decision: Codable, Identifiable, Hashable {
    enum Source: String, Codable {
        case manual       // classified in the console
        case approval     // answered a lockdown prompt
        case edit         // flipped a rule in the rules view
        case suggestion   // accepted a suggestion
    }

    var id = UUID()
    var date = Date()
    var verdict: Verdict
    var source: Source
    var scope: String
    var appName: String
    var appKey: String
    var signer: String           // "apple", "team XXXX", "unsigned"
    var direction: Direction
    var proto: Proto?
    var host: String
    var port: Int?
    var category: String?
    var summary: String?
    var risk: Int
    var reputation: Reputation
    /// What Elliott suggested before the user chose, if anything (for the match rate).
    var suggested: Verdict?

    init(profile p: Profile, verdict: Verdict, source: Source, scope: String) {
        self.verdict = verdict
        self.source = source
        self.scope = scope
        appName = p.appName
        appKey = p.key.appKey
        signer = p.appleSigned ? "apple" : p.teamID.map { "team \($0)" } ?? "unsigned"
        direction = p.key.direction
        proto = p.key.proto
        host = p.key.direction == .inbound ? "*" : (p.hostname ?? p.key.host)
        port = p.key.port
        category = p.analysis?.category
        summary = p.analysis?.description
        risk = p.riskScore
        reputation = p.intel?.reputation ?? .unknown
        suggested = p.suggestion?.verdict
    }

    init(rule r: Rule, verdict: Verdict, source: Source) {
        self.verdict = verdict
        self.source = source
        scope = r.scopeLabel
        appName = r.appKey == "*" ? "any app" : r.appName
        appKey = r.appKey
        signer = r.signer.map { $0 == "apple" ? "apple" : "team \($0)" }
            ?? (r.appKey.hasPrefix("apple:") ? "apple" : r.appKey.hasPrefix("/") ? "unsigned" : "team \(r.appKey.split(separator: ":").first ?? "")")
        direction = r.direction
        proto = r.proto
        host = r.host
        port = r.port
        summary = r.note
        risk = 0
        reputation = .unknown
    }

    /// One line for the prompt.
    var exampleLine: String {
        var s = "\(verdict == .allow ? "ALLOWED" : "DENIED"): \(appName) [\(signer)] \(direction.rawValue) "
        s += direction == .inbound ? "on port \(port.map(String.init) ?? "any")" : "to \(host)\(port.map { ":\($0)" } ?? "")"
        if let category { s += ", category \(category)" }
        if risk > 0 { s += ", risk \(risk)" }
        if reputation >= .suspicious { s += ", threat intel: \(reputation.label)" }
        if scope == "everything" { s += " (rule covers everything this app does)" }
        return s
    }
}

struct Suggestion: Codable, Hashable {
    var verdict: Verdict
    var confidence: Int
    var rationale: String
    var basedOn: Int        // decisions observed when this was made
    var date = Date()
}

enum Advisor {
    static let minimumDecisions = 20
    /// Re-suggest after this many new decisions.
    static let refreshEvery = 5

    /// Past decisions most like this connection, keeping both verdicts in view when the user has made both.
    static func examples(for p: Profile, in decisions: [Decision], limit: Int = 12) -> [Decision] {
        let domain = registrableDomain(p.hostname ?? p.key.host)
        let signer = p.appleSigned ? "apple" : p.teamID.map { "team \($0)" } ?? "unsigned"
        func score(_ d: Decision) -> Double {
            var s = 0.0
            if d.appKey == p.key.appKey { s += 6 } else if d.appName == p.appName { s += 4 }
            if d.host != "*" && registrableDomain(d.host) == domain { s += 4 }
            if let c = d.category, c == p.analysis?.category { s += 3 }
            if d.signer == signer { s += 2 }
            if d.port == p.key.port { s += 1.5 }
            if d.direction == p.key.direction { s += 1 }
            if d.reputation >= .suspicious && (p.intel?.reputation ?? .unknown) >= .suspicious { s += 3 }
            s -= abs(Double(d.risk - p.riskScore)) / 50
            s += max(0, 1 - Date().timeIntervalSince(d.date) / (30 * 86400)) * 0.5   // slight recency bonus
            return s
        }
        let ranked = decisions.sorted { score($0) > score($1) }
        var picked = Array(ranked.prefix(limit))
        for v in [Verdict.allow, .deny] where !picked.contains(where: { $0.verdict == v }) {
            if let other = ranked.first(where: { $0.verdict == v }) { picked[picked.count - 1] = other }
        }
        return picked
    }

    static func registrableDomain(_ host: String) -> String {
        let labels = host.lowercased().split(separator: ".")
        guard labels.count > 2, !RiskHeuristics.isIPLiteral(host) else { return host.lowercased() }
        let two = labels.suffix(2).joined(separator: ".")
        // co.uk, com.au, …: keep three labels.
        return labels[labels.count - 2].count <= 3 && labels.last!.count == 2 ? labels.suffix(3).joined(separator: ".") : two
    }

    private static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "decision": ["type": "string", "enum": ["allow", "deny"]],
            "confidence": ["type": "integer", "minimum": 0, "maximum": 100],
            "rationale": ["type": "string"],
        ],
        "required": ["decision", "confidence", "rationale"],
    ]

    private static let system = """
    You help a person run the firewall on their Mac. You see examples of connections they allowed or denied, then \
    a new connection. Predict what THIS person would decide, following their demonstrated habits (which apps, \
    destinations, categories and risk levels they accept or block), not your own preferences. Reply with JSON:
    - "decision": "allow" or "deny"
    - "confidence": 0-100, how sure you are this person would choose that. Use under 60 when their examples don't \
    clearly cover a case like this.
    - "rationale": one short sentence citing the pattern in their past choices that drives the prediction.
    """

    static func suggest(_ p: Profile, decisions: [Decision], llm: LocalLLM) async throws -> Suggestion {
        let examples = examples(for: p, in: decisions)
        let allows = decisions.filter { $0.verdict == .allow }.count
        var user = "This person has made \(decisions.count) decisions: \(allows) allowed, \(decisions.count - allows) denied.\n"
        user += "Their most similar past decisions:\n" + examples.map { "- " + $0.exampleLine }.joined(separator: "\n")
        user += "\n\nNew connection:\n"
        user += "App: \(p.appName) [\(p.appleSigned ? "apple" : p.teamID.map { "team \($0)" } ?? "unsigned")], path \(p.processPath)\n"
        user += p.key.direction == .inbound ? "Inbound on local port \(p.key.port) \(p.key.proto.rawValue)\n"
                                            : "Outbound to \(p.hostname ?? p.key.host):\(p.key.port) \(p.key.proto.rawValue)\n"
        if let a = p.analysis { user += "What it is: \(a.description) (category \(a.category))\n" }
        user += "Risk score: \(p.riskScore)/100\n"
        if let i = p.intel, !i.hits.isEmpty { user += "Threat intel: " + i.hits.map { "\($0.source): \($0.detail)" }.joined(separator: "; ") + "\n" }

        let content = try await llm.complete(system: system, user: user, schema: schema)
        guard let obj = LocalLLM.jsonObject(content), let d = obj["decision"] as? String,
              let verdict = Verdict(rawValue: d.lowercased()) else {
            throw LocalLLM.Failure.badResponse(String(content.prefix(200)))
        }
        var s = Suggestion(verdict: verdict,
                           confidence: min(100, max(0, (obj["confidence"] as? Int) ?? Int((obj["confidence"] as? Double) ?? 50))),
                           rationale: (obj["rationale"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                           basedOn: decisions.count)
        return guarded(s: &s, p)
    }

    /// A small model shouldn't confidently wave through something on a threat feed.
    static func guarded(s: inout Suggestion, _ p: Profile) -> Suggestion {
        s.confidence = min(s.confidence, 95)   // a 3B model claiming certainty isn't
        if s.verdict == .allow, p.intel?.reputation == .knownBad {
            s.confidence = min(s.confidence, 40)
            s.rationale += " Caution: this IP is on a threat-intelligence blocklist."
        }
        return s
    }

    /// How often suggestions matched what the user then chose.
    static func matchRate(_ decisions: [Decision]) -> (matched: Int, total: Int) {
        let scored = decisions.filter { $0.suggested != nil && $0.source != .suggestion }
        return (scored.filter { $0.suggested == $0.verdict }.count, scored.count)
    }
}
