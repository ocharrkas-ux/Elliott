import Foundation

/// Asks the local model whether an EDR finding looks like an attack or like normal software.
enum TriageLLM {
    private static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "assessment": ["type": "string", "enum": ["likely malicious", "suspicious", "likely benign"]],
            "confidence": ["type": "integer", "minimum": 0, "maximum": 100],
            "explanation": ["type": "string"],
            "recommendation": ["type": "string"],
        ],
        "required": ["assessment", "confidence", "explanation", "recommendation"],
    ]

    private static let system = """
    You are an endpoint detection and response (EDR) analyst triaging an alert on a macOS computer. Decide whether \
    the activity is most likely an attack, or legitimate software (developer tools, installers, updaters, admin \
    scripts often trip these rules). Weigh the code signature, file location, parent processes, the exact command \
    line, and any network activity. Reply with JSON:
    - "assessment": "likely malicious", "suspicious" or "likely benign"
    - "confidence": 0-100
    - "explanation": 2 plain-English sentences on what is happening and why it is or isn't concerning
    - "recommendation": one short action for the user (e.g. "Kill the process and delete /tmp/x", "Safe to mark benign")
    Only state facts present in the alert; don't invent payloads, backdoors or behavior you can't see. For \
    command-line alerts the program is usually a legitimate system shell or tool being misused: point at what \
    launched it. Never recommend deleting or changing anything under /bin, /sbin, /usr, /System or /Applications.
    """

    static func triage(_ f: Finding, signature: String, network: [String], llm: LocalLLM) async throws -> Triage {
        var user = "Alert: \(f.title) (severity \(f.severity.label), MITRE \(f.mitre.joined(separator: ", ")))\n"
        user += "Rule detail: \(f.detail)\n"
        if let path = f.path { user += "Program: \(path)\nCode signature: \(signature)\n" }
        if let u = f.user { user += "Runs as user: \(u)\n" }
        if let cmd = f.commandLine { user += "Command line: \(String(cmd.prefix(800)))\n" }
        if !f.chain.isEmpty { user += "Parent chain (nearest first): \(f.chain.joined(separator: " ← "))\n" }
        if !f.evidence.isEmpty { user += "Evidence: \(f.evidence.joined(separator: "; "))\n" }
        user += network.isEmpty ? "Network: no connections seen from this program\n"
                                : "Network connections from this program: \(network.prefix(8).joined(separator: "; "))\n"
        user += "Seen \(f.count) time(s) since \(f.firstSeen.formatted(date: .abbreviated, time: .shortened)).\n"

        let content = try await llm.complete(system: system, user: user, schema: schema)
        guard let obj = LocalLLM.jsonObject(content), let assessment = obj["assessment"] as? String else {
            throw LocalLLM.Failure.badResponse(String(content.prefix(200)))
        }
        return Triage(assessment: assessment.lowercased(),
                      confidence: min(95, max(0, (obj["confidence"] as? Int) ?? 50)),
                      explanation: firstSentences((obj["explanation"] as? String ?? ""), 3),
                      recommendation: safeRecommendation(obj["recommendation"] as? String ?? "", finding: f),
                      model: llm.settings.model)
    }

    static func firstSentences(_ text: String, _ n: Int) -> String {
        var out: [String] = []
        text.enumerateSubstrings(in: text.startIndex..., options: .bySentences) { s, _, _, stop in
            if let s { out.append(s.trimmingCharacters(in: .whitespacesAndNewlines)) }
            if out.count == n { stop = true }
        }
        return out.isEmpty ? text.trimmingCharacters(in: .whitespacesAndNewlines) : out.joined(separator: " ")
    }

    static let protectedPrefixes = ["/bin/", "/sbin/", "/usr/", "/System/", "/Applications/", "/Library/Apple/", "/private/var/db/"]

    /// A small model can suggest deleting /bin/bash. Never pass that on.
    static func safeRecommendation(_ text: String, finding f: Finding) -> String {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let destructive = t.range(of: #"\b(delete|remove|rm|erase|uninstall|move)\b"#, options: [.regularExpression, .caseInsensitive]) != nil
        let mentionsProtected = protectedPrefixes.contains { t.contains($0) }
            || (f.path.map { p in protectedPrefixes.contains { p.hasPrefix($0) } } ?? false) && destructive
        guard destructive && mentionsProtected else { return t.isEmpty ? "Review the evidence before acting." : t }
        return f.category == .commandLine
            ? "Kill the process if it's still running and find out what launched it (see Parents). Don't delete system files: this is a built-in tool being misused."
            : "Kill the process if it's still running and investigate how it got here. Don't delete files under system folders."
    }
}
