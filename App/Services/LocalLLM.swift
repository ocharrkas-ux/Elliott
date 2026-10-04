import Foundation

struct LLMSettings: Codable, Equatable {
    enum Provider: String, Codable, CaseIterable { case ollama, openAICompatible }
    var provider: Provider = .ollama
    /// Ollama: http://127.0.0.1:11434 · LM Studio: http://127.0.0.1:1234 · llama.cpp server: http://127.0.0.1:8080
    var baseURL = "http://127.0.0.1:11434"
    var model = "qwen2.5:3b"
    var enabled = true
}

/// Describes and risk-rates connections with a small model running on this Mac. Nothing leaves the machine:
/// the URL must be loopback.
struct LocalLLM {
    var settings: LLMSettings

    enum Failure: LocalizedError {
        case notLocal, badResponse(String)
        var errorDescription: String? {
            switch self {
            case .notLocal: "The LLM server must run on this Mac (localhost / 127.0.0.1)."
            case .badResponse(let s): "Unexpected LLM response: \(s)"
            }
        }
    }

    private static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "description": ["type": "string"],
            "category": ["type": "string"],
            "risk": ["type": "integer", "minimum": 0, "maximum": 100],
            "reasons": ["type": "array", "items": ["type": "string"]],
        ],
        "required": ["description", "category", "risk", "reasons"],
    ]

    private static let system = """
    You are a network security analyst on a macOS computer. You get one network connection profile observed on \
    this Mac. Reply with JSON only:
    - "description": 1-2 plain-English sentences saying what this connection most likely is and what it's for \
    (name the service or company behind the destination when you can tell). Don't speculate beyond the evidence.
    - "category": one of: system, software-update, cloud-sync, push-notifications, web-browsing, messaging, \
    media-streaming, telemetry-analytics, advertising, developer-tools, remote-access, file-sharing, \
    local-network, security-software, ai-service, unknown, suspicious.
    - "risk": 0-100. 0-24 routine and expected; 25-49 worth a look; 50-74 unusual for this app or destination; \
    75-100 likely malicious (command-and-control, data exfiltration, reverse shell, cryptomining).
    - "reasons": 1-4 short reasons for the risk score.
    Apple-signed system daemons talking to Apple, Akamai or other CDN hosts on 443/5223 are routine. Unsigned \
    binaries, script interpreters, temp-folder executables, raw IPs, odd ports and inbound listeners deserve suspicion. \
    A remote IP on a threat-intelligence blocklist (botnet C2, compromised host, attacker) is strong evidence of \
    risk; a Tor exit node is notable but not proof of malice.
    """

    func analyze(_ p: Profile) async throws -> Analysis {
        let h = p.heuristic
        let facts: [String] = [
            "Process: \(p.processName)",
            "Path: \(p.processPath)",
            "App: \(p.appName)",
            "Code signature: " + (p.appleSigned ? "Apple" : p.teamID.map { "developer team \($0), identifier \(p.signingID ?? "?")" } ?? "unsigned/ad-hoc"),
            "Direction: \(p.key.direction.rawValue)",
            "Protocol: \(p.key.proto.rawValue.uppercased())",
            p.key.direction == .inbound
                ? "Local listening port: \(p.key.port) (\(RiskHeuristics.wellKnownPorts[p.key.port] ?? "unregistered"))"
                : "Destination: \(p.hostname ?? "(no hostname)") port \(p.key.port) (\(RiskHeuristics.wellKnownPorts[p.key.port] ?? "unregistered"))",
            "Remote IPs seen: \(p.addresses.prefix(6).joined(separator: ", "))",
            "Connections seen: \(p.count) since \(p.firstSeen.formatted(date: .abbreviated, time: .shortened))",
            "Automated checks: \(h.flags.isEmpty ? "none" : h.flags.joined(separator: "; ")) (score \(h.score))",
        ]
        var lines = facts
        if let intel = p.intel, !intel.hits.isEmpty {
            lines.append("Threat intelligence on the remote IP: " + intel.hits.map { "\($0.source): \($0.detail)" }.joined(separator: "; "))
        } else if p.intel != nil {
            lines.append("Threat intelligence on the remote IP: not on any blocklist")
        }
        if let edr = p.edr {
            lines.append("EDR alerts on this program (\(edr.severity.label)): " + edr.titles.joined(separator: "; "))
        }
        let content = try await complete(system: Self.system, user: lines.joined(separator: "\n"), schema: Self.schema)
        return try Self.decode(content, model: settings.model)
    }

    /// The JSON object in a model reply, tolerating code fences or chatter around it.
    static func jsonObject(_ content: String) -> [String: Any]? {
        var text = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if let start = text.firstIndex(of: "{"), let end = text.lastIndex(of: "}") { text = String(text[start...end]) }
        return try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
    }

    static func decode(_ content: String, model: String) throws -> Analysis {
        guard let obj = jsonObject(content), let desc = obj["description"] as? String else {
            throw Failure.badResponse(String(content.prefix(200)))
        }
        let risk = (obj["risk"] as? Int) ?? Int((obj["risk"] as? Double) ?? 50)
        return Analysis(description: desc.trimmingCharacters(in: .whitespacesAndNewlines),
                        category: (obj["category"] as? String) ?? "unknown",
                        risk: min(100, max(0, risk)),
                        reasons: (obj["reasons"] as? [String]) ?? [],
                        model: model)
    }

    /// Model names the server offers.
    func models() async throws -> [String] {
        let base = try baseURL()
        switch settings.provider {
        case .ollama:
            let (data, _) = try await URLSession.shared.data(from: base.appendingPathComponent("api/tags"))
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return ((obj?["models"] as? [[String: Any]]) ?? []).compactMap { $0["name"] as? String }
        case .openAICompatible:
            let (data, _) = try await URLSession.shared.data(from: base.appendingPathComponent("v1/models"))
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return ((obj?["data"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String }
        }
    }

    private func baseURL() throws -> URL {
        guard let url = URL(string: settings.baseURL), let host = url.host?.lowercased(),
              ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host) else { throw Failure.notLocal }
        return url
    }

    func complete(system: String, user: String, schema: [String: Any]) async throws -> String {
        let base = try baseURL()
        var req: URLRequest
        var body: [String: Any]
        let messages = [["role": "system", "content": system], ["role": "user", "content": user]]
        switch settings.provider {
        case .ollama:
            req = URLRequest(url: base.appendingPathComponent("api/chat"))
            body = ["model": settings.model, "messages": messages, "stream": false, "format": schema,
                    "options": ["temperature": 0.1]]
        case .openAICompatible:
            req = URLRequest(url: base.appendingPathComponent("v1/chat/completions"))
            body = ["model": settings.model, "messages": messages, "temperature": 0.1,
                    "response_format": ["type": "json_schema",
                                        "json_schema": ["name": "bastion_answer", "schema": schema]]]
        }
        req.httpMethod = "POST"
        req.timeoutInterval = 120
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Failure.badResponse(String(decoding: data.prefix(300), as: UTF8.self))
        }
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        switch settings.provider {
        case .ollama:
            if let s = (obj?["message"] as? [String: Any])?["content"] as? String { return s }
        case .openAICompatible:
            if let s = ((obj?["choices"] as? [[String: Any]])?.first?["message"] as? [String: Any])?["content"] as? String { return s }
        }
        throw Failure.badResponse(String(decoding: data.prefix(300), as: UTF8.self))
    }
}
