import Foundation

import Security

/// Which program answers on the LLM port: pinned on first use so a look-alike server can't feed Elliott verdicts.
struct LLMServerIdentity: Codable, Equatable, Hashable {
    var path: String
    var cdhash: String
    var signer: String

    /// The process listening on `port` (TCP), identified by path, code-directory hash and signer.
    static func listening(on port: Int) -> LLMServerIdentity? {
        guard let l = Inventory.listeners().first(where: { $0.port == port && $0.proto == "tcp" }),
              let path = ProcessTable.path(l.pid) else { return nil }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            return LLMServerIdentity(path: path, cdhash: "unsigned", signer: "unsigned")
        }
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, [], &info)
        let cdhash = ((info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data)?.map { String(format: "%02x", $0) }.joined() ?? "unsigned"
        let (_, team, apple) = PassiveMonitor.staticIdentity(path)
        return LLMServerIdentity(path: path, cdhash: cdhash, signer: apple ? "Apple" : team.map { "team \($0)" } ?? (cdhash == "unsigned" ? "unsigned" : "ad-hoc"))
    }
}

struct LLMSettings: Codable, Equatable {
    enum Provider: String, Codable, CaseIterable { case ollama, openAICompatible }
    var provider: Provider = .ollama
    /// Ollama: http://127.0.0.1:11434 · LM Studio: http://127.0.0.1:1234 · llama.cpp server: http://127.0.0.1:8080
    var baseURL = "http://127.0.0.1:11434"
    var model = "qwen2.5:3b"
    var enabled = true
    var pinnedServer: LLMServerIdentity?
    /// Low power: the LLM only runs when the user asks (analyze, suggest, triage, reachability), never in the
    /// background, and the model is unloaded soon after.
    var lowPower = false

    var port: Int { URL(string: baseURL)?.port ?? (URL(string: baseURL)?.scheme == "https" ? 443 : 80) }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = LLMSettings()
        provider = try c.decodeIfPresent(Provider.self, forKey: .provider) ?? d.provider
        baseURL = try c.decodeIfPresent(String.self, forKey: .baseURL) ?? d.baseURL
        model = try c.decodeIfPresent(String.self, forKey: .model) ?? d.model
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        pinnedServer = try c.decodeIfPresent(LLMServerIdentity.self, forKey: .pinnedServer)
        lowPower = try c.decodeIfPresent(Bool.self, forKey: .lowPower) ?? d.lowPower
    }
}

/// Describes and risk-rates connections with a small model running on this Mac. Nothing leaves the machine:
/// the URL must be loopback.
struct LocalLLM {
    var settings: LLMSettings
    /// When set, completions run on another Elliott node instead of the local server.
    var remote: (@Sendable (String, String, Data) async throws -> String)? = nil

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
            "Process: " + Untrusted.field("process", p.processName),
            "Path: " + Untrusted.field("path", p.processPath),
            "App: " + Untrusted.field("app", p.appName),
            "Code signature: " + (p.appleSigned ? "Apple" : p.teamID.map { "developer team \($0), identifier " + Untrusted.field("identifier", p.signingID ?? "?") } ?? "unsigned/ad-hoc"),
            "Direction: \(p.key.direction.rawValue)",
            "Protocol: \(p.key.proto.rawValue.uppercased())",
            p.key.direction == .inbound
                ? "Local listening port: \(p.key.port) (\(RiskHeuristics.wellKnownPorts[p.key.port] ?? "unregistered"))"
                : "Destination: \(p.hostname.map { Untrusted.field("hostname", $0) + " (from \(NameSource(rawValue: p.hostnameSource ?? "")?.label ?? "unknown source"))" } ?? (p.nameChecked == true ? "raw IP (no DNS lookup or TLS name preceded the connection)" : "hostname not observable")) port \(p.key.port) (\(RiskHeuristics.wellKnownPorts[p.key.port] ?? "unregistered"))",
            "Remote IPs seen: \(p.addresses.prefix(6).joined(separator: ", "))",
            "Connections seen: \(p.count) since \(p.firstSeen.formatted(date: .abbreviated, time: .shortened))",
            "Automated checks: " + (h.flags.isEmpty ? "none" : Untrusted.field("checks", h.flags.joined(separator: "; "), max: 800)) + " (score \(h.score))",
        ]
        var lines = facts
        if let intel = p.intel, !intel.hits.isEmpty {
            lines.append("Threat intelligence on the remote IP: " + intel.hits.map { "\($0.source): \($0.detail)" }.joined(separator: "; "))
        } else if p.intel != nil {
            lines.append("Threat intelligence on the remote IP: not on any blocklist")
        }
        if let v = p.vuln {
            lines.append("The app has \(v.count) known vulnerabilities, CVSS up to \(v.maxScore)\(v.kev ? ", including actively exploited ones" : "")")
        }
        if let edr = p.edr {
            lines.append("EDR alerts on this program (\(edr.severity.label)): " + edr.titles.joined(separator: "; "))
        }
        let content = try await complete(system: Self.system + "\n" + Untrusted.systemNote, user: lines.joined(separator: "\n"), schema: Self.schema)
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
            let (data, _) = try await LimitedDownload.fetch(URLRequest(url: base.appendingPathComponent("api/tags")), maxBytes: 4 * 1024 * 1024)
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return ((obj?["models"] as? [[String: Any]]) ?? []).compactMap { $0["name"] as? String }
        case .openAICompatible:
            let (data, _) = try await LimitedDownload.fetch(URLRequest(url: base.appendingPathComponent("v1/models")), maxBytes: 4 * 1024 * 1024)
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
        if let remote {
            return try await remote(system, user, try JSONSerialization.data(withJSONObject: schema))
        }
        return try await completeLocally(system: system, user: user, schema: schema)
    }

    func completeLocally(system: String, user: String, schema: [String: Any]) async throws -> String {
        let base = try baseURL()
        var req: URLRequest
        var body: [String: Any]
        let messages = [["role": "system", "content": system], ["role": "user", "content": user]]
        switch settings.provider {
        case .ollama:
            req = URLRequest(url: base.appendingPathComponent("api/chat"))
            body = ["model": settings.model, "messages": messages, "stream": false, "format": schema,
                    "options": ["temperature": 0.1]]
            if settings.lowPower { body["keep_alive"] = "1m" }   // free the model's memory soon after
        case .openAICompatible:
            req = URLRequest(url: base.appendingPathComponent("v1/chat/completions"))
            body = ["model": settings.model, "messages": messages, "temperature": 0.1,
                    "response_format": ["type": "json_schema",
                                        "json_schema": ["name": "elliott_answer", "schema": schema]]]
        }
        req.httpMethod = "POST"
        req.timeoutInterval = 120
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await LimitedDownload.fetch(req, maxBytes: 4 * 1024 * 1024)
        guard response.statusCode == 200 else {
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
