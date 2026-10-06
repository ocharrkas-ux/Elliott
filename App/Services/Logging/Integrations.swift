import Foundation
import Network
import os

private let log = Logger(subsystem: ElliottIDs.appBundleID, category: "integrations")

// MARK: - Settings

/// A SIEM destination for Elliott's events.
struct Forwarder: Codable, Hashable, Identifiable {
    enum Kind: String, Codable, CaseIterable, Identifiable { case syslog = "Syslog", splunk = "Splunk HEC", elastic = "Elastic"; var id: String { rawValue } }
    enum Transport: String, Codable, CaseIterable, Identifiable { case udp = "UDP", tcp = "TCP", tls = "TLS"; var id: String { rawValue } }
    enum Format: String, Codable, CaseIterable, Identifiable { case cef = "CEF", json = "JSON"; var id: String { rawValue } }
    var id = UUID()
    var kind: Kind = .syslog
    var enabled = true
    var name = ""
    /// Syslog: host. Splunk/Elastic: base URL (https://splunk.example:8088, https://es.example:9200).
    var host = ""
    var port = 514
    var transport: Transport = .tcp
    var format: Format = .cef
    var index = "elliott"
    var minSeverity: Severity = .info
    var kinds: Set<SecurityEvent.Kind> = Set(SecurityEvent.Kind.allCases)
    /// Keychain account for the token / API key.
    var secretAccount: String { "forwarder-\(id.uuidString)" }
}

/// Somewhere to send alerts off this Mac.
struct AlertChannel: Codable, Hashable, Identifiable {
    enum Kind: String, Codable, CaseIterable, Identifiable {
        case slack = "Slack", teams = "Microsoft Teams", discord = "Discord", webhook = "Webhook (JSON)",
             ntfy = "ntfy (phone push)", pushover = "Pushover (phone push)", email = "Email (SMTP)"
        var id: String { rawValue }
    }
    var id = UUID()
    var kind: Kind = .slack
    var enabled = true
    var name = ""
    /// Webhook URL; ntfy: server + topic URL (https://ntfy.sh/my-topic); Pushover: user key; email: SMTP host.
    var target = ""
    var smtpPort = 465
    var smtpUser = ""
    var from = ""
    var to = ""
    var minSeverity: Severity = .high
    var secretAccount: String { "alert-\(id.uuidString)" }   // webhook URL secrets, tokens, SMTP password
}

struct IntegrationSettings: Codable, Equatable {
    var forwarders: [Forwarder] = []
    var channels: [AlertChannel] = []
    /// At most this many alerts per channel per hour (the rest are summarized).
    var maxAlertsPerHour = 20

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        forwarders = try c.decodeIfPresent([Forwarder].self, forKey: .forwarders) ?? []
        channels = try c.decodeIfPresent([AlertChannel].self, forKey: .channels) ?? []
        maxAlertsPerHour = try c.decodeIfPresent(Int.self, forKey: .maxAlertsPerHour) ?? 20
    }
}

// MARK: - Formatting

enum EventFormat {
    /// CEF severity 0–10.
    static func cefSeverity(_ s: Severity) -> Int { [1, 3, 5, 8, 10][s.rawValue] }

    static func cefEscapeHeader(_ s: String) -> String { s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "|", with: "\\|") }
    static func cefEscapeValue(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "=", with: "\\=")
            .replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "")
    }

    static func cef(_ e: SecurityEvent, build: String) -> String {
        var ext = ["rt=\(Int64(e.time.timeIntervalSince1970 * 1000))", "dvchost=\(cefEscapeValue(e.node))"]
        if let a = e.app { ext.append("sproc=\(cefEscapeValue(a))") }
        if let a = e.actor { ext.append("suser=\(cefEscapeValue(a))") }
        ext.append("msg=\(cefEscapeValue(e.summary))")
        for (k, v) in e.detail.sorted(by: { $0.key < $1.key }) {
            let key = k.filter { $0.isLetter || $0.isNumber }
            if !key.isEmpty { ext.append("cs\(key)=\(cefEscapeValue(v))") }
        }
        return "CEF:0|Elliott|Elliott|\(cefEscapeHeader(build))|\(cefEscapeHeader(e.kind.rawValue))|\(cefEscapeHeader(e.summary))|\(cefSeverity(e.severity))|\(ext.joined(separator: " "))"
    }

    static func json(_ e: SecurityEvent) -> [String: Any] {
        var o: [String: Any] = ["@timestamp": ISO8601DateFormatter().string(from: e.time), "kind": e.kind.rawValue,
                                "severity": e.severity.label.lowercased(), "severity_level": e.severity.rawValue,
                                "host": e.node, "summary": e.summary, "vendor": "Elliott"]
        if let a = e.app { o["app"] = a }
        if let a = e.actor { o["actor"] = a }
        if !e.detail.isEmpty { o["detail"] = e.detail }
        return o
    }

    static func jsonLine(_ e: SecurityEvent) -> String {
        (try? String(data: JSONSerialization.data(withJSONObject: json(e), options: [.sortedKeys]), encoding: .utf8)) ?? "{}"
    }

    /// RFC 5424 syslog line.
    static func syslog(_ e: SecurityEvent, body: String) -> String {
        let pri = 8 * 13 + [6, 5, 4, 3, 2][e.severity.rawValue]   // facility log_audit(13); info…crit
        let ts = ISO8601DateFormatter().string(from: e.time)
        let host = e.node.replacingOccurrences(of: " ", with: "-")
        return "<\(pri)>1 \(ts) \(host.isEmpty ? "-" : host) Elliott - \(e.kind.rawValue) - \(body)"
    }
}

// MARK: - Delivery

/// Queues events for each forwarder and alert channel and delivers them in the background, with retries.
actor Integrations {
    struct Status: Equatable { var lastSuccess: Date?; var lastError: String?; var queued = 0 }

    private var settings = IntegrationSettings()
    private var queues: [UUID: [SecurityEvent]] = [:]
    private var status: [UUID: Status] = [:]
    private var backoff: [UUID: Date] = [:]
    private var sentPerHour: [UUID: [Date]] = [:]
    private var suppressed: [UUID: Int] = [:]
    private var recentAlertKeys: [String: Date] = [:]
    private var pump: Task<Void, Never>?
    private let build: String

    init(build: String) { self.build = build }

    func configure(_ s: IntegrationSettings) {
        settings = s
        let ids = Set(s.forwarders.map(\.id) + s.channels.map(\.id))
        queues = queues.filter { ids.contains($0.key) }
        if pump == nil {
            pump = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(5))
                    await self?.deliver()
                }
            }
        }
    }

    func statuses() -> [UUID: Status] {
        var s = status
        for (id, q) in queues { s[id, default: Status()].queued = q.count }
        return s
    }

    /// Every event goes to forwarders that want it; detections/alerts at or above a channel's level also alert.
    func submit(_ events: [SecurityEvent]) {
        for f in settings.forwarders where f.enabled {
            let want = events.filter { f.kinds.contains($0.kind) && $0.severity >= f.minSeverity }
            enqueue(f.id, want, cap: 20_000)
        }
        let alertable = events.filter { $0.kind == .detection || $0.kind == .alert || ($0.kind == .vulnerability && $0.severity >= .high) }
        for c in settings.channels where c.enabled {
            var want: [SecurityEvent] = []
            for e in alertable where e.severity >= c.minSeverity {
                // The same thing again within an hour isn't a new alert.
                let k = "\(c.id)|\(e.summary)"
                if let t = recentAlertKeys[k], Date().timeIntervalSince(t) < 3600 { continue }
                recentAlertKeys[k] = Date()
                want.append(e)
            }
            enqueue(c.id, want, cap: 500)
        }
        if recentAlertKeys.count > 5000 { recentAlertKeys = recentAlertKeys.filter { Date().timeIntervalSince($0.value) < 3600 } }
    }

    private func enqueue(_ id: UUID, _ events: [SecurityEvent], cap: Int) {
        guard !events.isEmpty else { return }
        var q = queues[id] ?? []
        q += events
        if q.count > cap { q.removeFirst(q.count - cap) }   // oldest dropped when a destination is down for long
        queues[id] = q
    }

    /// Sends one test event to a destination right away.
    func test(forwarder f: Forwarder) async -> String? {
        let e = SecurityEvent(time: Date(), kind: .system, severity: .info, node: Host.current().localizedName ?? "Mac",
                              summary: "Elliott test event", detail: ["test": "true"])
        do { try await send([e], to: f); return nil } catch { return error.localizedDescription }
    }

    func test(channel c: AlertChannel) async -> String? {
        let e = SecurityEvent(time: Date(), kind: .alert, severity: .high, node: Host.current().localizedName ?? "Mac",
                              summary: "Test alert from Elliott", detail: ["test": "true"])
        do { try await alert(e, via: c); return nil } catch { return error.localizedDescription }
    }

    private func deliver() async {
        for f in settings.forwarders where f.enabled {
            guard let q = queues[f.id], !q.isEmpty, (backoff[f.id] ?? .distantPast) < Date() else { continue }
            let batch = Array(q.prefix(500))
            do {
                try await send(batch, to: f)
                queues[f.id]?.removeFirst(min(batch.count, queues[f.id]?.count ?? 0))
                status[f.id] = Status(lastSuccess: Date(), lastError: nil)
                backoff[f.id] = nil
            } catch {
                fail(f.id, error)
            }
        }
        for c in settings.channels where c.enabled {
            guard var q = queues[c.id], !q.isEmpty, (backoff[c.id] ?? .distantPast) < Date() else { continue }
            var sent = (sentPerHour[c.id] ?? []).filter { Date().timeIntervalSince($0) < 3600 }
            while let e = q.first {
                if sent.count >= settings.maxAlertsPerHour { suppressed[c.id, default: 0] += q.count; q.removeAll(); break }
                do {
                    try await alert(e, via: c)
                    q.removeFirst()
                    sent.append(Date())
                    status[c.id] = Status(lastSuccess: Date(), lastError: nil)
                } catch {
                    fail(c.id, error)
                    break
                }
            }
            // After a quiet hour, say how many were held back.
            if q.isEmpty, let n = suppressed[c.id], n > 0, sent.count < settings.maxAlertsPerHour {
                let e = SecurityEvent(time: Date(), kind: .alert, severity: .medium, node: Host.current().localizedName ?? "Mac",
                                      summary: "\(n) more Elliott alert(s) were held back by the hourly limit. See Elliott's events.")
                if (try? await alert(e, via: c)) != nil { suppressed[c.id] = 0; sent.append(Date()) }
            }
            queues[c.id] = q
            sentPerHour[c.id] = sent
        }
    }

    private func fail(_ id: UUID, _ error: Error) {
        let n = (status[id]?.lastError == nil) ? 1 : 2
        status[id, default: Status()].lastError = error.localizedDescription
        backoff[id] = Date().addingTimeInterval(Double(min(300, 15 * n)))
        log.error("delivery failed: \(error.localizedDescription, privacy: .public)")
    }

    // MARK: SIEM

    private func send(_ events: [SecurityEvent], to f: Forwarder) async throws {
        let secret = Keychain.get(f.secretAccount)
        switch f.kind {
        case .syslog:
            let lines = events.map { EventFormat.syslog($0, body: f.format == .cef ? EventFormat.cef($0, build: build) : EventFormat.jsonLine($0)) }
            try await SocketSender.send(lines, host: f.host, port: f.port, transport: f.transport)
        case .splunk:
            guard let base = URL(string: f.host), let token = secret, !token.isEmpty else { throw IntegrationError("Splunk needs a URL and an HEC token") }
            var req = URLRequest(url: base.appendingPathComponent("services/collector/event"), timeoutInterval: 20)
            req.httpMethod = "POST"
            req.setValue("Splunk \(token)", forHTTPHeaderField: "Authorization")
            req.httpBody = Data(events.map { e -> String in
                let o: [String: Any] = ["time": e.time.timeIntervalSince1970, "host": e.node, "sourcetype": "elliott:\(e.kind.rawValue)",
                                        "index": f.index, "event": EventFormat.json(e)]
                return (try? String(data: JSONSerialization.data(withJSONObject: o), encoding: .utf8)) ?? "{}"
            }.joined(separator: "\n").utf8)
            try await post(req)
        case .elastic:
            guard let base = URL(string: f.host) else { throw IntegrationError("Elastic needs a URL") }
            var req = URLRequest(url: base.appendingPathComponent("_bulk"), timeoutInterval: 20)
            req.httpMethod = "POST"
            req.setValue("application/x-ndjson", forHTTPHeaderField: "Content-Type")
            if let k = secret, !k.isEmpty { req.setValue("ApiKey \(k)", forHTTPHeaderField: "Authorization") }
            let action = "{\"index\":{\"_index\":\"\(f.index.replacingOccurrences(of: "\"", with: ""))\"}}"
            req.httpBody = Data((events.map { action + "\n" + EventFormat.jsonLine($0) }.joined(separator: "\n") + "\n").utf8)
            try await post(req)
        }
    }

    // MARK: Alerts

    private func alert(_ e: SecurityEvent, via c: AlertChannel) async throws {
        let title = "Elliott \(e.severity.label) — \(e.node)"
        var lines = [e.summary]
        if let a = e.app { lines.append("App: \(a)") }
        for (k, v) in e.detail.sorted(by: { $0.key < $1.key }).prefix(6) where k != "test" { lines.append("\(k): \(v)") }
        let text = lines.joined(separator: "\n")
        let secret = Keychain.get(c.secretAccount)
        func jsonPost(_ url: String?, _ body: [String: Any]) async throws {
            guard let s = url, let u = URL(string: s), u.scheme == "https" else { throw IntegrationError("needs an https webhook URL") }
            var req = URLRequest(url: u, timeoutInterval: 20)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            try await post(req)
        }
        switch c.kind {
        case .slack: try await jsonPost(secret, ["text": "*\(title)*\n\(text)"])
        case .teams: try await jsonPost(secret, ["text": "**\(title)**\n\n\(text.replacingOccurrences(of: "\n", with: "\n\n"))"])
        case .discord: try await jsonPost(secret, ["content": "**\(title)**\n\(text)"])
        case .webhook:
            var body = EventFormat.json(e)
            body["title"] = title
            try await jsonPost(secret, body)
        case .ntfy:
            guard let u = URL(string: c.target), u.scheme == "https" else { throw IntegrationError("needs an https ntfy topic URL") }
            var req = URLRequest(url: u, timeoutInterval: 20)
            req.httpMethod = "POST"
            req.setValue(title, forHTTPHeaderField: "Title")
            req.setValue(e.severity >= .critical ? "urgent" : e.severity >= .high ? "high" : "default", forHTTPHeaderField: "Priority")
            req.setValue("rotating_light", forHTTPHeaderField: "Tags")
            if let t = secret, !t.isEmpty { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
            req.httpBody = Data(text.utf8)
            try await post(req)
        case .pushover:
            guard let token = secret, !token.isEmpty, !c.target.isEmpty else { throw IntegrationError("Pushover needs an app token and your user key") }
            var req = URLRequest(url: URL(string: "https://api.pushover.net/1/messages.json")!, timeoutInterval: 20)
            req.httpMethod = "POST"
            var form = URLComponents()
            form.queryItems = [.init(name: "token", value: token), .init(name: "user", value: c.target), .init(name: "title", value: title),
                               .init(name: "message", value: text), .init(name: "priority", value: e.severity >= .critical ? "1" : "0")]
            req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            req.httpBody = Data((form.percentEncodedQuery ?? "").utf8)
            try await post(req)
        case .email:
            try await SMTP.send(host: c.target, port: c.smtpPort, user: c.smtpUser, password: secret ?? "",
                                from: c.from.isEmpty ? c.smtpUser : c.from, to: c.to, subject: title, body: text)
        }
    }

    private func post(_ req: URLRequest) async throws {
        let (_, resp) = try await LimitedDownload.fetch(req, maxBytes: 256 * 1024)
        guard (200..<300).contains(resp.statusCode) else { throw IntegrationError("the server answered HTTP \(resp.statusCode)") }
    }
}

struct IntegrationError: LocalizedError {
    var message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}

// MARK: - Syslog transport

enum SocketSender {
    /// Sends lines over UDP (one datagram each), TCP or TLS (newline-delimited).
    static func send(_ lines: [String], host: String, port: Int, transport: Forwarder.Transport) async throws {
        guard !host.isEmpty, let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { throw IntegrationError("needs a host and port") }
        let params: NWParameters = switch transport { case .udp: .udp; case .tcp: .tcp; case .tls: .tls }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: params)
        defer { conn.cancel() }
        try await ready(conn)
        if transport == .udp {
            for l in lines { try await write(conn, Data(l.utf8)) }
        } else {
            try await write(conn, Data((lines.joined(separator: "\n") + "\n").utf8))
        }
    }

    static func ready(_ conn: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let once = OnceFlag()
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: if once.take() { cont.resume() }
                case .failed(let e), .waiting(let e): if once.take() { cont.resume(throwing: e) }
                case .cancelled: if once.take() { cont.resume(throwing: IntegrationError("connection cancelled")) }
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 15) { if once.take() { cont.resume(throwing: IntegrationError("connection timed out")) } }
        }
    }

    static func write(_ conn: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { e in if let e { cont.resume(throwing: e) } else { cont.resume() } })
        }
    }
}

final class OnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func take() -> Bool { lock.withLock { if done { return false }; done = true; return true } }
}

// MARK: - Email

/// Minimal SMTP client over implicit TLS (port 465, "SSL/TLS"), AUTH LOGIN. Enough to email alerts through
/// Gmail/iCloud/Fastmail app passwords.
enum SMTP {
    static func send(host: String, port: Int, user: String, password: String, from: String, to: String, subject: String, body: String) async throws {
        guard !host.isEmpty, !to.isEmpty, let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { throw IntegrationError("needs an SMTP server and a recipient") }
        guard port != 587 && port != 25 else { throw IntegrationError("use port 465 (SSL/TLS); STARTTLS isn't supported") }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tls)
        defer { conn.cancel() }
        try await SocketSender.ready(conn)
        let reader = LineReader(conn)
        func expect(_ code: String) async throws {
            let reply = try await reader.reply()
            guard reply.hasPrefix(code) else { throw IntegrationError("SMTP: \(reply.prefix(120))") }
        }
        func cmd(_ s: String, _ code: String) async throws {
            try await SocketSender.write(conn, Data((s + "\r\n").utf8))
            try await expect(code)
        }
        try await expect("220")
        try await cmd("EHLO elliott.local", "250")
        if !user.isEmpty {
            try await cmd("AUTH LOGIN", "334")
            try await cmd(Data(user.utf8).base64EncodedString(), "334")
            try await cmd(Data(password.utf8).base64EncodedString(), "235")
        }
        let clean = { (s: String) in s.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: " ") }
        try await cmd("MAIL FROM:<\(clean(from))>", "250")
        for r in to.split(separator: ",") { try await cmd("RCPT TO:<\(clean(r.trimmingCharacters(in: .whitespaces)))>", "250") }
        try await cmd("DATA", "354")
        let date = DateFormatter()
        date.locale = Locale(identifier: "en_US_POSIX")
        date.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        let message = "From: Elliott <\(clean(from))>\r\nTo: \(clean(to))\r\nSubject: \(clean(subject))\r\nDate: \(date.string(from: Date()))\r\n"
            + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            + body.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false)
                .map { $0.hasPrefix(".") ? "." + $0 : String($0) }.joined(separator: "\r\n")
            + "\r\n.\r\n"
        try await SocketSender.write(conn, Data(message.utf8))
        try await expect("250")
        try? await SocketSender.write(conn, Data("QUIT\r\n".utf8))
    }

    /// Reads complete (possibly multi-line) SMTP replies.
    final class LineReader: @unchecked Sendable {
        private let conn: NWConnection
        private var buffer = ""
        init(_ c: NWConnection) { conn = c }

        func reply() async throws -> String {
            while true {
                // A reply ends with a line "NNN text" (a space, not a dash, after the code).
                let lines = buffer.components(separatedBy: "\r\n")
                if lines.count > 1, let last = lines.dropLast().last(where: { $0.count >= 4 }), last.count >= 4,
                   last[last.index(last.startIndex, offsetBy: 3)] == " " {
                    buffer = lines.last ?? ""
                    return last
                }
                let chunk: Data = try await withCheckedThrowingContinuation { cont in
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, done, err in
                        if let err { cont.resume(throwing: err) }
                        else if let data, !data.isEmpty { cont.resume(returning: data) }
                        else { cont.resume(throwing: IntegrationError(done ? "SMTP server closed the connection" : "no data")) }
                    }
                }
                buffer += String(decoding: chunk, as: UTF8.self)
                if buffer.count > 64_000 { throw IntegrationError("SMTP reply too long") }
            }
        }
    }
}
