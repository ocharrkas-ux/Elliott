import CryptoKit
import Foundation
import SQLite3

/// Something that happened, for the searchable history, the audit trail, SIEM export and alerts.
struct SecurityEvent: Codable, Hashable, Identifiable, Sendable {
    enum Kind: String, Codable, CaseIterable, Identifiable, Sendable {
        case connection, detection, decision, rule, vulnerability, posture, alert, system
        var id: String { rawValue }
        /// Audit events record what someone (or something) changed.
        var isAudit: Bool { self == .decision || self == .rule }
    }
    var id: Int64 = 0
    var time: Date
    var kind: Kind
    var severity: Severity
    var node: String
    var app: String?
    var summary: String
    var detail: [String: String] = [:]
    /// Who did it, for audit events: "you", "suggestion (auto-accepted)", "network: <node>", "lockdown approval".
    var actor: String?
}

struct LoggingSettings: Codable, Equatable {
    var enabled = true
    var retentionDays = 30
    var logConnections = true

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = LoggingSettings()
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        retentionDays = try c.decodeIfPresent(Int.self, forKey: .retentionDays) ?? d.retentionDays
        logConnections = try c.decodeIfPresent(Bool.self, forKey: .logConnections) ?? d.logConnections
    }
}

/// Append-only local event store (SQLite + full-text search). Every row carries an HMAC over its content and the
/// previous row's HMAC, keyed with Elliott's state key (Keychain): edits, insertions and deletions in the middle
/// break the chain, and malware can't re-sign it without the key. Writes are batched off the main thread.
final class EventLog: @unchecked Sendable {
    private let queue = DispatchQueue(label: "elliott.eventlog")
    private var db: OpaquePointer?
    private var pending: [SecurityEvent] = []
    private var lastMAC = ""
    private let key: SymmetricKey?
    private var flushScheduled = false
    static let maxRows = 1_000_000

    init(path: URL, key: SymmetricKey?) {
        self.key = key
        queue.sync {
            guard sqlite3_open_v2(path.path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else { return }
            exec("PRAGMA journal_mode=WAL")
            exec("""
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL,
              severity INTEGER NOT NULL, node TEXT, app TEXT, summary TEXT NOT NULL, detail TEXT, actor TEXT, mac TEXT NOT NULL)
            """)
            exec("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
            exec("CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(summary, app, detail, actor, content='events', content_rowid='id')")
            exec("""
            CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
              INSERT INTO events_fts(rowid, summary, app, detail, actor) VALUES (new.id, new.summary, new.app, new.detail, new.actor); END
            """)
            exec("""
            CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
              INSERT INTO events_fts(events_fts, rowid, summary, app, detail, actor) VALUES ('delete', old.id, old.summary, old.app, old.detail, old.actor); END
            """)
            lastMAC = scalar("SELECT mac FROM events ORDER BY id DESC LIMIT 1") ?? ""
        }
    }

    // No other reference exists by now, and deinit may itself run on `queue` (the last flush block can hold the
    // final reference): close directly rather than syncing onto the queue.
    deinit { sqlite3_close(db) }

    // MARK: Writing

    func append(_ e: SecurityEvent) { append([e]) }

    func append(_ events: [SecurityEvent]) {
        guard !events.isEmpty else { return }
        queue.async {
            self.pending += events
            guard !self.flushScheduled else { return }
            self.flushScheduled = true
            self.queue.asyncAfter(deadline: .now() + 2) { self.flush() }
        }
    }

    /// Writes buffered events now (on the log's queue).
    func flushNow() { queue.sync { flush() } }

    private func flush() {
        flushScheduled = false
        guard let db, !pending.isEmpty else { return }
        exec("BEGIN")
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, "INSERT INTO events(ts, kind, severity, node, app, summary, detail, actor, mac) VALUES (?,?,?,?,?,?,?,?,?)", -1, &stmt, nil)
        for e in pending {
            let detail = (try? String(data: JSONSerialization.data(withJSONObject: e.detail, options: [.sortedKeys]), encoding: .utf8)) ?? "{}"
            let mac = Self.mac(previous: lastMAC, time: e.time.timeIntervalSince1970, kind: e.kind.rawValue, severity: e.severity.rawValue,
                               node: e.node, app: e.app, summary: e.summary, detail: detail, actor: e.actor, key: key)
            sqlite3_bind_double(stmt, 1, e.time.timeIntervalSince1970)
            bind(stmt, 2, e.kind.rawValue)
            sqlite3_bind_int(stmt, 3, Int32(e.severity.rawValue))
            bind(stmt, 4, e.node); bind(stmt, 5, e.app); bind(stmt, 6, e.summary); bind(stmt, 7, detail)
            bind(stmt, 8, e.actor); bind(stmt, 9, mac)
            if sqlite3_step(stmt) == SQLITE_DONE { lastMAC = mac }
            sqlite3_reset(stmt)
        }
        sqlite3_finalize(stmt)
        exec("COMMIT")
        pending.removeAll()
    }

    static func mac(previous: String, time: Double, kind: String, severity: Int, node: String, app: String?,
                    summary: String, detail: String, actor: String?, key: SymmetricKey?) -> String {
        let body = [previous, String(format: "%.6f", time), kind, String(severity), node, app ?? "", summary, detail, actor ?? ""]
            .joined(separator: "\u{1F}")
        guard let key else { return SHA256.hash(data: Data(body.utf8)).map { String(format: "%02x", $0) }.joined() }
        return HMAC<SHA256>.authenticationCode(for: Data(body.utf8), using: key).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Retention

    /// Drops events older than `days` (and beyond the row cap). The chain then starts at the oldest kept row.
    func prune(olderThan days: Int) {
        queue.async {
            let cutoff = Date().addingTimeInterval(-Double(max(days, 1)) * 86400).timeIntervalSince1970
            self.exec("DELETE FROM events WHERE ts < \(cutoff)")
            self.exec("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - \(Self.maxRows)")
            self.exec("INSERT INTO events_fts(events_fts) VALUES('optimize')")
        }
    }

    // MARK: Reading

    struct Query {
        var text = ""
        var kinds: Set<SecurityEvent.Kind> = []
        var minSeverity: Severity = .info
        var since: Date?
        var limit = 500
    }

    func search(_ q: Query) -> [SecurityEvent] {
        queue.sync {
            flush()
            guard let db else { return [] }
            var sql = "SELECT e.id, e.ts, e.kind, e.severity, e.node, e.app, e.summary, e.detail, e.actor FROM events e"
            var clauses: [String] = [], binds: [String] = []
            let terms = Self.ftsQuery(q.text)
            if !terms.isEmpty {
                sql += " JOIN events_fts f ON f.rowid = e.id"
                clauses.append("events_fts MATCH ?"); binds.append(terms)
            }
            if !q.kinds.isEmpty { clauses.append("e.kind IN (\(q.kinds.map { "'\($0.rawValue)'" }.joined(separator: ",")))") }
            if q.minSeverity > .info { clauses.append("e.severity >= \(q.minSeverity.rawValue)") }
            if let s = q.since { clauses.append("e.ts >= \(s.timeIntervalSince1970)") }
            if !clauses.isEmpty { sql += " WHERE " + clauses.joined(separator: " AND ") }
            sql += " ORDER BY e.id DESC LIMIT \(max(1, min(q.limit, 10_000)))"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            defer { sqlite3_finalize(stmt) }
            for (i, b) in binds.enumerated() { bind(stmt, Int32(i + 1), b) }
            var out: [SecurityEvent] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                let detail = text(stmt, 7).flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: String] } ?? [:]
                out.append(SecurityEvent(id: sqlite3_column_int64(stmt, 0), time: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
                                         kind: SecurityEvent.Kind(rawValue: text(stmt, 2) ?? "") ?? .system,
                                         severity: Severity(rawValue: Int(sqlite3_column_int(stmt, 3))) ?? .info,
                                         node: text(stmt, 4) ?? "", app: text(stmt, 5), summary: text(stmt, 6) ?? "",
                                         detail: detail, actor: text(stmt, 8)))
            }
            return out
        }
    }

    /// User text → an FTS5 query: each word as a quoted prefix term (so punctuation can't break the syntax).
    static func ftsQuery(_ text: String) -> String {
        text.split(whereSeparator: { $0.isWhitespace }).map { w in
            "\"" + w.replacingOccurrences(of: "\"", with: "") + "\"*"
        }.joined(separator: " ")
    }

    var count: Int { queue.sync { Int(scalar("SELECT COUNT(*) FROM events") ?? "0") ?? 0 } }

    /// Recomputes the chain. Returns nil if intact, else the first row id where it breaks.
    func verify() -> (checked: Int, brokenAt: Int64?) {
        queue.sync {
            flush()
            guard let db else { return (0, nil) }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "SELECT id, ts, kind, severity, node, app, summary, detail, actor, mac FROM events ORDER BY id", -1, &stmt, nil) == SQLITE_OK else { return (0, nil) }
            defer { sqlite3_finalize(stmt) }
            var prev: String?, n = 0
            while sqlite3_step(stmt) == SQLITE_ROW {
                let mac = text(stmt, 9) ?? ""
                if let p = prev {
                    let expect = Self.mac(previous: p, time: sqlite3_column_double(stmt, 1), kind: text(stmt, 2) ?? "",
                                          severity: Int(sqlite3_column_int(stmt, 3)), node: text(stmt, 4) ?? "", app: text(stmt, 5),
                                          summary: text(stmt, 6) ?? "", detail: text(stmt, 7) ?? "{}", actor: text(stmt, 8), key: key)
                    if expect != mac { return (n, sqlite3_column_int64(stmt, 0)) }
                }
                // The oldest kept row starts the chain (its predecessor may have been pruned).
                prev = mac
                n += 1
            }
            return (n, nil)
        }
    }

    // MARK: SQLite helpers

    private func exec(_ sql: String) { sqlite3_exec(db, sql, nil, nil, nil) }

    private func scalar(_ sql: String) -> String? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW ? text(stmt, 0) : nil
    }

    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private func bind(_ stmt: OpaquePointer?, _ i: Int32, _ s: String?) {
        if let s { sqlite3_bind_text(stmt, i, s, -1, Self.transient) } else { sqlite3_bind_null(stmt, i) }
    }

    private func text(_ stmt: OpaquePointer?, _ i: Int32) -> String? {
        sqlite3_column_text(stmt, i).map { String(cString: $0) }
    }
}
