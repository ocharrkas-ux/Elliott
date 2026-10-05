import Foundation

/// How a connection's hostname was established.
enum NameSource: String, Codable {
    case sni            // the connection's own TLS ClientHello named the server: proof about this connection
    case dns            // a DNS answer for this IP arrived shortly before the connection and was still valid
    case dnsAmbiguous   // several names resolved to this IP in the valid window (shared CDN IP); most recent shown
    case filter         // the Network Extension filter (hostname from the connecting API or its DNS view)

    var label: String {
        switch self {
        case .sni: "TLS server name"
        case .dns: "DNS lookup before the connection"
        case .dnsAmbiguous: "DNS (shared IP; ambiguous)"
        case .filter: "network filter"
        }
    }
}

struct NameMatch: Equatable {
    var name: String
    var source: NameSource
    var alternatives: [String] = []
    /// Seconds between the DNS answer and the connection (DNS matches only).
    var lead: Double?
}

/// Ties hostnames to connections only when the evidence belongs to that connection in time:
///  1. SNI from the same TCP connection (local port + remote IP + remote port) at about the same time.
///  2. Otherwise a DNS answer for the IP that arrived *before* the connection started, while still valid (TTL
///     clamped to 1 min…1 h, plus a short grace). Answers after the connection never name it.
///  3. Connections whose start time is unknown (open before capture or before Elliott started) get SNI only.
final class NameResolver: @unchecked Sendable {
    private let lock = NSLock()
    private var dns: [String: [DNSObservation]] = [:]      // ip → answers, oldest first
    private var sni: [String: SNIObservation] = [:]        // "localPort|remoteIP|remotePort" → observation
    private(set) var captureSince: Date?
    private(set) var capturing = false
    var cursor: Double = 0

    static let minValidity: Double = 60, maxValidity: Double = 3600, grace: Double = 30
    /// A connection's first sighting can lag its real start by up to the poll interval (+ slack).
    static let observationLag: Double = 5
    static let sniWindow: Double = 120

    func ingest(_ b: NameBatch) {
        lock.lock(); defer { lock.unlock() }
        capturing = b.capturing
        captureSince = b.capturing && b.since > 0 ? Date(timeIntervalSince1970: b.since) : nil
        cursor = max(cursor, b.cursor)
        for d in b.dns {
            var list = dns[d.ip, default: []]
            list.append(d)
            if list.count > 32 { list.removeFirst(list.count - 32) }
            dns[d.ip] = list
        }
        for s in b.sni { sni["\(s.localPort)|\(s.remoteIP)|\(s.remotePort)"] = s }
        // Forget what can no longer bind to anything.
        let now = Date().timeIntervalSince1970
        if dns.count > 20_000 { dns = dns.filter { ($0.value.last?.time ?? 0) > now - 6 * 3600 } }
        if sni.count > 20_000 { sni = sni.filter { $0.value.time > now - 15 * 60 } }
    }

    /// True when a connection first seen at `observed` started after capture began, so absence of evidence means
    /// something (a genuine raw-IP connection) rather than "we weren't looking".
    func coveredByCapture(observed: Date, preexisting: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard capturing, let since = captureSince, !preexisting else { return false }
        return observed.timeIntervalSince(since) > Self.observationLag + 5
    }

    func resolve(remoteIP: String, remotePort: Int, localPort: Int?, observed: Date, preexisting: Bool) -> NameMatch? {
        lock.lock(); defer { lock.unlock() }
        let t = observed.timeIntervalSince1970

        // 1. This connection's own ClientHello.
        if let lp = localPort, let s = sni["\(lp)|\(remoteIP)|\(remotePort)"], abs(s.time - t) <= Self.sniWindow {
            return NameMatch(name: s.name, source: .sni)
        }
        // 3. Unknown start time: DNS can't be tied to it.
        guard !preexisting, let since = captureSince, observed.timeIntervalSince(since) > Self.observationLag else { return nil }

        // 2. DNS answers that arrived before the connection started and were still valid then. The connection began
        //    at most `observationLag` before it was first seen; requiring the answer to precede that point keeps an
        //    answer from naming a connection that was already underway.
        let start = t - Self.observationLag
        let valid = (dns[remoteIP] ?? []).filter { d in
            let validity = min(max(d.ttl, Self.minValidity), Self.maxValidity) + Self.grace
            return d.time <= t && start - d.time <= validity
        }
        guard let latest = valid.max(by: { $0.time < $1.time }) else { return nil }
        let others = Set(valid.map(\.name)).subtracting([latest.name]).sorted()
        return NameMatch(name: latest.name, source: others.isEmpty ? .dns : .dnsAmbiguous, alternatives: others,
                         lead: max(0, t - latest.time))
    }
}
