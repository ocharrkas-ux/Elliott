import Foundation

// Minimal, bounds-checked parsing for hostname capture: Ethernet/BSD-loopback/raw IP → IPv4/IPv6 → UDP/TCP, DNS
// answers and the TLS ClientHello server name (SNI). Runs as root on untrusted packets, so every read is checked.

/// A DNS answer seen on the wire: `name` resolved to `ip` at `time`, valid for `ttl` seconds.
struct DNSObservation: Codable, Hashable, Sendable {
    var ip: String
    var name: String
    var ttl: Double
    var time: Double          // seconds since 1970 (packet timestamp)
}

/// The server name a TLS client asked for, on one specific TCP connection.
struct SNIObservation: Codable, Hashable, Sendable {
    var localIP: String
    var localPort: Int
    var remoteIP: String
    var remotePort: Int
    var name: String
    var time: Double
}

struct NameBatch: Codable, Sendable {
    var dns: [DNSObservation] = []
    var sni: [SNIObservation] = []
    var capturing = false
    var interfaces: [String] = []
    var since: Double = 0     // capture start (connections before this have unknown start times)
    var cursor: Double = 0    // pass back to get only newer observations
    /// DNS answers that matched no query from this Mac (possible spoofing); ignored.
    var unsolicitedDNS: Int?
    /// The packet-parsing process runs without root, and inside a sandbox.
    var privilegesDropped: Bool?
    var sandboxed: Bool?
}

struct Packet {
    enum Proto { case tcp, udp }
    var proto: Proto
    var src: String
    var dst: String
    var srcPort: Int
    var dstPort: Int
    var payload: ArraySlice<UInt8>
    var tcpSeq: UInt32 = 0
    var syn = false
    var ack = false
}

enum PacketParse {
    static let DLT_NULL: Int32 = 0, DLT_EN10MB: Int32 = 1, DLT_RAW: Int32 = 12, DLT_RAW_BSD: Int32 = 14, DLT_LOOP: Int32 = 108

    static func u16(_ b: ArraySlice<UInt8>, _ i: Int) -> Int? {
        guard i >= b.startIndex, i + 1 < b.endIndex else { return nil }
        return Int(b[i]) << 8 | Int(b[i + 1])
    }

    static func u32(_ b: ArraySlice<UInt8>, _ i: Int) -> UInt32? {
        guard i >= b.startIndex, i + 3 < b.endIndex else { return nil }
        return UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
    }

    /// One captured frame → transport packet, for the link types macOS interfaces use.
    static func parse(frame: ArraySlice<UInt8>, linkType: Int32) -> Packet? {
        var b = frame
        switch linkType {
        case DLT_EN10MB:
            guard var type = u16(b, b.startIndex + 12) else { return nil }
            var off = b.startIndex + 14
            if type == 0x8100, let inner = u16(b, b.startIndex + 16) { type = inner; off += 4 }   // VLAN
            guard type == 0x0800 || type == 0x86DD, off <= b.endIndex else { return nil }
            b = b[off...]
        case DLT_NULL, DLT_LOOP:
            guard b.count > 4 else { return nil }
            b = b[(b.startIndex + 4)...]
        case DLT_RAW, DLT_RAW_BSD:
            break
        default:
            return nil
        }
        return parseIP(b)
    }

    static func parseIP(_ b: ArraySlice<UInt8>) -> Packet? {
        guard let first = b.first else { return nil }
        let s = b.startIndex
        var proto: UInt8, src: String, dst: String, l4: Int
        switch first >> 4 {
        case 4:
            let ihl = Int(first & 0x0F) * 4
            guard ihl >= 20, b.count >= ihl else { return nil }
            if let frag = u16(b, s + 6), frag & 0x1FFF != 0 { return nil }   // later fragments carry no headers
            proto = b[s + 9]
            src = b[(s + 12)..<(s + 16)].map(String.init).joined(separator: ".")
            dst = b[(s + 16)..<(s + 20)].map(String.init).joined(separator: ".")
            l4 = s + ihl
        case 6:
            guard b.count >= 40 else { return nil }
            proto = b[s + 6]
            src = ipv6(b[(s + 8)..<(s + 24)])
            dst = ipv6(b[(s + 24)..<(s + 40)])
            l4 = s + 40
        default:
            return nil
        }
        guard l4 < b.endIndex else { return nil }
        let t = b[l4...]
        switch proto {
        case 17:
            guard let sp = u16(t, l4), let dp = u16(t, l4 + 2), t.count >= 8 else { return nil }
            return Packet(proto: .udp, src: src, dst: dst, srcPort: sp, dstPort: dp, payload: t[(l4 + 8)...])
        case 6:
            guard let sp = u16(t, l4), let dp = u16(t, l4 + 2), let seq = u32(t, l4 + 4), t.count >= 20 else { return nil }
            let doff = Int(t[l4 + 12] >> 4) * 4
            guard doff >= 20, t.count >= doff else { return nil }
            return Packet(proto: .tcp, src: src, dst: dst, srcPort: sp, dstPort: dp, payload: t[(l4 + doff)...],
                          tcpSeq: seq, syn: t[l4 + 13] & 0x02 != 0, ack: t[l4 + 13] & 0x10 != 0)
        default:
            return nil
        }
    }

    static func ipv6(_ b: ArraySlice<UInt8>) -> String {
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: b) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)) != nil ? String(cString: buf) : "?"
    }

    /// DNS answers in a UDP response from port 53.
    static func dnsAnswers(_ p: Packet, time: Double) -> [DNSObservation] {
        guard p.proto == .udp, p.srcPort == 53 else { return [] }
        return DNSCache.parse(Data(p.payload)).map { DNSObservation(ip: $0.0, name: $0.1, ttl: $0.2, time: time) }
    }

    enum SNIResult: Equatable { case name(String), needMore, notTLS }

    /// Server name from a TLS ClientHello (possibly the first part of one spanning several TCP segments).
    static func sni(_ data: [UInt8]) -> SNIResult {
        let b = data[...]
        // TLS record: handshake(22), version, length; handshake: ClientHello(1), 3-byte length
        guard b.count >= 1 else { return .needMore }
        guard b[0] == 0x16 else { return .notTLS }
        guard b.count >= 9 else { return .needMore }
        guard b[1] == 0x03, b[5] == 0x01 else { return .notTLS }
        var i = 9 + 2 + 32                                   // client version + random
        guard i < b.count else { return .needMore }
        i += 1 + Int(b[i])                                   // session id
        guard let cs = u16(b, i) else { return .needMore }
        i += 2 + cs                                          // cipher suites
        guard i < b.count else { return .needMore }
        i += 1 + Int(b[i])                                   // compression methods
        guard let extLen = u16(b, i) else { return .needMore }
        i += 2
        let end = i + extLen
        while i + 4 <= min(end, b.count) {
            guard let type = u16(b, i), let len = u16(b, i + 2) else { return .needMore }
            let body = i + 4
            if type == 0 {                                   // server_name
                guard body + len <= b.count else { return .needMore }
                // list length (2), name type (1) = host_name(0), name length (2), name
                guard let nameLen = u16(b, body + 3), body + 2 < b.count, b[body + 2] == 0,
                      body + 5 + nameLen <= b.count, nameLen > 0, nameLen <= 253 else { return .notTLS }
                let name = String(decoding: b[(body + 5)..<(body + 5 + nameLen)], as: UTF8.self).lowercased()
                return name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }) ? .name(name) : .notTLS
            }
            i = body + len
        }
        return i >= end ? .notTLS : .needMore                // all extensions seen and no SNI
    }
}

/// Accepts DNS answers only when they answer a query this Mac sent: same transaction id, same client port, same
/// server, same question, within a few seconds. Forged answers from elsewhere on the network don't match.
struct DNSMatcher {
    private var queries: [String: (name: String, time: Double)] = [:]
    private(set) var unsolicited = 0
    static let window: Double = 10

    /// Queries are remembered; answers come back as observations, or [] when they don't match (counted).
    mutating func observe(_ p: Packet, time: Double) -> [DNSObservation]? {
        guard p.proto == .udp else { return nil }
        if p.dstPort == 53, let h = Self.header(p.payload), !h.response {
            if queries.count > 4096 { queries = queries.filter { time - $0.value.time < Self.window } }
            queries["\(h.id)|\(p.srcPort)|\(p.dst)"] = (h.name, time)
            return nil
        }
        guard p.srcPort == 53, let h = Self.header(p.payload), h.response else { return nil }
        // Several servers may answer the same query, so a query stays valid for the whole window.
        guard let q = queries["\(h.id)|\(p.dstPort)|\(p.src)"], q.name == h.name, time - q.time <= Self.window, time >= q.time else {
            unsolicited += 1
            return []
        }
        return PacketParse.dnsAnswers(p, time: time)
    }

    static func header(_ payload: ArraySlice<UInt8>) -> (id: UInt16, response: Bool, name: String)? {
        let b = Array(payload)
        guard b.count >= 12 else { return nil }
        let qd = Int(b[4]) << 8 | Int(b[5])
        guard qd >= 1, let (name, _) = DNSCache.readName(b, 12) else { return nil }
        return (UInt16(b[0]) << 8 | UInt16(b[1]), b[2] & 0x80 != 0, name.lowercased())
    }
}

/// Reassembles the first bytes of outbound TLS connections until the ClientHello's server name is readable.
/// Flows are only tracked from their SYN, kept briefly, and capped.
struct SNIAssembler {
    struct Flow { var nextSeq: UInt32?; var bytes: [UInt8] = []; var started: Double }
    private(set) var flows: [String: Flow] = [:]
    static let tlsPorts: Set<Int> = [443, 8443, 9443, 993, 995, 465, 853, 5223]

    /// Feeds an outbound TCP packet; returns an SNI observation when one completes.
    mutating func feed(_ p: Packet, time: Double) -> SNIObservation? {
        guard p.proto == .tcp, Self.tlsPorts.contains(p.dstPort) else { return nil }
        let key = "\(p.src)|\(p.srcPort)|\(p.dst)|\(p.dstPort)"
        if p.syn {
            if flows.count > 4096 { flows = flows.filter { time - $0.value.started < 30 } }
            flows[key] = Flow(nextSeq: p.tcpSeq &+ 1, started: time)
            return nil
        }
        guard var f = flows[key], !p.payload.isEmpty else { return nil }
        if let next = f.nextSeq, p.tcpSeq != next { return nil }      // out of order / retransmit: wait for the right one
        f.bytes += p.payload
        f.nextSeq = p.tcpSeq &+ UInt32(p.payload.count)
        switch PacketParse.sni(f.bytes) {
        case .name(let n):
            flows[key] = nil
            return SNIObservation(localIP: p.src, localPort: p.srcPort, remoteIP: p.dst, remotePort: p.dstPort, name: n, time: f.started)
        case .notTLS:
            flows[key] = nil
        case .needMore:
            if f.bytes.count > 16_384 || time - f.started > 10 { flows[key] = nil } else { flows[key] = f }
        }
        return nil
    }
}
