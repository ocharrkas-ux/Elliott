import Foundation

/// What to record: packets of an application, to/from a destination, or both (both must match).
/// Recording uses the kernel's per-packet process tags (pktap), so an application's packets are attributed exactly,
/// including the first packet of a connection.
struct PcapSpec: Codable, Hashable, Sendable {
    var id = UUID()
    var label: String
    /// Executable names, as the kernel records them (the first 16 characters).
    var processNames: [String] = []
    /// Known process ids of the application (also matches traffic a daemon sends on its behalf).
    var pids: [Int32] = []
    /// Destination IPs (an FQDN is resolved by the app; the list is refreshed while recording).
    var addresses: [String] = []
    var maxBytes = 200 * 1024 * 1024
    var maxSeconds = 3600

    var hasApp: Bool { !processNames.isEmpty || !pids.isEmpty }
    var hasDestination: Bool { !addresses.isEmpty }
    var isValid: Bool { hasApp || hasDestination }

    static func kernelName(_ executable: String) -> String { String(decoding: executable.utf8.prefix(16), as: UTF8.self) }
}

/// A recording, as reported by the helper.
struct PcapStatus: Codable, Hashable, Sendable, Identifiable {
    var id: UUID
    var label: String
    var file: String
    var started: Date
    var ended: Date?
    var packets = 0
    var bytes = 0
    var error: String?
    var running: Bool { ended == nil }
}

/// The per-packet header macOS adds on the pktap pseudo-interface (struct pktap_header, xnu bsd/net/pktap.h).
struct PktapMeta: Equatable {
    var headerLength: Int
    var dlt: Int32
    var interface: String
    var pid: Int32
    var command: String
    var effectivePID: Int32
    var effectiveCommand: String
    /// PTH_FLAG_DIR_IN (1) / PTH_FLAG_DIR_OUT (2).
    var flags: UInt32 = 0

    var isOutgoing: Bool? { flags & 2 != 0 ? true : flags & 1 != 0 ? false : nil }

    /// The process the traffic is for: the effective one when the kernel sent it on an app's behalf.
    var owner: (pid: Int32, name: String)? {
        if effectivePID > 0 && !effectiveCommand.isEmpty { return (effectivePID, effectiveCommand) }
        if pid > 0 && !command.isEmpty { return (pid, command) }
        return nil
    }

    static let minimumLength = 108

    /// The kernel tags incoming packets with the receiving process (often as kernel_task "for" the app), but
    /// outgoing packets frequently arrive with pid -1 and no name.
    var hasProcess: Bool { (pid > 0 && !command.isEmpty) || (effectivePID > 0 && !effectiveCommand.isEmpty) }

    var label: String {
        if effectivePID > 0 && effectivePID != pid && !effectiveCommand.isEmpty {
            return pid > 0 || !command.isEmpty ? "\(command) (\(pid)) for \(effectiveCommand) (\(effectivePID))" : "\(effectiveCommand) (\(effectivePID))"
        }
        return hasProcess ? "\(command) (\(pid))" : "process not recorded"
    }

    static func parse(_ b: UnsafeRawBufferPointer) -> PktapMeta? {
        guard b.count >= minimumLength else { return nil }
        func u32(_ o: Int) -> UInt32 { UInt32(littleEndian: b.loadUnaligned(fromByteOffset: o, as: UInt32.self)) }
        func str(_ o: Int, _ n: Int) -> String {
            let bytes = b[o..<(o + n)].prefix { $0 != 0 }
            return String(decoding: bytes, as: UTF8.self)
        }
        let len = Int(u32(0))
        guard len >= minimumLength, len <= b.count else { return nil }
        return PktapMeta(headerLength: len, dlt: Int32(bitPattern: u32(8)), interface: str(12, 24),
                         pid: Int32(bitPattern: u32(52)), command: str(56, 17),
                         effectivePID: Int32(bitPattern: u32(84)), effectiveCommand: str(88, 17), flags: u32(36))
    }
}

/// Decides per packet whether it belongs to a recording.
struct PcapMatcher {
    let spec: PcapSpec
    private let names: Set<String>
    private let pids: Set<Int32>
    private let addresses: Set<String>

    init(_ spec: PcapSpec) {
        self.spec = spec
        names = Set(spec.processNames.map(PcapSpec.kernelName))
        pids = Set(spec.pids)
        addresses = Set(spec.addresses.compactMap(PcapMatcher.canonicalIP))
    }

    /// For packets that carry their process. (Outgoing packets often don't: see FlowAttribution.)
    func matches(_ m: PktapMeta, src: String?, dst: String?) -> Bool {
        guard spec.isValid, destinationMatches(src: src, dst: dst) else { return false }
        return !spec.hasApp || appMatches(m) == true
    }

    func destinationMatches(src: String?, dst: String?) -> Bool {
        !spec.hasDestination || (src.map(addresses.contains) ?? false) || (dst.map(addresses.contains) ?? false)
    }

    /// Whether the packet belongs to the application; nil when the kernel didn't record its process.
    func appMatches(_ m: PktapMeta) -> Bool? {
        guard m.hasProcess else { return nil }
        return pids.contains(m.pid) || (m.effectivePID > 0 && pids.contains(m.effectivePID))
            || names.contains(m.command) || (!m.effectiveCommand.isEmpty && names.contains(m.effectiveCommand))
    }

    /// One textual form per address, so "::ffff:1.2.3.4"-style variants and zone ids compare correctly.
    static func canonicalIP(_ s: String) -> String? {
        let bare = s.split(separator: "%").first.map(String.init) ?? s
        var v4 = in_addr()
        if inet_pton(AF_INET, bare, &v4) == 1 { return bare }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, bare, &v6) == 1 else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return inet_ntop(AF_INET6, &v6, &buf, socklen_t(buf.count)).map { _ in String(cString: buf) }
    }
}

/// A connection, the same in both directions.
struct FlowKey: Hashable {
    let a: String, b: String
    let tcp: Bool

    init?(frame: ArraySlice<UInt8>, linkType: Int32) {
        guard let p = PacketParse.parse(frame: frame, linkType: linkType) else { return nil }
        let x = "\(p.src)|\(p.srcPort)", y = "\(p.dst)|\(p.dstPort)"
        (a, b) = x < y ? (x, y) : (y, x)
        tcp = p.proto == .tcp
    }
}

/// Attributes packets without process info to the process of their connection. Unattributed packets are held
/// briefly (an outgoing SYN precedes the reply that names the process) and written in order once known.
struct FlowAttribution<P> {
    var hold: Double = 3
    var maxPending = 5000
    private var known: [FlowKey: (match: Bool, who: String, seen: Double)] = [:]
    private var pending: [FlowKey: (since: Double, packets: [P])] = [:]
    private var pendingCount = 0
    private var lastSweep = 0.0

    /// `app`: whether this packet's own process matches (nil = not recorded). Returns packets to write, in order,
    /// each with the process label to record.
    mutating func feed(_ p: P, flow: FlowKey?, app: Bool?, who: String, now: Double) -> [(P, String)] {
        sweep(now)
        guard let flow else { return app == true ? [(p, who)] : [] }
        if let app {
            known[flow] = (app, who, now)
            let held = pending.removeValue(forKey: flow)?.packets ?? []
            pendingCount -= held.count
            return app ? held.map { ($0, who) } + [(p, who)] : []
        }
        if let k = known[flow] {
            known[flow]?.seen = now
            return k.match ? [(p, k.who)] : []
        }
        if pendingCount < maxPending {
            pending[flow, default: (now, [])].packets.append(p)
            pendingCount += 1
        }
        return []
    }

    /// The process label for a connection, if known (for captures that don't filter by app).
    func label(_ flow: FlowKey?) -> String? { flow.flatMap { known[$0]?.who } }

    /// Records who a connection belongs to without holding anything (destination-only captures).
    mutating func learn(_ flow: FlowKey?, who: String, now: Double) {
        if let flow { known[flow] = (true, who, now) }
        sweep(now)
    }

    private mutating func sweep(_ now: Double) {
        guard now - lastSweep > 1 else { return }
        lastSweep = now
        for (k, v) in pending where now - v.since > hold {
            pending[k] = nil
            pendingCount -= v.packets.count
        }
        if known.count > 100_000 { known = known.filter { now - $0.value.seen < 600 } }
    }
}

extension PacketParse {
    /// Source and destination IP of a frame of any IP protocol (TCP, UDP, ICMP, …).
    static func ipEndpoints(frame: ArraySlice<UInt8>, linkType: Int32) -> (src: String, dst: String)? {
        var b = frame
        switch linkType {
        case DLT_EN10MB:
            guard var type = u16(b, b.startIndex + 12) else { return nil }
            var off = b.startIndex + 14
            if type == 0x8100, let inner = u16(b, b.startIndex + 16) { type = inner; off += 4 }
            guard type == 0x0800 || type == 0x86DD, off < b.endIndex else { return nil }
            b = b[off...]
        case DLT_NULL, DLT_LOOP:
            guard b.count > 4 else { return nil }
            b = b[(b.startIndex + 4)...]
        case DLT_RAW, DLT_RAW_BSD:
            break
        default:
            return nil
        }
        guard let first = b.first else { return nil }
        let s = b.startIndex
        switch first >> 4 {
        case 4:
            guard b.count >= 20 else { return nil }
            return (b[s + 12..<s + 16].map(String.init).joined(separator: "."), b[s + 16..<s + 20].map(String.init).joined(separator: "."))
        case 6:
            guard b.count >= 40 else { return nil }
            return (ipv6(b[s + 8..<s + 24]), ipv6(b[s + 24..<s + 40]))
        default:
            return nil
        }
    }
}

/// Minimal pcapng writer (opens in Wireshark). Each packet carries a comment naming its process.
final class PcapNGWriter {
    private let handle: FileHandle
    private var interfaces: [String: UInt32] = [:]
    private(set) var bytes = 0

    init(handle: FileHandle) {
        self.handle = handle
        var body = Data()
        body.le(UInt32(0x1A2B3C4D)); body.le(UInt16(1)); body.le(UInt16(0)); body.le(Int64(-1))
        body += Self.option(4, Data("Elliott".utf8)) + Self.option(0, Data())
        write(type: 0x0A0D0D0A, body)
    }

    /// pcapng uses LINKTYPE_ values; Darwin's raw-IP DLTs differ from them.
    static func linkType(_ dlt: Int32) -> UInt16 {
        switch dlt {
        case 12, 14: 101       // DLT_RAW → LINKTYPE_RAW
        default: UInt16(truncatingIfNeeded: dlt)
        }
    }

    func packet(interface: String, dlt: Int32, time: (sec: Int, usec: Int), data: UnsafeRawBufferPointer, originalLength: Int, comment: String) {
        let key = "\(interface)|\(dlt)"
        let ifid: UInt32
        if let id = interfaces[key] { ifid = id } else {
            ifid = UInt32(interfaces.count)
            interfaces[key] = ifid
            var idb = Data()
            idb.le(Self.linkType(dlt)); idb.le(UInt16(0)); idb.le(UInt32(65535))
            idb += Self.option(2, Data(interface.utf8)) + Self.option(0, Data())
            write(type: 1, idb)
        }
        let ts = UInt64(time.sec) * 1_000_000 + UInt64(time.usec)
        var epb = Data()
        epb.le(ifid); epb.le(UInt32(ts >> 32)); epb.le(UInt32(ts & 0xFFFF_FFFF))
        epb.le(UInt32(data.count)); epb.le(UInt32(originalLength))
        epb += Data(data) + Data(repeating: 0, count: (4 - data.count % 4) % 4)
        epb += Self.option(1, Data(comment.utf8)) + Self.option(0, Data())
        write(type: 6, epb)
    }

    private static func option(_ code: UInt16, _ value: Data) -> Data {
        var d = Data()
        d.le(code); d.le(UInt16(value.count))
        return d + value + Data(repeating: 0, count: (4 - value.count % 4) % 4)
    }

    private func write(type: UInt32, _ body: Data) {
        var block = Data()
        let total = UInt32(12 + body.count)
        block.le(type); block.le(total); block += body; block.le(total)
        handle.write(block)
        bytes += block.count
    }
}

private extension Data {
    mutating func le<T: FixedWidthInteger>(_ v: T) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
}

/// A connection seen on the wire with the process the kernel attributed it to (emitted once per connection).
struct ConnObservation: Codable, Hashable, Sendable {
    var time: Double            // first packet (the SYN for TCP), seconds since 1970
    var tcp: Bool
    var outbound: Bool
    var localIP: String
    var localPort: Int
    var remoteIP: String
    var remotePort: Int
    var pid: Int32
    var name: String            // process name as the kernel records it (16 chars)
    var path: String?           // resolved by the helper while the process is alive
    var start: Double?          // process start time, to tell a reused pid apart
    var received: Double = 0    // when the helper got it (the polling cursor)
}

/// Turns the pktap packet stream into one ConnObservation per new connection. A connection is reported once its
/// direction is known (from the first packet: the SYN for TCP) and some packet names its process (incoming
/// packets do; outgoing ones often don't). Connections already open when watching began are ignored.
struct ConnTracker {
    private struct Flow { var first: Double; var outbound: Bool; var local: (String, Int); var remote: (String, Int); var tcp: Bool; var last: Double; var done: Bool }
    private var flows: [String: Flow] = [:]
    private var ignored: [String: Double] = [:]
    private var lastPrune = 0.0
    var maxFlows = 50_000

    mutating func feed(_ m: PktapMeta, _ p: Packet, time: Double) -> ConnObservation? {
        prune(time)
        guard let out = m.isOutgoing, !Self.isLocalOnly(p.src), !Self.isLocalOnly(p.dst) else { return nil }
        let x = "\(p.src)|\(p.srcPort)", y = "\(p.dst)|\(p.dstPort)"
        let key = (p.proto == .tcp ? "t" : "u") + (x < y ? x + ">" + y : y + ">" + x)
        if ignored[key] != nil { ignored[key] = time; return nil }
        if flows[key] == nil {
            let isSyn = p.proto == .tcp && p.syn && !p.ack
            // TCP: only connections whose opening SYN we saw (others predate watching).
            if p.proto == .tcp && !isSyn { ignored[key] = time; return nil }
            // UDP has no handshake: an incoming first packet is nearly always the tail of an older flow.
            if p.proto == .udp && !out { ignored[key] = time; return nil }
            guard flows.count < maxFlows else { return nil }
            flows[key] = Flow(first: time, outbound: out, local: out ? (p.src, p.srcPort) : (p.dst, p.dstPort),
                              remote: out ? (p.dst, p.dstPort) : (p.src, p.srcPort), tcp: p.proto == .tcp, last: time, done: false)
        }
        flows[key]!.last = time
        guard let f = flows[key], !f.done, let owner = m.owner else { return nil }
        flows[key]!.done = true
        return ConnObservation(time: f.first, tcp: f.tcp, outbound: f.outbound, localIP: f.local.0, localPort: f.local.1,
                               remoteIP: f.remote.0, remotePort: f.remote.1, pid: owner.pid, name: owner.name)
    }

    static func isLocalOnly(_ ip: String) -> Bool {
        ip.hasPrefix("127.") || ip == "::1" || ip.hasPrefix("fe80:") || ip.hasPrefix("224.") || ip.hasPrefix("239.")
            || ip.hasPrefix("ff0") || ip == "255.255.255.255" || ip == "0.0.0.0"
    }

    private mutating func prune(_ now: Double) {
        guard now - lastPrune > 30 else { return }
        lastPrune = now
        flows = flows.filter { now - $0.value.last < 600 }
        ignored = ignored.filter { now - $0.value < 600 }
    }
}
