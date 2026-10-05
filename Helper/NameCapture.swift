import Foundation
import os

private let log = Logger(subsystem: ElliottIDs.helperLabel, category: "names")

/// Watches DNS answers and TLS ClientHello server names on every active interface (root needed for BPF).
/// Keeps only names, addresses, ports and timestamps, in memory, for a limited time; never stores payloads.
final class NameCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var dns: [DNSObservation] = []
    private var sni: [SNIObservation] = []
    private var assemblers: [String: SNIAssembler] = [:]
    private var handles: [String: OpaquePointer] = [:]
    private var running = false
    private(set) var since: Double = 0
    private var rescan: DispatchSourceTimer?

    /// DNS responses, plus outbound packets to TLS ports (SYNs and the first data segments are what matter).
    static let filter = "udp src port 53 or (tcp and (dst port 443 or dst port 8443 or dst port 9443 or dst port 993 or dst port 995 or dst port 465 or dst port 853 or dst port 5223))"

    var interfaces: [String] { lock.withLock { Array(handles.keys).sorted() } }
    var isRunning: Bool { lock.withLock { running } }

    func start() {
        let already: Bool = lock.withLock { let r = running; running = true; return r }
        guard !already else { return }
        since = Date().timeIntervalSince1970
        openInterfaces()
        // Interfaces come and go (Wi-Fi changes, VPN up/down).
        let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        t.schedule(deadline: .now() + 60, repeating: 60)
        t.setEventHandler { [weak self] in self?.openInterfaces() }
        t.resume()
        rescan = t
    }

    func stop() {
        lock.withLock {
            running = false
            for (_, h) in handles { pcap_breakloop(h) }
            handles.removeAll()
            dns.removeAll(); sni.removeAll()
        }
        rescan?.cancel()
        rescan = nil
    }

    /// Observations newer than `cursor` (packet time); old ones are dropped after 6 h (DNS) / 15 min (SNI).
    func batch(since cursor: Double) -> NameBatch {
        lock.withLock {
            let now = Date().timeIntervalSince1970
            dns.removeAll { now - $0.time > 6 * 3600 }
            sni.removeAll { now - $0.time > 15 * 60 }
            let d = dns.filter { $0.time > cursor }, s = sni.filter { $0.time > cursor }
            let newest = max(cursor, d.map(\.time).max() ?? cursor, s.map(\.time).max() ?? cursor)
            return NameBatch(dns: d, sni: s, capturing: running, interfaces: Array(handles.keys).sorted(), since: since, cursor: newest)
        }
    }

    private func openInterfaces() {
        guard lock.withLock({ running }) else { return }
        var list: UnsafeMutablePointer<pcap_if_t>?
        var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard pcap_findalldevs(&list, &err) == 0, let first = list else { return }
        defer { pcap_freealldevs(list) }
        var wanted: [String] = []
        for dev in sequence(first: first, next: { $0.pointee.next }) {
            let name = String(cString: dev.pointee.name)
            let flags = dev.pointee.flags
            guard flags & UInt32(PCAP_IF_LOOPBACK) == 0, flags & UInt32(PCAP_IF_UP) != 0, flags & UInt32(PCAP_IF_RUNNING) != 0,
                  dev.pointee.addresses != nil,
                  ["en", "utun", "ipsec", "ppp", "bridge"].contains(where: { name.hasPrefix($0) }) else { continue }
            wanted.append(name)
        }
        for name in wanted where lock.withLock({ handles[name] == nil }) { open(name) }
    }

    private func open(_ name: String) {
        var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let h = pcap_open_live(name, 2048, 0, 500, &err) else {
            log.error("pcap_open_live \(name, privacy: .public): \(String(cString: err), privacy: .public)")
            return
        }
        var prog = bpf_program()
        guard pcap_compile(h, &prog, Self.filter, 1, PCAP_NETMASK_UNKNOWN) == 0, pcap_setfilter(h, &prog) == 0 else {
            log.error("pcap filter on \(name, privacy: .public) failed")
            pcap_close(h)
            return
        }
        pcap_freecode(&prog)
        let link = pcap_datalink(h)
        lock.withLock { handles[name] = h; assemblers[name] = SNIAssembler() }
        Thread.detachNewThread { [weak self] in
            self?.loop(h, name: name, link: link)
            pcap_close(h)
            self?.lock.withLock { if self?.handles[name] == h { self?.handles[name] = nil } }
        }
    }

    private func loop(_ h: OpaquePointer, name: String, link: Int32) {
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<UInt8>?
        while lock.withLock({ running && handles[name] == h }) {
            let r = pcap_next_ex(h, &header, &data)
            if r == 0 { continue }          // timeout
            if r < 0 { break }              // interface gone or breakloop
            guard let header, let data else { continue }
            let len = Int(header.pointee.caplen)
            let time = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1e6
            let frame = Array(UnsafeBufferPointer(start: data, count: len))[...]
            guard let p = PacketParse.parse(frame: frame, linkType: link) else { continue }
            if p.proto == .udp {
                let answers = PacketParse.dnsAnswers(p, time: time)
                if !answers.isEmpty { lock.withLock { dns += answers; if dns.count > 50_000 { dns.removeFirst(10_000) } } }
            } else {
                let obs: SNIObservation? = lock.withLock { assemblers[name]?.feed(p, time: time) }
                if let obs { lock.withLock { sni.append(obs); if sni.count > 20_000 { sni.removeFirst(5_000) } } }
            }
        }
    }
}
