import Foundation
import os

private let log = Logger(subsystem: ElliottIDs.helperLabel, category: "names")

/// One line from the capture process to the helper.
enum CaptureLine: Codable {
    case dns(DNSObservation)
    case sni(SNIObservation)
    case stats(unsolicited: Int)
    case started(uid: UInt32, sandboxed: Bool)
    case conn(ConnObservation)
    case pktap(active: Bool, kernelFiltered: Bool)
}

/// Hostname capture with privilege separation. This (root) side only enumerates interfaces and supervises; a
/// separate process opens the capture devices as root, drops to "nobody", sandboxes itself, and only then parses
/// packets. Its output is names, addresses, ports and times, one JSON line each.
final class NameCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var dns: [DNSObservation] = []
    private var sni: [SNIObservation] = []
    private var conns: [ConnObservation] = []
    private(set) var pktapActive = false
    private var child: Process?
    private var childInterfaces: [String] = []
    private var running = false
    private var crashes: [Date] = []
    private var useSandbox = true
    private var unsolicited = 0
    private var childUID: UInt32?
    private var childSandboxed = false
    private var buffer = Data()
    private(set) var since: Double = 0
    private var rescan: DispatchSourceTimer?

    var isRunning: Bool { lock.withLock { running } }

    func start() {
        let already: Bool = lock.withLock { let r = running; running = true; return r }
        guard !already else { return }
        since = Date().timeIntervalSince1970
        relaunchIfNeeded(force: true)
        // Interfaces come and go (Wi-Fi changes, VPN up/down): restart the capture process with the new set.
        let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        t.schedule(deadline: .now() + 60, repeating: 60)
        t.setEventHandler { [weak self] in self?.relaunchIfNeeded(force: false) }
        t.resume()
        rescan = t
    }

    func stop() {
        let c: Process? = lock.withLock {
            running = false
            dns.removeAll(); sni.removeAll(); conns.removeAll()
            let c = child; child = nil
            return c
        }
        c?.terminate()
        rescan?.cancel()
        rescan = nil
    }

    /// Connections seen since `cursor` (a `received` time), oldest first.
    func connections(since cursor: Double) -> [ConnObservation] {
        lock.withLock { conns.filter { $0.received > cursor } }
    }

    func batch(since cursor: Double) -> NameBatch {
        lock.withLock {
            let now = Date().timeIntervalSince1970
            dns.removeAll { now - $0.time > 6 * 3600 }
            sni.removeAll { now - $0.time > 15 * 60 }
            let d = dns.filter { $0.time > cursor }, s = sni.filter { $0.time > cursor }
            let newest = max(cursor, d.map(\.time).max() ?? cursor, s.map(\.time).max() ?? cursor)
            return NameBatch(dns: d, sni: s, capturing: running && child != nil, interfaces: childInterfaces, since: since,
                             cursor: newest, unsolicitedDNS: unsolicited,
                             privilegesDropped: childUID.map { $0 != 0 }, sandboxed: childUID == nil ? nil : childSandboxed)
        }
    }

    // MARK: Supervision (root, no packet parsing)

    static func interfaces() -> [String] {
        var list: UnsafeMutablePointer<pcap_if_t>?
        var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard pcap_findalldevs(&list, &err) == 0, let first = list else { return [] }
        defer { pcap_freealldevs(list) }
        var out: [String] = []
        for dev in sequence(first: first, next: { $0.pointee.next }) {
            let name = String(cString: dev.pointee.name)
            let flags = dev.pointee.flags
            guard flags & UInt32(PCAP_IF_LOOPBACK) == 0, flags & UInt32(PCAP_IF_UP) != 0, flags & UInt32(PCAP_IF_RUNNING) != 0,
                  dev.pointee.addresses != nil,
                  ["en", "utun", "ipsec", "ppp", "bridge"].contains(where: { name.hasPrefix($0) }) else { continue }
            out.append(name)
        }
        return out.sorted()
    }

    private func relaunchIfNeeded(force: Bool) {
        let ifaces = Self.interfaces()
        let (shouldStart, old): (Bool, Process?) = lock.withLock {
            guard running else { return (false, nil) }
            if !force, child != nil, ifaces == childInterfaces { return (false, nil) }
            let old = child
            child = nil
            return (!ifaces.isEmpty, old)
        }
        old?.terminationHandler = nil
        old?.terminate()
        guard shouldStart, let me = ProcessTable.path(getpid()) else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: me)
        let sandbox = lock.withLock { useSandbox }
        p.arguments = ["--capture"] + (sandbox ? [] : ["--no-sandbox"]) + ifaces
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let chunk = h.availableData
            if chunk.isEmpty { h.readabilityHandler = nil; return }
            self?.consume(chunk)
        }
        p.terminationHandler = { [weak self] proc in self?.childExited(proc) }
        do {
            try p.run()
            lock.withLock { child = p; childInterfaces = ifaces; childUID = nil }
        } catch {
            log.error("capture process failed to start: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func childExited(_ p: Process) {
        let retry: Bool = lock.withLock {
            guard running, child === p else { return false }
            child = nil
            crashes.append(Date())
            crashes.removeAll { Date().timeIntervalSince($0) > 60 }
            // A sandbox profile this macOS won't honor kills the process at once: fall back to privilege drop alone.
            if useSandbox && crashes.count >= 3 {
                useSandbox = false
                crashes.removeAll()
                log.error("capture process keeps exiting under the sandbox; continuing without it (still unprivileged)")
            }
            return crashes.count < 6
        }
        guard retry else { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in self?.relaunchIfNeeded(force: true) }
    }

    private func consume(_ chunk: Data) {
        lock.withLock {
            buffer.append(chunk)
            while let nl = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<nl]
                buffer.removeSubrange(buffer.startIndex...nl)
                guard line.count < 4096, let msg = try? JSONDecoder().decode(CaptureLine.self, from: line) else { continue }
                switch msg {
                case .dns(let d): dns.append(d); if dns.count > 50_000 { dns.removeFirst(10_000) }
                case .sni(let s): sni.append(s); if sni.count > 20_000 { sni.removeFirst(5_000) }
                case .stats(let u): unsolicited = u
                case .started(let uid, let sandboxed): childUID = uid; childSandboxed = sandboxed
                case .conn(var c):
                    // Resolve the program now, while the process (often short-lived) is still running.
                    c.path = ProcessTable.path(c.pid)
                    c.start = ProcessTable.startTime(c.pid)?.timeIntervalSince1970
                    c.received = max(Date().timeIntervalSince1970, (conns.last?.received ?? 0) + 0.000001)
                    conns.append(c)
                    if conns.count > 20_000 { conns.removeFirst(5_000) }
                case .pktap(let active, let filtered):
                    pktapActive = active
                    log.notice("connection capture (pktap): \(active ? "on" : "unavailable", privacy: .public)\(active ? (filtered ? ", kernel-filtered" : ", filtered in user space") : "", privacy: .public)")
                }
            }
            if buffer.count > 1_000_000 { buffer.removeAll() }
        }
    }
}

// MARK: - The capture process (started with --capture)

enum CaptureChild {
    static let filter = "udp port 53 or (tcp and (dst port 443 or dst port 8443 or dst port 9443 or dst port 993 or dst port 995 or dst port 465 or dst port 853 or dst port 5223))"

    static func run(interfaces: [String], sandbox: Bool) -> Never {
        // 1. As root: open the capture devices (the only thing root is needed for).
        var handles: [(OpaquePointer, Int32)] = []
        for name in interfaces {
            var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
            guard let h = pcap_open_live(name, 2048, 0, 500, &err) else { continue }
            var prog = bpf_program()
            if pcap_compile(h, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) == 0, pcap_setfilter(h, &prog) == 0 {
                pcap_freecode(&prog)
                handles.append((h, pcap_datalink(h)))
            } else {
                pcap_close(h)
            }
        }
        // Every interface with each packet's process (pktap): new TCP connections and who made them, so even
        // connections that last a fraction of a second are seen. Only SYNs are needed.
        var pktap: OpaquePointer?
        var kernelFiltered = false
        var perr = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        if let h = pcap_create("pktap", &perr) {
            _ = pcap_set_want_pktap(h, 1)
            pcap_set_snaplen(h, 320)
            pcap_set_timeout(h, 1000)
            // Deliver each SYN at once: the program path is looked up while the process is alive, and a quick
            // connection's process can exit within a buffering interval. Only SYNs pass the filter, so this is cheap.
            pcap_set_immediate_mode(h, 1)
            pcap_set_buffer_size(h, 2 * 1024 * 1024)
            if pcap_activate(h) >= 0, PcapChild.dltPktap.contains(pcap_datalink(h)) {
                var prog = bpf_program()
                if pcap_compile(h, &prog, "tcp[tcpflags] & tcp-syn != 0", 1, PCAP_NETMASK_UNKNOWN) == 0 {
                    kernelFiltered = pcap_setfilter(h, &prog) == 0
                    pcap_freecode(&prog)
                }
                pktap = h
            } else {
                pcap_close(h)
            }
        }
        // 2. Drop root for good before touching any packet.
        guard let pw = getpwnam("nobody") else { exit(2) }
        guard setgroups(0, nil) == 0, setgid(pw.pointee.pw_gid) == 0, setuid(pw.pointee.pw_uid) == 0,
              setuid(0) != 0, getuid() != 0, geteuid() != 0 else { exit(3) }
        // 3. Sandbox: no files, no network, no processes. Already-open descriptors keep working.
        var sandboxed = false
        if sandbox, let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "sandbox_init") {
            typealias SandboxInit = @convention(c) (UnsafePointer<CChar>, UInt64, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
            var err: UnsafeMutablePointer<CChar>?
            // An inline deny-all profile: the named "pure-computation" profile is killed on apply on current macOS.
            sandboxed = unsafeBitCast(sym, to: SandboxInit.self)("(version 1)(deny default)(allow sysctl-read)", 0, &err) == 0
        }
        let out = Output()
        out.send(.started(uid: getuid(), sandboxed: sandboxed))
        out.send(.pktap(active: pktap != nil, kernelFiltered: kernelFiltered))
        guard !handles.isEmpty || pktap != nil else { exit(4) }

        // 4. Parse (unprivileged). One thread per interface; exit if the helper goes away.
        let parent = getppid()
        for (h, link) in handles {
            Thread.detachNewThread { loop(h, link: link, out: out) }
        }
        if let pktap { Thread.detachNewThread { connectionLoop(pktap, out: out) } }
        while getppid() == parent { sleep(2) }
        exit(0)
    }

    final class Output: @unchecked Sendable {
        private let lock = NSLock()
        private let stdout = FileHandle.standardOutput
        func send(_ line: CaptureLine) {
            guard let data = try? JSONEncoder().encode(line) else { return }
            lock.withLock { stdout.write(data + Data("\n".utf8)) }
        }
    }

    static func connectionLoop(_ h: OpaquePointer, out: Output) {
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<UInt8>?
        var tracker = ConnTracker()
        while true {
            let r = pcap_next_ex(h, &header, &data)
            if r == 0 { continue }
            if r < 0 { return }
            guard let header, let data else { continue }
            let raw = UnsafeRawBufferPointer(start: data, count: Int(header.pointee.caplen))
            guard let meta = PktapMeta.parse(raw), meta.headerLength < raw.count,
                  let p = PacketParse.parse(frame: Array(raw[meta.headerLength...])[...], linkType: meta.dlt),
                  p.proto == .tcp, p.syn   // in case the kernel filter wasn't accepted
            else { continue }
            let time = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1e6
            if let c = tracker.feed(meta, p, time: time) { out.send(.conn(c)) }
        }
    }

    static func loop(_ h: OpaquePointer, link: Int32, out: Output) {
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<UInt8>?
        var dns = DNSMatcher()
        var tls = SNIAssembler()
        var reported = 0
        while true {
            let r = pcap_next_ex(h, &header, &data)
            if r == 0 { continue }
            if r < 0 { return }
            guard let header, let data else { continue }
            let time = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1e6
            let frame = Array(UnsafeBufferPointer(start: data, count: Int(header.pointee.caplen)))[...]
            guard let p = PacketParse.parse(frame: frame, linkType: link) else { continue }
            if p.proto == .udp {
                for a in dns.observe(p, time: time) ?? [] { out.send(.dns(a)) }
                if dns.unsolicited != reported { reported = dns.unsolicited; out.send(.stats(unsolicited: reported)) }
            } else if let s = tls.feed(p, time: time) {
                out.send(.sni(s))
            }
        }
    }
}
