import Foundation
import os

private let log = Logger(subsystem: ElliottIDs.helperLabel, category: "pcap")

/// Progress from a recording process, one JSON line each on its stderr.
struct PcapProgress: Codable {
    var packets: Int
    var bytes: Int
    var error: String?
}

/// Packet captures the user started for an application, a destination, or both. Same privilege separation as
/// hostname capture: this (root) side creates the file and supervises; a separate process opens the pktap device
/// as root, drops to "nobody", sandboxes itself, and only then reads packets, writing matches to the file it was
/// handed as stdout. Files live in a root-owned folder the user can read but nothing else can write.
final class PcapRecorder: @unchecked Sendable {
    static let folder = URL(fileURLWithPath: "/Library/Application Support/Elliott/Captures")
    static let maxConcurrent = 4

    private final class Session {
        var status: PcapStatus
        var process: Process
        var control: Pipe
        init(status: PcapStatus, process: Process, control: Pipe) { self.status = status; self.process = process; self.control = control }
    }

    private let lock = NSLock()
    private var sessions: [UUID: Session] = [:]

    func start(_ spec: PcapSpec) -> String? {
        guard spec.isValid else { return "Choose an application, a destination, or both." }
        guard spec.maxBytes > 0, spec.maxBytes <= 2 * 1024 * 1024 * 1024, spec.maxSeconds > 0, spec.maxSeconds <= 86_400
        else { return "Limits out of range." }
        let running = lock.withLock { sessions.values.filter { $0.status.running }.count }
        guard running < Self.maxConcurrent else { return "At most \(Self.maxConcurrent) captures can run at once." }
        guard let me = ProcessTable.path(getpid()) else { return "helper path unknown" }

        try? FileManager.default.createDirectory(at: Self.folder, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let safe = String(spec.label.unicodeScalars.map { CharacterSet.alphanumerics.contains($0) || "-_.".unicodeScalars.contains($0) ? Character($0) : "_" }).prefix(60)
        let url = Self.folder.appendingPathComponent("\(stamp)-\(safe).pcapng")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o644)
        guard fd >= 0 else { return "can't create \(url.lastPathComponent): \(String(cString: strerror(errno)))" }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)

        let p = Process()
        p.executableURL = URL(fileURLWithPath: me)
        p.arguments = ["--pcap"]
        let control = Pipe(), progress = Pipe()
        p.standardInput = control
        p.standardOutput = file
        p.standardError = progress
        let status = PcapStatus(id: spec.id, label: spec.label, file: url.path, started: Date())
        let session = Session(status: status, process: p, control: control)
        var buffer = Data()
        progress.fileHandleForReading.readabilityHandler = { [weak self] h in
            let chunk = h.availableData
            if chunk.isEmpty { h.readabilityHandler = nil; return }
            buffer.append(chunk)
            while let nl = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<nl]
                buffer.removeSubrange(buffer.startIndex...nl)
                guard line.count < 4096, let pr = try? JSONDecoder().decode(PcapProgress.self, from: line) else { continue }
                self?.lock.withLock {
                    session.status.packets = pr.packets
                    session.status.bytes = pr.bytes
                    if let e = pr.error { session.status.error = e }
                }
            }
            if buffer.count > 100_000 { buffer.removeAll() }
        }
        p.terminationHandler = { [weak self] proc in
            self?.lock.withLock {
                session.status.ended = Date()
                if proc.terminationStatus != 0 && session.status.error == nil {
                    session.status.error = "recorder exited (\(proc.terminationStatus))"
                }
            }
            let st = self?.lock.withLock { session.status }
            log.notice("pcap ended: \(spec.label, privacy: .public) status \(proc.terminationStatus) packets \(st?.packets ?? 0) error \(st?.error ?? "-", privacy: .public)")
        }
        do {
            try p.run()
        } catch {
            try? FileManager.default.removeItem(at: url)
            return error.localizedDescription
        }
        try? file.close()   // the child has its own copy
        lock.withLock { sessions[spec.id] = session }
        send(spec, to: session)
        log.notice("pcap started: \(spec.label, privacy: .public)")
        return nil
    }

    /// New destination addresses (an FQDN re-resolved) or process ids while recording.
    func update(_ spec: PcapSpec) -> Bool {
        guard let s = lock.withLock({ sessions[spec.id] }), s.status.running, spec.isValid else { return false }
        send(spec, to: s)
        return true
    }

    func stop(_ id: UUID) {
        guard let s = lock.withLock({ sessions[id] }) else { return }
        try? s.control.fileHandleForWriting.close()   // EOF: the recorder flushes and exits
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if s.process.isRunning { s.process.terminate() } }
    }

    func stopAll() { for id in lock.withLock({ Array(sessions.keys) }) { stop(id) } }

    /// Recordings this run plus capture files left from before.
    func list() -> [PcapStatus] {
        var out = lock.withLock { sessions.values.map(\.status) }
        let known = Set(out.map(\.file))
        let files = (try? FileManager.default.contentsOfDirectory(at: Self.folder, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey])) ?? []
        for f in files where f.pathExtension == "pcapng" && !known.contains(f.path) {
            let v = try? f.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
            let mtime = (try? FileManager.default.attributesOfItem(atPath: f.path)[.modificationDate] as? Date) ?? nil
            out.append(PcapStatus(id: UUID(), label: f.deletingPathExtension().lastPathComponent, file: f.path,
                                  started: v?.creationDate ?? Date.distantPast, ended: mtime ?? v?.creationDate ?? Date(),
                                  packets: 0, bytes: v?.fileSize ?? 0))
        }
        return out.sorted { $0.started > $1.started }
    }

    /// Deletes a finished capture file (only files directly in the captures folder).
    func delete(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        guard url.deletingLastPathComponent().path == Self.folder.standardizedFileURL.path, url.pathExtension == "pcapng",
              !lock.withLock({ sessions.values.contains { $0.status.file == url.path && $0.status.running } })
        else { return false }
        guard (try? FileManager.default.removeItem(at: url)) != nil else { return false }
        lock.withLock { sessions = sessions.filter { $0.value.status.file != url.path } }
        return true
    }

    private func send(_ spec: PcapSpec, to s: Session) {
        guard let d = try? JSONEncoder().encode(spec) else { return }
        try? s.control.fileHandleForWriting.write(contentsOf: d + Data("\n".utf8))
    }
}

// MARK: - The recording process (started with --pcap)

enum PcapChild {
    static let dltPktap: Set<Int32> = [149, 258]

    static func run() -> Never {
        let progress = FileHandle.standardError
        func report(_ p: PcapProgress) {
            if let d = try? JSONEncoder().encode(p) { try? progress.write(contentsOf: d + Data("\n".utf8)) }
        }
        let input = LineReader(FileHandle.standardInput)
        guard let first = input.next(), let spec = try? JSONDecoder().decode(PcapSpec.self, from: first) else { exit(2) }

        // 1. As root: open the pktap device (all interfaces, packets tagged with their process).
        var err = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let h = pcap_create("pktap", &err) else {
            report(PcapProgress(packets: 0, bytes: 0, error: String(cString: err))); exit(4)
        }
        _ = pcap_set_want_pktap(h, 1)
        pcap_set_snaplen(h, 65535)
        pcap_set_timeout(h, 500)
        pcap_set_buffer_size(h, 8 * 1024 * 1024)
        let act = pcap_activate(h)
        if act >= 0, !dltPktap.contains(pcap_datalink(h)) { _ = pcap_set_datalink(h, 149) }
        guard act >= 0, dltPktap.contains(pcap_datalink(h)) else {
            report(PcapProgress(packets: 0, bytes: 0, error: act < 0 ? String(cString: pcap_geterr(h)) : "pktap unavailable (link type \(pcap_datalink(h)))"))
            exit(4)
        }

        // 2. Drop root for good, 3. sandbox (stdout is the capture file, stdin/stderr the helper's pipes).
        guard let pw = getpwnam("nobody") else { exit(2) }
        guard setgroups(0, nil) == 0, setgid(pw.pointee.pw_gid) == 0, setuid(pw.pointee.pw_uid) == 0,
              setuid(0) != 0, getuid() != 0, geteuid() != 0 else { exit(3) }
        if let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "sandbox_init") {
            typealias SandboxInit = @convention(c) (UnsafePointer<CChar>, UInt64, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
            var e: UnsafeMutablePointer<CChar>?
            _ = unsafeBitCast(sym, to: SandboxInit.self)("(version 1)(deny default)(allow sysctl-read)", 0, &e)
        }

        // 4. Record. The helper sends spec updates on stdin; EOF means stop.
        let lock = NSLock()
        var matcher = PcapMatcher(spec)
        let stop = Atomic()
        Thread.detachNewThread {
            while let line = input.next() {
                if let s = try? JSONDecoder().decode(PcapSpec.self, from: line), s.id == spec.id {
                    lock.withLock { matcher = PcapMatcher(s) }
                }
            }
            stop.set()
            pcap_breakloop(h)
        }
        let writer = PcapNGWriter(handle: FileHandle.standardOutput)
        let deadline = Date().addingTimeInterval(TimeInterval(spec.maxSeconds))
        struct Held { var meta: PktapMeta; var sec: Int; var usec: Int; var frame: [UInt8]; var length: Int }
        var flows = FlowAttribution<Held>()
        var packets = 0, lastReport = Date.distantPast
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<UInt8>?
        func write(_ h: Held, _ who: String) {
            h.frame.withUnsafeBytes {
                writer.packet(interface: h.meta.interface, dlt: h.meta.dlt, time: (h.sec, h.usec), data: $0,
                              originalLength: h.length, comment: who)
            }
            packets += 1
        }
        while !stop.isSet && Date() < deadline && writer.bytes < spec.maxBytes {
            if Date().timeIntervalSince(lastReport) > 1 {
                report(PcapProgress(packets: packets, bytes: writer.bytes))
                lastReport = Date()
            }
            let r = pcap_next_ex(h, &header, &data)
            if r == 0 { continue }
            if r < 0 { break }
            guard let header, let data else { continue }
            let caplen = Int(header.pointee.caplen)
            let raw = UnsafeRawBufferPointer(start: data, count: caplen)
            guard let meta = PktapMeta.parse(raw), meta.headerLength < caplen else { continue }
            let frame = Array(raw[meta.headerLength...])
            let ends = PacketParse.ipEndpoints(frame: frame[...], linkType: meta.dlt)
            let m = lock.withLock { matcher }
            guard m.destinationMatches(src: ends?.src, dst: ends?.dst) else { continue }
            let flow = FlowKey(frame: frame[...], linkType: meta.dlt)
            let held = Held(meta: meta, sec: Int(header.pointee.ts.tv_sec), usec: Int(header.pointee.ts.tv_usec),
                            frame: frame, length: Int(header.pointee.len) - meta.headerLength)
            let now = Double(held.sec) + Double(held.usec) / 1e6
            if m.spec.hasApp {
                for (p, who) in flows.feed(held, flow: flow, app: m.appMatches(meta), who: meta.label, now: now) { write(p, who) }
            } else {
                if meta.hasProcess { flows.learn(flow, who: meta.label, now: now) }
                write(held, meta.hasProcess ? meta.label : flows.label(flow) ?? meta.label)
            }
        }
        report(PcapProgress(packets: packets, bytes: writer.bytes))
        try? FileHandle.standardOutput.synchronize()
        pcap_close(h)
        exit(0)
    }

    final class Atomic: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func set() { lock.withLock { value = true } }
        var isSet: Bool { lock.withLock { value } }
    }

    /// Newline-delimited reads from a file handle (blocking).
    final class LineReader: @unchecked Sendable {
        private let handle: FileHandle
        private var buffer = Data()
        init(_ h: FileHandle) { handle = h }
        func next() -> Data? {
            while true {
                if let nl = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                    let line = buffer[buffer.startIndex..<nl]
                    buffer.removeSubrange(buffer.startIndex...nl)
                    return Data(line)
                }
                let chunk = handle.availableData
                if chunk.isEmpty || buffer.count > 1_000_000 { return nil }
                buffer.append(chunk)
            }
        }
    }
}
