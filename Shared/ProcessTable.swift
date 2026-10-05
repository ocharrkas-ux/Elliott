import Darwin
import Foundation

/// One running process. Shared by the app (unprivileged snapshot) and the helper (root snapshot, which can read
/// every process's arguments).
struct ProcInfo: Codable, Hashable, Identifiable, Sendable {
    var pid: Int32
    var ppid: Int32
    var uid: UInt32
    var start: Date
    var name: String
    var path: String
    var args: [String]?
    var id: Int32 { pid }

    var commandLine: String? { args.map { $0.joined(separator: " ") } }
    var displayName: String { path.isEmpty ? name : (path as NSString).lastPathComponent }
}

enum ProcessTable {
    /// Every process from the kernel's process table. Arguments are only readable for the caller's own processes
    /// unless running as root.
    static func snapshot(withArgs: Bool) -> [ProcInfo] {
        snapshot { pid, _ in (path(pid) ?? "", withArgs ? arguments(pid) : nil) }
    }

    /// The process list with path and arguments from `details` (lets callers cache them per process).
    static func snapshot(details: (Int32, Date) -> (String, [String]?)) -> [ProcInfo] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        size += size / 8   // the table can grow between the two calls
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return [] }
        let n = size / MemoryLayout<kinfo_proc>.stride

        var out: [ProcInfo] = []
        out.reserveCapacity(n)
        for kp in procs.prefix(n) {
            let pid = kp.kp_proc.p_pid
            guard pid > 0 else { continue }
            let comm = withUnsafeBytes(of: kp.kp_proc.p_comm) { raw in
                String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
            }
            let tv = kp.kp_proc.p_un.__p_starttime
            let start = Date(timeIntervalSince1970: Double(tv.tv_sec) + Double(tv.tv_usec) / 1e6)
            let (path, args) = details(pid, start)
            out.append(ProcInfo(pid: pid, ppid: kp.kp_eproc.e_ppid, uid: kp.kp_eproc.e_ucred.cr_uid,
                                start: start, name: comm, path: path, args: args))
        }
        return out
    }

    /// When `pid` started, or nil if no such process. Process ids get reused, so (pid, start time) is what
    /// identifies one process.
    static func startTime(_ pid: Int32) -> Date? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var kp = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &kp, &size, nil, 0) == 0, size > 0, kp.kp_proc.p_pid == pid else { return nil }
        let tv = kp.kp_proc.p_un.__p_starttime
        return Date(timeIntervalSince1970: Double(tv.tv_sec) + Double(tv.tv_usec) / 1e6)
    }

    /// True if `pid` is still the same process that started at `start` (to within a millisecond).
    static func isSameProcess(_ pid: Int32, startedAt start: Date) -> Bool {
        guard let now = startTime(pid) else { return false }
        return abs(now.timeIntervalSince(start)) < 0.001
    }

    static func path(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
    }

    /// argv from KERN_PROCARGS2: [argc: Int32][exec path\0][padding \0s][argv[0]\0 … argv[argc-1]\0][env…]
    static func arguments(_ pid: Int32) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: Int(argmax))
        mib = [CTL_KERN, KERN_PROCARGS2, pid]
        size = buf.count
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        let argc = buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var i = MemoryLayout<Int32>.size
        while i < size && buf[i] != 0 { i += 1 }     // exec path
        while i < size && buf[i] == 0 { i += 1 }     // padding
        var args: [String] = []
        while args.count < argc && i < size {
            let start = i
            while i < size && buf[i] != 0 { i += 1 }
            args.append(String(decoding: buf[start..<i], as: UTF8.self))
            i += 1
        }
        return args
    }

    static func userName(_ uid: UInt32) -> String {
        guard let pw = getpwuid(uid) else { return "\(uid)" }
        return String(cString: pw.pointee.pw_name)
    }

    /// Total CPU time used so far, in seconds (nil if not readable).
    static func cpuSeconds(_ pid: Int32) -> Double? {
        var info = rusage_info_v2()
        let ok = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V2, $0) }
        }
        guard ok == 0 else { return nil }
        var tb = mach_timebase_info_data_t()
        mach_timebase_info(&tb)
        let ticks = Double(info.ri_user_time + info.ri_system_time)
        return ticks * Double(tb.numer) / Double(tb.denom) / 1e9
    }
}

/// Process snapshots that read each process's path and arguments once (polled every few seconds, almost every
/// process is unchanged; reading ~800 argument vectors each time is most of the cost).
final class ProcessSnapshotCache: @unchecked Sendable {
    private let lock = NSLock()
    private var cache: [Int32: (start: Date, path: String, args: [String]?)] = [:]

    func snapshot(withArgs: Bool) -> [ProcInfo] {
        lock.withLock {
            var next: [Int32: (start: Date, path: String, args: [String]?)] = [:]
            let procs = ProcessTable.snapshot { pid, start in
                if let c = cache[pid], c.start == start, !c.path.isEmpty, !withArgs || c.args != nil {
                    next[pid] = c
                    return (c.path, withArgs ? c.args : nil)
                }
                let d = (start: start, path: ProcessTable.path(pid) ?? "", args: withArgs ? ProcessTable.arguments(pid) : nil)
                next[pid] = d
                return (d.path, d.args)
            }
            cache = next   // exited processes drop out
            return procs
        }
    }
}
