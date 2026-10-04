import Foundation
import Security

/// Observe-only fallback while the filter extension isn't running: polls `nettop` (which sees every process's
/// sockets without root) and reports each new connection once. It can't block anything.
final class PassiveMonitor: @unchecked Sendable {
    private var task: Task<Void, Never>?
    private var seen: Set<String> = []
    private var identities: [String: (String?, String?, Bool)] = [:]   // path → signing id, team, apple

    /// Seconds between polls; shortened during packet-filter lockdown so held handshakes are noticed quickly.
    var interval: Duration = .seconds(3)

    func start(onEvents: @escaping @Sendable ([FlowEvent]) -> Void) {
        guard task == nil else { return }
        task = Task.detached(priority: .utility) { [self] in
            while !Task.isCancelled {
                let events = self.poll()
                if !events.isEmpty { onEvents(events) }
                try? await Task.sleep(for: self.interval)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    private func poll() -> [FlowEvent] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = ["-L", "1", "-n", "-x", "-J", "state"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return [] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()

        let snapshot = Self.parse(String(decoding: data, as: UTF8.self))
        var current: Set<String> = []
        var out: [FlowEvent] = []
        for c in snapshot {
            let id = "\(c.pid)|\(c.proto)|\(c.local)|\(c.remote)"
            current.insert(id)
            guard !seen.contains(id) else { continue }
            let path = Self.path(for: c.pid) ?? c.name
            let (sid, team, apple) = identity(path)
            out.append(FlowEvent(pid: c.pid, processPath: path, signingID: sid, teamID: team, appleSigned: apple,
                                 direction: c.inbound ? .inbound : .outbound, proto: c.proto,
                                 localAddress: c.localAddr, localPort: c.localPort,
                                 remoteAddress: c.remoteAddr, remotePort: c.remotePort,
                                 remoteHostname: DNSCache.shared.name(for: c.remoteAddr),
                                 outcome: c.synSent ? .pending : .observed))
        }
        seen = current
        return out
    }

    struct Conn {
        var name: String, pid: Int32, proto: Proto
        var local: String, remote: String
        var localAddr: String, localPort: Int, remoteAddr: String, remotePort: Int
        var inbound: Bool
        var synSent = false
    }

    /// Parses `nettop -L 1 -n -x -J state` CSV: a "name.pid" line, then that process's sockets.
    static func parse(_ text: String) -> [Conn] {
        var out: [Conn] = []
        var name = "", pid: Int32 = 0
        var listening: [Int32: Set<Int>] = [:]
        var pendingConns: [Conn] = []
        for line in text.split(separator: "\n").dropFirst() {
            let cols = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard let first = cols.first, !first.isEmpty else { continue }
            let state = cols.count > 1 ? cols[1] : ""
            if first.hasPrefix("tcp") || first.hasPrefix("udp") {
                let parts = first.split(separator: " ", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let ends = parts[1].components(separatedBy: "<->")
                guard ends.count == 2, let l = endpoint(ends[0]), let r = endpoint(ends[1]) else { continue }
                if state == "Listen" || r.addr == "*" {
                    listening[pid, default: []].insert(l.port)
                    continue
                }
                if r.addr.hasPrefix("127.") || r.addr == "::1" { continue }
                pendingConns.append(Conn(name: name, pid: pid, proto: first.hasPrefix("tcp") ? .tcp : .udp,
                                         local: ends[0], remote: ends[1], localAddr: l.addr, localPort: l.port,
                                         remoteAddr: r.addr, remotePort: r.port, inbound: false,
                                         synSent: state == "SynSent"))
            } else if let dot = first.lastIndex(of: "."), let p = Int32(first[first.index(after: dot)...]) {
                name = String(first[..<dot]); pid = p
            }
        }
        for var c in pendingConns {
            // A socket on a port its process also listens on was accepted, i.e. inbound.
            c.inbound = c.proto == .tcp && listening[c.pid]?.contains(c.localPort) == true
            out.append(c)
        }
        return out
    }

    /// "192.168.1.2:443", "fe80::1%en0.443", "*:*", "*.*"
    static func endpoint(_ s: String) -> (addr: String, port: Int)? {
        if s.hasPrefix("*") { return ("*", Int(s.dropFirst(2)) ?? 0) }
        let sep: Character = s.contains("::") || s.filter({ $0 == ":" }).count > 1 ? "." : ":"
        guard let i = s.lastIndex(of: sep) else { return nil }
        var addr = String(s[..<i])
        if let pct = addr.firstIndex(of: "%") { addr = String(addr[..<pct]) }
        return (addr, Int(s[s.index(after: i)...]) ?? 0)
    }

    static func path(for pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
    }

    private func identity(_ path: String) -> (String?, String?, Bool) {
        if let hit = identities[path] { return hit }
        let result = Self.staticIdentity(path)
        identities[path] = result
        return result
    }

    static func staticIdentity(_ path: String) -> (String?, String?, Bool) {
        var code: SecStaticCode?
        guard path.hasPrefix("/"),
              SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), nil) == errSecSuccess
        else { return (nil, nil, false) }
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = info as? [String: Any] ?? [:]
        var req: SecRequirement?
        SecRequirementCreateWithString("anchor apple" as CFString, [], &req)
        let apple = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), req) == errSecSuccess
        return (dict[kSecCodeInfoIdentifier as String] as? String, dict[kSecCodeInfoTeamIdentifier as String] as? String, apple)
    }
}
