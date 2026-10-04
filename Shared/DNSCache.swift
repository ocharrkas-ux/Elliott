import Foundation

/// IP → hostname, learned from DNS responses. Many apps resolve names themselves and connect by IP, so this is
/// how a flow to 142.250.72.14 gets shown (and ruled) as www.google.com.
final class DNSCache: @unchecked Sendable {
    static let shared = DNSCache()

    private let lock = NSLock()
    private var names: [String: (name: String, expires: Date)] = [:]

    func name(for address: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard let hit = names[address], hit.expires > Date() else { return nil }
        return hit.name
    }

    func remember(_ address: String, name: String, ttl: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        if names.count > 50_000 { names = names.filter { $0.value.expires > Date() } }
        // Keep at least an hour: connections often outlive short TTLs.
        names[address] = (name, Date().addingTimeInterval(max(ttl, 3600)))
    }

    /// Parses a DNS response (UDP payload) and records its A/AAAA answers under the queried name.
    func ingest(response: Data) {
        for (address, name, ttl) in DNSCache.parse(response) { remember(address, name: name, ttl: ttl) }
    }

    static func parse(_ data: Data) -> [(String, String, TimeInterval)] {
        let b = [UInt8](data)
        guard b.count >= 12, b[2] & 0x80 != 0 else { return [] }   // must be a response
        let qd = Int(b[4]) << 8 | Int(b[5]), an = Int(b[6]) << 8 | Int(b[7])
        var i = 12
        var question: String?
        for _ in 0..<qd {
            guard let (name, next) = readName(b, i), next + 4 <= b.count else { return [] }
            question = question ?? name
            i = next + 4
        }
        var out: [(String, String, TimeInterval)] = []
        for _ in 0..<an {
            guard let (name, next) = readName(b, i), next + 10 <= b.count else { break }
            let type = Int(b[next]) << 8 | Int(b[next + 1])
            let ttl = TimeInterval(UInt32(b[next + 4]) << 24 | UInt32(b[next + 5]) << 16 | UInt32(b[next + 6]) << 8 | UInt32(b[next + 7]))
            let len = Int(b[next + 8]) << 8 | Int(b[next + 9])
            let rdata = next + 10
            guard rdata + len <= b.count else { break }
            let label = (question ?? name).lowercased()
            if type == 1, len == 4 {
                out.append((b[rdata..<rdata + 4].map(String.init).joined(separator: "."), label, ttl))
            } else if type == 28, len == 16 {
                var addr = in6_addr()
                withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: b[rdata..<rdata + 16]) }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)) != nil {
                    out.append((String(cString: buf), label, ttl))
                }
            }
            i = rdata + len
        }
        return out
    }

    /// Reads a (possibly compressed) name at `start`; returns it and the offset just past it.
    private static func readName(_ b: [UInt8], _ start: Int) -> (String, Int)? {
        var labels: [String] = []
        var i = start, end: Int?, hops = 0
        while i < b.count {
            let len = Int(b[i])
            if len == 0 { return (labels.joined(separator: "."), end ?? i + 1) }
            if len & 0xC0 == 0xC0 {
                guard i + 1 < b.count, hops < 16 else { return nil }
                if end == nil { end = i + 2 }
                i = (len & 0x3F) << 8 | Int(b[i + 1]); hops += 1
                continue
            }
            guard i + 1 + len <= b.count else { return nil }
            labels.append(String(decoding: b[(i + 1)...(i + len)], as: UTF8.self))
            i += 1 + len
        }
        return nil
    }
}
