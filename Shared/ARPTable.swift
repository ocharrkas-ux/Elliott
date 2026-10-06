import Foundation

/// The kernel's ARP table (IP → MAC) via sysctl, as `arp -an` reads it. Recent macOS only returns it to root,
/// so the app asks the helper and falls back to reading it itself.
enum ARPTable {
    static func read() -> [String: String] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
        var size = 0
        guard sysctl(&mib, 6, nil, &size, nil, 0) == 0, size > 0 else { return [:] }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 6, &buf, &size, nil, 0) == 0 else { return [:] }
        var out: [String: String] = [:]
        var off = 0
        while off + MemoryLayout<rt_msghdr>.size <= size {
            let msgLen = buf.withUnsafeBytes { Int($0.loadUnaligned(fromByteOffset: off, as: rt_msghdr.self).rtm_msglen) }
            guard msgLen > 0 else { break }
            let sinOff = off + MemoryLayout<rt_msghdr>.size
            if sinOff + MemoryLayout<sockaddr_in>.size <= min(size, off + msgLen) {
                let sin = buf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sinOff, as: sockaddr_in.self) }
                let sinLen = Int(sin.sin_len)
                let dlOff = sinOff + (sinLen > 0 ? ((sinLen + 3) & ~3) : 4)   // sockaddr_dl follows, 4-byte aligned
                if sin.sin_family == UInt8(AF_INET), dlOff + 8 <= min(size, off + msgLen) {
                    let nlen = Int(buf[dlOff + 5]), alen = Int(buf[dlOff + 6])
                    let macStart = dlOff + 8 + nlen
                    if alen == 6, macStart + 6 <= min(size, off + msgLen) {
                        var a = sin.sin_addr
                        var ip = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                        inet_ntop(AF_INET, &a, &ip, socklen_t(ip.count))
                        out[String(cString: ip)] = buf[macStart..<(macStart + 6)].map { String($0, radix: 16) }.joined(separator: ":")
                    }
                }
            }
            off += msgLen
        }
        return out
    }

}
