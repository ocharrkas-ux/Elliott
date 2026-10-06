import CryptoKit
import Foundation

/// The parts of a TLS ClientHello that identify the client software (JA3 / JA4 fingerprints).
/// Parsed from untrusted bytes: every read is bounds-checked.
struct ClientHello: Equatable {
    var legacyVersion: Int
    var ciphers: [Int]
    var extensions: [Int]          // in order sent
    var serverName: String?
    var alpn: [String]
    var groups: [Int]              // supported_groups (elliptic curves)
    var pointFormats: [Int]
    var signatureAlgorithms: [Int]
    var supportedVersions: [Int]

    static func isGREASE(_ v: Int) -> Bool { v & 0x0F0F == 0x0A0A && (v >> 8) == (v & 0xFF) }

    /// Parses a complete TLS record containing a ClientHello.
    static func parse(_ data: [UInt8]) -> ClientHello? {
        let b = data
        func u8(_ i: Int) -> Int? { i >= 0 && i < b.count ? Int(b[i]) : nil }
        func u16(_ i: Int) -> Int? { guard let h = u8(i), let l = u8(i + 1) else { return nil }; return h << 8 | l }
        guard u8(0) == 0x16, u8(5) == 0x01, let recLen = u16(3), b.count >= 5 + recLen else { return nil }
        guard let version = u16(9) else { return nil }
        var i = 11 + 32
        guard let sid = u8(i) else { return nil }
        i += 1 + sid
        guard let csLen = u16(i), csLen % 2 == 0, i + 2 + csLen <= b.count else { return nil }
        var ciphers: [Int] = []
        for k in stride(from: i + 2, to: i + 2 + csLen, by: 2) { if let c = u16(k) { ciphers.append(c) } }
        i += 2 + csLen
        guard let comp = u8(i) else { return nil }
        i += 1 + comp
        var hello = ClientHello(legacyVersion: version, ciphers: ciphers, extensions: [], serverName: nil, alpn: [],
                                groups: [], pointFormats: [], signatureAlgorithms: [], supportedVersions: [])
        guard let extLen = u16(i) else { return hello }   // no extensions
        i += 2
        let end = min(i + extLen, b.count)
        while i + 4 <= end {
            guard let type = u16(i), let len = u16(i + 2), i + 4 + len <= end else { return nil }
            let body = i + 4
            hello.extensions.append(type)
            func list16(_ start: Int, _ count: Int) -> [Int] {
                stride(from: start, to: start + count - 1, by: 2).compactMap { u16($0) }
            }
            switch type {
            case 0x0000:   // server_name
                if let nl = u16(body + 3), u8(body + 2) == 0, body + 5 + nl <= b.count, nl > 0, nl <= 253 {
                    hello.serverName = String(decoding: b[(body + 5)..<(body + 5 + nl)], as: UTF8.self).lowercased()
                }
            case 0x0010:   // ALPN
                if let total = u16(body) {
                    var k = body + 2
                    while k < body + 2 + total, let l = u8(k), k + 1 + l <= b.count {
                        hello.alpn.append(String(decoding: b[(k + 1)..<(k + 1 + l)], as: UTF8.self))
                        k += 1 + l
                    }
                }
            case 0x000A:   // supported_groups
                if let l = u16(body) { hello.groups = list16(body + 2, l) }
            case 0x000B:   // ec_point_formats
                if let l = u8(body) { hello.pointFormats = (0..<l).compactMap { u8(body + 1 + $0) } }
            case 0x000D:   // signature_algorithms
                if let l = u16(body) { hello.signatureAlgorithms = list16(body + 2, l) }
            case 0x002B:   // supported_versions
                if let l = u8(body) { hello.supportedVersions = list16(body + 1, l) }
            default: break
            }
            i = body + len
        }
        return hello
    }

    /// JA3: "version,ciphers,extensions,curves,point formats" (decimal, dash-joined, GREASE removed), and its MD5.
    var ja3String: String {
        func j(_ v: [Int]) -> String { v.filter { !Self.isGREASE($0) }.map(String.init).joined(separator: "-") }
        return "\(legacyVersion),\(j(ciphers)),\(j(extensions)),\(j(groups)),\(j(pointFormats))"
    }
    var ja3: String { Insecure.MD5.hash(data: Data(ja3String.utf8)).map { String(format: "%02x", $0) }.joined() }

    /// JA4 (FoxIO): e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1".
    var ja4: String {
        let c = ciphers.filter { !Self.isGREASE($0) }
        let e = extensions.filter { !Self.isGREASE($0) }
        let highest = supportedVersions.filter { !Self.isGREASE($0) }.max() ?? legacyVersion
        let ver: String = switch highest {
        case 0x0304: "13"; case 0x0303: "12"; case 0x0302: "11"; case 0x0301: "10"; case 0x0300: "s3"; default: "00"
        }
        let alpnPart: String = {
            guard let first = alpn.first, let f = first.unicodeScalars.first, let l = first.unicodeScalars.last else { return "00" }
            let alnum = { (u: Unicode.Scalar) in CharacterSet.alphanumerics.contains(u) && u.isASCII }
            if alnum(f) && alnum(l) { return "\(Character(f))\(Character(l))" }
            let bytes = Array(first.utf8)
            return String(format: "%x%x", (bytes.first ?? 0) >> 4, (bytes.last ?? 0) & 0xF)
        }()
        let a = "t\(ver)\(serverName == nil ? "i" : "d")\(String(format: "%02d", min(c.count, 99)))\(String(format: "%02d", min(e.count, 99)))\(alpnPart)"
        func hex4(_ v: Int) -> String { String(format: "%04x", v) }
        func trunc(_ s: String) -> String {
            s.isEmpty ? "000000000000" : String(SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined().prefix(12))
        }
        let bPart = trunc(c.map(hex4).sorted().joined(separator: ","))
        let exts = e.filter { $0 != 0x0000 && $0 != 0x0010 }.map(hex4).sorted().joined(separator: ",")
        let sigs = signatureAlgorithms.filter { !Self.isGREASE($0) }.map(hex4).joined(separator: ",")
        let cPart = trunc(sigs.isEmpty ? exts : exts + "_" + sigs)
        return "\(a)_\(bPart)_\(cPart)"
    }
}
