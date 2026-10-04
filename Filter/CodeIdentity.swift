import Foundation
import Security

/// Who opened a flow, from its audit token. A signing identifier is only reported when the signature checks out.
struct CodeIdentity {
    var pid: Int32 = 0
    var path: String
    var signingID: String?
    var teamID: String?
    var appleSigned = false

    private static let lock = NSLock()
    private static var cache: [Data: CodeIdentity] = [:]   // audit tokens are unique per process instance
    private static let appleRequirement: SecRequirement? = {
        var r: SecRequirement?
        SecRequirementCreateWithString("anchor apple" as CFString, [], &r)
        return r
    }()

    static func inspect(_ token: Data) -> CodeIdentity {
        lock.lock()
        if let hit = cache[token] { lock.unlock(); return hit }
        lock.unlock()

        var id = CodeIdentity(path: "unknown")
        if token.count == MemoryLayout<audit_token_t>.size {
            id.pid = Int32(bitPattern: token.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }.val.5)
        }
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: token] as CFDictionary
        if SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code {
            var staticCode: SecStaticCode?
            if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode {
                var url: CFURL?
                if SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url {
                    id.path = (url as URL).path
                }
                if SecCodeCheckValidity(code, [], nil) == errSecSuccess {
                    var info: CFDictionary?
                    SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
                    let dict = info as? [String: Any] ?? [:]
                    id.signingID = dict[kSecCodeInfoIdentifier as String] as? String
                    id.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
                    id.appleSigned = SecCodeCheckValidity(code, [], appleRequirement) == errSecSuccess
                }
            }
        }
        if id.path == "unknown", id.pid > 0 {
            var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            if proc_pidpath(id.pid, &buf, UInt32(buf.count)) > 0 { id.path = String(cString: buf) }
        }

        lock.lock()
        if cache.count > 4000 { cache.removeAll() }
        cache[token] = id
        lock.unlock()
        return id
    }
}
