import Foundation
import Security

/// Who signed a program, for display: the developer's name from the signing certificate, not just a team ID.
struct SignerInfo: Hashable {
    enum Kind: Int, Comparable {
        case unsigned, adhoc, developer, appStore, apple
        static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    }
    var kind: Kind
    var teamID: String?
    var name: String

    /// Key for a signer rule ("apple" or the team ID); nil for ad-hoc/unsigned, which can't be trusted as a group.
    var ruleKey: String? {
        switch kind {
        case .apple: "apple"
        case .developer, .appStore: teamID
        default: nil
        }
    }

    var display: String {
        switch kind {
        case .apple: "Apple"
        case .developer: name
        case .appStore: name == teamID ? "App Store (\(teamID ?? "?"))" : "\(name) (App Store)"
        case .adhoc: "ad-hoc (unverified)"
        case .unsigned: "unsigned"
        }
    }
}

/// Resolves and caches signers by path. Certificate details are read without re-validating the whole bundle;
/// whether a signature is *valid* still comes from the filter/monitor (the team ID on the profile).
final class Signers: @unchecked Sendable {
    static let shared = Signers()
    private let lock = NSLock()
    private var cache: [String: SignerInfo] = [:]
    private var namesByTeam: [String: String] = [:]

    func info(path: String, teamID: String?, appleSigned: Bool) -> SignerInfo {
        if appleSigned { return SignerInfo(kind: .apple, teamID: nil, name: "Apple") }
        let key = "\(path)|\(teamID ?? "")"
        lock.lock()
        if let hit = cache[key] { lock.unlock(); return hit }
        lock.unlock()

        var info: SignerInfo
        if let teamID {
            let (leaf, _) = Self.leafSummary(path)
            if let leaf, leaf.hasPrefix("Apple Mac OS Application Signing") || leaf.hasPrefix("3rd Party Mac Developer") {
                // Mac App Store: Apple re-signs; the developer's name isn't in the certificate.
                info = SignerInfo(kind: .appStore, teamID: teamID, name: lock.withLock { namesByTeam[teamID] } ?? teamID)
            } else {
                let name = leaf.map(Self.developerName) ?? teamID
                info = SignerInfo(kind: .developer, teamID: teamID, name: name)
                lock.withLock { if name != teamID { namesByTeam[teamID] = name } }
            }
        } else {
            info = SignerInfo(kind: Self.hasSignature(path) ? .adhoc : .unsigned, teamID: nil, name: "")
        }
        lock.withLock { cache[key] = info }
        return info
    }

    /// "Developer ID Application: Google LLC (EQHXZ8M8AV)" → "Google LLC"
    static func developerName(_ summary: String) -> String {
        var s = summary
        if let colon = s.firstIndex(of: ":") { s = String(s[s.index(after: colon)...]) }
        if let paren = s.range(of: #"\s*\([A-Z0-9]{10}\)\s*$"#, options: .regularExpression) { s.removeSubrange(paren) }
        return s.trimmingCharacters(in: .whitespaces)
    }

    static func leafSummary(_ path: String) -> (String?, SecStaticCode?) {
        var code: SecStaticCode?
        guard path.hasPrefix("/"), SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return (nil, nil) }
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        guard let certs = (info as? [String: Any])?[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = certs.first else { return (nil, code) }
        return (SecCertificateCopySubjectSummary(leaf) as String?, code)
    }

    static func hasSignature(_ path: String) -> Bool {
        var code: SecStaticCode?
        guard path.hasPrefix("/"), SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, [], &info)
        return (info as? [String: Any])?[kSecCodeInfoIdentifier as String] != nil
    }
}

extension Profile {
    var signer: SignerInfo { Signers.shared.info(path: processPath, teamID: teamID, appleSigned: appleSigned) }
}
