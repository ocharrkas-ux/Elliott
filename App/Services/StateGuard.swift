import CryptoKit
import Foundation

/// Tamper evidence for Elliott's saved state. Anything running as the user can write state.json, so it's signed
/// with an HMAC key kept in the Keychain, which macOS only releases to Elliott's own code signature.
enum StateGuard {
    enum Verdict: Equatable {
        case valid
        case firstUse                 // no key and no signature yet: adopt the file and start signing
        case tampered(String)
    }

    static let account = "state-signing-key"

    static func existingKey() -> SymmetricKey? {
        Keychain.get(account).flatMap { Data(base64Encoded: $0) }.map { SymmetricKey(data: $0) }
    }

    static func createKey() -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        Keychain.set(key.withUnsafeBytes { Data($0) }.base64EncodedString(), for: account)
        return key
    }

    static func signature(_ data: Data, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
    }

    /// One file, written atomically: line 1 is the base64 HMAC, the rest is the JSON. A file starting with "{" is the
    /// older unsigned format.
    static func seal(_ json: Data, key: SymmetricKey) -> Data {
        Data(signature(json, key: key).base64EncodedString().utf8) + Data("\n".utf8) + json
    }

    static func open(_ file: Data) -> (json: Data, signature: Data?) {
        guard file.first != UInt8(ascii: "{"), let nl = file.firstIndex(of: UInt8(ascii: "\n")),
              let sig = Data(base64Encoded: file[file.startIndex..<nl]) else { return (file, nil) }
        return (file[(nl + 1)...], sig)
    }

    /// Root-owned marker written by the helper once state signing is in use.
    static let signedMarkerURL = URL(fileURLWithPath: "/Library/Application Support/Elliott/state-signed")
    static var signingEstablished: Bool { FileManager.default.fileExists(atPath: signedMarkerURL.path) }

    static func check(data: Data, signature sig: Data?, key: SymmetricKey?, established: Bool = signingEstablished) -> Verdict {
        switch (key, sig) {
        case (nil, nil):
            // Malware that deletes the key and writes an unsigned file mustn't look like a first launch.
            return established ? .tampered("the signing key and signature are both gone, but this Mac was already using signed state") : .firstUse
        case (nil, _?): return .tampered("the state is signed but the signing key is missing from the Keychain")
        case (_?, nil): return .tampered("the state's signature file was removed")
        case let (k?, s?):
            return HMAC<SHA256>.isValidAuthenticationCode(s, authenticating: data, using: k)
                ? .valid : .tampered("the state was modified outside Elliott")
        }
    }

    /// The policy the root helper last enforced (root-owned, so user-level malware can't change it).
    static let helperPolicyURL = URL(fileURLWithPath: "/Library/Application Support/Elliott/policy.json")

    static func helperPolicy() -> FilterPolicy? {
        (try? Data(contentsOf: helperPolicyURL)).flatMap { try? JSONDecoder.elliott.decode(FilterPolicy.self, from: $0) }
    }
}
