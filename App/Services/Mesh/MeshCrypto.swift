import CryptoKit
import Foundation

/// A node's public identity: who it is and the ML-DSA-65 key that proves it.
struct NodeInfo: Codable, Hashable, Identifiable, Sendable {
    var id: UUID
    var name: String
    var publicKey: Data          // ML-DSA-65 public key

    /// Short, human-comparable key fingerprint.
    var fingerprint: String {
        SHA256.hash(data: publicKey).prefix(8).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    func verify(_ signature: Data, over data: Data) -> Bool {
        (try? MLDSA65.PublicKey(rawRepresentation: publicKey))?.isValidSignature(signature, for: data) ?? false
    }
}

/// This node's long-term identity. The ML-DSA-65 signing seed lives in the Keychain (only Elliott can read it).
final class NodeIdentity: @unchecked Sendable {
    let id: UUID
    private(set) var name: String
    private let key: MLDSA65.PrivateKey

    var info: NodeInfo { NodeInfo(id: id, name: name, publicKey: key.publicKey.rawRepresentation) }

    init(id: UUID, name: String, key: MLDSA65.PrivateKey) {
        self.id = id; self.name = name; self.key = key
    }

    func sign(_ data: Data) throws -> Data { try key.signature(for: data) }
    func rename(_ n: String) { name = n }

    /// Loads (or creates on first use) the identity stored under `account`.
    static func loadOrCreate(account: String = "mesh-identity", name: String) throws -> NodeIdentity {
        if let stored = Keychain.get(account), let data = Data(base64Encoded: stored),
           let obj = try? JSONDecoder().decode(Stored.self, from: data) {
            return NodeIdentity(id: obj.id, name: name, key: try MLDSA65.PrivateKey(seedRepresentation: obj.seed, publicKey: nil))
        }
        let key = try MLDSA65.PrivateKey()
        let id = UUID()
        Keychain.set(try JSONEncoder().encode(Stored(id: id, seed: key.seedRepresentation)).base64EncodedString(), for: account)
        return NodeIdentity(id: id, name: name, key: key)
    }

    /// For tests: an identity that never touches the Keychain.
    static func ephemeral(name: String) throws -> NodeIdentity { NodeIdentity(id: UUID(), name: name, key: try MLDSA65.PrivateKey()) }

    private struct Stored: Codable { var id: UUID; var seed: Data }
}

enum ConnectPurpose: String, Codable, Sendable { case member, join }

/// Mutually authenticated, post-quantum key agreement:
///   initiator → Hello  (identity, X-Wing ephemeral public key, nonce, time, purpose), ML-DSA signed
///   responder → Reply  (identity, X-Wing ciphertext encapsulated to that ephemeral key, nonce), ML-DSA signed over
///                       the whole transcript
/// Both derive per-direction AES-256 keys with HKDF over the X-Wing shared secret, salted with the transcript hash.
/// The ephemeral key gives forward secrecy; X-Wing (ML-KEM-768 + X25519) is secure if either half holds.
enum Handshake {
    static let version = 1
    static let maxAge: Double = 120

    struct Hello: Codable, Sendable {
        var version = Handshake.version
        var node: NodeInfo
        var ephemeral: Data
        var nonce: Data
        var time: Double
        var purpose: ConnectPurpose
        var networkID: UUID?
        var signature = Data()

        var signedBytes: Data {
            var d = Data("ELLIOTT-HELLO-v1".utf8)
            d += withUnsafeBytes(of: node.id.uuid) { Data($0) } + Data(node.name.utf8) + Data([0]) + node.publicKey
            d += ephemeral + nonce + withUnsafeBytes(of: time.bitPattern.bigEndian) { Data($0) }
            d += Data(purpose.rawValue.utf8) + (networkID.map { withUnsafeBytes(of: $0.uuid) { Data($0) } } ?? Data())
            return d
        }
    }

    struct Reply: Codable, Sendable {
        var node: NodeInfo
        var encapsulated: Data
        var nonce: Data
        var signature = Data()

        func signedBytes(hello: Hello) -> Data {
            var d = Data("ELLIOTT-REPLY-v1".utf8) + hello.signedBytes + hello.signature
            d += withUnsafeBytes(of: node.id.uuid) { Data($0) } + Data(node.name.utf8) + Data([0]) + node.publicKey
            return d + encapsulated + nonce
        }
    }

    struct Keys: Sendable {
        var send: SymmetricKey
        var receive: SymmetricKey
        var transcript: Data
        /// Six digits both people compare when a node asks to join. An attacker in the middle would run two
        /// different handshakes, so the two screens would show different codes.
        var sas: String {
            let h = SHA256.hash(data: Data("ELLIOTT-SAS-v1".utf8) + transcript)
            let n = h.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } % 1_000_000
            return String(format: "%03d %03d", n / 1000, n % 1000)
        }
    }

    enum Failure: Error, LocalizedError {
        case badSignature, stale, badVersion, crypto(String)
        var errorDescription: String? {
            switch self {
            case .badSignature: "handshake signature didn't verify"
            case .stale: "handshake too old (clock skew or replay)"
            case .badVersion: "unsupported protocol version"
            case .crypto(let s): "crypto: \(s)"
            }
        }
    }

    static func random(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }

    /// Initiator, step 1.
    static func hello(identity: NodeIdentity, purpose: ConnectPurpose, networkID: UUID?) throws -> (Hello, XWingMLKEM768X25519.PrivateKey) {
        let eph = try XWingMLKEM768X25519.PrivateKey.generate()
        var h = Hello(node: identity.info, ephemeral: eph.publicKey.rawRepresentation, nonce: random(32),
                      time: Date().timeIntervalSince1970, purpose: purpose, networkID: networkID)
        h.signature = try identity.sign(h.signedBytes)
        return (h, eph)
    }

    /// Responder: verify the hello, encapsulate to its ephemeral key, sign the transcript.
    static func reply(to hello: Hello, identity: NodeIdentity, now: Date = Date()) throws -> (Reply, Keys) {
        guard hello.version == version else { throw Failure.badVersion }
        guard abs(now.timeIntervalSince1970 - hello.time) <= maxAge else { throw Failure.stale }
        guard hello.node.verify(hello.signature, over: hello.signedBytes) else { throw Failure.badSignature }
        let pub: XWingMLKEM768X25519.PublicKey
        do { pub = try XWingMLKEM768X25519.PublicKey(rawRepresentation: hello.ephemeral) } catch { throw Failure.crypto("bad ephemeral key") }
        let enc = try pub.encapsulate()
        var r = Reply(node: identity.info, encapsulated: enc.encapsulated, nonce: random(32))
        r.signature = try identity.sign(r.signedBytes(hello: hello))
        let transcript = Data(SHA256.hash(data: r.signedBytes(hello: hello) + r.signature))
        return (r, derive(enc.sharedSecret, transcript: transcript, initiator: false))
    }

    /// Initiator, step 2: verify the reply and derive the same keys.
    static func finish(hello: Hello, reply: Reply, ephemeral: XWingMLKEM768X25519.PrivateKey) throws -> Keys {
        guard reply.node.verify(reply.signature, over: reply.signedBytes(hello: hello)) else { throw Failure.badSignature }
        let secret: SymmetricKey
        do { secret = try ephemeral.decapsulate(reply.encapsulated) } catch { throw Failure.crypto("decapsulation failed") }
        let transcript = Data(SHA256.hash(data: reply.signedBytes(hello: hello) + reply.signature))
        return derive(secret, transcript: transcript, initiator: true)
    }

    static func derive(_ secret: SymmetricKey, transcript: Data, initiator: Bool) -> Keys {
        let i2r = HKDF<SHA256>.deriveKey(inputKeyMaterial: secret, salt: transcript, info: Data("elliott/v1/i2r".utf8), outputByteCount: 32)
        let r2i = HKDF<SHA256>.deriveKey(inputKeyMaterial: secret, salt: transcript, info: Data("elliott/v1/r2i".utf8), outputByteCount: 32)
        return Keys(send: initiator ? i2r : r2i, receive: initiator ? r2i : i2r, transcript: transcript)
    }
}

/// AES-256-GCM records with per-direction keys and strictly increasing counters as nonces: a replayed, dropped or
/// reordered record fails authentication.
final class SecureChannel: @unchecked Sendable {
    private let sendKey: SymmetricKey
    private let receiveKey: SymmetricKey
    private var sendCounter: UInt64 = 0
    private var receiveCounter: UInt64 = 0
    private let lock = NSLock()
    /// Re-key (reconnect) well before counters or key usage get large.
    static let maxRecords: UInt64 = 1 << 24

    init(keys: Handshake.Keys) { sendKey = keys.send; receiveKey = keys.receive }

    var needsRekey: Bool { lock.withLock { sendCounter > Self.maxRecords || receiveCounter > Self.maxRecords } }

    private static func nonce(_ n: UInt64) -> AES.GCM.Nonce {
        try! AES.GCM.Nonce(data: Data(repeating: 0, count: 4) + withUnsafeBytes(of: n.bigEndian) { Data($0) })
    }

    func seal(_ plaintext: Data) throws -> Data {
        let n: UInt64 = lock.withLock { defer { sendCounter += 1 }; return sendCounter }
        return try AES.GCM.seal(plaintext, using: sendKey, nonce: Self.nonce(n)).combined!
    }

    func open(_ record: Data) throws -> Data {
        let n: UInt64 = lock.withLock { defer { receiveCounter += 1 }; return receiveCounter }
        let box = try AES.GCM.SealedBox(combined: record)
        guard box.nonce.withUnsafeBytes({ Data($0) }) == Self.nonce(n).withUnsafeBytes({ Data($0) }) else {
            throw Handshake.Failure.crypto("out-of-order record")
        }
        return try AES.GCM.open(box, using: receiveKey)
    }
}
