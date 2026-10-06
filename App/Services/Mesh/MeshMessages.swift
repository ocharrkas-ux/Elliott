import CryptoKit
import Foundation

/// A rule as shared across the network. Signed by the node that last changed it, so a node relaying it can't
/// alter it. Addresses are node-local (each Mac learns its own IPs) and aren't part of the shared rule.
struct SharedRule: Codable, Hashable, Sendable {
    var rule: Rule
    var deleted = false
    var version: Date
    var origin: UUID
    var signature = Data()

    /// What's shared and signed: no node-local addresses, timestamps in whole seconds (so they survive any date
    /// encoding unchanged).
    static func canonical(_ r: Rule) -> Rule {
        var c = r
        c.addresses = []
        c.created = r.created.wholeSeconds
        c.expires = r.expires?.wholeSeconds
        return c
    }

    var signedBytes: Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        enc.dateEncodingStrategy = .secondsSince1970
        let body = (try? enc.encode(SharedRule.canonical(rule))) ?? Data()
        return Data("ELLIOTT-RULE-v1".utf8) + body + Data([deleted ? 1 : 0])
            + withUnsafeBytes(of: version.timeIntervalSince1970.bitPattern.bigEndian) { Data($0) }
            + withUnsafeBytes(of: origin.uuid) { Data($0) }
    }

    static func make(_ rule: Rule, deleted: Bool = false, by identity: NodeIdentity, at: Date = Date()) throws -> SharedRule {
        var s = SharedRule(rule: canonical(rule), deleted: deleted, version: at.wholeSeconds, origin: identity.id)
        s.signature = try identity.sign(s.signedBytes)
        return s
    }

    /// Last writer wins; ties broken by node id so every node picks the same winner.
    func isNewer(than other: SharedRule) -> Bool {
        (version, origin.uuidString) > (other.version, other.origin.uuidString)
    }
}

extension Date {
    var wholeSeconds: Date { Date(timeIntervalSince1970: timeIntervalSince1970.rounded(.down)) }
}

/// What a node knows about itself, for the network view.
struct NodeReport: Codable, Sendable {
    var node: NodeInfo
    var generated = Date()
    var hostname: String
    var os: String
    var enforcement: String
    var lockdown: Bool
    var profiles: [Profile]
    var findings: [Finding]
    var vulnFindings: [VulnFinding]
    var componentCount: Int
    var decisionCount: Int
    var scanHosts: [ScannedHost]? = nil
    /// The node's own IPs (to recognize one device connecting to another).
    var addresses: [String]? = nil
}

/// Load and capacity, for deciding where LLM work runs.
struct NodeStatus: Codable, Hashable, Sendable {
    var node: UUID
    var time = Date()
    var chip: String
    var memoryGB: Double
    var cpuCores: Int
    var cpuLoad: Double          // 1-minute load average / cores
    var gpuUtilization: Int?     // %, from IOAccelerator
    var llmModels: [String]      // models the node's LLM server offers (empty = no local LLM)
    var llmQueue: Int
    var acceptsLLMWork: Bool
    /// Elliott build this node runs (CFBundleVersion), so outdated nodes can be spotted.
    var appBuild: String? = nil
    var appCommit: String? = nil
}

enum MeshMessage: Codable, Sendable {
    case joinPending(sas: String)
    case joinApproved(Membership)
    case joinRejected(String)
    case membership(Membership)
    case rules([SharedRule])
    case report(Data)            // zlib-compressed NodeReport JSON
    case status(NodeStatus)
    case llmRequest(id: UUID, system: String, user: String, schema: Data)
    case llmResponse(id: UUID, content: String?, error: String?)
    case ping, pong
}

enum MeshCodec {
    static let maxFrame = 32 * 1024 * 1024
    static let maxHandshakeFrame = 64 * 1024

    static func encode<T: Encodable>(_ v: T) throws -> Data {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .secondsSince1970   // lossless, unlike ISO 8601 without fractions
        return try e.encode(v)
    }

    static func decode<T: Decodable>(_ t: T.Type, _ d: Data) throws -> T {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        return try dec.decode(t, from: d)
    }

    static func frame(_ payload: Data) -> Data {
        withUnsafeBytes(of: UInt32(payload.count).bigEndian) { Data($0) } + payload
    }

    static func compress(_ d: Data) -> Data { (try? (d as NSData).compressed(using: .zlib) as Data) ?? d }
    static func decompress(_ d: Data) -> Data? { try? (d as NSData).decompressed(using: .zlib) as Data }
}
