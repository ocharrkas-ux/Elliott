import Foundation

/// One signed fact about membership: `node` was admitted to (or removed from) the network by `by`.
struct MemberEntry: Codable, Hashable, Sendable {
    var node: NodeInfo
    var networkID: UUID
    var by: UUID                 // admitting (or removing) member; the founder admits itself
    var at: Date
    var removed = false
    var signature = Data()

    var signedBytes: Data {
        var d = Data("ELLIOTT-MEMBER-v1".utf8)
        d += withUnsafeBytes(of: networkID.uuid) { Data($0) } + withUnsafeBytes(of: node.id.uuid) { Data($0) }
        d += Data(node.name.utf8) + Data([0]) + node.publicKey + withUnsafeBytes(of: by.uuid) { Data($0) }
        d += withUnsafeBytes(of: at.timeIntervalSince1970.bitPattern.bigEndian) { Data($0) } + Data([removed ? 1 : 0])
        return d
    }

    static func signed(node: NodeInfo, networkID: UUID, by signer: NodeIdentity, removed: Bool = false, at: Date = Date()) throws -> MemberEntry {
        // Whole seconds: signed timestamps must survive any date encoding unchanged.
        var e = MemberEntry(node: node, networkID: networkID, by: signer.id, at: at.wholeSeconds, removed: removed)
        e.signature = try signer.sign(e.signedBytes)
        return e
    }
}

/// The network's roster. Every entry is signed; an entry only counts if its signer was a valid member at the time.
/// Only the recorded founder may sign for itself, so a member can't mint a second "founder" and admit nodes alone.
struct Membership: Codable, Hashable, Sendable {
    var networkID: UUID
    var name: String
    var founder: UUID
    var entries: [MemberEntry] = []

    static func found(name: String, by identity: NodeIdentity) throws -> Membership {
        let id = UUID()
        return Membership(networkID: id, name: name, founder: identity.id,
                          entries: [try MemberEntry.signed(node: identity.info, networkID: id, by: identity)])
    }

    /// Replays entries in time order. Entries in the same second (common: timestamps are whole seconds) are
    /// re-tried until nothing changes, so an admission is never judged before its admitter is in.
    static func replay(_ entries: [MemberEntry], networkID: UUID, founder: UUID) -> (members: [UUID: NodeInfo], valid: [MemberEntry]) {
        var current: [UUID: NodeInfo] = [:]
        var valid: [MemberEntry] = []
        let groups = Dictionary(grouping: entries.filter { $0.networkID == networkID }, by: \.at).sorted { $0.key < $1.key }
        for (_, group) in groups {
            var pending = group.sorted { $0.node.id.uuidString < $1.node.id.uuidString }
            var progress = true
            while progress && !pending.isEmpty {
                progress = false
                for (i, e) in pending.enumerated().reversed() {
                    let signer: NodeInfo?
                    if e.by == e.node.id {
                        signer = (e.node.id == founder && !e.removed && current.isEmpty && valid.isEmpty) ? e.node : nil
                    } else {
                        signer = current[e.by]
                    }
                    guard let signer, signer.verify(e.signature, over: e.signedBytes) else { continue }
                    if e.removed { current[e.node.id] = nil } else { current[e.node.id] = e.node }
                    valid.append(e)
                    pending.remove(at: i)
                    progress = true
                }
            }
        }
        return (current, valid)
    }

    /// Current members (node id → info).
    var members: [UUID: NodeInfo] { Self.replay(entries, networkID: networkID, founder: founder).members }

    func isMember(_ node: NodeInfo) -> Bool { members[node.id]?.publicKey == node.publicKey }

    /// Adds entries from a peer's roster, keeping only ones that are valid in sequence (junk can't accumulate).
    mutating func merge(_ other: Membership) -> Bool {
        guard other.networkID == networkID, other.founder == founder else { return false }
        let before = Set(entries)
        entries = Self.replay(Array(before.union(other.entries)), networkID: networkID, founder: founder).valid
        return Set(entries) != before
    }
}
