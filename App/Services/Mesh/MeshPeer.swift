import Foundation
import Network

/// One connection to another Elliott node: handshake first (plaintext but signed), then encrypted, length-framed
/// MeshMessages. Nothing but a valid handshake is ever parsed from an unauthenticated peer.
final class MeshPeer: @unchecked Sendable {
    enum Role { case initiator, responder }

    let connection: NWConnection
    let role: Role
    private let queue = DispatchQueue(label: "elliott.mesh.peer")
    private(set) var remote: NodeInfo?
    private(set) var purpose: ConnectPurpose = .member
    private(set) var keys: Handshake.Keys?
    private var channel: SecureChannel?
    private var closed = false
    let opened = Date()

    /// Responder: may this (verified) hello proceed?
    var admitHello: (@Sendable (Handshake.Hello) -> Bool)?
    /// Initiator: is this (verified) responder who we meant to reach?
    var admitReply: (@Sendable (Handshake.Reply) -> Bool)?
    var onReady: (@Sendable (MeshPeer) -> Void)?
    var onMessage: (@Sendable (MeshPeer, MeshMessage) -> Void)?
    var onClose: (@Sendable (MeshPeer, String?) -> Void)?

    init(connection: NWConnection, role: Role) {
        self.connection = connection
        self.role = role
    }

    var remoteHost: String? {
        if case .hostPort(let h, _) = connection.endpoint { return "\(h)".components(separatedBy: "%")[0] }
        return nil
    }

    // MARK: Lifecycle

    func startInitiator(identity: NodeIdentity, purpose: ConnectPurpose, networkID: UUID?) {
        self.purpose = purpose
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                do {
                    let (hello, eph) = try Handshake.hello(identity: identity, purpose: purpose, networkID: networkID)
                    self.write(try MeshCodec.encode(hello))
                    self.readFrame(limit: MeshCodec.maxHandshakeFrame) { data in
                        guard let data, let reply = try? MeshCodec.decode(Handshake.Reply.self, data) else { return self.close("no handshake reply") }
                        do {
                            let keys = try Handshake.finish(hello: hello, reply: reply, ephemeral: eph)
                            guard self.admitReply?(reply) ?? false else { return self.close("peer not admitted") }
                            self.established(keys: keys, remote: reply.node)
                        } catch {
                            self.close(error.localizedDescription)
                        }
                    }
                } catch {
                    self.close(error.localizedDescription)
                }
            case .failed(let e): self.close(e.localizedDescription)
            case .cancelled: self.close(nil)
            default: break
            }
        }
        armHandshakeTimeout()
        connection.start(queue: queue)
    }

    func startResponder(identity: NodeIdentity) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.readFrame(limit: MeshCodec.maxHandshakeFrame) { data in
                    guard let data, let hello = try? MeshCodec.decode(Handshake.Hello.self, data) else { return self.close("bad hello") }
                    do {
                        let (reply, keys) = try Handshake.reply(to: hello, identity: identity)   // verifies the signature
                        guard self.admitHello?(hello) ?? false else { return self.close("not admitted") }
                        self.purpose = hello.purpose
                        self.write(try MeshCodec.encode(reply))
                        self.established(keys: keys, remote: hello.node)
                    } catch {
                        self.close(error.localizedDescription)
                    }
                }
            case .failed(let e): self.close(e.localizedDescription)
            case .cancelled: self.close(nil)
            default: break
            }
        }
        armHandshakeTimeout()
        connection.start(queue: queue)
    }

    private func armHandshakeTimeout() {
        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            if let self, self.channel == nil { self.close("handshake timed out") }
        }
    }

    private func established(keys: Handshake.Keys, remote: NodeInfo) {
        self.keys = keys
        self.remote = remote
        channel = SecureChannel(keys: keys)
        onReady?(self)
        receiveLoop()
    }

    func send(_ message: MeshMessage) {
        queue.async { [weak self] in
            guard let self, let channel = self.channel, !self.closed else { return }
            do {
                let sealed = try channel.seal(try MeshCodec.encode(message))
                self.write(sealed)
                if channel.needsRekey { self.close("rekey") }   // reconnect for fresh keys
            } catch {
                self.close("encrypt failed")
            }
        }
    }

    func close(_ reason: String?) {
        guard !closed else { return }
        closed = true
        connection.cancel()
        onClose?(self, reason)
    }

    // MARK: Framing

    private func write(_ payload: Data) {
        connection.send(content: MeshCodec.frame(payload), completion: .contentProcessed { [weak self] e in
            if let e { self?.close(e.localizedDescription) }
        })
    }

    private func readFrame(limit: Int, _ done: @escaping (Data?) -> Void) {
        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] head, _, _, err in
            guard let self, err == nil, let head, head.count == 4 else { return done(nil) }
            let len = Int(head.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian)
            guard len > 0, len <= limit else { return done(nil) }
            self.connection.receive(minimumIncompleteLength: len, maximumLength: len) { body, _, _, err in
                guard err == nil, let body, body.count == len else { return done(nil) }
                done(body)
            }
        }
    }

    private func receiveLoop() {
        readFrame(limit: MeshCodec.maxFrame) { [weak self] data in
            guard let self, let channel = self.channel else { return }
            guard let data else { return self.close("connection closed") }
            do {
                let message = try MeshCodec.decode(MeshMessage.self, try channel.open(data))
                self.onMessage?(self, message)
                self.receiveLoop()
            } catch {
                self.close("bad record: \(error.localizedDescription)")
            }
        }
    }
}
