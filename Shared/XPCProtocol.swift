import Foundation

/// Exported by the filter extension (runs as root). Only the signed Bastion app may connect.
@objc protocol FilterXPC {
    /// Registers the caller for callbacks. Replies with the JSON events buffered while no app was connected.
    func hello(reply: @escaping (Data) -> Void)
    /// Replaces the enforced policy (JSON `FilterPolicy`).
    func setPolicy(_ policy: Data, reply: @escaping (Bool) -> Void)
    /// Answers a pending approval: resumes every connection paused on that key.
    func resolve(keyID: String, allow: Bool)
}

/// Exported by the app so the filter can call back.
@objc protocol AppXPC {
    /// JSON `[FlowEvent]`, batched.
    func flowsSeen(_ events: Data)
    /// JSON `ApprovalRequest`.
    func approvalNeeded(_ request: Data)
}
