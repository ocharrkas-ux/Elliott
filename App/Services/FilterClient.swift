import Foundation
import NetworkExtension
import SystemExtensions
import os

private let log = Logger(subsystem: ElliottIDs.appBundleID, category: "filter-client")

/// Installs/enables the content-filter system extension and talks to it over XPC.
@MainActor
final class FilterClient: NSObject, ObservableObject {
    enum State: Equatable {
        case unknown, notInstalled, awaitingApproval, installing, disabled, enabled, failed(String)
        var label: String {
            switch self {
            case .unknown: "Checking…"
            case .notInstalled: "Filter not installed"
            case .awaitingApproval: "Allow the extension in System Settings → General → Login Items & Extensions"
            case .installing: "Installing filter…"
            case .disabled: "Filter installed but off"
            case .enabled: "Filter active"
            case .failed(let m): "Filter error: \(m)"
            }
        }
    }

    @Published private(set) var state: State = .unknown
    @Published private(set) var connected = false

    var onEvents: (([FlowEvent]) -> Void)?
    var onApproval: ((ApprovalRequest) -> Void)?
    var onConnected: (() -> Void)?

    private var connection: NSXPCConnection?
    private lazy var receiver = Receiver(owner: self)

    func refresh() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if manager.providerConfiguration == nil { state = .notInstalled; return }
            state = manager.isEnabled ? .enabled : .disabled
            if manager.isEnabled { connect() }
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    /// Activates the system extension (first time: the user approves it in System Settings), then enables the filter.
    func install() {
        state = .installing
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: ElliottIDs.filterBundleID,
                                                                 queue: .main)
        request.delegate = receiver
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func setEnabled(_ on: Bool) async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if manager.providerConfiguration == nil {
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true
                config.filterPackets = false
                manager.providerConfiguration = config
                manager.localizedDescription = "Elliott"
            }
            manager.isEnabled = on
            try await manager.saveToPreferences()
            state = on ? .enabled : .disabled
            if on { connect() } else { disconnect() }
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    fileprivate func extensionActivated() { Task { await setEnabled(true) } }
    fileprivate func extensionNeedsApproval() { state = .awaitingApproval }
    fileprivate func extensionFailed(_ error: Error) { state = .failed(error.localizedDescription) }

    // MARK: XPC

    private func connect() {
        guard connection == nil else { return }
        let c = NSXPCConnection(machServiceName: ElliottIDs.machService, options: [])
        c.setCodeSigningRequirement(ElliottIDs.requirement(for: ElliottIDs.filterBundleID))
        c.remoteObjectInterface = NSXPCInterface(with: FilterXPC.self)
        c.exportedInterface = NSXPCInterface(with: AppXPC.self)
        c.exportedObject = receiver
        c.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.connection = nil
                self?.connected = false
                // The extension restarts on upgrade/reboot; try again shortly.
                try? await Task.sleep(for: .seconds(3))
                if self?.state == .enabled { self?.connect() }
            }
        }
        c.interruptionHandler = { [weak self] in Task { @MainActor in self?.connected = false } }
        c.resume()
        connection = c
        proxy?.hello { [weak self] data in
            let backlog = (try? JSONDecoder.elliott.decode([FlowEvent].self, from: data)) ?? []
            Task { @MainActor in
                guard let self else { return }
                self.connected = true
                self.onConnected?()
                if !backlog.isEmpty { self.onEvents?(backlog) }
            }
        }
    }

    private func disconnect() {
        connection?.invalidate()
        connection = nil
        connected = false
    }

    private var proxy: FilterXPC? {
        connection?.remoteObjectProxyWithErrorHandler { error in
            log.error("filter proxy: \(error.localizedDescription)")
        } as? FilterXPC
    }

    func push(_ policy: FilterPolicy) {
        guard let data = try? JSONEncoder.elliott.encode(policy) else { return }
        proxy?.setPolicy(data) { ok in if !ok { log.error("filter rejected policy") } }
    }

    func resolve(_ keyID: String, allow: Bool) {
        proxy?.resolve(keyID: keyID, allow: allow)
    }

    /// Bridges XPC callbacks and system-extension delegate calls (which arrive off the main actor).
    private final class Receiver: NSObject, AppXPC, OSSystemExtensionRequestDelegate {
        weak var owner: FilterClient?
        init(owner: FilterClient) { self.owner = owner }

        func flowsSeen(_ events: Data) {
            guard let list = try? JSONDecoder.elliott.decode([FlowEvent].self, from: events) else { return }
            Task { @MainActor in self.owner?.onEvents?(list) }
        }

        func approvalNeeded(_ request: Data) {
            guard let r = try? JSONDecoder.elliott.decode(ApprovalRequest.self, from: request) else { return }
            Task { @MainActor in self.owner?.onApproval?(r) }
        }

        func request(_ request: OSSystemExtensionRequest,
                     actionForReplacingExtension existing: OSSystemExtensionProperties,
                     withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
            .replace
        }

        func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
            Task { @MainActor in self.owner?.extensionNeedsApproval() }
        }

        func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
            Task { @MainActor in self.owner?.extensionActivated() }
        }

        func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
            Task { @MainActor in self.owner?.extensionFailed(error) }
        }
    }
}
