import Foundation
import ServiceManagement
import os

private let log = Logger(subsystem: ElliottIDs.appBundleID, category: "helper-client")

/// Registers the privileged pf helper (SMAppService) and sends it the policy.
@MainActor
final class HelperClient: ObservableObject {
    @Published private(set) var status: SMAppService.Status = .notRegistered
    @Published private(set) var connected = false
    @Published private(set) var lastError: String?

    private let service = SMAppService.daemon(plistName: "\(ElliottIDs.helperLabel).plist")
    private var connection: NSXPCConnection?
    private var pingTask: Task<Void, Never>?

    var statusLabel: String {
        switch status {
        case .enabled: connected ? "Packet filter helper running" : "Helper enabled, starting…"
        case .requiresApproval: "Allow “Elliott” in System Settings → General → Login Items & Extensions"
        case .notRegistered: "Packet filter helper not installed"
        case .notFound: "Helper missing from the app bundle"
        @unknown default: "Unknown helper state"
        }
    }

    func start() {
        status = service.status
        pingTask?.cancel()
        pingTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.status = self.service.status
                if self.status == .enabled && !self.connected { await self.connect() }
                try? await Task.sleep(for: .seconds(self.connected ? 15 : 3))
            }
        }
    }

    func install() {
        do {
            try service.register()
        } catch {
            lastError = error.localizedDescription
        }
        status = service.status
        if status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
    }

    func uninstall() async {
        _ = await clear()
        try? await service.unregister()
        connection?.invalidate()
        connection = nil
        connected = false
        status = service.status
    }

    private func connect() async {
        if connection == nil {
            let c = NSXPCConnection(machServiceName: ElliottIDs.helperLabel, options: .privileged)
            c.setCodeSigningRequirement(ElliottIDs.requirement(for: ElliottIDs.helperLabel))
            c.remoteObjectInterface = NSXPCInterface(with: HelperXPC.self)
            c.invalidationHandler = { [weak self] in
                Task { @MainActor in self?.connection = nil; self?.connected = false }
            }
            c.interruptionHandler = { [weak self] in Task { @MainActor in self?.connected = false } }
            c.resume()
            connection = c
        }
        let ok: Bool = await withCheckedContinuation { cont in
            let once = Once<Bool>(cont)
            let proxy = connection?.remoteObjectProxyWithErrorHandler { _ in once.resume(false) } as? HelperXPC
            guard let proxy else { return once.resume(false) }
            proxy.ping { _ in once.resume(true) }
        }
        if ok && !connected { onConnected?() }
        connected = ok
    }

    var onConnected: (() -> Void)?

    func push(_ policy: FilterPolicy) {
        guard let data = try? JSONEncoder.elliott.encode(policy),
              let proxy = connection?.remoteObjectProxyWithErrorHandler({ e in log.error("helper: \(e.localizedDescription)") }) as? HelperXPC
        else { return }
        proxy.apply(policy: data) { err in
            Task { @MainActor in self.lastError = err }
        }
    }

    /// Root's view of every process (with arguments), or nil if the helper isn't available.
    func processes() async -> [ProcInfo]? {
        guard connected, connection != nil else { return nil }
        let data: Data? = await withCheckedContinuation { cont in
            let once = Once<Data?>(cont)
            let proxy = connection?.remoteObjectProxyWithErrorHandler { _ in once.resume(nil) } as? HelperXPC
            guard let proxy else { return once.resume(nil) }
            proxy.processes { once.resume($0) }
        }
        return data.flatMap { try? JSONDecoder.elliott.decode([ProcInfo].self, from: $0) }
    }

    func setNameCapture(_ on: Bool) async -> Bool {
        guard connected, connection != nil else { return false }
        return await withCheckedContinuation { cont in
            let once = Once<Bool>(cont)
            let proxy = connection?.remoteObjectProxyWithErrorHandler { _ in once.resume(false) } as? HelperXPC
            guard let proxy else { return once.resume(false) }
            proxy.setNameCapture(on) { once.resume($0) }
        }
    }

    func names(since cursor: Double) async -> NameBatch? {
        guard connected, connection != nil else { return nil }
        let data: Data? = await withCheckedContinuation { cont in
            let once = Once<Data?>(cont)
            let proxy = connection?.remoteObjectProxyWithErrorHandler { _ in once.resume(nil) } as? HelperXPC
            guard let proxy else { return once.resume(nil) }
            proxy.names(since: cursor) { once.resume($0) }
        }
        return data.flatMap { try? JSONDecoder.elliott.decode(NameBatch.self, from: $0) }
    }

    func terminate(pid: Int32, startedAt: Date) async -> String? {
        guard connection != nil else { return "helper not connected" }
        return await withCheckedContinuation { cont in
            let once = Once<String?>(cont)
            let proxy = connection?.remoteObjectProxyWithErrorHandler { e in once.resume(e.localizedDescription) } as? HelperXPC
            proxy?.terminate(pid: pid, startedAt: startedAt.timeIntervalSince1970) { once.resume($0) }
        }
    }

    func clear() async -> String? {
        guard connection != nil else { return nil }
        return await withCheckedContinuation { cont in
            let once = Once<String?>(cont)
            let proxy = connection?.remoteObjectProxyWithErrorHandler { e in once.resume(e.localizedDescription) } as? HelperXPC
            proxy?.clear { once.resume($0) }
        }
    }

    /// XPC may call the error handler and the reply; resume only once.
    private final class Once<T>: @unchecked Sendable {
        private var cont: CheckedContinuation<T, Never>?
        private let lock = NSLock()
        init(_ c: CheckedContinuation<T, Never>) { cont = c }
        func resume(_ v: T) {
            lock.lock(); let c = cont; cont = nil; lock.unlock()
            c?.resume(returning: v)
        }
    }
}
