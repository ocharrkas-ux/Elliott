import ServiceManagement
import SwiftUI

/// Closing the window leaves Elliott running in the menu bar, so filtering, EDR and scheduled checks continue.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

/// "Open at login" via SMAppService (the user can also manage it in System Settings → General → Login Items).
@MainActor
final class LoginItem: ObservableObject {
    @Published private(set) var status = SMAppService.mainApp.status
    @Published private(set) var error: String?
    var enabled: Bool { status == .enabled }

    func set(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        status = SMAppService.mainApp.status
        if status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
    }
}

@main
struct ElliottApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Elliott", id: "main") {
            MainView()
                .environmentObject(model)
                .frame(minWidth: 1000, minHeight: 600)
                .hackerTheme()
                .containerBackground(Theme.background, for: .window)
        }
        .defaultSize(width: 1280, height: 780)

        MenuBarExtra {
            MenuBarMenu().environmentObject(model)
        } label: {
            Image(systemName: model.settings.lockdown ? "lock.shield.fill" : "terminal")
        }

        Settings {
            SettingsView().environmentObject(model).hackerTheme()
        }
    }
}

struct MenuBarMenu: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.backend == .filter ? "[+] enforcing: per-app filter" : model.backend == .packetFilter ? "[+] enforcing: pf" : "[!] observe only")
        Text("\(model.profiles.count) connections · \(model.unclassifiedCount) unclassified")
        if !model.approvals.isEmpty {
            Button("\(model.approvals.count) waiting for approval…") { ApprovalPanel.shared.show(model: model) }
        }
        Divider()
        Toggle("LOCKDOWN", isOn: Binding(get: { model.settings.lockdown }, set: { model.setLockdown($0) }))
            .disabled(!model.enforcing)
        Button("Open Console") {
            openWindow(id: "main")
            NSApp.activate()
        }
        SettingsLink { Text("Settings…") }
        Divider()
        Button("Quit Elliott") { NSApp.terminate(nil) }
    }
}
