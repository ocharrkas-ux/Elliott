import SwiftUI

@main
struct BastionApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Bastion", id: "main") {
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
        Button("Quit Bastion") { NSApp.terminate(nil) }
    }
}
