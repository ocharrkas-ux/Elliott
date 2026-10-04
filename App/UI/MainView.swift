import SwiftUI

struct MainView: View {
    enum Section: String, CaseIterable, Identifiable {
        case console = "connections", log = "live.log", rules = "rules", firewall = "palo_alto.sync"
        var id: String { rawValue }
        var icon: String {
            switch self {
            case .console: "network"
            case .log: "list.bullet.rectangle"
            case .rules: "checklist"
            case .firewall: "flame"
            }
        }
    }

    @EnvironmentObject var model: AppModel
    @State private var section: Section = .console
    @State private var confirmLockdown = false

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.icon).tag(s)
                    .badge(s == .rules ? model.rules.count : 0)
            }
            .navigationSplitViewColumnWidth(230)
            .safeAreaInset(edge: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    GlitchText(text: "BASTION")
                    HStack(spacing: 4) { PromptLine(command: "./watch --all"); BlinkingCursor() }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14).padding(.vertical, 8)
            }
            .safeAreaInset(edge: .bottom) { StatusPanel().padding(10) }
            .overlay(Scanlines())
        } detail: {
            switch section {
            case .console: ConsoleView()
            case .log: LogView()
            case .rules: RulesView()
            case .firewall: FirewallView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Toggle(isOn: Binding(get: { model.settings.lockdown }, set: { on in
                    if on && model.unclassifiedCount > 0 { confirmLockdown = true } else { model.setLockdown(on) }
                })) {
                    Label(model.settings.lockdown ? "LOCKDOWN: ON" : "LOCKDOWN: OFF",
                          systemImage: model.settings.lockdown ? "lock.fill" : "lock.open")
                }
                .toggleStyle(.button)
                .tint(model.settings.lockdown ? .red : nil)
                .disabled(!model.enforcing)
                .help(model.enforcing ? "In lockdown, connections without a rule wait for your approval"
                                      : "Lockdown needs the packet filter helper (Settings → Filter)")
            }
        }
        .sheet(isPresented: $confirmLockdown) { LockdownSheet() }
    }
}

struct StatusPanel: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(model.backend == .filter ? "[+] enforcing: per-app filter"
                 : model.backend == .packetFilter ? "[+] enforcing: pf" : "[!] observe only")
                .foregroundStyle(model.enforcing ? Theme.green : Theme.amber)
            let total = max(model.profiles.count, 1)
            ProgressView(value: Double(model.analyzedCount), total: Double(total)) {
                Text("profiled \(model.analyzedCount)/\(model.profiles.count)")
            }
            Text("\(model.unclassifiedCount) unclassified").foregroundStyle(model.unclassifiedCount > 0 ? Theme.red : Theme.dim)
            if model.knownBadCount > 0 {
                Text("[!] \(model.knownBadCount) known-bad destinations").foregroundStyle(Theme.red).fontWeight(.bold)
            }
            Text("intel: \(model.threatIntel.loadedFeeds) lists · \(model.threatIntel.totalEntries.formatted()) ranges")
                .foregroundStyle(Theme.dim)
            Text(model.canSuggest ? "advisor: \(model.suggestionCount) suggestions"
                 : "advisor: learning \(model.decisions.count)/\(Advisor.minimumDecisions)")
                .foregroundStyle(Theme.dim)
            Text("> " + model.llmStatus).foregroundStyle(Theme.dim).lineLimit(2)
        }
        .font(.caption)
    }
}

struct LockdownSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var maxRisk = 30.0

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            GlitchText(text: "ENTER LOCKDOWN?")
            Text("\(model.unclassifiedCount) connections haven't been classified. In lockdown, any connection without an allow rule is paused until you approve it (or denied after \(Int(model.settings.approvalTimeout)) seconds).")
            if model.settings.trustAppleSigned {
                Text("Apple-signed system software is let through without asking (change in Settings).").foregroundStyle(.secondary)
            }
            GroupBox {
                VStack(alignment: .leading) {
                    Text("Allow the unclassified connections with risk ≤ \(Int(maxRisk)) first")
                    Slider(value: $maxRisk, in: 0...100, step: 5)
                    let n = model.profiles.values.filter { model.decision(for: $0) == nil && $0.riskScore <= Int(maxRisk) }.count
                    Text("\(n) would be allowed").foregroundStyle(.secondary)
                }.padding(4)
            }
            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button("Lock Down Without Allowing") { model.setLockdown(true); dismiss() }
                Button("Allow & Lock Down") {
                    _ = model.allowUnclassified(maxRisk: Int(maxRisk))
                    model.setLockdown(true)
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}
