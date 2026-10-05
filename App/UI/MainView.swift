import SwiftUI

enum MainSection: String, CaseIterable, Identifiable {
    case console = "connections", detections = "detections", vulns = "vulns", netscan = "net.scan", captures = "pcap", log = "live.log", rules = "rules", firewall = "palo_alto.sync"
    case netOverview = "overview", netDevices = "devices", netConnections = "all.connections", netDetections = "all.detections", netVulns = "all.vulns", netHosts = "all.hosts"
    /// The List tags rows with their id, so the id must be the same type as the selection.
    var id: MainSection { self }
    var scope: AppModel.AppScope {
        switch self {
        case .netOverview, .netDevices, .netConnections, .netDetections, .netVulns, .netHosts: .network
        default: .machine
        }
    }
    var icon: String {
        switch self {
        case .console: "network"
        case .detections: "exclamationmark.shield"
        case .vulns: "ladybug"
        case .log: "list.bullet.rectangle"
        case .rules: "checklist"
        case .firewall: "flame"
        case .netOverview: "square.grid.2x2"
        case .netDevices: "desktopcomputer.and.arrow.down"
        case .netConnections: "point.3.connected.trianglepath.dotted"
        case .netDetections: "exclamationmark.shield"
        case .netVulns: "ladybug"
        case .netscan: "dot.radiowaves.left.and.right"
        case .captures: "waveform.path.ecg.rectangle"
        case .netHosts: "server.rack"
        }
    }
}

struct MainView: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmLockdown = false

    var body: some View {
        NavigationSplitView {
            // Optional binding: the standard single-selection form for a sidebar List.
            List(MainSection.allCases.filter { $0.scope == model.scope },
                 selection: Binding<MainSection?>(get: { model.section }, set: { if let s = $0 { model.section = s } })) { s in
                Label(s.rawValue, systemImage: s.icon).tag(s)
                    .badge(s == .rules ? model.rules.count : s == .detections ? model.openFindingCount : s == .vulns ? model.openSeriousVulnCount
                           : s == .netDevices ? (model.mesh?.pendingJoins.count ?? 0) : 0)
            }
            .navigationSplitViewColumnWidth(230)
            .safeAreaInset(edge: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    GlitchText(text: "ELLIOTT")
                    HStack(spacing: 4) { PromptLine(command: "./watch --all"); BlinkingCursor() }
                    Picker("Scope", selection: Binding(get: { model.scope }, set: { s in
                        model.scope = s
                        if model.section.scope != s { model.section = s == .network ? .netOverview : .console }
                    })) {
                        ForEach(AppModel.AppScope.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented).labelsHidden()
                    if let n = model.mesh?.pendingJoins.count, n > 0 {
                        Button("\(n) device\(n == 1 ? "" : "s") waiting to join") { model.scope = .network; model.section = .netDevices }
                            .buttonStyle(.borderless).foregroundStyle(Theme.amber).font(.caption.weight(.bold))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14).padding(.vertical, 8)
                .overlay(Scanlines())
            }
            // Decoration stays off the list itself: an overlay above an AppKit-backed List can swallow its clicks.
            .safeAreaInset(edge: .bottom) { StatusPanel().padding(10).overlay(Scanlines()) }
        } detail: {
            switch model.section {
            case .console: ConsoleView()
            case .detections: DetectionsView()
            case .vulns: VulnView()
            case .log: LogView()
            case .rules: RulesView()
            case .firewall: FirewallView()
            case .netOverview: NetworkOverview()
            case .netDevices: DevicesView()
            case .netConnections: NetworkConnectionsView()
            case .netDetections: NetworkDetectionsView()
            case .netVulns: NetworkVulnsView()
            case .netscan: NetScanView()
            case .captures: CapturesView()
            case .netHosts: NetworkHostsView()
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
            if model.tamperAlert != nil {
                Text("[!] data integrity check failed").foregroundStyle(Theme.red).fontWeight(.heavy)
            }
            if model.llmServerIssue != nil {
                Text("[!] LLM paused: unknown server").foregroundStyle(Theme.red).fontWeight(.bold)
            }
            Text(model.backend == .filter ? "[+] enforcing: per-app filter"
                 : model.backend == .packetFilter ? "[+] enforcing: pf" : "[!] observe only")
                .foregroundStyle(model.enforcing ? Theme.green : Theme.amber)
            let total = max(model.profiles.count, 1)
            ProgressView(value: Double(model.analyzedCount), total: Double(total)) {
                Text("profiled \(model.analyzedCount)/\(model.profiles.count)")
            }
            Text("\(model.unclassifiedCount) unclassified").foregroundStyle(model.unclassifiedCount > 0 ? Theme.red : Theme.dim)
            Text("edr: \(model.openFindingCount) open\(model.openSeriousCount > 0 ? " (\(model.openSeriousCount) high+)" : "")")
                .foregroundStyle(model.openSeriousCount > 0 ? Theme.red : Theme.dim)
                .fontWeight(model.openSeriousCount > 0 ? .bold : .regular)
            Text(model.vulnScanning ? "vulns: scanning…" : "vulns: \(model.openSeriousVulnCount) high+\(model.newVulnIDs.isEmpty ? "" : ", \(model.newVulnIDs.count) new")\(model.openVulns.contains(where: \.kev) ? " (exploited!)" : "")")
                .foregroundStyle(model.openVulns.contains(where: \.kev) ? Theme.red : Theme.dim)
            if model.knownBadCount > 0 {
                Text("[!] \(model.knownBadCount) known-bad destinations").foregroundStyle(Theme.red).fontWeight(.bold)
            }
            let stale = model.threatIntel.staleFeeds.count
            Text("intel: \(model.threatIntel.loadedFeeds) lists · \(model.threatIntel.totalEntries.formatted()) ranges\(stale > 0 ? " · \(stale) stale" : "")")
                .foregroundStyle(stale > 0 ? Theme.amber : Theme.dim)
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
