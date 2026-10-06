import SwiftUI

/// macOS security posture: a score, each check with its fix, privacy permissions and browser extensions.
struct PostureView: View {
    @EnvironmentObject var model: AppModel
    @ObservedObject var store: SecurityStore
    enum Tab: String, CaseIterable, Identifiable { case checks = "Checks", privacy = "Privacy permissions", extensions = "Browser extensions"; var id: String { rawValue } }
    @State private var tab: Tab = .checks
    @State private var riskyOnly = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Picker("", selection: $tab) { ForEach(Tab.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().padding(.horizontal, 16).padding(.bottom, 8)
            Divider()
            if let r = store.posture {
                switch tab {
                case .checks: checks(r)
                case .privacy: privacy(r)
                case .extensions: extensions(r)
                }
            } else {
                ContentUnavailableView(store.postureRunning ? "auditing…" : "not audited yet", systemImage: "checkmark.shield",
                                       description: Text("Checks updates, encryption, Gatekeeper, sharing services, login, accounts, profiles, trusted certificates, backups, privacy permissions and browser extensions."))
            }
        }
        .toolbar {
            ToolbarItem {
                Button(store.postureRunning ? "Auditing…" : "Run Audit") { Task { await model.runPostureAudit() } }
                    .disabled(store.postureRunning)
            }
        }
        .navigationTitle("posture")
    }

    private var header: some View {
        HStack(spacing: 16) {
            let score = store.posture?.score
            ZStack {
                Circle().stroke(Theme.dim.opacity(0.3), lineWidth: 6)
                Circle().trim(from: 0, to: Double(score ?? 0) / 100)
                    .stroke(color(score), style: StrokeStyle(lineWidth: 6, lineCap: .round)).rotationEffect(.degrees(-90))
                Text(score.map(String.init) ?? "–").font(.title2.weight(.heavy).monospacedDigit())
            }
            .frame(width: 64, height: 64)
            VStack(alignment: .leading, spacing: 4) {
                Text("Security posture").font(.headline)
                if let r = store.posture {
                    let fails = r.checks.filter { $0.status == .fail }.count, warns = r.checks.filter { $0.status == .warn }.count
                    Text("\(fails) failing · \(warns) to review · \(r.checks.filter { $0.status == .pass }.count) passing").foregroundStyle(Theme.dim)
                    Text("Audited \(r.date.formatted(.relative(presentation: .named)))").font(.caption).foregroundStyle(Theme.dim)
                }
            }
            Spacer()
        }
        .padding(16)
    }

    private func color(_ score: Int?) -> Color {
        guard let s = score else { return Theme.dim }
        return s >= 85 ? Theme.green : s >= 65 ? Theme.amber : Theme.red
    }

    private func checks(_ r: PostureReport) -> some View {
        List {
            ForEach(Array(Dictionary(grouping: r.checks, by: \.area).sorted { $0.key < $1.key }), id: \.key) { area, checks in
                Section(area) {
                    ForEach(checks.sorted { order($0.status) < order($1.status) }) { c in
                        HStack(alignment: .top, spacing: 10) {
                            icon(c.status).frame(width: 18)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(c.title).fontWeight(.semibold)
                                Text(c.detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                                if c.status == .fail || c.status == .warn, let fix = c.fix {
                                    Text("Fix: \(fix)").font(.caption).foregroundStyle(Theme.amber).textSelection(.enabled)
                                }
                            }
                            Spacer()
                            if let s = c.settings, c.status != .pass, let url = URL(string: s) {
                                Button("Open Settings") { NSWorkspace.shared.open(url) }.buttonStyle(.link).font(.caption)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
        }
    }

    private func order(_ s: PostureCheck.Status) -> Int { [.fail: 0, .warn: 1, .unknown: 2, .pass: 3][s] ?? 4 }

    @ViewBuilder private func icon(_ s: PostureCheck.Status) -> some View {
        switch s {
        case .pass: Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.green)
        case .warn: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.amber)
        case .fail: Image(systemName: "xmark.octagon.fill").foregroundStyle(Theme.red)
        case .unknown: Image(systemName: "questionmark.circle").foregroundStyle(Theme.dim)
        }
    }

    @ViewBuilder private func privacy(_ r: PostureReport) -> some View {
        if !r.grantsReadable {
            ContentUnavailableView {
                Label("Elliott needs Full Disk Access", systemImage: "lock.shield")
            } description: {
                Text("macOS keeps the privacy-permission database (which apps can record the screen, read keystrokes, read every file…) behind Full Disk Access. Grant it to Elliott, then run the audit again.")
            } actions: {
                Button("Open Full Disk Access Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles")!)
                }
            }
        } else {
            let rows = r.grants.filter { $0.allowed && (!riskyOnly || $0.risky || $0.sensitive) }
            VStack(spacing: 0) {
                Toggle("Sensitive permissions only", isOn: $riskyOnly).padding(.horizontal, 16).padding(.vertical, 6).frame(maxWidth: .infinity, alignment: .trailing)
                Table(rows) {
                    TableColumn("Permission") { g in
                        HStack {
                            if g.risky { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.red) }
                            Text(g.label).fontWeight(g.sensitive ? .semibold : .regular)
                        }
                    }.width(min: 150, ideal: 190)
                    TableColumn("App") { g in
                        VStack(alignment: .leading) {
                            Text(((g.path ?? g.client) as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: ""))
                            Text(g.client).font(.caption).foregroundStyle(Theme.dim).lineLimit(1)
                        }
                    }.width(min: 180, ideal: 260)
                    TableColumn("Signed by") { g in Text(g.signer).foregroundStyle(g.risky ? Theme.red : .secondary).lineLimit(1) }.width(min: 120, ideal: 200)
                    TableColumn("Scope") { Text($0.systemWide ? "system" : "this user").foregroundStyle(Theme.dim) }.width(80)
                    TableColumn("Granted") { g in Text(g.modified.map(Ago.text) ?? "—").foregroundStyle(Theme.dim) }.width(90)
                }
            }
        }
    }

    private func extensions(_ r: PostureReport) -> some View {
        Table(r.extensions) {
            TableColumn("Extension") { e in
                VStack(alignment: .leading) {
                    Text(e.name).fontWeight(.semibold)
                    Text("\(e.id) · \(e.version)").font(.caption).foregroundStyle(Theme.dim).lineLimit(1)
                }
            }.width(min: 180, ideal: 260)
            TableColumn("Browser") { Text($0.browser) }.width(min: 80, ideal: 120)
            TableColumn("Source") { e in Text(e.fromStore ? "store" : "sideloaded").foregroundStyle(e.fromStore ? Theme.dim : Theme.amber) }.width(90)
            TableColumn("Powerful permissions") { e in
                Text(e.risky.isEmpty ? "—" : e.risky.joined(separator: ", ")).font(.caption).foregroundStyle(e.risky.isEmpty ? Theme.dim : Theme.amber).lineLimit(2)
            }
        }
        .overlay { if r.extensions.isEmpty { ContentUnavailableView("no browser extensions found", systemImage: "puzzlepiece.extension") } }
    }
}
