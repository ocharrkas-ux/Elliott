import SwiftUI

extension Severity {
    var color: Color {
        switch self {
        case .info: Theme.dim
        case .low: .yellow.opacity(0.8)
        case .medium: Theme.amber
        case .high: Color(red: 1, green: 0.35, blue: 0.2)
        case .critical: Theme.red
        }
    }
}

struct SeverityBadge: View {
    var severity: Severity
    var body: some View {
        Text(severity.label)
            .font(.caption.weight(.heavy))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .foregroundStyle(severity >= .high ? .white : .black)
            .background(severity.color, in: RoundedRectangle(cornerRadius: 4))
    }
}

struct AssessmentLabel: View {
    var triage: Triage?
    var pending: Bool
    var body: some View {
        if let t = triage {
            let color: Color = t.assessment.contains("malicious") ? Theme.red : t.assessment.contains("benign") ? Theme.green : Theme.amber
            Text("\(t.assessment) \(t.confidence)%").foregroundStyle(color).lineLimit(1)
        } else {
            Text(pending ? "triaging…" : "—").foregroundStyle(Theme.dim)
        }
    }
}

struct FindingRow: Identifiable {
    var f: Finding
    var id: UUID { f.id }
    var severity: Int { f.severity.rawValue }
    var title: String { f.title }
    var target: String { f.target }
    var mitre: String { f.mitre.joined(separator: " ") }
    var lastSeen: Date { f.lastSeen }
    var count: Int { f.count }
    var assessment: String { f.triage?.assessment ?? "" }
}

struct DetectionsView: View {
    enum Tab: String, CaseIterable, Identifiable { case findings, processes; var id: String { rawValue } }
    enum Show: String, CaseIterable, Identifiable {
        case open, acknowledged, benign, all
        var id: String { rawValue }
    }

    @EnvironmentObject var model: AppModel
    @State private var tab: Tab = .findings
    @State private var show: Show = .open
    @State private var minSeverity: Severity = .low
    @State private var search = ""
    @State private var selection: Set<UUID> = []
    @State private var sortOrder = [KeyPathComparator(\FindingRow.severity, order: .reverse)]
    @State private var showInspector = true

    private func rows() -> [FindingRow] {
        let q = search.lowercased()
        return model.findings.filter { f in
            switch show {
            case .open: if f.status != .open { return false }
            case .acknowledged: if f.status != .acknowledged { return false }
            case .benign: if f.status != .benign { return false }
            case .all: break
            }
            guard f.severity >= minSeverity else { return false }
            return q.isEmpty || [f.title, f.detail, f.path ?? "", f.commandLine ?? "", f.mitre.joined(separator: " ")]
                .contains { $0.lowercased().contains(q) }
        }.map(FindingRow.init).sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            switch tab {
            case .findings: findingsTable
            case .processes: ProcessesTable(store: model.processStore)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Title, path, command line, MITRE ID")
        .toolbar {
            ToolbarItem {
                Button { model.edr.rescanNow() } label: { Label("Rescan Persistence", systemImage: "arrow.clockwise") }
                    .help("Re-check launch agents/daemons, cron, login hook, shell profiles and security settings now")
            }
            ToolbarItem {
                Button("Clear All Detections") { clearAll() }
                    .disabled(model.findings.isEmpty)
                    .help("Erase every detection (ones marked benign stay silenced)")
            }
            ToolbarItem {
                Button { showInspector.toggle() } label: { Label("Details", systemImage: "sidebar.right") }
            }
        }
        .navigationTitle("detections")
    }

    private var header: some View {
        let open = model.openFindings
        return HStack(spacing: 16) {
            ForEach([Severity.critical, .high, .medium, .low], id: \.self) { sev in
                let n = open.filter { $0.severity == sev }.count
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("\(n)").font(.title2.weight(.heavy)).monospacedDigit().foregroundStyle(n > 0 ? sev.color : Theme.dim)
                    Text(sev.label.lowercased()).foregroundStyle(Theme.dim)
                }
            }
            Spacer()
            if tab == .findings {
                Picker("Status", selection: $show) { ForEach(Show.allCases) { Text($0.rawValue).tag($0) } }
                    .labelsHidden().frame(width: 130)
                Picker("Minimum", selection: $minSeverity) {
                    ForEach(Severity.allCases) { Text("≥ \($0.label.lowercased())").tag($0) }
                }
                .labelsHidden().frame(width: 120)
            }
            Picker("View", selection: $tab) { ForEach(Tab.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().frame(width: 200)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    private var findingsTable: some View {
        let rows = rows()
        return Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Severity", value: \.severity) { SeverityBadge(severity: $0.f.severity) }.width(80)
            TableColumn("Detection", value: \.title) { r in
                Text(r.title).lineLimit(1).fontWeight(r.f.severity >= .high ? .semibold : .regular)
            }.width(min: 200, ideal: 300)
            TableColumn("Program / target", value: \.target) { r in
                HStack(spacing: 6) {
                    if let p = r.f.path, FileManager.default.fileExists(atPath: p) {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: p)).resizable().frame(width: 16, height: 16)
                    }
                    Text(r.target).lineLimit(1)
                }
            }.width(min: 120, ideal: 170)
            TableColumn("Category") { Text($0.f.category.rawValue).foregroundStyle(Theme.dim) }.width(90)
            TableColumn("MITRE", value: \.mitre) { Text($0.mitre).font(.caption).foregroundStyle(Theme.dim) }.width(90)
            TableColumn("LLM triage", value: \.assessment) { r in
                AssessmentLabel(triage: r.f.triage, pending: model.triagingID == r.id)
            }.width(min: 110, ideal: 150)
            TableColumn("Seen", value: \.count) { Text("\($0.count)").monospacedDigit() }.width(45)
            TableColumn("Last", value: \.lastSeen) { Text(Ago.text($0.lastSeen)).foregroundStyle(Theme.dim) }.width(90)
        }
        .contextMenu(forSelectionType: UUID.self) { ids in
            Button("Acknowledge") { model.setStatus(ids, .acknowledged) }
            Button("Mark Benign (stop alerting)") { model.setStatus(ids, .benign) }
            Button("Reopen") { model.setStatus(ids, .open) }
            Divider()
            Button("Re-triage with LLM") { model.retriage(Array(ids)) }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if selection.count == 1, let f = model.findings.first(where: { $0.id == selection.first }) {
                    FindingDetail(finding: f)
                } else if selection.count > 1 {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("\(selection.count) detections").font(.headline)
                        Button("Acknowledge All") { model.setStatus(selection, .acknowledged) }
                        Button("Mark All Benign") { model.setStatus(selection, .benign) }
                        Spacer()
                    }.padding().frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ContentUnavailableView("select a detection", systemImage: "exclamationmark.shield",
                                           description: Text("\(rows.count) shown"))
                }
            }
            .inspectorColumnWidth(min: 320, ideal: 400, max: 560)
        }
        .overlay {
            if rows.isEmpty {
                ContentUnavailableView(model.findings.isEmpty ? "no detections" : "nothing matches",
                                       systemImage: "checkmark.shield",
                                       description: Text(model.settings.edr.enabled
                                                         ? "Watching processes, persistence and security settings."
                                                         : "EDR monitoring is off (Settings → EDR)."))
            }
        }
    }
}

struct FindingDetail: View {
    @EnvironmentObject var model: AppModel
    var finding: Finding
    @State private var confirmKill = false
    @State private var actionResult: String?

    var body: some View {
        let f = finding
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack { SeverityBadge(severity: f.severity); Text(f.category.rawValue).foregroundStyle(Theme.dim); Spacer()
                    Text(f.status.rawValue).foregroundStyle(f.status == .open ? Theme.red : Theme.dim) }
                Text(f.title).font(.title3.bold())
                Text(f.detail).textSelection(.enabled)

                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        if let t = f.triage {
                            AssessmentLabel(triage: t, pending: false).font(.headline)
                            Text(t.explanation).textSelection(.enabled)
                            Text("→ " + t.recommendation).fontWeight(.semibold)
                            Text(t.model).font(.caption2).foregroundStyle(Theme.dim)
                        } else {
                            Text(model.triagingID == f.id ? "Triaging…"
                                 : model.lowPowerLLM ? "Low power: not triaged unless you ask."
                                 : f.severity >= .medium ? "Queued for triage." : "Low severity: not triaged automatically.")
                                .foregroundStyle(Theme.dim)
                            if model.triagingID != f.id && (f.severity < .medium || model.lowPowerLLM) {
                                Button("Triage Now") { model.retriage([f.id]) }
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                } label: { Label("LLM triage", systemImage: "brain") }

                GroupBox("Respond") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            if f.pid != nil, f.category != .persistence, f.category != .posture {
                                if model.isRunning(f) {
                                    Button { confirmKill = true } label: { Label("Kill Process", systemImage: "xmark.octagon") }
                                        .tint(Theme.red).buttonStyle(.borderedProminent)
                                } else {
                                    Label("Process has exited", systemImage: "checkmark.circle").foregroundStyle(Theme.dim)
                                        .help("Pid \(f.pid!) no longer belongs to the detected process, so there's nothing to kill.")
                                }
                            }
                            if let p = f.path, f.category != .posture {
                                let apple = model.edr.identity(p).appleSigned
                                Button { model.blockNetwork(f); actionResult = "Network access denied for \(f.target)." } label: {
                                    Label("Block Network", systemImage: "network.slash")
                                }
                                .disabled(apple)
                                .help(apple ? "\(f.target) is part of macOS; blocking it would cut off everything that uses it. Kill the process instead."
                                            : "Deny all inbound and outbound connections for this program")
                            }
                        }
                        HStack {
                            Button("Acknowledge") { model.setStatus([f.id], .acknowledged) }
                            Button("Mark Benign") { model.setStatus([f.id], .benign) }
                            if f.status != .open { Button("Reopen") { model.setStatus([f.id], .open) } }
                        }
                        if let p = f.path, f.category != .posture {
                            Button("Reveal in Finder") { NSWorkspace.shared.selectFile(revealPath(f, p), inFileViewerRootedAtPath: "") }
                        }
                        if let r = actionResult { Text(r).font(.caption).foregroundStyle(Theme.amber) }
                        Text("Mark Benign stops alerts for this exact behavior (same rule, program and command).")
                            .font(.caption2).foregroundStyle(Theme.dim)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }

                GroupBox("Evidence") {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                        if let p = f.path { row("Program", p) }
                        if let p = f.path, f.category != .posture { row("Signature", model.edr.identity(p).label) }
                        if let pid = f.pid { row("PID", "\(pid)") }
                        if let u = f.user { row("User", u) }
                        if let c = f.commandLine { row("Command", c) }
                        if !f.chain.isEmpty { row("Parents", f.chain.joined(separator: "\n")) }
                        ForEach(Array(f.evidence.enumerated()), id: \.offset) { _, e in row("•", e) }
                        row("MITRE", f.mitre.joined(separator: ", "))
                        row("First seen", f.firstSeen.formatted())
                        row("Last seen", "\(f.lastSeen.formatted()) (\(f.count)×)")
                    }.font(.callout).padding(4)
                }

                let conns = model.profiles.values.filter { $0.processPath == f.path }
                if !conns.isEmpty {
                    GroupBox("Network activity of this program") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(conns.sorted { $0.lastSeen > $1.lastSeen }.prefix(12)) { p in
                                HStack {
                                    Text(p.destination).lineLimit(1)
                                    Spacer()
                                    IntelBadge(intel: p.intel)
                                    VerdictLabel(rule: model.decision(for: p)).labelStyle(.iconOnly)
                                }.font(.callout)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    }
                }
                ForEach(f.mitre, id: \.self) { t in
                    Link("MITRE ATT&CK \(t)", destination: URL(string: "https://attack.mitre.org/techniques/\(t.replacingOccurrences(of: ".", with: "/"))/")!)
                        .font(.caption)
                }
            }
            .padding()
        }
        .confirmationDialog("Kill \(f.target) (pid \(f.pid ?? 0))?", isPresented: $confirmKill) {
            Button("Kill Process", role: .destructive) {
                Task { actionResult = await model.kill(f) ?? "Process \(f.pid ?? 0) killed." }
            }
        } message: {
            Text("It stops immediately without saving. If it's persistent malware it may come back; check the persistence detections too.")
        }
    }

    private func revealPath(_ f: Finding, _ p: String) -> String {
        if f.category == .persistence, let plist = f.evidence.first(where: { $0.hasPrefix("plist: ") }) {
            return String(plist.dropFirst(7))
        }
        return p
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary)
            Text(v).textSelection(.enabled).lineLimit(12)
        }
    }
}

struct ProcessesTable: View {
    @EnvironmentObject var model: AppModel
    @ObservedObject var store: ProcessStore
    @State private var sortOrder = [KeyPathComparator(\ProcRow.start, order: .reverse)]
    @State private var onlyFlagged = false

    struct ProcRow: Identifiable {
        var p: ProcInfo
        var signer: String
        var flagged: Int
        var id: Int32 { p.pid }
        var pid: Int32 { p.pid }
        var name: String { p.displayName }
        var user: String
        var start: Date { p.start }
        var path: String { p.path }
        var parent: String
    }

    var body: some View {
        let byPID = Dictionary(store.list.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        let rows = store.list.compactMap { p -> ProcRow? in
            let flagged = model.openFindings.filter { $0.path == p.path && !p.path.isEmpty }.map(\.severity.rawValue).max() ?? -1
            if onlyFlagged && flagged < 0 { return nil }
            return ProcRow(p: p, signer: p.path.isEmpty ? "?" : model.edr.identity(p.path).label, flagged: flagged,
                           user: ProcessTable.userName(p.uid), parent: byPID[p.ppid]?.displayName ?? "\(p.ppid)")
        }.sorted(using: sortOrder)
        VStack(spacing: 0) {
            HStack {
                Toggle("Only programs with detections", isOn: $onlyFlagged)
                Spacer()
                Text("\(store.list.count) processes · \(model.helper.connected ? "full command lines (helper)" : "command lines for your own processes only")")
                    .font(.caption).foregroundStyle(Theme.dim)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            Table(rows, sortOrder: $sortOrder) {
                TableColumn("PID", value: \.pid) { Text("\($0.pid)").monospacedDigit() }.width(60)
                TableColumn("Name", value: \.name) { r in
                    HStack(spacing: 4) {
                        if r.flagged >= 0 {
                            Image(systemName: "exclamationmark.shield.fill").foregroundStyle(Severity(rawValue: r.flagged)!.color)
                        }
                        Text(r.name).lineLimit(1)
                    }
                }.width(min: 120, ideal: 180)
                TableColumn("User", value: \.user) { Text($0.user) }.width(80)
                TableColumn("Signer", value: \.signer) { r in
                    Text(r.signer).foregroundStyle(r.signer == "unsigned" || r.signer == "ad-hoc" ? Theme.amber : Theme.dim)
                }.width(110)
                TableColumn("Parent", value: \.parent) { Text($0.parent).lineLimit(1) }.width(min: 90, ideal: 120)
                TableColumn("Started", value: \.start) { Text(Ago.text($0.start)).foregroundStyle(Theme.dim) }.width(90)
                TableColumn("Command") { r in
                    Text(r.p.commandLine ?? r.path).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                        .help(r.p.commandLine ?? r.path)
                }
            }
        }
    }
}

struct EDRSettingsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Form {
            Section {
                Toggle("Watch processes, persistence and security settings", isOn: $model.settings.edr.enabled)
                Picker("Notify for", selection: $model.settings.edr.notifyAt) {
                    ForEach(Severity.allCases.filter { $0 >= .medium }) { Text("\($0.label.lowercased()) and above").tag($0) }
                }
                Toggle("Flag unsigned programs that pin the CPU (cryptominers)", isOn: $model.settings.edr.minerDetection)
            } header: { Text("EDR") } footer: {
                Text("Checks every new process (signature, location, parent chain, command line) every 2 seconds, and launch agents/daemons, cron, login hooks, shell startup files, SIP, Gatekeeper and FileVault every 5 minutes. Medium and higher detections are triaged by the local LLM. Real-time kernel events would need Apple's Endpoint Security entitlement, so very short-lived processes can be missed. Install the packet filter helper (Filter tab) to see the command lines of root and other users' processes and to kill them.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }
            Section("Known persistence (\(model.launchItems.count))") {
                ForEach(model.launchItems.sorted { $0.label < $1.label }, id: \.plist) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.label)
                        Text(item.program).font(.caption).foregroundStyle(Theme.dim).lineLimit(1).truncationMode(.middle)
                    }
                }
            }
            let benign = model.findings.filter { $0.status == .benign }
            if !benign.isEmpty {
                Section("Marked benign (\(benign.count))") {
                    ForEach(benign) { f in
                        HStack {
                            VStack(alignment: .leading) { Text(f.title); Text(f.target).font(.caption).foregroundStyle(Theme.dim) }
                            Spacer()
                            Button("Restore") { model.setStatus([f.id], .open) }
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}

extension DetectionsView {
    func clearAll() {
        let open = model.openFindings.count
        guard Confirm.run(title: "Clear all \(model.findings.count) detections?",
                          message: "Removes every detection and its triage\(open > 0 ? ", including \(open) still open" : ""). Detections you marked benign stay silenced. Suspicious activity that is still going on will be detected again. Your rules, connections and vulnerabilities are kept. This can't be undone.",
                          action: "Clear Detections", destructive: true) else { return }
        selection.removeAll()
        model.clearDetections()
    }
}
