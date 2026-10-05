import AppKit
import SwiftUI

struct ReachBadge: View {
    var r: ReachabilityResult
    var body: some View {
        switch r.verdict {
        case .reachable: Label("reachable", systemImage: "scope").foregroundStyle(Theme.red).fontWeight(.bold)
        case .imported: Label("imported", systemImage: "arrow.down.doc").foregroundStyle(Theme.amber)
        case .notImported: Label("not imported", systemImage: "minus.circle").foregroundStyle(Theme.dim)
        case .unknown: Text("unknown").foregroundStyle(Theme.dim)
        case .notApplicable: Text("—").foregroundStyle(.tertiary)
        }
    }
}

struct VulnRow: Identifiable {
    var f: VulnFinding
    var id: String { f.id }
    var priority: Int { f.priority }
    var score: Double { f.vuln.score }
    var vulnID: String { f.vuln.cve ?? f.vuln.id }
    var component: String { f.component.name }
    var kind: String { f.component.kind.rawValue }
    var reach: Int { [Reachability.notApplicable: 0, .notImported: 1, .unknown: 2, .imported: 3, .reachable: 4][f.reachability.verdict]! }
}

struct VulnView: View {
    enum Tab: String, CaseIterable, Identifiable { case findings, inventory, remediation; var id: String { rawValue } }
    enum Show: String, CaseIterable, Identifiable {
        case open, new = "new since last scan", exploited = "exploited (KEV)", reachable, exposed = "network-exposed", accepted, fixed, all
        var id: String { rawValue }
    }

    @EnvironmentObject var model: AppModel
    @State private var tab: Tab = .findings
    @State private var show: Show = .open
    @State private var kind: Component.Kind?
    @State private var minSeverity: Severity = .low
    @State private var search = ""
    @State private var selection: Set<String> = []
    @State private var sortOrder = [KeyPathComparator(\VulnRow.priority, order: .reverse)]
    @State private var showInspector = true
    @State private var remediate = false

    private func rows() -> [VulnRow] {
        let q = search.lowercased()
        return model.vulnFindings.filter { f in
            switch show {
            case .open: if f.status != .open { return false }
            case .new: if !model.newVulnIDs.contains(f.id) || f.status != .open { return false }
            case .exploited: if !f.kev || f.status != .open { return false }
            case .reachable: if f.reachability.verdict != .reachable || f.status != .open { return false }
            case .exposed: if f.component.exposedPorts.isEmpty || f.status != .open { return false }
            case .accepted: if f.status != .accepted { return false }
            case .fixed: if f.status != .fixed { return false }
            case .all: break
            }
            if let kind, f.component.kind != kind { return false }
            guard f.severity >= minSeverity else { return false }
            return q.isEmpty || [f.vuln.id, f.vuln.aliases.joined(separator: " "), f.vuln.summary, f.component.name, f.component.location]
                .contains { $0.lowercased().contains(q) }
        }.map(VulnRow.init).sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            if model.vulnScanning {
                ProgressView(value: model.vulnProgress.1) { Text(model.vulnProgress.0).font(.caption) }
                    .padding(.horizontal, 16).padding(.bottom, 8)
            }
            if !model.vulnErrors.isEmpty {
                DisclosureGroup("\(model.vulnErrors.count) lookup problem\(model.vulnErrors.count == 1 ? "" : "s") in the last scan") {
                    ForEach(model.vulnErrors, id: \.self) { Text($0).font(.caption).frame(maxWidth: .infinity, alignment: .leading) }
                }
                .font(.caption).foregroundStyle(Theme.amber).padding(.horizontal, 16).padding(.bottom, 6)
            }
            Divider()
            switch tab {
            case .findings: findingsTable
            case .inventory: InventoryTable()
            case .remediation: RemediationHistory()
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "CVE, package, app, path")
        .toolbar {
            ToolbarItem {
                Button { remediate = true } label: { Label("Remediate…", systemImage: "wrench.and.screwdriver") }
                    .disabled(model.vulnScanning || model.remediating || model.settings.remediation.mode == .off || model.openVulns.isEmpty)
                    .help(model.settings.remediation.mode == .off ? "Remediation is off (Settings → Vulnerabilities)" : "Preview and apply fixes")
            }
            ToolbarItem {
                Button { Task { await model.scanVulnerabilities() } } label: {
                    Label(model.vulnScanning ? "Scanning…" : "Scan Now", systemImage: "magnifyingglass")
                }
                .disabled(model.vulnScanning)
            }
            ToolbarItem {
                Button { showInspector.toggle() } label: { Label("Details", systemImage: "sidebar.right") }
            }
        }
        .navigationTitle("vulns")
        .sheet(isPresented: $remediate) { RemediationSheet(componentIDs: nil).environmentObject(model).hackerTheme() }
    }

    private var header: some View {
        let open = model.openVulns
        return HStack(spacing: 14) {
            ForEach([Severity.critical, .high, .medium, .low], id: \.self) { sev in
                let n = open.filter { $0.severity == sev }.count
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("\(n)").font(.title2.weight(.heavy)).monospacedDigit().foregroundStyle(n > 0 ? sev.color : Theme.dim)
                    Text(sev.label.lowercased()).foregroundStyle(Theme.dim)
                }
            }
            let kev = open.filter(\.kev).count
            if kev > 0 { Label("\(kev) exploited", systemImage: "flame.fill").foregroundStyle(Theme.red).fontWeight(.bold) }
            let fresh = open.filter { model.newVulnIDs.contains($0.id) }.count
            if fresh > 0 {
                Button { show = .new } label: { Label("\(fresh) new", systemImage: "sparkle") }
                    .buttonStyle(.borderless).foregroundStyle(Theme.amber)
            }
            let reach = open.filter { $0.reachability.verdict == .reachable }.count
            if reach > 0 { Label("\(reach) reachable", systemImage: "scope").foregroundStyle(Theme.amber) }
            Spacer()
            VStack(alignment: .trailing, spacing: 1) {
                if let last = model.settings.vuln.lastScan {
                    Text("scanned \(last.formatted(.relative(presentation: .named)))")
                }
                if let k = model.settings.vuln.lastExploitCheck {
                    Text(model.exploitChecking ? "checking exploits…" : "exploits checked \(k.formatted(.relative(presentation: .named)))")
                }
            }
            .font(.caption).foregroundStyle(Theme.dim)
            if tab == .findings {
                Picker("Show", selection: $show) { ForEach(Show.allCases) { Text($0.rawValue).tag($0) } }
                    .labelsHidden().frame(width: 150)
                Picker("Source", selection: $kind) {
                    Text("all sources").tag(Component.Kind?.none)
                    ForEach(Component.Kind.allCases, id: \.self) { Text($0.rawValue).tag(Component.Kind?.some($0)) }
                }
                .labelsHidden().frame(width: 120)
                Picker("Minimum", selection: $minSeverity) {
                    ForEach(Severity.allCases) { Text("≥ \($0.label.lowercased())").tag($0) }
                }
                .labelsHidden().frame(width: 110)
            }
            Picker("View", selection: $tab) { ForEach(Tab.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden().frame(width: 270)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    private var findingsTable: some View {
        let rows = rows()
        return Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Priority", value: \.priority) { r in
                HStack(spacing: 4) {
                    Text("\(r.priority)").monospacedDigit().fontWeight(.heavy).foregroundStyle(RiskLevel(score: r.priority).color)
                    if r.f.kev { Image(systemName: "flame.fill").foregroundStyle(Theme.red).help("CISA: known exploited in the wild") }
                    if !r.f.component.exposedPorts.isEmpty { Image(systemName: "network").foregroundStyle(Theme.amber).help("Listening on the network: \(r.f.component.exposedPorts.map(String.init).joined(separator: ", "))") }
                }
            }.width(80)
            TableColumn("CVSS", value: \.score) { r in
                HStack(spacing: 4) {
                    SeverityBadge(severity: r.f.severity)
                    Text(String(format: "%.1f", r.f.vuln.score)).monospacedDigit()
                }
            }.width(100)
            TableColumn("ID", value: \.vulnID) { r in
                HStack(spacing: 4) {
                    Text(r.vulnID).font(.callout.monospaced())
                    if model.newVulnIDs.contains(r.id) {
                        Text("NEW").font(.caption2.weight(.heavy)).padding(.horizontal, 4)
                            .foregroundStyle(.black).background(Theme.amber, in: RoundedRectangle(cornerRadius: 3))
                    }
                }
            }.width(min: 140, ideal: 180)
            TableColumn("Component", value: \.component) { r in
                VStack(alignment: .leading, spacing: 1) {
                    Text(r.f.component.display).lineLimit(1)
                    if let fix = r.f.vuln.fixedVersions.first {
                        Text("fix: \(fix)").font(.caption).foregroundStyle(Theme.green)
                    }
                }
            }.width(min: 140, ideal: 190)
            TableColumn("Source", value: \.kind) { r in
                Text(r.f.component.kind == .package ? "\(r.f.component.ecosystem ?? "") · \(((r.f.component.project ?? "") as NSString).lastPathComponent)" : r.kind)
                    .foregroundStyle(Theme.dim).lineLimit(1)
            }.width(min: 90, ideal: 130)
            TableColumn("Reachability", value: \.reach) { r in
                HStack(spacing: 4) {
                    ReachBadge(r: r.f.reachability)
                    if let v = r.f.reachability.llmVerdict {
                        Image(systemName: "brain").foregroundStyle(v == "reachable" ? Theme.red : v == "not reachable" ? Theme.green : Theme.dim)
                            .help("LLM: \(v)")
                    }
                }
            }.width(min: 110, ideal: 130)
            TableColumn("Summary") { Text($0.f.vuln.summary).lineLimit(2).foregroundStyle(.secondary) }
        }
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Accept Risk") { model.setVulnStatus(ids, .accepted) }
            Button("Reopen") { model.setVulnStatus(ids, .open) }
            Divider()
            Button("Re-check Reachability with LLM") { model.rejudgeReachability(Array(ids)) }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if selection.count == 1, let f = model.vulnFindings.first(where: { $0.id == selection.first }) {
                    VulnDetail(f: f)
                } else if selection.count > 1 {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("\(selection.count) vulnerabilities").font(.headline)
                        Button("Accept Risk for All") { model.setVulnStatus(selection, .accepted) }
                        Button("Reopen All") { model.setVulnStatus(selection, .open) }
                        Spacer()
                    }.padding().frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ContentUnavailableView("select a vulnerability", systemImage: "ladybug", description: Text("\(rows.count) shown"))
                }
            }
            .inspectorColumnWidth(min: 320, ideal: 420, max: 580)
        }
        .overlay {
            if rows.isEmpty && !model.vulnScanning {
                ContentUnavailableView(model.settings.vuln.lastScan == nil ? "not scanned yet" : "nothing matches",
                                       systemImage: "checkmark.shield",
                                       description: Text(model.settings.vuln.lastScan == nil
                                                         ? "Scan Now checks macOS, apps, Homebrew, listening services and your project folders (Settings → Vulnerabilities)."
                                                         : "No vulnerabilities match these filters."))
            }
        }
    }
}

struct VulnDetail: View {
    @EnvironmentObject var model: AppModel
    var f: VulnFinding
    @State private var remediate = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    SeverityBadge(severity: f.severity)
                    Text("CVSS \(String(format: "%.1f", f.vuln.score))\(f.vuln.cvssVersion.map { " (v\($0))" } ?? "")").foregroundStyle(Theme.dim)
                    Spacer()
                    Text("priority \(f.priority)").fontWeight(.bold).foregroundStyle(RiskLevel(score: f.priority).color)
                }
                Text(f.vuln.cve ?? f.vuln.id).font(.title3.bold()).textSelection(.enabled)
                if !f.vuln.aliases.isEmpty {
                    Text(([f.vuln.id] + f.vuln.aliases).filter { $0 != f.vuln.cve }.joined(separator: " · ")).font(.caption).foregroundStyle(Theme.dim)
                }
                Text(f.vuln.summary).font(.headline).textSelection(.enabled)
                if f.kev {
                    Label("Listed in CISA's Known Exploited Vulnerabilities catalog: attackers are using this in the wild.", systemImage: "flame.fill")
                        .foregroundStyle(.white).padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.red, in: RoundedRectangle(cornerRadius: 6))
                }

                GroupBox("Affected") {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                        row("Component", f.component.display)
                        row("Source", f.component.kind == .package ? "\(f.component.ecosystem ?? "") package" : f.component.kind.rawValue)
                        row("Location", f.component.location)
                        if let d = f.component.direct { row("Dependency", d ? "direct" : "transitive") }
                        if !f.component.exposedPorts.isEmpty { row("Exposed", "listening on port \(f.component.exposedPorts.map(String.init).joined(separator: ", "))") }
                        row("Fixed in", f.vuln.fixedVersions.isEmpty ? "no fixed version listed" : f.vuln.fixedVersions.joined(separator: ", "))
                        if let e = f.epss { row("EPSS", String(format: "%.1f%% chance of exploitation in 30 days", e * 100)) }
                        if let v = f.vuln.cvssVector { row("Vector", v) }
                        if let p = f.vuln.published { row("Published", p.formatted(date: .abbreviated, time: .omitted)) }
                    }.font(.callout).padding(4)
                }

                if f.component.kind == .package {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            ReachBadge(r: f.reachability).font(.headline)
                            ForEach(Array(f.reachability.evidence.enumerated()), id: \.offset) { _, e in
                                Text(e).font(.caption.monospaced()).textSelection(.enabled).lineLimit(4)
                            }
                            Divider()
                            if let v = f.reachability.llmVerdict {
                                HStack { Image(systemName: "brain"); Text("LLM: \(v)").fontWeight(.semibold) }
                                    .foregroundStyle(v == "reachable" ? Theme.red : v == "not reachable" ? Theme.green : Theme.dim)
                                if let why = f.reachability.llmRationale { Text(why).font(.callout) }
                            } else if model.reachJudgingID == f.id {
                                Text("LLM reviewing the call sites…").foregroundStyle(Theme.dim)
                            }
                            Button("Re-check with LLM") { model.rejudgeReachability([f.id]) }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    } label: { Label("Reachability", systemImage: "scope") }
                }

                GroupBox("Fix") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(remediation).textSelection(.enabled)
                        HStack {
                            if f.status == .open && model.settings.remediation.mode != .off {
                                Button { remediate = true } label: { Label("Remediate…", systemImage: "wrench.and.screwdriver") }
                                    .buttonStyle(.borderedProminent).tint(Theme.red).disabled(model.remediating)
                            }
                            Button("Accept Risk") { model.setVulnStatus([f.id], .accepted) }
                            if f.status != .open { Button("Reopen") { model.setVulnStatus([f.id], .open) } }
                            if f.component.location.hasPrefix("/") {
                                Button("Reveal") { NSWorkspace.shared.selectFile(f.component.location, inFileViewerRootedAtPath: "") }
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }

                if !f.vuln.details.isEmpty && f.vuln.details != f.vuln.summary {
                    DisclosureGroup("Advisory details") {
                        Text(f.vuln.details.prefix(4000)).font(.callout).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    if let cve = f.vuln.cve { link("NVD \(cve)", "https://nvd.nist.gov/vuln/detail/\(cve)") }
                    if !f.vuln.id.hasPrefix("EXPOSED") { link("OSV \(f.vuln.id)", "https://osv.dev/vulnerability/\(f.vuln.id)") }
                    ForEach(f.vuln.references.prefix(5), id: \.self) { link($0, $0) }
                }
                .font(.caption)
            }
            .padding()
        }
        .sheet(isPresented: $remediate) { RemediationSheet(componentIDs: [f.component.id]).environmentObject(model).hackerTheme() }
    }

    private var remediation: String {
        let fix = f.vuln.fixedVersions.first
        switch f.component.kind {
        case .package:
            let file = (f.component.location as NSString).lastPathComponent
            return fix.map { "Upgrade \(f.component.name) to \($0) or later and regenerate \(file)." }
                ?? "No fixed release is listed yet. Consider replacing \(f.component.name) or limiting how untrusted input reaches it."
        case .app: return "Update \(f.component.name)\(fix.map { " to \($0) or later" } ?? "") (its own updater, the App Store, or the vendor's site)."
        case .homebrew: return "Run: brew upgrade \(f.component.name)"
        case .os: return "Install the latest macOS update (System Settings → General → Software Update)."
        case .remote:
            return f.vuln.id.hasPrefix("EXPOSED") ? f.vuln.details + " This is another device: change it on that device (or its admin page)."
                : "Update the software on \(f.component.location)\(fix.map { " to \($0) or later" } ?? "") (firmware or package update on that device)."
        case .service:
            return f.vuln.id.hasPrefix("EXPOSED") ? f.vuln.details
                : "Update \(f.component.name)\(fix.map { " to \($0) or later" } ?? ""), or stop exposing it on the network."
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow { Text(k).foregroundStyle(.secondary); Text(v).textSelection(.enabled).lineLimit(6) }
    }

    private func link(_ title: String, _ url: String) -> some View {
        Button(title) { if let u = URL(string: url) { NSWorkspace.shared.open(u) } }
            .buttonStyle(.link).lineLimit(1).truncationMode(.middle)
    }
}

struct InventoryTable: View {
    @EnvironmentObject var model: AppModel
    @State private var sortOrder = [KeyPathComparator(\Row.kind)]

    struct Row: Identifiable {
        var c: Component
        var vulns: Int
        var id: String { c.id }
        var kind: String { c.kind.rawValue }
        var name: String { c.name }
        var matched: String { c.cpe ?? c.ecosystem ?? "not matched" }
    }

    var body: some View {
        let counts = Dictionary(grouping: model.openVulns, by: { $0.component.id }).mapValues(\.count)
        let rows = model.components.map { Row(c: $0, vulns: counts[$0.id] ?? 0) }.sorted(using: sortOrder)
        Table(rows, sortOrder: $sortOrder) {
            TableColumn("Kind", value: \.kind) { Text($0.kind) }.width(80)
            TableColumn("Name", value: \.name) { Text($0.name).lineLimit(1) }.width(min: 140, ideal: 200)
            TableColumn("Version") { Text($0.c.version).monospacedDigit() }.width(100)
            TableColumn("Matched via", value: \.matched) { r in
                Text(r.c.cpe.map { "NVD \($0)\(r.c.cpeAuto == true ? " (auto)" : "")" } ?? r.c.ecosystem.map { "OSV \($0)" } ?? "no CPE mapping")
                    .foregroundStyle(r.c.cpe == nil && r.c.ecosystem == nil ? .tertiary : .secondary).lineLimit(1)
            }.width(min: 120, ideal: 190)
            TableColumn("Open vulns") { r in
                Text(r.vulns == 0 ? "—" : "\(r.vulns)").fontWeight(r.vulns > 0 ? .bold : .regular)
                    .foregroundStyle(r.vulns > 0 ? Theme.red : Theme.dim)
            }.width(80)
            TableColumn("Network") { r in
                Text(r.c.exposedPorts.isEmpty ? "" : r.c.exposedPorts.map(String.init).joined(separator: ", ")).foregroundStyle(Theme.amber)
            }.width(80)
            TableColumn("Location") { Text($0.c.location).foregroundStyle(Theme.dim).lineLimit(1).truncationMode(.middle) }
        }
        .overlay {
            if rows.isEmpty { ContentUnavailableView("no inventory yet", systemImage: "shippingbox", description: Text("Run a scan.")) }
        }
    }
}

struct VulnSettingsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form {
            Section {
                Toggle("Vulnerability scanning", isOn: $model.settings.vuln.enabled)
                Toggle("Scan automatically once a day", isOn: $model.settings.vuln.autoScanDaily)
                Toggle("Installed apps", isOn: $model.settings.vuln.includeApps)
                Toggle("Homebrew packages", isOn: $model.settings.vuln.includeHomebrew)
                Toggle("This Mac's listening services (network exposure)", isOn: $model.settings.vuln.includeServices)
            } header: { Text("Scope") } footer: {
                Text("Network checks only look at this Mac: which of its own services listen on the network, and their versions (read from their banner over 127.0.0.1). Elliott doesn't probe other machines.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }

            Section {
                ForEach(model.settings.vuln.projectFolders, id: \.self) { folder in
                    HStack {
                        Image(systemName: "folder")
                        Text(folder).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button(role: .destructive) { model.settings.vuln.projectFolders.removeAll { $0 == folder } } label: {
                            Image(systemName: "minus.circle")
                        }.buttonStyle(.borderless)
                    }
                }
                Button("Add Folder…") { addFolder() }
            } header: { Text("Projects (software composition analysis)") } footer: {
                Text("Elliott reads lockfiles (npm, yarn, pnpm, pip/Poetry/uv/Pipfile, Cargo, Go, Bundler, Composer, SwiftPM) under these folders, then checks whether your code imports each vulnerable package and calls the vulnerable functions.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }

            Section {
                Toggle("Notify me about new vulnerabilities", isOn: $model.settings.vuln.notify)
                if model.settings.vuln.notify {
                    Picker("Severity", selection: $model.settings.vuln.notifyAt) {
                        ForEach(Severity.allCases.filter { $0 >= .medium }) { Text("\($0.label.lowercased()) and above").tag($0) }
                    }
                }
                Toggle("Look up NVD products for apps and Homebrew formulae not in Elliott's table", isOn: $model.settings.vuln.autoMapCPE)
                HStack {
                    Button(model.exploitChecking ? "Checking…" : "Check Exploit Status Now") { Task { await model.refreshExploitSignals() } }
                        .disabled(model.exploitChecking || model.vulnFindings.isEmpty)
                    Spacer()
                    if let k = model.settings.vuln.lastExploitCheck {
                        Text("last checked \(k.formatted(.relative(presentation: .named)))").font(.caption).foregroundStyle(Theme.dim)
                    }
                }
            } header: { Text("Staying current") } footer: {
                Text("Every 3 hours Elliott re-checks CISA's Known Exploited Vulnerabilities list (and daily EPSS scores) against what it has already found, and always notifies when something on this Mac becomes actively exploited. A full rescan runs daily. Product lookups are strict (exact name, vendor confirmed by the app's code signature) and cached for 30 days; matches show as \"(auto)\" in the inventory.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }

            RemediationSettingsSection()

            Section {
                SecureField("NVD API key (optional, makes app/Homebrew lookups ~10× faster)", text: $model.nvdKey)
                Link("Request a free NVD API key", destination: URL(string: "https://nvd.nist.gov/developers/request-an-api-key")!)
                    .font(.caption)
            } header: { Text("Data sources") } footer: {
                Text("OSV.dev receives package names and versions; NVD receives product names and versions; FIRST EPSS receives CVE IDs; the CISA KEV list is downloaded. No file contents, code or IP addresses are sent. Responses are cached (OSV 3 days, NVD and KEV 1 day).")
                    .font(.caption).foregroundStyle(Theme.amber)
            }
        }
        .formStyle(.grouped)
    }

    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        guard panel.runModal() == .OK else { return }
        for url in panel.urls where !model.settings.vuln.projectFolders.contains(url.path) {
            model.settings.vuln.projectFolders.append(url.path)
        }
    }
}
