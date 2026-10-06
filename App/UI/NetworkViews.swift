import SwiftUI

extension AppModel {
    /// Every member's latest report, this Mac's own freshly built.
    var networkReports: [NodeReport] {
        guard let mesh, mesh.isMember else { return [displayedLocalReport()] }
        let members = mesh.members
        return [displayedLocalReport()] + mesh.reports.values.filter { $0.node.id != mesh.identity.id && members[$0.node.id] != nil }
            .sorted { $0.node.name < $1.node.name }
    }

    func isOnline(_ node: UUID) -> Bool { node == mesh?.identity.id || mesh?.connected[node] != nil }
}

/// Shown on every network view until this Mac belongs to a network.
/// Which device the network-wide tables show ("" = all devices). Stored once, so a device picked on one tab
/// stays picked on the others.
enum NodeFilter {
    static let key = "network.nodeFilter"
}

extension AppModel {
    /// Reports for the chosen device (all of them when none is chosen, or the chosen one is gone).
    func networkReports(for node: String) -> [NodeReport] {
        let all = networkReports
        guard !node.isEmpty, all.contains(where: { $0.node.id.uuidString == node }) else { return all }
        return all.filter { $0.node.id.uuidString == node }
    }
}

struct NodeFilterPicker: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(NodeFilter.key) private var node = ""

    var body: some View {
        let reports = model.networkReports.sorted { $0.node.name.localizedCaseInsensitiveCompare($1.node.name) == .orderedAscending }
        let known = reports.contains { $0.node.id.uuidString == node }
        Picker("Device", selection: Binding(get: { known ? node : "" }, set: { node = $0 })) {
            Text("All devices").tag("")
            Divider()
            ForEach(reports, id: \.node.id) { r in
                let isSelf = r.node.id == model.mesh?.identity.id
                Text(r.node.name + (isSelf ? " (this Mac)" : model.isOnline(r.node.id) ? "" : " (offline)")).tag(r.node.id.uuidString)
            }
        }
        .pickerStyle(.menu)
        .help("Show one device, or every device in the network")
    }
}

struct NotInNetworkPlaceholder: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        ContentUnavailableView {
            Label("not part of an Elliott network", systemImage: "point.3.connected.trianglepath.dotted")
        } description: {
            Text("Create a network on this Mac, or join one another Mac already runs. New devices only get in after you approve them on a device that's already a member, by comparing a 6-digit code.")
        } actions: {
            Button("Set Up Network…") { model.section = .netDevices }.buttonStyle(.borderedProminent)
        }
    }
}

// MARK: Overview

struct NetworkOverview: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Group {
            if let mesh = model.mesh, mesh.isMember {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        header(mesh)
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 14)], spacing: 14) {
                            ForEach(model.networkReports, id: \.node.id) { NodeCard(report: $0) }
                            ForEach(mesh.members.values.filter { id in !model.networkReports.contains { $0.node.id == id.id } }
                                .sorted { $0.name < $1.name }) { m in
                                OfflineCard(node: m)
                            }
                        }
                    }
                    .padding()
                }
            } else {
                NotInNetworkPlaceholder()
            }
        }
        .navigationTitle("overview")
    }

    @State private var exporting = false

    private func header(_ mesh: MeshNode) -> some View {
        let reports = model.networkReports
        let serious = reports.reduce(0) { $0 + $1.findings.filter { $0.status == .open && $0.severity >= .high }.count }
        let vulns = reports.reduce(0) { $0 + $1.vulnFindings.filter { $0.severity >= .high }.count }
        let kev = reports.reduce(0) { $0 + $1.vulnFindings.filter(\.kev).count }
        return VStack(alignment: .leading, spacing: 6) {
            GlitchText(text: mesh.membership?.name.uppercased() ?? "NETWORK", font: .system(size: 20, weight: .heavy, design: .monospaced))
            HStack(spacing: 18) {
                stat("\(mesh.members.count)", "devices")
                stat("\(mesh.connected.count + 1)", "online")
                stat("\(serious)", "high+ detections", serious > 0 ? Theme.red : nil)
                stat("\(vulns)", "high+ vulns", vulns > 0 ? Theme.amber : nil)
                if kev > 0 { stat("\(kev)", "exploited", Theme.red) }
                Spacer()
                Label("LLM: \(model.llmRunsOn)", systemImage: "cpu").foregroundStyle(Theme.dim)
            }
            Text("Post-quantum encrypted links (X-Wing ML-KEM-768 + X25519, ML-DSA-65 signatures, AES-256-GCM). Rules and decisions are shared; every device enforces them.")
                .font(.caption).foregroundStyle(Theme.dim)
            if let n = model.newerClient {
                HStack {
                    Image(systemName: "arrow.down.circle.fill").foregroundStyle(Theme.amber)
                    Text("There's an updated version of Elliott available: \(n.node) runs build \(n.build), this Mac runs \(AppModel.appBuild).")
                    Spacer()
                    Button("How to Update…") { model.showUpdateSteps() }
                }
                .font(.callout)
                .padding(8)
                .background(Theme.amber.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
            }
            HStack {
                Text("This Mac: Elliott build \(AppModel.appBuild)\(AppModel.appCommit.map { " (\($0))" } ?? "")")
                    .font(.caption.monospaced()).foregroundStyle(Theme.dim)
                Spacer()
                Button(exporting ? "Exporting…" : "Export Installer") {
                    exporting = true
                    Task { _ = await model.exportInstaller(); exporting = false }
                }
                .disabled(exporting)
                .help("Save this Mac's Elliott as a zip in Downloads, to install on an outdated Mac")
            }
        }
    }

    private func stat(_ n: String, _ label: String, _ color: Color? = nil) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Text(n).font(.title2.weight(.heavy)).monospacedDigit().foregroundStyle(color ?? .primary)
            Text(label).foregroundStyle(Theme.dim)
        }
    }
}

struct NodeCard: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(NodeFilter.key) private var nodeFilter = ""
    var report: NodeReport

    var body: some View {
        let id = report.node.id
        let isSelf = id == model.mesh?.identity.id
        let status = isSelf ? model.localStatus() : model.mesh?.statuses[id]
        let openHigh = report.findings.filter { $0.status == .open && $0.severity >= .high }.count
        let vulns = report.vulnFindings.filter { $0.severity >= .high }.count
        let bad = report.profiles.filter { $0.intel?.reputation == .knownBad }.count
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Circle().fill(model.isOnline(id) ? Theme.green : Theme.dim).frame(width: 8, height: 8)
                    Text(report.node.name).font(.headline)
                    if isSelf { Text("this Mac").font(.caption2).padding(.horizontal, 5).background(Theme.dim.opacity(0.3), in: Capsule()) }
                    Spacer()
                    if report.lockdown { Label("LOCKDOWN", systemImage: "lock.fill").font(.caption.weight(.heavy)).foregroundStyle(Theme.red) }
                }
                Text("\(report.enforcement) · \(report.os.replacingOccurrences(of: "Version ", with: "macOS "))")
                    .font(.caption).foregroundStyle(Theme.dim)
                if let b = isSelf ? AppModel.appBuild : status?.appBuild {
                    HStack(spacing: 6) {
                        Text("Elliott build \(b)").font(.caption.monospaced()).foregroundStyle(Theme.dim)
                        if let newest = model.newestKnownBuild, Version.compare(b, newest) == .orderedAscending {
                            Text("outdated").font(.caption2.weight(.bold)).foregroundStyle(Theme.amber)
                        }
                    }
                } else if status != nil {
                    Text("Elliott build: older than build tracking").font(.caption).foregroundStyle(Theme.amber)
                }
                HStack(spacing: 14) {
                    metric("\(report.profiles.count)", "connections")
                    metric("\(openHigh)", "high+ alerts", openHigh > 0 ? Theme.red : nil)
                    metric("\(vulns)", "high+ vulns", vulns > 0 ? Theme.amber : nil)
                    if bad > 0 { metric("\(bad)", "known-bad", Theme.red) }
                }
                if let s = status {
                    Divider()
                    HStack(spacing: 10) {
                        Text("\(s.chip) · \(Int(s.memoryGB.rounded())) GB").font(.caption)
                        if let g = s.gpuUtilization {
                            Text("GPU \(g)%").font(.caption).foregroundStyle(g >= LLMRouter.busyGPU ? Theme.amber : Theme.dim)
                        }
                        Spacer()
                        Text(s.llmModels.isEmpty ? "no LLM" : (s.acceptsLLMWork ? "LLM: \(s.llmModels.first!)" : "LLM private"))
                            .font(.caption).foregroundStyle(Theme.dim)
                    }
                    if model.llmRunsOn == report.node.name || (isSelf && model.llmRunsOn == "this Mac") {
                        Label("Running Elliott's LLM work", systemImage: "cpu.fill").font(.caption).foregroundStyle(Theme.green)
                    }
                }
                HStack {
                    Text("updated \(report.generated.formatted(.relative(presentation: .named)))").font(.caption2).foregroundStyle(Theme.dim)
                    Spacer()
                    // Jump to the network tables, showing only this device.
                    Button("Connections") { nodeFilter = id.uuidString; model.section = .netConnections }
                    Button("Detections") { nodeFilter = id.uuidString; model.section = .netDetections }
                }
                .buttonStyle(.link).font(.caption)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        }
    }

    private func metric(_ n: String, _ label: String, _ color: Color? = nil) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(n).font(.title3.weight(.bold)).monospacedDigit().foregroundStyle(color ?? .primary)
            Text(label).font(.caption2).foregroundStyle(Theme.dim)
        }
    }
}

struct OfflineCard: View {
    var node: NodeInfo
    var body: some View {
        GroupBox {
            HStack {
                Circle().fill(Theme.dim).frame(width: 8, height: 8)
                Text(node.name).font(.headline)
                Spacer()
                Text("offline · no report yet").font(.caption).foregroundStyle(Theme.dim)
            }
            .padding(4)
        }
    }
}

// MARK: Devices

struct DevicesView: View {
    @EnvironmentObject var model: AppModel
    @State private var networkName = "Home"
    @State private var confirmLeave = false

    var body: some View {
        Form {
            if let mesh = model.mesh {
                Section {
                    Toggle("Connect this Mac to other Elliott devices", isOn: Binding(get: { model.settings.mesh.enabled }, set: { model.setMeshEnabled($0) }))
                    LabeledContent("This device", value: "\(mesh.identity.name) · key \(mesh.identity.info.fingerprint)")
                    if let port = mesh.listeningPort { LabeledContent("Listening", value: "port \(port), advertised with Bonjour") }
                } header: { Text("This device") } footer: {
                    Text("Links between devices use a post-quantum key exchange (X-Wing: ML-KEM-768 + X25519) with ML-DSA-65 signatures and AES-256-GCM. Each device's signing key stays in its Keychain.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                if !mesh.pendingJoins.isEmpty {
                    Section("Waiting for your approval") {
                        ForEach(mesh.pendingJoins) { j in
                            VStack(alignment: .leading, spacing: 8) {
                                Text("\(j.node.name) wants to join").font(.headline)
                                HStack(alignment: .firstTextBaseline) {
                                    Text("Code").foregroundStyle(Theme.dim)
                                    Text(j.sas).font(.system(size: 30, weight: .heavy, design: .monospaced)).foregroundStyle(Theme.amber)
                                }
                                Text("Approve only if \(j.node.name) shows exactly this code. Different codes mean someone may be intercepting the connection. Key \(j.node.fingerprint).")
                                    .font(.caption).foregroundStyle(Theme.dim)
                                HStack {
                                    Button("Codes Match: Approve") { try? mesh.approve(j) }.buttonStyle(.borderedProminent).tint(Theme.green.opacity(0.8))
                                    Button("Reject", role: .destructive) { mesh.reject(j) }
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }

                if mesh.isMember, let m = mesh.membership {
                    Section("Network “\(m.name)” · \(m.members.count) device\(m.members.count == 1 ? "" : "s")") {
                        ForEach(m.members.values.sorted { $0.name < $1.name }) { node in
                            HStack {
                                Circle().fill(model.isOnline(node.id) ? Theme.green : Theme.dim).frame(width: 8, height: 8)
                                VStack(alignment: .leading) {
                                    Text(node.name + (node.id == mesh.identity.id ? " (this Mac)" : ""))
                                    Text("key \(node.fingerprint)\(node.id == m.founder ? " · founder" : "")").font(.caption2.monospaced()).foregroundStyle(Theme.dim)
                                }
                                Spacer()
                                if node.id != mesh.identity.id {
                                    Button("Remove…", role: .destructive) {
                                        if Confirm.run(title: "Remove \(node.name) from the network?",
                                                       message: "It stops receiving rules and data, and its links are cut. It would have to ask to join again.",
                                                       action: "Remove", destructive: true) {
                                            try? mesh.remove(node.id)
                                        }
                                    }
                                }
                            }
                        }
                        Button("Leave This Network…", role: .destructive) { confirmLeave = true }
                    }
                    Section {
                        Picker("Run LLM work on", selection: $model.settings.mesh.llmRoute) {
                            Text("Automatic (best available device)").tag(MeshSettings.LLMRoute.automatic)
                            Text("This Mac").tag(MeshSettings.LLMRoute.local)
                            ForEach(m.members.values.filter { $0.id != mesh.identity.id }.sorted { $0.name < $1.name }) { n in
                                Text(n.name).tag(MeshSettings.LLMRoute.node(n.id))
                            }
                        }
                        Toggle("Let other devices run their LLM work on this Mac", isOn: $model.settings.mesh.shareLLM)
                        LabeledContent("Next job runs on", value: model.llmRunsOn)
                    } header: { Text("LLM processing") } footer: {
                        Text("Automatic picks the device with the strongest hardware (chip and memory) that has a model loaded, isn't busy (GPU under \(LLMRouter.busyGPU)%, short queue), and accepts work; otherwise it stays on this Mac. A device that fails or goes away hands the job back here.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else if model.settings.mesh.enabled {
                    Section("Join a network") {
                        if let state = mesh.joinState {
                            joinStatus(state, mesh)
                        }
                        if mesh.discovered.isEmpty {
                            Text("Looking for Elliott networks on this network…").foregroundStyle(Theme.dim)
                        }
                        ForEach(mesh.discovered) { n in
                            HStack {
                                VStack(alignment: .leading) { Text(n.name); Text("via \(n.via)").font(.caption).foregroundStyle(Theme.dim) }
                                Spacer()
                                Button("Ask to Join") { mesh.join(n) }.disabled(mesh.joinState != nil)
                            }
                        }
                    }
                    Section("Or start a new network") {
                        TextField("Network name", text: $networkName)
                        Button("Create Network") { try? mesh.createNetwork(name: networkName.isEmpty ? "Home" : networkName) }
                    }
                }
            } else {
                Text("Couldn't create this device's identity (Keychain unavailable).").foregroundStyle(Theme.red)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("devices")
        .confirmationDialog("Leave the network?", isPresented: $confirmLeave) {
            Button("Leave", role: .destructive) { model.mesh?.leaveNetwork() }
        } message: {
            Text("This Mac stops sharing and receiving. Your current rules stay on this Mac.")
        }
    }

    @ViewBuilder private func joinStatus(_ s: MeshNode.JoinState, _ mesh: MeshNode) -> some View {
        switch s {
        case .connecting(let n):
            HStack { ProgressView().controlSize(.small); Text("Contacting \(n)…") }
        case .waiting(let code, let n):
            VStack(alignment: .leading, spacing: 6) {
                Text("Waiting for approval on \(n)").font(.headline)
                Text(code).font(.system(size: 34, weight: .heavy, design: .monospaced)).foregroundStyle(Theme.amber)
                Text("On a device that's already in the network, open Elliott → Your Network → Devices and approve only if it shows this same code.")
                    .font(.caption).foregroundStyle(Theme.dim)
                Button("Cancel") { mesh.cancelJoin() }
            }
        case .approved(let n): Label("Joined \(n)", systemImage: "checkmark.seal.fill").foregroundStyle(Theme.green)
        case .rejected(let why): Label("Not approved: \(why)", systemImage: "xmark.seal").foregroundStyle(Theme.red)
        case .failed(let why):
            HStack { Label("Couldn't join: \(why)", systemImage: "exclamationmark.triangle").foregroundStyle(Theme.amber); Button("OK") { mesh.cancelJoin() } }
        }
    }
}

// MARK: Consolidated tables

struct NodeConnectionRow: Identifiable {
    var node: String
    var profile: Profile
    var rule: Rule?
    var id: String { node + profile.id }
    var app: String { profile.appName }
    var destination: String { profile.destination }
    var risk: Int { profile.riskScore }
    var lastSeen: Date { profile.lastSeen }
}

struct NetworkConnectionsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(NodeFilter.key) private var node = ""
    @State private var search = ""
    @State private var sortOrder = [KeyPathComparator(\NodeConnectionRow.lastSeen, order: .reverse)]

    var body: some View {
        Group {
            if model.mesh?.isMember == true {
                let q = search.lowercased()
                let rows = model.networkReports(for: node).flatMap { r in r.profiles.map { NodeConnectionRow(node: r.node.name, profile: $0, rule: model.decision(for: $0)) } }
                    .filter { q.isEmpty || "\($0.node) \($0.app) \($0.destination) \($0.profile.analysis?.description ?? "")".lowercased().contains(q) }
                    .sorted(using: sortOrder)
                Table(rows, sortOrder: $sortOrder) {
                    TableColumn("Device", value: \.node) { Text($0.node).fontWeight(.semibold) }.width(min: 90, ideal: 130)
                    TableColumn("Status") { VerdictLabel(rule: $0.rule).labelStyle(.iconOnly) }.width(44)
                    TableColumn("App", value: \.app) { Text($0.app).lineLimit(1) }.width(min: 110, ideal: 160)
                    TableColumn("Connection", value: \.destination) { Text($0.destination).lineLimit(1) }.width(min: 150, ideal: 240)
                    TableColumn("Intel") { IntelBadge(intel: $0.profile.intel) }.width(80)
                    TableColumn("Risk", value: \.risk) { RiskBadge(score: $0.risk, pending: $0.profile.analysis == nil) }.width(100)
                    TableColumn("What it's doing") { Text($0.profile.analysis?.description ?? "—").lineLimit(2).foregroundStyle(.secondary) }
                    TableColumn("Last", value: \.lastSeen) { Text(Ago.text($0.lastSeen)).foregroundStyle(Theme.dim) }.width(90)
                }
                .searchable(text: $search, placement: .toolbar, prompt: "Device, app, destination")
                .toolbar { ToolbarItem { NodeFilterPicker() } }
            } else {
                NotInNetworkPlaceholder()
            }
        }
        .navigationTitle("all.connections")
    }
}

struct NodeFindingRow: Identifiable {
    var node: String
    var f: Finding
    var id: String { node + f.id.uuidString }
    var severity: Int { f.severity.rawValue }
    var lastSeen: Date { f.lastSeen }
}

struct NetworkDetectionsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(NodeFilter.key) private var node = ""
    @State private var sortOrder = [KeyPathComparator(\NodeFindingRow.severity, order: .reverse)]
    @State private var openOnly = true

    var body: some View {
        Group {
            if model.mesh?.isMember == true {
                let rows = model.networkReports(for: node).flatMap { r in r.findings.map { NodeFindingRow(node: r.node.name, f: $0) } }
                    .filter { !openOnly || $0.f.status == .open }.sorted(using: sortOrder)
                VStack(spacing: 0) {
                    Toggle("Open only", isOn: $openOnly).padding(.horizontal, 16).padding(.vertical, 6).frame(maxWidth: .infinity, alignment: .trailing)
                    Table(rows, sortOrder: $sortOrder) {
                        TableColumn("Device") { Text($0.node).fontWeight(.semibold) }.width(min: 90, ideal: 130)
                        TableColumn("Severity", value: \.severity) { SeverityBadge(severity: $0.f.severity) }.width(80)
                        TableColumn("Detection") { Text($0.f.title).lineLimit(1) }.width(min: 200, ideal: 300)
                        TableColumn("Target") { Text($0.f.target).lineLimit(1) }.width(min: 100, ideal: 150)
                        TableColumn("LLM triage") { AssessmentLabel(triage: $0.f.triage, pending: false) }.width(min: 110, ideal: 150)
                        TableColumn("Last", value: \.lastSeen) { Text(Ago.text($0.lastSeen)).foregroundStyle(Theme.dim) }.width(90)
                    }
                }
                .toolbar { ToolbarItem { NodeFilterPicker() } }
            } else {
                NotInNetworkPlaceholder()
            }
        }
        .navigationTitle("all.detections")
    }
}

struct NodeVulnRow: Identifiable {
    var node: String
    var f: VulnFinding
    var id: String { node + f.id }
    var priority: Int { f.priority }
}

struct NetworkVulnsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(NodeFilter.key) private var node = ""
    @State private var sortOrder = [KeyPathComparator(\NodeVulnRow.priority, order: .reverse)]

    var body: some View {
        Group {
            if model.mesh?.isMember == true {
                let rows = model.networkReports(for: node).flatMap { r in r.vulnFindings.map { NodeVulnRow(node: r.node.name, f: $0) } }.sorted(using: sortOrder)
                Table(rows, sortOrder: $sortOrder) {
                    TableColumn("Device") { Text($0.node).fontWeight(.semibold) }.width(min: 90, ideal: 130)
                    TableColumn("Priority", value: \.priority) { r in
                        HStack(spacing: 4) {
                            Text("\(r.priority)").fontWeight(.heavy).monospacedDigit().foregroundStyle(RiskLevel(score: r.priority).color)
                            if r.f.kev { Image(systemName: "flame.fill").foregroundStyle(Theme.red) }
                        }
                    }.width(80)
                    TableColumn("CVSS") { r in HStack { SeverityBadge(severity: r.f.severity); Text(String(format: "%.1f", r.f.vuln.score)) } }.width(100)
                    TableColumn("ID") { Text($0.f.vuln.cve ?? $0.f.vuln.id).font(.callout.monospaced()) }.width(min: 120, ideal: 150)
                    TableColumn("Component") { r in
                        VStack(alignment: .leading) {
                            Text(r.f.component.display).lineLimit(1)
                            if let fix = r.f.vuln.fixedVersions.first { Text("fix: \(fix)").font(.caption).foregroundStyle(Theme.green) }
                        }
                    }.width(min: 140, ideal: 190)
                    TableColumn("Summary") { Text($0.f.vuln.summary).lineLimit(2).foregroundStyle(.secondary) }
                }
                .toolbar { ToolbarItem { NodeFilterPicker() } }
            } else {
                NotInNetworkPlaceholder()
            }
        }
        .navigationTitle("all.vulns")
    }
}
