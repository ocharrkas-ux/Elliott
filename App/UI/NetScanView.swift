import SwiftUI

struct NetScanView: View {
    @EnvironmentObject var model: AppModel
    @State private var newCIDR = ""
    @State private var newLabel = ""
    @State private var extraPorts = ""

    var body: some View {
        HSplitView {
            Form {
                Section {
                    Toggle("Scan my networks for vulnerable devices", isOn: $model.settings.netscan.enabled)
                } footer: {
                    Text("Detection only: TCP connections to common service ports, reading the banner a service announces (and an HTTP HEAD for web ports). No logins, exploits or payloads. Only the subnets below are touched.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Subnets") {
                    ForEach($model.settings.netscan.targets) { $t in
                        HStack {
                            Toggle("", isOn: $t.enabled).labelsHidden()
                            VStack(alignment: .leading) {
                                Text(t.cidr).font(.body.monospaced())
                                Text("\(t.label.isEmpty ? "" : t.label + " · ")\(CIDR.count(t.cidr)) hosts\(CIDR.isPrivate(t.cidr) ? "" : " · public (confirmed owned)")")
                                    .font(.caption).foregroundStyle(Theme.dim)
                            }
                            Spacer()
                            Button(role: .destructive) { model.settings.netscan.targets.removeAll { $0.id == t.id } } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless)
                        }
                    }
                    if let s = model.suggestedSubnet, !model.settings.netscan.targets.contains(where: { $0.cidr == s }) {
                        Button("Add this Mac's network (\(s))") { model.settings.netscan.targets.append(ScanTarget(cidr: s, label: "This network")) }
                    }
                    HStack {
                        TextField("CIDR", text: $newCIDR, prompt: Text("192.168.1.0/24"))
                        TextField("Label", text: $newLabel, prompt: Text("optional"))
                        Button("Add") { add() }.disabled(CIDR.parse(newCIDR) == nil)
                    }
                    if !newCIDR.isEmpty, let problem = CIDR.check(newCIDR, ownedPublic: false), problem != .publicRange {
                        Text(problem == .invalid ? "Not a valid IPv4 range (e.g. 10.0.0.0/24)." : "Too large: Elliott scans at most a /16 at a time.")
                            .font(.caption).foregroundStyle(Theme.red)
                    }
                }
                Section("How") {
                    Picker("Schedule", selection: $model.settings.netscan.schedule) {
                        ForEach(NetScanSettings.Schedule.allCases) { Text($0.rawValue).tag($0) }
                    }
                    Stepper("At most \(model.settings.netscan.rate) new connections per second",
                            value: $model.settings.netscan.rate, in: 20...1000, step: 20)
                    TextField("Extra ports (comma-separated)", text: $extraPorts)
                        .onSubmit { model.settings.netscan.extraPorts = extraPorts.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) } }
                    Text("Always checks \(NetScanner.defaultPorts.count) common ports (SSH, web, file sharing, databases, remote desktop, printers, IoT…).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section {
                    HStack {
                        Button(model.netScanning ? "Scanning…" : "Scan Now") { Task { await model.runNetworkScan() } }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.netScanning || !model.settings.netscan.enabled || !model.settings.netscan.targets.contains(where: \.enabled))
                        Spacer()
                        if let last = model.settings.netscan.lastScan {
                            Text("last scan \(last.formatted(.relative(presentation: .named)))").font(.caption).foregroundStyle(Theme.dim)
                        }
                    }
                    if model.netScanning || !model.netScanProgress.0.isEmpty {
                        ProgressView(value: model.netScanProgress.1) { Text(model.netScanProgress.0).font(.caption) }
                    }
                }
            }
            .formStyle(.grouped)
            .frame(minWidth: 360, idealWidth: 420)
            .onAppear { extraPorts = model.settings.netscan.extraPorts.map(String.init).joined(separator: ", ") }

            HostsTable(hosts: model.scanHosts, findings: model.vulnFindings, showNode: false)
                .frame(minWidth: 480)
        }
        .navigationTitle("net.scan")
    }

    private func add() {
        let cidr = newCIDR.trimmingCharacters(in: .whitespaces)
        var target = ScanTarget(cidr: cidr, label: newLabel)
        switch CIDR.check(cidr, ownedPublic: false) {
        case .invalid?, .tooLarge?: return
        case .publicRange?:
            guard Confirm.run(title: "\(cidr) is a public address range",
                              message: "Only scan networks you own or are authorized to test. Scanning other people's networks can be illegal and will look like an attack to them.",
                              action: "I Own This Network") else { return }
            target.ownedPublic = true
        case nil: break
        }
        model.settings.netscan.targets.append(target)
        newCIDR = ""; newLabel = ""
    }
}

/// Hosts found by scans (this Mac's, or every node's), with their open services and findings.
struct HostsTable: View {
    var hosts: [ScannedHost]
    var findings: [VulnFinding]
    var showNode: Bool
    @State private var selection: ScannedHost.ID?

    struct Row: Identifiable {
        var h: ScannedHost
        var serious: Int
        var count: Int
        var id: String { h.scannedBy + h.ip }
        var ipValue: UInt32 { IPv4Set.parse(h.ip) ?? 0 }
        var name: String { h.hostname ?? "" }
        var ports: Int { h.ports.count }
    }

    var body: some View {
        let byHost = Dictionary(grouping: findings.filter { $0.component.kind == .remote && $0.status == .open },
                                by: { $0.component.location.components(separatedBy: ":").dropLast().joined(separator: ":") })
        let rows = hosts.map { h in
            let fs = byHost[h.label] ?? []
            return Row(h: h, serious: fs.filter { $0.severity >= .high }.count, count: fs.count)
        }
        Table(rows) {
            if showNode {
                TableColumn("Scanned by") { Text($0.h.scannedBy).fontWeight(.semibold) }.width(min: 90, ideal: 120)
            }
            TableColumn("Host") { r in
                VStack(alignment: .leading) {
                    Text(r.h.ip).font(.callout.monospaced())
                    if let n = r.h.hostname { Text(n).font(.caption).foregroundStyle(Theme.dim) }
                }
            }.width(min: 120, ideal: 170)
            TableColumn("Open services") { r in
                Text(r.h.ports.map { p in "\(p.port) \(p.product.map { "\($0) \(p.version ?? "")" } ?? p.service)" }.joined(separator: " · "))
                    .lineLimit(2).font(.caption)
            }.width(min: 200, ideal: 340)
            TableColumn("Findings") { r in
                if r.count == 0 { Text("—").foregroundStyle(Theme.dim) }
                else { Text("\(r.count)\(r.serious > 0 ? " (\(r.serious) high+)" : "")").fontWeight(.bold).foregroundStyle(r.serious > 0 ? Theme.red : Theme.amber) }
            }.width(110)
            TableColumn("MAC") { Text($0.h.mac ?? "").font(.caption.monospaced()).foregroundStyle(Theme.dim) }.width(130)
        }
        .overlay {
            if hosts.isEmpty {
                ContentUnavailableView("no scan results", systemImage: "dot.radiowaves.left.and.right",
                                       description: Text("Add a subnet and run a scan. Findings also appear in vulns (source: network host)."))
            }
        }
    }
}

struct NetworkHostsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Group {
            if model.mesh?.isMember == true {
                let reports = model.networkReports
                HostsTable(hosts: reports.flatMap { $0.scanHosts ?? [] },
                           findings: reports.flatMap(\.vulnFindings), showNode: true)
            } else {
                NotInNetworkPlaceholder()
            }
        }
        .navigationTitle("all.hosts")
    }
}
