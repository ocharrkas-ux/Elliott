import SwiftUI

struct LogView: View {
    @EnvironmentObject var model: AppModel
    @State private var search = ""

    var body: some View {
        let q = search.lowercased()
        let events = q.isEmpty ? model.recent : model.recent.filter {
            "\($0.processName) \($0.remoteHostname ?? "") \($0.remoteAddress) \($0.remotePort)".lowercased().contains(q)
        }
        Table(events) {
            TableColumn("Time") { Text($0.date.formatted(date: .omitted, time: .standard)).monospacedDigit() }.width(80)
            TableColumn("Outcome") { e in Text(e.outcome.rawValue).foregroundStyle(e.outcome.color) }.width(70)
            TableColumn("Process") { e in Text("\(e.processName) (\(e.pid))").lineLimit(1) }.width(min: 120, ideal: 180)
            TableColumn("Dir") { Image(systemName: $0.direction.symbol) }.width(30)
            TableColumn("Proto") { Text($0.proto.rawValue.uppercased()) }.width(44)
            TableColumn("Local") { e in Text("\(e.localAddress ?? "")\(e.localPort.map { ":\($0)" } ?? "")").lineLimit(1) }
                .width(min: 100, ideal: 150)
            TableColumn("Remote") { e in
                Text("\(e.remoteHostname.map { "\($0) " } ?? "")\(e.remoteAddress):\(e.remotePort)").lineLimit(1)
            }.width(min: 160, ideal: 320)
        }
        .searchable(text: $search, placement: .toolbar)
        .toolbar {
            ToolbarItem {
                Button("Clear Log") { model.clearLiveLog() }
                    .disabled(model.recent.isEmpty)
                    .help("Clear the live log (logged connections stay in the connections view)")
            }
        }
        .navigationTitle("live.log")
    }
}

struct FirewallView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let plan = model.shadowPlan()
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading) {
                    Text(model.settings.pan.enabled ? "Shadow policy → \(model.settings.pan.host)" : "Palo Alto sync is off")
                        .font(.headline)
                    Text("Rules are tagged “\(PolicyPlanner.tag)” and kept at the top of the \(model.settings.pan.target == .panorama ? "device group's pre-rulebase" : "security rulebase").")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if model.syncing { ProgressView().controlSize(.small) }
                Button("Sync Now") { Task { await model.syncFirewall() } }
                    .disabled(!model.settings.pan.enabled || model.syncing)
                SettingsLink { Text("Configure…") }
            }
            .padding()
            Divider()
            HSplitView {
                Table(plan.rules, columns: {
                    TableColumn("Name") { Text($0.name).font(.callout.monospaced()) }.width(min: 150, ideal: 200)
                    TableColumn("Action") { r in Text(r.action.rawValue.uppercased()).foregroundStyle(r.action == .allow ? Theme.green : Theme.red) }.width(50)
                    TableColumn("Source") { Text($0.source.joined(separator: ", ")) }
                    TableColumn("Destination") { Text($0.destination.joined(separator: ", ")) }
                    TableColumn("Service") { Text($0.service.joined(separator: ", ")) }.width(min: 90, ideal: 120)
                    TableColumn("Description") { Text($0.description).lineLimit(2).foregroundStyle(.secondary) }
                })
                .frame(minWidth: 500)
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Notes").font(.headline)
                        if plan.notes.isEmpty { Text("None").foregroundStyle(.secondary) }
                        ForEach(plan.notes, id: \.self) { Text("• \($0)").font(.callout) }
                        Divider()
                        Text("Last sync").font(.headline)
                        if let r = model.syncReport {
                            Text(r.date.formatted()).foregroundStyle(.secondary)
                            if let e = r.error { Text(e).foregroundStyle(Theme.red).textSelection(.enabled) }
                            ForEach(r.lines, id: \.self) { Text($0).font(.callout.monospaced()).textSelection(.enabled) }
                        } else {
                            Text("Never").foregroundStyle(.secondary)
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minWidth: 260)
            }
        }
        .navigationTitle("palo_alto.sync")
    }
}

extension ShadowPlan.SecurityRule: Identifiable { var id: String { name } }
