import SwiftUI
import UniformTypeIdentifiers

/// Searchable history of everything Elliott saw and did, with the tamper-evident audit trail.
struct EventsView: View {
    @EnvironmentObject var model: AppModel
    @State private var search = ""
    @State private var kinds: Set<SecurityEvent.Kind> = []
    @State private var minSeverity: Severity = .info
    @State private var range: Range = .week
    @State private var rows: [SecurityEvent] = []
    @State private var selection: SecurityEvent.ID?
    @State private var chain: String?
    @State private var total = 0

    enum Range: String, CaseIterable, Identifiable {
        case hour = "Last hour", day = "Last 24 hours", week = "Last 7 days", all = "Everything kept"
        var id: String { rawValue }
        var since: Date? {
            switch self {
            case .hour: Date().addingTimeInterval(-3600)
            case .day: Date().addingTimeInterval(-86400)
            case .week: Date().addingTimeInterval(-7 * 86400)
            case .all: nil
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Menu(kinds.isEmpty ? "All types" : kinds.map(\.rawValue).sorted().joined(separator: ", ")) {
                    Button("All types") { kinds = [] }
                    Button("Audit trail (decisions & rule changes)") { kinds = [.decision, .rule] }
                    Divider()
                    ForEach(SecurityEvent.Kind.allCases) { k in
                        Toggle(k.rawValue, isOn: Binding(get: { kinds.contains(k) }, set: { on in if on { kinds.insert(k) } else { kinds.remove(k) } }))
                    }
                }
                .fixedSize()
                Picker("Severity", selection: $minSeverity) { ForEach(Severity.allCases) { Text("\($0.label)+").tag($0) } }.fixedSize()
                Picker("When", selection: $range) { ForEach(Range.allCases) { Text($0.rawValue).tag($0) } }.fixedSize()
                Spacer()
                Text("\(rows.count) shown · \(total) kept").font(.caption).foregroundStyle(Theme.dim)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            if let chain {
                Text(chain).font(.caption).foregroundStyle(chain.hasPrefix("✓") ? Theme.green : Theme.red)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).padding(.bottom, 6)
            }
            Table(rows, selection: $selection) {
                TableColumn("Time") { Text($0.time.formatted(date: .abbreviated, time: .standard)).font(.caption.monospacedDigit()).foregroundStyle(Theme.dim) }.width(150)
                TableColumn("Type") { e in Text(e.kind.rawValue).font(.caption).foregroundStyle(e.kind.isAudit ? Theme.cyan : .secondary) }.width(90)
                TableColumn("Severity") { SeverityBadge(severity: $0.severity) }.width(80)
                TableColumn("Event") { e in Text(e.summary).lineLimit(2).textSelection(.enabled) }
                TableColumn("App") { Text($0.app ?? "").lineLimit(1).foregroundStyle(.secondary) }.width(min: 80, ideal: 120)
                TableColumn("By") { Text($0.actor ?? "").font(.caption).foregroundStyle(Theme.dim).lineLimit(1) }.width(min: 70, ideal: 140)
            }
            if let id = selection, let e = rows.first(where: { $0.id == id }), !e.detail.isEmpty {
                Divider()
                ScrollView {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 3) {
                        ForEach(e.detail.sorted { $0.key < $1.key }, id: \.key) { k, v in
                            GridRow {
                                Text(k).foregroundStyle(Theme.dim)
                                Text(v).textSelection(.enabled)
                            }
                        }
                    }
                    .font(.caption).padding(10).frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 140)
            }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search events (app, host, detection, rule…)")
        .toolbar {
            ToolbarItem {
                Button("Verify Audit Trail") { verify() }
                    .help("Recompute the signature chain over every kept event: any edit, insertion or deletion in the middle breaks it")
            }
            ToolbarItem { Button("Export…") { export() }.disabled(rows.isEmpty) }
        }
        .task(id: "\(search)|\(kinds)|\(minSeverity)|\(range)") {
            try? await Task.sleep(for: .milliseconds(250))   // let typing settle
            await reload()
        }
        .navigationTitle("events")
    }

    private func reload() async {
        guard let log = model.sec.log else { return }
        var q = EventLog.Query()
        q.text = search; q.kinds = kinds; q.minSeverity = minSeverity; q.since = range.since; q.limit = 1000
        let (found, count) = await Task.detached { (log.search(q), log.count) }.value
        rows = found
        total = count
    }

    private func verify() {
        guard let log = model.sec.log else { return }
        Task {
            let r = await Task.detached { log.verify() }.value
            chain = r.brokenAt.map { "✗ The audit trail was altered: the chain breaks at event #\($0) (\(r.checked) events check out before it)." }
                ?? "✓ Audit trail intact: \(r.checked) events, each signed over the one before (\(Date().formatted(date: .omitted, time: .shortened)))."
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json, .commaSeparatedText]
        panel.nameFieldStringValue = "elliott-events.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if url.pathExtension.lowercased() == "csv" {
            func q(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
            let lines = ["time,type,severity,node,app,actor,summary,detail"] + rows.map { e in
                [ISO8601DateFormatter().string(from: e.time), e.kind.rawValue, e.severity.label, e.node, e.app ?? "", e.actor ?? "", e.summary,
                 e.detail.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: "; ")].map(q).joined(separator: ",")
            }
            try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        } else {
            let objs = rows.map(EventFormat.json)
            if let data = try? JSONSerialization.data(withJSONObject: objs, options: [.prettyPrinted, .sortedKeys]) { try? data.write(to: url) }
        }
    }
}
