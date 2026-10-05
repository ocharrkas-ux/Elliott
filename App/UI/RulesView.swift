import SwiftUI

/// One row of the rules review table.
struct RuleRow: Identifiable {
    var rule: Rule
    var covers: [Profile]
    var iconPath: String?
    var id: UUID { rule.id }

    var verdictOrder: Int { rule.verdict == .deny ? 0 : 1 }
    var app: String { rule.signer != nil ? "signed by \(rule.appName)" : rule.appKey == "*" ? "any app" : rule.appName }
    var scope: String { rule.scopeLabel }
    var destination: String { rule.destinationLabel }
    var coverCount: Int { covers.count }
    var created: Date { rule.created }
    var expiresSort: Date { rule.expires ?? .distantFuture }
}

extension Rule {
    var scopeLabel: String {
        if signer != nil { return "signer" }
        if host == "*" && port == nil { return "everything" }
        if port == nil { return "any port" }
        return "dest + port"
    }

    var destinationLabel: String {
        if direction == .inbound {
            let from = host == "*" ? "anyone" : host
            return "\(from) → :\(port.map(String.init) ?? "any")\(proto.map { "/" + $0.rawValue } ?? "")"
        }
        let to = host == "*" ? "anywhere" : host
        return "\(to)\(port.map { ":\($0)" } ?? "")\(proto.map { "/" + $0.rawValue } ?? "")"
    }

    /// "Allow Google Chrome to connect to www.google.com on TCP port 443."
    var sentence: String {
        let who = signer != nil ? "any app signed by \(appName)" : appKey == "*" ? "any app" : appName
        let verb = verdict == .allow ? "Allow" : "Block"
        let p = proto?.rawValue.uppercased() ?? "TCP/UDP"
        if direction == .inbound {
            let from = host == "*" ? "anyone" : host
            return "\(verb) \(from) connecting in to \(who) on \(port.map { "\(p) port \($0)" } ?? "any port")."
        }
        let to = host == "*" ? "any destination" : host
        return "\(verb) \(who) connecting to \(to)\(port.map { " on \(p) port \($0)" } ?? " on any port")."
    }
}

struct RulesView: View {
    enum Show: String, CaseIterable, Identifiable {
        case all = "all", allow = "allow", deny = "deny", temporary = "temporary"
        var id: String { rawValue }
    }

    @EnvironmentObject var model: AppModel
    @State private var show: Show = .all
    @State private var search = ""
    @State private var selection: Set<UUID> = []
    @State private var sortOrder = [KeyPathComparator(\RuleRow.created, order: .reverse)]
    @State private var showInspector = true
    @State private var pendingDelete: Set<UUID> = []

    private func rows() -> [RuleRow] {
        let coverage = model.coverage()
        var paths: [String: String] = [:]
        for p in model.profiles.values where paths[p.key.appKey] == nil { paths[p.key.appKey] = p.processPath }
        let q = search.lowercased()
        return model.rules.compactMap { r -> RuleRow? in
            switch show {
            case .all: break
            case .allow: if r.verdict != .allow { return nil }
            case .deny: if r.verdict != .deny { return nil }
            case .temporary: if r.expires == nil { return nil }
            }
            if !q.isEmpty && ![r.appName, r.appKey, r.host, r.note ?? "", r.addresses.joined(separator: " "),
                               r.port.map(String.init) ?? ""].contains(where: { $0.lowercased().contains(q) }) {
                return nil
            }
            return RuleRow(rule: r, covers: coverage[r.id] ?? [], iconPath: paths[r.appKey])
        }.sorted(using: sortOrder)
    }

    var body: some View {
        let rows = rows()
        VStack(spacing: 0) {
            summary
            Divider()
            table(rows)
        }
        .searchable(text: $search, placement: .toolbar, prompt: "App, host, IP, port or note")
        .toolbar {
            ToolbarItem {
                Button { showInspector.toggle() } label: { Label("Details", systemImage: "sidebar.right") }
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if selection.count == 1, let row = rows.first(where: { $0.id == selection.first }) {
                    RuleDetail(row: row, onDelete: { pendingDelete = [row.id] })
                } else if selection.count > 1 {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("\(selection.count) rules selected").font(.headline)
                        HStack {
                            Button("Set to Allow") { model.setVerdict(selection, .allow) }
                            Button("Set to Deny") { model.setVerdict(selection, .deny) }
                        }
                        Button("Delete \(selection.count) Rules…", role: .destructive) { pendingDelete = selection }
                        Spacer()
                    }
                    .padding().frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ContentUnavailableView("select a rule", systemImage: "checklist",
                                           description: Text("\(rows.count) shown"))
                }
            }
            .inspectorColumnWidth(min: 300, ideal: 380, max: 520)
        }
        .confirmationDialog(pendingDelete.count == 1 ? "Delete this rule?" : "Delete \(pendingDelete.count) rules?",
                            isPresented: Binding(get: { !pendingDelete.isEmpty }, set: { if !$0 { pendingDelete = [] } })) {
            Button("Delete", role: .destructive) {
                model.removeRules(pendingDelete)
                selection.subtract(pendingDelete)
                pendingDelete = []
            }
        } message: {
            Text(model.settings.lockdown
                 ? "In lockdown, connections these rules allowed will ask for approval again."
                 : "The connections they cover go back to unclassified.")
        }
        .navigationTitle("rules [\(model.rules.count)]")
    }

    private var summary: some View {
        let allows = model.rules.filter { $0.verdict == .allow }.count
        let denies = model.rules.count - allows
        let temps = model.rules.filter { $0.expires != nil }.count
        return HStack(spacing: 16) {
            stat("\(allows)", "allow", Theme.green)
            stat("\(denies)", "deny", Theme.red)
            if temps > 0 { stat("\(temps)", "temporary", Theme.amber) }
            Spacer()
            Picker("Show", selection: $show) {
                ForEach(Show.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 320)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    private func stat(_ n: String, _ label: String, _ color: Color) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 5) {
            Text(n).font(.title2.weight(.heavy)).foregroundStyle(color).monospacedDigit()
            Text(label).foregroundStyle(Theme.dim)
        }
    }

    private func table(_ rows: [RuleRow]) -> some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Verdict", value: \.verdictOrder) { r in
                HStack(spacing: 4) {
                    Text(r.rule.verdict == .allow ? "ALLOW" : "DENY").fontWeight(.bold)
                        .foregroundStyle(r.rule.verdict == .allow ? Theme.green : Theme.red)
                    if r.rule.expires != nil { Image(systemName: "timer").foregroundStyle(Theme.amber).help("Temporary") }
                }
            }.width(70)
            TableColumn("App", value: \.app) { r in
                HStack(spacing: 6) {
                    if let path = r.iconPath {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable().frame(width: 16, height: 16)
                    } else {
                        Image(systemName: r.rule.signer != nil ? "signature" : r.rule.appKey == "*" ? "asterisk" : "app.dashed").frame(width: 16)
                    }
                    Text(r.app).lineLimit(1)
                }
            }.width(min: 120, ideal: 170)
            TableColumn("Dir") { r in Image(systemName: r.rule.direction.symbol).help(r.rule.direction.rawValue) }.width(30)
            TableColumn("Destination", value: \.destination) { Text($0.destination).lineLimit(1) }.width(min: 160, ideal: 260)
            TableColumn("Scope", value: \.scope) { Text($0.scope).foregroundStyle(Theme.dim) }.width(90)
            TableColumn("Covers", value: \.coverCount) { r in
                Text("\(r.coverCount)").monospacedDigit().foregroundStyle(r.coverCount == 0 ? Theme.dim : .primary)
                    .help(r.coverCount == 0 ? "No connection seen so far uses this rule" : "Connections this rule decides")
            }.width(55)
            TableColumn("Note") { Text($0.rule.note ?? "").lineLimit(1).foregroundStyle(.secondary) }
            TableColumn("Created", value: \.created) { Text($0.created.formatted(date: .abbreviated, time: .shortened)) }.width(130)
            TableColumn("Expires", value: \.expiresSort) { r in
                if let e = r.rule.expires { Text(e, style: .relative).foregroundStyle(Theme.amber) } else { Text("never").foregroundStyle(Theme.dim) }
            }.width(80)
        }
        .contextMenu(forSelectionType: UUID.self) { ids in
            Button("Set to Allow") { model.setVerdict(ids, .allow) }
            Button("Set to Deny") { model.setVerdict(ids, .deny) }
            Divider()
            Button(ids.count == 1 ? "Delete Rule…" : "Delete \(ids.count) Rules…", role: .destructive) { pendingDelete = ids }
        }
        .onDeleteCommand { if !selection.isEmpty { pendingDelete = selection } }
        .overlay {
            if model.rules.isEmpty {
                ContentUnavailableView("no rules yet", systemImage: "checklist",
                                       description: Text("Allow or deny connections in the connections view and they'll be listed here."))
            } else if rows.isEmpty {
                ContentUnavailableView.search(text: search)
            }
        }
    }
}

struct RuleDetail: View {
    @EnvironmentObject var model: AppModel
    var row: RuleRow
    var onDelete: () -> Void

    var body: some View {
        let r = row.rule
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(r.verdict == .allow ? "ALLOW" : "DENY")
                    .font(.title2.weight(.heavy))
                    .foregroundStyle(r.verdict == .allow ? Theme.green : Theme.red)
                Text(r.sentence).font(.headline).textSelection(.enabled)
                if let e = r.expires {
                    Label("Temporary: expires \(e.formatted(date: .omitted, time: .standard))", systemImage: "timer")
                        .foregroundStyle(Theme.amber)
                }

                HStack {
                    if r.verdict == .allow {
                        Button { model.setVerdict([r.id], .deny) } label: { Label("Change to Deny", systemImage: "xmark") }
                            .tint(Theme.red)
                    } else {
                        Button { model.setVerdict([r.id], .allow) } label: { Label("Change to Allow", systemImage: "checkmark") }
                            .tint(Theme.green.opacity(0.8))
                    }
                    Spacer()
                    Button("Delete…", role: .destructive, action: onDelete)
                }
                .buttonStyle(.borderedProminent)

                if let note = r.note, !note.isEmpty {
                    GroupBox("Why (model's description at the time)") {
                        Text(note).frame(maxWidth: .infinity, alignment: .leading).padding(4).textSelection(.enabled)
                    }
                }

                GroupBox("Covers \(row.covers.count) connection\(row.covers.count == 1 ? "" : "s")") {
                    VStack(alignment: .leading, spacing: 6) {
                        if row.covers.isEmpty {
                            Text("Nothing seen so far uses this rule.").foregroundStyle(Theme.dim)
                        }
                        ForEach(row.covers.sorted { $0.lastSeen > $1.lastSeen }.prefix(50)) { p in
                            HStack {
                                Text(p.appName).lineLimit(1)
                                Text(p.destination).foregroundStyle(Theme.dim).lineLimit(1)
                                Spacer()
                                RiskBadge(score: p.riskScore)
                            }
                            .font(.callout)
                        }
                        if row.covers.count > 50 { Text("and \(row.covers.count - 50) more").foregroundStyle(Theme.dim) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }

                GroupBox("Details") {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                        row("App", r.appKey == "*" ? "any app" : r.appName)
                        row("Identity", r.appKey)
                        row("Direction", r.direction.rawValue)
                        row("Protocol", r.proto?.rawValue.uppercased() ?? "any")
                        row("Host", r.host == "*" ? "any" : r.host)
                        row("Port", r.port.map(String.init) ?? "any")
                        row("Known IPs", r.addresses.isEmpty ? "—" : r.addresses.joined(separator: "\n"))
                        row("Created", r.created.formatted())
                    }
                    .font(.callout).padding(4)
                }
                if model.settings.pan.enabled {
                    Text("Mirrored to \(model.settings.pan.host) as a shadow rule (see palo_alto.sync).")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
            }
            .padding()
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary)
            Text(v).textSelection(.enabled).lineLimit(10)
        }
    }
}
