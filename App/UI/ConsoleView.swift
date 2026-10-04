import SwiftUI

struct ConsoleRow: Identifiable {
    var profile: Profile
    var rule: Rule?
    var id: String { profile.id }
    var app: String { profile.appName }
    var destination: String { profile.destination }
    var risk: Int { profile.riskScore }
    var lastSeen: Date { profile.lastSeen }
    var count: Int { profile.count }
    var status: Int { rule == nil ? 0 : rule!.verdict == .deny ? 1 : 2 }
    var summary: String { profile.analysis?.description ?? "" }
    var intelRank: Int { profile.intel?.reputation.rawValue ?? 0 }
    var edrRank: Int { profile.edr?.severity.rawValue ?? -1 }
    /// Deny suggestions sort above allows, then by confidence.
    var suggestRank: Int { profile.suggestion.map { ($0.verdict == .deny ? 1000 : 0) + $0.confidence } ?? -1 }
}

struct ConsoleView: View {
    enum Filter: String, CaseIterable, Identifiable {
        case all = "All", unclassified = "Unclassified", allowed = "Allowed", denied = "Denied", risky = "High risk",
             knownBad = "Threat intel hits", processAlerts = "Process alerts (EDR)", suggested = "Has suggestion"
        var id: String { rawValue }
    }

    @EnvironmentObject var model: AppModel
    @State private var search = ""
    @State private var filter: Filter = .all
    @State private var selection: Set<String> = []
    @State private var sortOrder = [KeyPathComparator(\ConsoleRow.lastSeen, order: .reverse)]
    @State private var showInspector = true
    @State private var acceptThreshold: Int?

    private var rows: [ConsoleRow] {
        let q = search.lowercased()
        return model.profiles.values.compactMap { p -> ConsoleRow? in
            let row = ConsoleRow(profile: p, rule: model.decision(for: p))
            switch filter {
            case .all: break
            case .unclassified: if row.rule != nil { return nil }
            case .allowed: if row.rule?.verdict != .allow { return nil }
            case .denied: if row.rule?.verdict != .deny { return nil }
            case .risky: if row.risk < 50 { return nil }
            case .knownBad: if (p.intel?.reputation ?? .unknown) < .suspicious { return nil }
            case .suggested: if p.suggestion == nil || row.rule != nil { return nil }
            case .processAlerts: if p.edr == nil { return nil }
            }
            if !q.isEmpty && ![p.appName, p.processPath, p.destination, p.hostname ?? "", row.summary,
                               p.addresses.joined(separator: " ")].contains(where: { $0.lowercased().contains(q) }) {
                return nil
            }
            return row
        }.sorted(using: sortOrder)
    }

    var body: some View {
        let rows = rows
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Status", value: \.status) { VerdictLabel(rule: $0.rule).labelStyle(.iconOnly) }
                .width(44)
            TableColumn("App", value: \.app) { r in
                HStack(spacing: 6) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: r.profile.processPath))
                        .resizable().frame(width: 16, height: 16)
                    Text(r.app).lineLimit(1)
                        .foregroundStyle(r.profile.intel?.reputation == .knownBad ? Theme.red : .primary)
                        .fontWeight(r.profile.intel?.reputation == .knownBad ? .bold : .regular)
                }
            }.width(min: 120, ideal: 170)
            TableColumn("Connection", value: \.destination) { r in
                HStack(spacing: 4) {
                    Image(systemName: r.profile.key.direction.symbol).foregroundStyle(.secondary)
                    Text(r.destination).lineLimit(1)
                    Text(r.profile.key.proto.rawValue.uppercased()).font(.caption2).foregroundStyle(.tertiary)
                }
            }.width(min: 160, ideal: 260)
            TableColumn("Intel", value: \.intelRank) { r in IntelBadge(intel: r.profile.intel) }.width(min: 70, ideal: 100)
            TableColumn("EDR", value: \.edrRank) { r in
                if let e = r.profile.edr {
                    Image(systemName: "exclamationmark.shield.fill").foregroundStyle(e.severity.color)
                        .help("Process alerts: " + e.titles.joined(separator: "\n"))
                }
            }.width(40)
            TableColumn("Risk", value: \.risk) { r in
                RiskBadge(score: r.risk, pending: r.profile.analysis == nil)
            }.width(min: 90, ideal: 110)
            TableColumn("Suggest", value: \.suggestRank) { r in
                if r.rule == nil, let s = r.profile.suggestion {
                    SuggestionBadge(suggestion: s).help(s.rationale)
                } else if r.rule == nil && model.suggestingID == r.id {
                    Text("thinking…").foregroundStyle(Theme.dim)
                }
            }.width(min: 80, ideal: 100)
            TableColumn("What it's doing", value: \.summary) { r in
                Text(r.summary.isEmpty ? (model.analyzingID == r.id ? "Analyzing…" : "—") : r.summary)
                    .lineLimit(2).foregroundStyle(r.summary.isEmpty ? .tertiary : .primary)
            }.width(min: 200, ideal: 420)
            TableColumn("Seen", value: \.count) { Text("\($0.count)").monospacedDigit() }.width(50)
            TableColumn("Last", value: \.lastSeen) { Text($0.lastSeen, style: .relative).foregroundStyle(.secondary) }
                .width(90)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            let ps = ids.compactMap { model.profiles[$0] }
            Button("Allow") { ps.forEach { model.classify($0, .allow) } }
            Button("Deny") { ps.forEach { model.classify($0, .deny) } }
            Button("Clear Classification") { ps.forEach(model.unclassify) }
            let suggested = ps.filter { $0.suggestion != nil && model.decision(for: $0) == nil }
            if !suggested.isEmpty {
                Button("Accept Suggestion\(suggested.count == 1 ? "" : "s (\(suggested.count))")") { model.acceptSuggestions(suggested.map(\.id)) }
            }
            Divider()
            Button("Re-analyze with LLM") { model.reanalyze(Array(ids)) }
            Button("Show in Finder") { ps.forEach { NSWorkspace.shared.selectFile($0.processPath, inFileViewerRootedAtPath: "") } }
            Divider()
            Button("Forget", role: .destructive) { model.forget(ids) }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "App, host, IP or description")
        .toolbar {
            ToolbarItem {
                Menu {
                    if model.canSuggest {
                        ForEach([90, 80, 70], id: \.self) { t in
                            let n = model.profiles.values.filter { $0.suggestion.map { $0.confidence >= t } == true && model.decision(for: $0) == nil }.count
                            Button("Accept all with confidence ≥ \(t)% (\(n))") { acceptThreshold = t }.disabled(n == 0)
                        }
                        Divider()
                        Button("Show suggested") { filter = .suggested }
                    } else {
                        Text("Learning: \(model.decisions.count)/\(Advisor.minimumDecisions) decisions observed")
                    }
                } label: { Label("Suggestions", systemImage: "wand.and.stars") }
            }
            ToolbarItem {
                Picker("Show", selection: $filter) { ForEach(Filter.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.menu)
            }
            ToolbarItem {
                Button { showInspector.toggle() } label: { Label("Details", systemImage: "sidebar.right") }
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if selection.count == 1, let p = model.profiles[selection.first!] {
                    ProfileDetail(profile: p)
                } else if selection.count > 1 {
                    BulkDetail(ids: selection)
                } else {
                    ContentUnavailableView("select a target", systemImage: "scope",
                                           description: Text("\(rows.count) shown"))
                }
            }
            .inspectorColumnWidth(min: 300, ideal: 360, max: 520)
        }
        .navigationTitle("connections")
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(spacing: 0) {
            let serious = model.openSeriousCount
            if serious > 0 {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.shield.fill")
                    Text("\(serious) open high/critical EDR detection\(serious == 1 ? "" : "s")").fontWeight(.bold)
                    Spacer()
                    Button("Connections") { filter = .processAlerts }.buttonStyle(.bordered)
                    Button("Detections") { model.section = .detections }.buttonStyle(.bordered)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(Color(red: 0.55, green: 0.05, blue: 0.1))
            }
            let bad = model.knownBadCount
            if bad > 0 {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.octagon.fill")
                    Text("\(bad) connection\(bad == 1 ? "" : "s") to KNOWN-BAD IP addresses (threat intel)").fontWeight(.bold)
                    Spacer()
                    Button("Show") { filter = .knownBad }.buttonStyle(.bordered)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(Theme.red.opacity(0.85))
            }
            }
        }
        .confirmationDialog("Accept every suggestion with confidence ≥ \(acceptThreshold ?? 0)%?",
                            isPresented: Binding(get: { acceptThreshold != nil }, set: { if !$0 { acceptThreshold = nil } })) {
            Button("Accept") {
                let t = acceptThreshold ?? 101
                model.acceptSuggestions(model.profiles.values.filter { $0.suggestion.map { $0.confidence >= t } == true && model.decision(for: $0) == nil }.map(\.id))
                acceptThreshold = nil
            }
        } message: {
            Text("Each becomes an allow or deny rule, as if you had chosen it.")
        }
        .overlay {
            if model.profiles.isEmpty {
                ContentUnavailableView("listening on all interfaces…", systemImage: "antenna.radiowaves.left.and.right",
                                       description: Text(model.enforcing ? "The filter is active." : "Observe-only mode: install the packet filter helper in Settings → Filter to enforce rules."))
            }
        }
    }
}

struct BulkDetail: View {
    @EnvironmentObject var model: AppModel
    var ids: Set<String>
    var body: some View {
        let ps = ids.compactMap { model.profiles[$0] }
        VStack(alignment: .leading, spacing: 12) {
            Text("\(ps.count) connections").font(.title3.bold())
            HStack {
                Button("Allow All") { ps.forEach { model.classify($0, .allow) } }
                Button("Deny All") { ps.forEach { model.classify($0, .deny) } }
            }
            Button("Re-analyze") { model.reanalyze(Array(ids)) }
            let suggested = ps.filter { $0.suggestion != nil && model.decision(for: $0) == nil }
            if !suggested.isEmpty {
                Button("Accept \(suggested.count) Suggestion\(suggested.count == 1 ? "" : "s")") { model.acceptSuggestions(suggested.map(\.id)) }
            }
            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct ProfileDetail: View {
    @EnvironmentObject var model: AppModel
    var profile: Profile
    @State private var scope: RuleScope = .exact

    var body: some View {
        let p = profile
        let rule = model.decision(for: p)
        let h = p.heuristic
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: p.processPath)).resizable().frame(width: 36, height: 36)
                    VStack(alignment: .leading) {
                        Text(p.appName).font(.title3.bold())
                        Text(p.destination).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                HStack { RiskBadge(score: p.riskScore); IntelBadge(intel: p.intel); Spacer(); VerdictLabel(rule: rule) }

                if rule == nil {
                    SuggestionBox(profile: p)
                }

                IntelBox(profile: p)

                let procFindings = model.findings(forPath: p.processPath)
                if !procFindings.isEmpty {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(procFindings.prefix(6)) { f in
                                HStack(alignment: .firstTextBaseline) {
                                    SeverityBadge(severity: f.severity)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(f.title).font(.callout)
                                        if let t = f.triage { AssessmentLabel(triage: t, pending: false).font(.caption) }
                                    }
                                }
                            }
                            Button("Open in Detections") { model.section = .detections }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    } label: { Label("Process behavior (EDR)", systemImage: "exclamationmark.shield") }
                }

                GroupBox("What it's doing") {
                    VStack(alignment: .leading, spacing: 6) {
                        if let a = p.analysis {
                            Text(a.description).textSelection(.enabled)
                            Text("Category: \(a.category) · LLM risk \(a.risk) · \(a.model)").font(.caption).foregroundStyle(.secondary)
                            ForEach(a.reasons, id: \.self) { Text("• \($0)").font(.callout) }
                        } else {
                            Text(model.analyzingID == p.id ? "Analyzing…" : "Not analyzed yet (\(model.llmStatus))")
                                .foregroundStyle(.secondary)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }

                GroupBox("Automated checks (score \(h.score))") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(h.flags, id: \.self) { Text("• \($0)").font(.callout) }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }

                GroupBox("Classify") {
                    VStack(alignment: .leading, spacing: 8) {
                        Picker("Applies to", selection: $scope) { ForEach(RuleScope.allCases) { Text($0.rawValue).tag($0) } }
                        HStack {
                            Button { model.classify(p, .allow, scope: scope) } label: { Label("Allow", systemImage: "checkmark") }
                                .tint(Theme.green.opacity(0.8))
                            Button { model.classify(p, .deny, scope: scope) } label: { Label("Deny", systemImage: "xmark") }
                                .tint(Theme.red)
                            Spacer()
                            if rule != nil { Button("Clear") { model.unclassify(p) } }
                        }
                        .buttonStyle(.borderedProminent)
                        if let rule {
                            Text("Decided by rule: \(rule.verdict.rawValue) \(rule.appName) → \(rule.host)\(rule.port.map { ":\($0)" } ?? "")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }.padding(4)
                }

                GroupBox("Details") {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                        row("Path", p.processPath)
                        row("Signature", p.appleSigned ? "Apple" : p.teamID.map { "Team \($0)" } ?? "Unsigned / ad-hoc")
                        row("Identifier", p.signingID ?? "—")
                        row("Direction", p.key.direction.rawValue)
                        row("Protocol", p.key.proto.rawValue.uppercased())
                        row("Hostname", p.hostname ?? "—")
                        row("Remote IPs", p.addresses.joined(separator: "\n"))
                        row("Connections", "\(p.count)")
                        row("First seen", p.firstSeen.formatted())
                        row("Last seen", p.lastSeen.formatted())
                        row("Last outcome", p.lastOutcome.rawValue)
                    }.font(.callout).padding(4)
                }
                Button("Re-analyze") { model.reanalyze([p.id]) }
            }
            .padding()
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary)
            Text(v).textSelection(.enabled).lineLimit(8)
        }
    }
}
