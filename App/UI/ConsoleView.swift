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
    var signer: SignerInfo { profile.signer }
    var signerName: String { signer.display }
}

/// Characteristics the console can hide. Several can be on at once; the choice is remembered.
enum HideOption: String, CaseIterable, Identifiable {
    case allowed, denied, unclassified, appleSigned, developerSigned, unsigned, lowRisk, inbound, outbound, localNetwork
    var id: String { rawValue }
    var label: String {
        switch self {
        case .allowed: "Allowed"
        case .denied: "Denied"
        case .unclassified: "Unclassified"
        case .appleSigned: "Signed by Apple"
        case .developerSigned: "Signed by a developer (incl. App Store)"
        case .unsigned: "Unsigned or ad-hoc"
        case .lowRisk: "Low risk (under 25)"
        case .inbound: "Inbound"
        case .outbound: "Outbound"
        case .localNetwork: "Local network destinations"
        }
    }

    func hides(_ r: ConsoleRow) -> Bool {
        let p = r.profile
        switch self {
        case .allowed: return r.rule?.verdict == .allow
        case .denied: return r.rule?.verdict == .deny
        case .unclassified: return r.rule == nil
        case .appleSigned: return r.signer.kind == .apple
        case .developerSigned: return r.signer.kind == .developer || r.signer.kind == .appStore
        case .unsigned: return r.signer.kind == .unsigned || r.signer.kind == .adhoc
        case .lowRisk: return r.risk < 25
        case .inbound: return p.key.direction == .inbound
        case .outbound: return p.key.direction == .outbound
        case .localNetwork: return p.key.direction == .outbound && RiskHeuristics.isPrivate(p.key.host)
        }
    }
}

struct ConsoleView: View {
    enum Filter: String, CaseIterable, Identifiable {
        case all = "All", unclassified = "Unclassified", allowed = "Allowed", denied = "Denied", risky = "High risk",
             knownBad = "Threat intel hits", processAlerts = "Process alerts (EDR)", vulnerable = "Vulnerable app",
             suggested = "Has suggestion"
        var id: String { rawValue }
    }

    @EnvironmentObject var model: AppModel
    @State private var search = ""
    @State private var filter: Filter = .all
    @State private var selection: Set<String> = []
    @State private var sortOrder = [KeyPathComparator(\ConsoleRow.lastSeen, order: .reverse)]
    @State private var showInspector = true
    @AppStorage("console.hide") private var hideRaw = ""
    @AppStorage("console.hideSigners") private var hideSignersRaw = ""
    @AppStorage("console.hideApps") private var hideAppsRaw = ""      // process paths, newline-separated
    @AppStorage("console.hideText") private var hideTextRaw = ""      // user patterns, newline-separated
    @State private var editingHideText = false

    private var hiddenApps: Set<String> { Set(hideAppsRaw.split(separator: "\n").map(String.init)) }
    private var hideTexts: [String] { hideTextRaw.split(separator: "\n").map(String.init) }
    private var hideCount: Int { hidden.count + hiddenSigners.count + hiddenApps.count + hideTexts.count }
    private func showEverything() { hideRaw = ""; hideSignersRaw = ""; hideAppsRaw = ""; hideTextRaw = "" }
    private func toggleApp(_ path: String) {
        var h = hiddenApps
        if h.contains(path) { h.remove(path) } else { h.insert(path) }
        hideAppsRaw = h.sorted().joined(separator: "\n")
    }
    /// Applications present in the console, most connections first.
    private var appsPresent: [(path: String, name: String, count: Int)] {
        var counts: [String: (String, Int)] = [:]
        for p in model.profiles.values { counts[p.processPath] = (p.appName, (counts[p.processPath]?.1 ?? 0) + 1) }
        return counts.map { ($0.key, $0.value.0, $0.value.1) }.sorted { $0.count > $1.count }
    }

    private var hidden: Set<HideOption> { Set(hideRaw.split(separator: ",").compactMap { HideOption(rawValue: String($0)) }) }
    private var hiddenSigners: Set<String> { Set(hideSignersRaw.split(separator: ",").map(String.init)) }
    private func toggle(_ o: HideOption) {
        var h = hidden
        if h.contains(o) { h.remove(o) } else { h.insert(o) }
        hideRaw = h.map(\.rawValue).sorted().joined(separator: ",")
    }
    private func toggleSigner(_ key: String) {
        var h = hiddenSigners
        if h.contains(key) { h.remove(key) } else { h.insert(key) }
        hideSignersRaw = h.sorted().joined(separator: ",")
    }
    /// Signers present in the console, most connections first (ad-hoc/unsigned grouped under one key).
    private var signersPresent: [(key: String, name: String, count: Int)] {
        var counts: [String: (String, Int)] = [:]
        for p in model.profiles.values {
            let s = p.signer
            let key = s.ruleKey ?? (s.kind == .adhoc ? "~adhoc" : "~unsigned")
            counts[key] = (s.display, (counts[key]?.1 ?? 0) + 1)
        }
        return counts.map { ($0.key, $0.value.0, $0.value.1) }.sorted { $0.count > $1.count }
    }
    private func signerKey(_ s: SignerInfo) -> String { s.ruleKey ?? (s.kind == .adhoc ? "~adhoc" : "~unsigned") }

    private func clearAll() {
        guard Confirm.run(title: "Clear all \(model.profiles.count) logged connections?",
                          message: "Removes every logged connection, its LLM description and suggestion, and the live log. Your allow/deny rules, decision history, detections and vulnerabilities are kept, and connections that happen again are profiled from scratch. This can't be undone.",
                          action: "Clear Connections", destructive: true) else { return }
        selection.removeAll()
        model.clearConnections()
    }

    private func acceptSuggestions(atLeast t: Int, count: Int) {
        guard Confirm.run(title: "Accept \(count) suggestion\(count == 1 ? "" : "s") with confidence ≥ \(t)%?",
                          message: "Each becomes an allow or deny rule, as if you had chosen it.", action: "Accept") else { return }
        model.acceptSuggestions(model.profiles.values.filter { $0.suggestion.map { $0.confidence >= t } == true && model.decision(for: $0) == nil }.map(\.id))
    }

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
            case .vulnerable: if p.vuln == nil { return nil }
            }
            if hidden.contains(where: { $0.hides(row) }) || hiddenSigners.contains(signerKey(row.signer))
                || hiddenApps.contains(p.processPath) { return nil }
            if !hideTexts.isEmpty {
                let fields = [p.appName, p.processPath, p.destination, p.hostname ?? "", row.summary, row.signerName,
                              p.addresses.joined(separator: " ")]
                if hideTexts.contains(where: { t in fields.contains { HideText.matches(t, $0) } }) { return nil }
            }
            if !q.isEmpty && ![p.appName, p.processPath, p.destination, p.hostname ?? "", row.summary, row.signerName,
                               p.addresses.joined(separator: " ")].contains(where: { $0.lowercased().contains(q) }) {
                return nil
            }
            return row
        }.sorted(using: sortOrder)
    }

    var body: some View {
        let rows = rows
        let hiddenCount = model.profiles.count - rows.count
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
            TableColumn("Signed by", value: \.signerName) { r in
                SignerCell(signer: r.signer, rule: r.signer.ruleKey.flatMap { model.signerRule($0) })
            }.width(min: 100, ideal: 150)
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
            Group {
            TableColumn("What it's doing", value: \.summary) { (r: ConsoleRow) in
                SummaryCell(summary: r.summary, analyzing: model.analyzingID == r.id)
            }.width(min: 200, ideal: 420)
            TableColumn("Seen", value: \.count) { (r: ConsoleRow) in Text(String(r.count)).monospacedDigit() }.width(50)
            TableColumn("Last", value: \.lastSeen) { (r: ConsoleRow) in Text(Ago.text(r.lastSeen)).foregroundStyle(.secondary) }
                .width(90)
            }
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
            let signers = Dictionary(grouping: ps.map(\.signer).filter { $0.ruleKey != nil }, by: { $0.ruleKey! }).compactMap { $0.value.first }
            if !signers.isEmpty {
                Divider()
                ForEach(signers, id: \.self) { s in
                    if let r = model.signerRule(s.ruleKey!) {
                        Button("Remove \(r.verdict == .allow ? "Trust" : "Block") for \(s.display)") { model.setSignerTrust(s, nil) }
                    } else {
                        Button("Trust Everything Signed by \(s.display)") { model.setSignerTrust(s, .allow) }
                        Button("Block Everything Signed by \(s.display)") { model.setSignerTrust(s, .deny) }
                    }
                }
            }
            Divider()
            let paths = Set(ps.map(\.processPath))
            Button(paths.count == 1 ? "Hide \(ps.first!.appName)" : "Hide These \(paths.count) Apps") {
                hideAppsRaw = hiddenApps.union(paths).sorted().joined(separator: "\n")
                selection.removeAll()
            }
            let hideSigners = Set(ps.map { signerKey($0.signer) })
            if hideSigners.count == 1, let s = ps.first?.signer {
                Button("Hide Everything Signed by \(s.display)") {
                    hideSignersRaw = hiddenSigners.union(hideSigners).sorted().joined(separator: ",")
                    selection.removeAll()
                }
            }
            Divider()
            Button("Analyze with LLM") { model.reanalyze(Array(ids)) }
            if model.canSuggest {
                Button("Suggest Action with LLM") { model.requestSuggestions(Array(ids)) }
            }
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
                            Button("Accept all with confidence ≥ \(t)% (\(n))") { acceptSuggestions(atLeast: t, count: n) }.disabled(n == 0)
                        }
                        Divider()
                        Button("Show suggested") { filter = .suggested }
                    } else {
                        Text("Learning: \(model.decisions.count)/\(Advisor.minimumDecisions) decisions observed")
                    }
                } label: { Label("Suggestions", systemImage: "wand.and.stars") }
            }
            ToolbarItem {
                Menu {
                    Section("Hide connections that are") {
                        ForEach(HideOption.allCases) { o in
                            Toggle(o.label, isOn: Binding(get: { hidden.contains(o) }, set: { _ in toggle(o) }))
                        }
                    }
                    Menu("Hide signers") {
                        ForEach(signersPresent, id: \.key) { s in
                            Toggle("\(s.name) (\(s.count))", isOn: Binding(get: { hiddenSigners.contains(s.key) }, set: { _ in toggleSigner(s.key) }))
                        }
                    }
                    Menu("Hide applications") {
                        ForEach(appsPresent, id: \.path) { a in
                            Toggle("\(a.name) (\(a.count))", isOn: Binding(get: { hiddenApps.contains(a.path) }, set: { _ in toggleApp(a.path) }))
                        }
                        // Hidden apps with no connections left still need a way back.
                        let gone = hiddenApps.subtracting(appsPresent.map(\.path))
                        if !gone.isEmpty {
                            Divider()
                            ForEach(gone.sorted(), id: \.self) { path in
                                Toggle((path as NSString).lastPathComponent, isOn: Binding(get: { true }, set: { _ in toggleApp(path) }))
                            }
                        }
                    }
                    Button(hideTexts.isEmpty ? "Hide Text…" : "Hide Text (\(hideTexts.count))…") { editingHideText = true }
                    Divider()
                    Button("Show Everything") { showEverything() }.disabled(hideCount == 0)
                } label: {
                    Label(hideCount == 0 ? "Hide" : "Hide (\(hideCount))",
                          systemImage: hideCount == 0 ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
                }
                .help("Hide connections by decision, signer, application, text, risk, direction…")
            }
            ToolbarItem {
                Picker("Show", selection: $filter) { ForEach(Filter.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.menu)
            }
            ToolbarItem {
                Button("Clear All Connections") { clearAll() }
                    .disabled(model.profiles.isEmpty)
                    .help("Erase every logged connection (rules are kept)")
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
        .sheet(isPresented: $editingHideText) { HideTextSheet(raw: $hideTextRaw) }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if hiddenCount > 0 && !(hideCount == 0 && filter == .all && search.isEmpty) {
                HStack {
                    Image(systemName: "eye.slash")
                    Text("\(hiddenCount) of \(model.profiles.count) connections hidden by filters")
                    Spacer()
                    Button("Show Everything") { showEverything(); filter = .all; search = "" }.buttonStyle(.bordered)
                }
                .font(.caption).foregroundStyle(Theme.dim)
                .padding(.horizontal, 14).padding(.vertical, 6)
                .background(.bar)
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(spacing: 0) {
            if let alert = model.tamperAlert {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "lock.trianglebadge.exclamationmark.fill")
                    Text(alert).fontWeight(.semibold).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Dismiss") { model.tamperAlert = nil }.buttonStyle(.bordered)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(Color(red: 0.6, green: 0.0, blue: 0.2))
            }
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
    @State private var who: RuleTarget.Who = .app
    @State private var dest: RuleTarget.Dest = .exact

    var body: some View {
        let p = profile
        // Selections from another connection may not apply to this one.
        let whoOpts = RuleTarget.whoOptions(p)
        let w = whoOpts.contains(who) ? who : .app
        let destOpts = RuleTarget.destOptions(p, who: w)
        let d = destOpts.contains(dest) ? dest : .exact
        let target = RuleTarget(who: w, dest: d)
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

                let appVulns = model.openVulns.filter { ($0.component.kind == .app || $0.component.kind == .homebrew)
                    && p.processPath.hasPrefix($0.component.location + "/") }.sorted { $0.priority > $1.priority }
                if !appVulns.isEmpty {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(appVulns.prefix(5)) { v in
                                HStack(alignment: .firstTextBaseline) {
                                    SeverityBadge(severity: v.severity)
                                    Text(v.vuln.cve ?? v.vuln.id).font(.callout.monospaced())
                                    if v.kev { Image(systemName: "flame.fill").foregroundStyle(Theme.red) }
                                    Spacer()
                                    if let fix = v.vuln.fixedVersions.first { Text("fix \(fix)").font(.caption).foregroundStyle(Theme.green) }
                                }
                            }
                            if appVulns.count > 5 { Text("and \(appVulns.count - 5) more").font(.caption).foregroundStyle(Theme.dim) }
                            Button("Open in Vulns") { model.section = .vulns }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    } label: { Label("Known vulnerabilities in \(p.appName)", systemImage: "ladybug") }
                }

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
                            if model.analyzingID == p.id {
                                Text("Analyzing…").foregroundStyle(.secondary)
                            } else if model.lowPowerLLM {
                                Text("Low power: not analyzed unless you ask.").foregroundStyle(.secondary)
                                Button("Analyze with LLM") { model.reanalyze([p.id]) }
                            } else {
                                Text("Not analyzed yet (\(model.llmStatus))").foregroundStyle(.secondary)
                            }
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
                        Picker("Who", selection: Binding(get: { w }, set: { who = $0 })) {
                            ForEach(whoOpts, id: \.self) { Text(RuleTarget.whoTitle($0, p)).tag($0) }
                        }
                        Picker(p.key.direction == .outbound ? "Destination" : "From", selection: Binding(get: { d }, set: { dest = $0 })) {
                            ForEach(destOpts, id: \.self) { Text(RuleTarget.destTitle($0, p)).tag($0) }
                        }
                        if w != .app && d != .exact {
                            Text(w == .signer
                                 ? "Covers every app with a verified signature from \(p.signer.display), and no other apps."
                                 : "Covers every app on this Mac, signed or not.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        HStack {
                            Button { model.classify(p, .allow, target: target) } label: { Label("Allow", systemImage: "checkmark") }
                                .tint(Theme.green.opacity(0.8))
                            Button { model.classify(p, .deny, target: target) } label: { Label("Deny", systemImage: "xmark") }
                                .tint(Theme.red)
                            Spacer()
                            if rule != nil { Button("Clear") { model.unclassify(p) } }
                        }
                        .buttonStyle(.borderedProminent)
                        if let rule {
                            Text("Decided by rule: \(rule.sentence)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        let s = p.signer
                        if s.ruleKey != nil {
                            Divider()
                            HStack {
                                Image(systemName: "signature")
                                Text(s.display).fontWeight(.semibold)
                                Spacer()
                                if let r = model.signerRule(s.ruleKey!) {
                                    Text(r.verdict == .allow ? "trusted" : "blocked").foregroundStyle(r.verdict == .allow ? Theme.green : Theme.red)
                                    Button("Remove") { model.setSignerTrust(s, nil) }
                                } else {
                                    Button("Trust Signer") { model.setSignerTrust(s, .allow) }
                                        .help("Allow outbound connections from every app with a verified signature from \(s.display)")
                                    Button("Block Signer") { model.setSignerTrust(s, .deny) }
                                }
                            }
                            .font(.callout)
                        }
                    }.padding(4)
                }

                CaptureBox(profile: p)

                GroupBox("Details") {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                        row("Path", p.processPath)
                        row("Signed by", p.signer.display + (p.teamID.map { " · team \($0)" } ?? ""))
                        row("Identifier", p.signingID ?? "—")
                        row("Direction", p.key.direction.rawValue)
                        row("Protocol", p.key.proto.rawValue.uppercased())
                        row("Hostname", hostnameText(p))
                        row("Remote IPs", p.addresses.joined(separator: "\n"))
                        row("Connections", "\(p.count)")
                        row("First seen", p.firstSeen.formatted())
                        row("Last seen", p.lastSeen.formatted())
                        row("Last outcome", p.lastOutcome.rawValue)
                    }.font(.callout).padding(4)
                }
                HStack {
                    Button(p.analysis == nil ? "Analyze" : "Re-analyze") { model.reanalyze([p.id]) }
                    if model.canSuggest && rule == nil {
                        Button(p.suggestion == nil ? "Suggest Action" : "Refresh Suggestion") { model.requestSuggestions([p.id]) }
                            .help("Ask the LLM what you'd likely decide, based on your past decisions")
                    }
                }
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

    private func hostnameText(_ p: Profile) -> String {
        guard let h = p.hostname else {
            if p.key.direction == .inbound { return "—" }
            return p.nameChecked == true ? "none: no DNS lookup or TLS server name preceded the connection"
                                         : "not observable (enable hostname capture in Settings → Filter)"
        }
        var s = h
        if let src = p.hostnameSource.flatMap(NameSource.init(rawValue:)) { s += "\nvia \(src.label)" }
        if let alt = p.alternativeNames, !alt.isEmpty { s += "\nsame IP also served: \(alt.prefix(4).joined(separator: ", "))" }
        return s
    }
}

struct SignerCell: View {
    var signer: SignerInfo
    var rule: Rule?
    var body: some View {
        HStack(spacing: 4) {
            if let t = rule {
                Image(systemName: t.verdict == .allow ? "checkmark.seal.fill" : "xmark.seal.fill")
                    .foregroundStyle(t.verdict == .allow ? Theme.green : Theme.red)
                    .help(t.verdict == .allow ? "Trusted signer" : "Blocked signer")
            }
            Text(signer.display).lineLimit(1).foregroundStyle(color)
        }
        .help(signer.teamID.map { "Team ID \($0)" } ?? (signer.kind == .apple ? "Apple platform signature" : "No verified developer signature"))
    }
    private var color: Color {
        switch signer.kind {
        case .unsigned, .adhoc: Theme.amber
        case .apple: Theme.dim
        default: .primary
        }
    }
}

struct SummaryCell: View {
    var summary: String
    var analyzing: Bool
    var body: some View {
        if summary.isEmpty {
            Text(analyzing ? "Analyzing…" : "—").foregroundStyle(.tertiary)
        } else {
            Text(summary).lineLimit(2)
        }
    }
}

/// Free-text hide patterns: case-insensitive substring, or a wildcard pattern when it contains "*".
enum HideText {
    static func matches(_ pattern: String, _ field: String) -> Bool {
        let p = pattern.trimmingCharacters(in: .whitespaces).lowercased()
        guard !p.isEmpty else { return false }
        let f = field.lowercased()
        guard p.contains("*") else { return f.contains(p) }
        let regex = "^" + p.split(separator: "*", omittingEmptySubsequences: false)
            .map { NSRegularExpression.escapedPattern(for: String($0)) }.joined(separator: ".*") + "$"
        return f.range(of: regex, options: .regularExpression) != nil
    }
}

struct HideTextSheet: View {
    @Binding var raw: String
    @Environment(\.dismiss) private var dismiss
    @State private var new = ""
    private var items: [String] { raw.split(separator: "\n").map(String.init) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Hide connections containing text").font(.headline)
            Text("Matches app name, path, destination, hostname, IPs, signer and description, ignoring case. Use * as a wildcard over a whole field (e.g. *.apple.com or 17.*).")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField("Text or pattern", text: $new).onSubmit(add)
                Button("Add", action: add).disabled(new.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            List {
                ForEach(items, id: \.self) { t in
                    HStack {
                        Text(t).font(.body.monospaced())
                        Spacer()
                        Button { raw = items.filter { $0 != t }.joined(separator: "\n") } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.borderless)
                    }
                }
            }
            .frame(minHeight: 160)
            .overlay { if items.isEmpty { Text("No text filters").foregroundStyle(.secondary) } }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func add() {
        let t = new.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "\n", with: " ")
        guard !t.isEmpty, !items.contains(t) else { return }
        raw = (items + [t]).joined(separator: "\n")
        new = ""
    }
}
