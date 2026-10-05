import SwiftUI

/// Preview-then-apply sheet: what will change, for which vulnerabilities, and why some can't be fixed automatically.
struct RemediationSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var componentIDs: Set<String>?

    @State private var plans: [RemediationPlan]?
    @State private var selected: Set<String> = []
    @State private var started = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GlitchText(text: "// REMEDIATE", font: .system(size: 18, weight: .heavy, design: .monospaced))
            if started {
                runLog
            } else if let plans {
                planList(plans)
            } else {
                HStack { ProgressView().controlSize(.small); Text("Working out fixes (checking Homebrew, virtualenvs, git status)…") }
                    .foregroundStyle(Theme.dim)
                Spacer()
            }
            HStack {
                if !started {
                    Text(selectionSummary).font(.caption).foregroundStyle(Theme.dim)
                }
                Spacer()
                Button(started && !model.remediating ? "Done" : "Cancel") { dismiss() }
                    .disabled(model.remediating)
                if !started {
                    Button("Apply \(selected.count) Fix\(selected.count == 1 ? "" : "es")") {
                        started = true
                        let chosen = (plans ?? []).filter { selected.contains($0.id) }
                        Task { await model.applyRemediation(chosen) }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected.isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: 760, height: 620)
        .task {
            let p = await model.remediationPlans(for: componentIDs)
            plans = p
            selected = Set(p.filter(\.actionable).map(\.id))
        }
    }

    private var selectionSummary: String {
        let chosen = (plans ?? []).filter { selected.contains($0.id) }
        let n = chosen.reduce(0) { $0 + $1.fixes.count }
        return "\(chosen.count) component\(chosen.count == 1 ? "" : "s") · fixes \(n) vulnerabilit\(n == 1 ? "y" : "ies"). Edited files are backed up; you can undo from the remediation tab."
    }

    private func planList(_ plans: [RemediationPlan]) -> some View {
        Group {
            if plans.isEmpty {
                ContentUnavailableView("nothing to remediate", systemImage: "checkmark.shield",
                                       description: Text("No open vulnerabilities at or above \(model.settings.remediation.minSeverity.label.lowercased()) severity (Settings → Vulnerabilities)."))
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(plans) { plan in PlanRow(plan: plan, selected: $selected) }
                    }
                }
            }
        }
    }

    private var runLog: some View {
        VStack(alignment: .leading, spacing: 6) {
            if model.remediating { ProgressView().progressViewStyle(.linear) }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(model.remediationLog.enumerated()), id: \.offset) { i, line in
                            Text(line).font(.caption.monospaced())
                                .foregroundStyle(line.hasPrefix("✓") ? Theme.green : line.hasPrefix("✗") ? Theme.red : line.hasPrefix("──") ? .primary : Theme.dim)
                                .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled).id(i)
                        }
                    }
                }
                .onChange(of: model.remediationLog.count) { _, n in proxy.scrollTo(n - 1, anchor: .bottom) }
            }
            .padding(8)
            .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

struct PlanRow: View {
    var plan: RemediationPlan
    @Binding var selected: Set<String>

    var body: some View {
        let on = Binding(get: { selected.contains(plan.id) },
                         set: { v in if v { selected.insert(plan.id) } else { selected.remove(plan.id) } })
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Toggle(isOn: on) { EmptyView() }.labelsHidden()
                        .disabled(!(plan.actionable || plan.steps.contains { $0.kind == .firewallRule }))
                    SeverityBadge(severity: plan.severity)
                    Text(plan.component.name).fontWeight(.bold)
                    Text(plan.target.map { "\(plan.component.version) → \($0)" } ?? plan.component.version).monospacedDigit()
                        .foregroundStyle(plan.majorUpgrade ? Theme.amber : Theme.green)
                    Spacer()
                    Text("fixes \(plan.fixes.count)").foregroundStyle(Theme.dim)
                    Text(plan.component.kind == .package ? (plan.component.ecosystem ?? "") : plan.component.kind.rawValue)
                        .font(.caption).foregroundStyle(Theme.dim)
                }
                if plan.component.kind == .package, let project = plan.component.project {
                    Text(project).font(.caption).foregroundStyle(Theme.dim).lineLimit(1).truncationMode(.middle)
                }
                ForEach(Array(plan.steps.enumerated()), id: \.offset) { _, step in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Image(systemName: icon(step.kind)).foregroundStyle(step.kind == .manual ? Theme.dim : Theme.red)
                            Text(step.summary).font(.callout.monospaced()).textSelection(.enabled)
                        }
                        ForEach(step.diff.prefix(6), id: \.self) { line in
                            Text(line).font(.caption.monospaced())
                                .foregroundStyle(line.hasPrefix("+") ? Theme.green : Theme.red).padding(.leading, 22)
                        }
                    }
                }
                ForEach(plan.warnings, id: \.self) { Label($0, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(Theme.amber) }
                if let why = plan.blocked {
                    Label(why, systemImage: "hand.raised").font(.caption).foregroundStyle(Theme.dim)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
            .opacity(plan.blocked != nil && !plan.steps.contains { $0.kind == .firewallRule } ? 0.7 : 1)
        }
    }

    private func icon(_ k: RemediationStep.Kind) -> String {
        switch k {
        case .command: "terminal"
        case .edit: "doc.text"
        case .firewallRule: "network.slash"
        case .manual: "hand.point.right"
        }
    }
}

/// History of applied remediations, with logs and undo.
struct RemediationHistory: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmUndo: RemediationRecord?

    var body: some View {
        List {
            if model.remediations.isEmpty {
                ContentUnavailableView("no remediations yet", systemImage: "wrench.and.screwdriver",
                                       description: Text("Use Remediate… to upgrade vulnerable Homebrew formulae and project dependencies."))
            }
            ForEach(model.remediations) { r in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        statusLabel(r.status)
                        Text(r.plan.component.name).fontWeight(.bold)
                        Text(r.plan.target.map { "\(r.plan.component.version) → \($0)" } ?? "").monospacedDigit().foregroundStyle(Theme.dim)
                        if let v = r.verifiedVersion { Text("now \(v)").font(.caption).foregroundStyle(Theme.green) }
                        if r.automatic { Text("auto").font(.caption2).padding(.horizontal, 4).background(Theme.dim.opacity(0.3), in: Capsule()) }
                        Spacer()
                        Text(r.date.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(Theme.dim)
                        if r.status != .undone && (!r.backups.isEmpty || !r.ruleIDs.isEmpty || r.plan.steps.contains { $0.undoCommand != nil }) {
                            Button("Undo…") { confirmUndo = r }.disabled(model.remediating)
                        }
                    }
                    DisclosureGroup("log (\(r.log.count) lines)") {
                        VStack(alignment: .leading, spacing: 1) {
                            ForEach(Array(r.log.enumerated()), id: \.offset) { _, l in
                                Text(l).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    .font(.caption)
                }
                .padding(.vertical, 4)
            }
        }
        .confirmationDialog("Undo remediation of \(confirmUndo?.plan.component.name ?? "")?",
                            isPresented: Binding(get: { confirmUndo != nil }, set: { if !$0 { confirmUndo = nil } })) {
            Button("Undo", role: .destructive) {
                if let r = confirmUndo { Task { await model.undoRemediation(r.id) } }
                confirmUndo = nil
            }
        } message: {
            Text("Restores edited files from backup, removes firewall rules it added, and reinstalls the previous version of pip packages. Homebrew upgrades can't be rolled back automatically.")
        }
    }

    private func statusLabel(_ s: RemediationRecord.Status) -> some View {
        let (text, color): (String, Color) = switch s {
        case .running: ("RUNNING", Theme.amber)
        case .succeeded: ("FIXED", Theme.green)
        case .partial: ("PARTIAL", Theme.amber)
        case .failed: ("FAILED", Theme.red)
        case .undone: ("UNDONE", Theme.dim)
        }
        return Text(text).font(.caption.weight(.heavy)).foregroundStyle(color)
    }
}

struct RemediationSettingsSection: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Section {
            Picker("Auto-remediation", selection: $model.settings.remediation.mode) {
                ForEach(RemediationSettings.Mode.allCases) { Text($0.rawValue).tag($0) }
            }
            if model.settings.remediation.mode != .off {
                Picker("Fix vulnerabilities rated", selection: $model.settings.remediation.minSeverity) {
                    ForEach(Severity.allCases.filter { $0 >= .low }) { Text("\($0.label.lowercased()) and above").tag($0) }
                }
                Toggle("Homebrew formulae (brew upgrade)", isOn: $model.settings.remediation.homebrew)
                Toggle("Project dependencies (re-pin requirements, npm/cargo/go/bundle/composer)", isOn: $model.settings.remediation.projects)
                Toggle("Also install upgrades into the project's Python virtualenv", isOn: $model.settings.remediation.installIntoVirtualenv)
                Toggle("Allow major-version upgrades", isOn: $model.settings.remediation.allowMajorUpgrades)
                Toggle("Skip projects with uncommitted changes in the files being edited", isOn: $model.settings.remediation.requireCleanGit)
                if model.settings.remediation.mode == .automatic {
                    Toggle("Automatically block network-exposed sensitive services", isOn: $model.settings.remediation.exposuresInAutomatic)
                }
            }
        } header: { Text("Remediation") } footer: {
            Text(model.settings.remediation.mode == .automatic
                 ? "After each scan Elliott applies every fix that isn't blocked (no major upgrades unless allowed, no dirty git files), verifies the new version, and notifies you. Edited files are backed up and can be undone from vulns → remediation."
                 : "Remediate… in the vulns view shows the exact commands and file changes before anything runs. Apps and macOS are never updated automatically: they update through their own updaters.")
                .font(.caption).foregroundStyle(model.settings.remediation.mode == .automatic ? Theme.amber : Theme.dim)
        }
    }
}
