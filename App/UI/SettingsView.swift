import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            FilterSettings().tabItem { Label("Filter", systemImage: "shield") }
            LLMSettingsView().tabItem { Label("Local LLM", systemImage: "cpu") }
            EDRSettingsView().tabItem { Label("EDR", systemImage: "exclamationmark.shield") }
            IntelSettingsView().tabItem { Label("Threat Intel", systemImage: "globe.badge.chevron.backward") }
            PaloAltoSettings().tabItem { Label("Palo Alto", systemImage: "flame") }
        }
        .frame(width: 600, height: 620)
        .padding()
    }
}

struct FilterSettings: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form {
            Section("Packet filter (pf) helper") {
                LabeledContent("Status", value: model.helper.statusLabel)
                if let e = model.helper.lastError { Text(e).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
                HStack {
                    Button("Install Helper") { model.helper.install() }
                        .disabled(model.helper.status == .enabled)
                    Button("Remove Helper") { Task { await model.helper.uninstall() } }
                        .disabled(model.helper.status == .notRegistered)
                }
                Text("A small root helper loads Bastion's rules into the macOS packet filter (anchor \(PFRules.anchor)). It enforces by address and port, so a rule applies to every app using that destination. In lockdown, new outbound TCP handshakes are held until you approve them. UDP to unapproved destinations is dropped (apps fall back to TCP). Rules stay enforced when the app is closed and after restart.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if model.hasFilterExtension {
            Section("Network Extension filter (per app)") {
                LabeledContent("Status", value: model.filter.state.label)
                LabeledContent("Connected to filter", value: model.filter.connected ? "Yes" : "No")
                HStack {
                    Button("Install / Update Filter") { model.filter.install() }
                    Button("Turn Off") { Task { await model.filter.setEnabled(false) } }
                        .disabled(model.filter.state != .enabled)
                }
                Text("Sees and decides on every connection per app, and pauses them in lockdown. Takes over from the pf helper while it's active. macOS asks you to allow it once in System Settings.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            }
            Section("Lockdown") {
                Toggle("Let Apple-signed system software through without asking", isOn: $model.settings.trustAppleSigned)
                Stepper("Deny unanswered requests after \(Int(model.settings.approvalTimeout)) s",
                        value: $model.settings.approvalTimeout, in: 10...600, step: 10)
                Text("If Bastion isn't running during lockdown, connections without a rule are denied (including Apple software, under the pf helper).")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

struct LLMSettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var models: [String] = []
    @State private var status = ""

    var body: some View {
        Form {
            Section("Model") {
                Toggle("Describe and rate connections with a local LLM", isOn: $model.settings.llm.enabled)
                Picker("Server", selection: $model.settings.llm.provider) {
                    Text("Ollama").tag(LLMSettings.Provider.ollama)
                    Text("OpenAI-compatible (LM Studio, llama.cpp)").tag(LLMSettings.Provider.openAICompatible)
                }
                TextField("URL", text: $model.settings.llm.baseURL)
                HStack {
                    TextField("Model", text: $model.settings.llm.model)
                    if !models.isEmpty {
                        Menu("Pick") { ForEach(models, id: \.self) { m in Button(m) { model.settings.llm.model = m } } }
                            .fixedSize()
                    }
                }
                HStack {
                    Button("Test") { Task { await test() } }
                    Text(status).font(.caption).foregroundStyle(.secondary)
                }
            }
            Section {
                Text("Runs entirely on this Mac. With Ollama: `brew install ollama`, `ollama serve`, then `ollama pull qwen2.5:3b` (about 2 GB). Any small instruction model works; 3–8B models give the best descriptions.")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                Button("Re-analyze All Connections") { model.reanalyze(Array(model.profiles.keys)) }
            }
            Section("Suggestions") {
                Toggle("Suggest allow/deny from my past decisions", isOn: $model.settings.suggestionsEnabled)
                let n = model.decisions.count
                LabeledContent("Decisions observed", value: "\(n)\(n < Advisor.minimumDecisions ? " (suggestions start at \(Advisor.minimumDecisions))" : "")")
                let rate = Advisor.matchRate(model.decisions)
                if rate.total > 0 {
                    LabeledContent("Suggestions matched your choice", value: "\(rate.matched)/\(rate.total) (\(rate.matched * 100 / rate.total)%)")
                }
                Text("Counts allow/deny choices made in the console, in lockdown prompts, rule edits and accepted suggestions. Bulk \"allow everything under risk X\" isn't counted. Suggestions are never applied without you.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Forget My Decisions", role: .destructive) { model.forgetDecisions() }.disabled(n == 0)
            }
        }
        .formStyle(.grouped)
    }

    private func test() async {
        status = "Connecting…"
        do {
            models = try await LocalLLM(settings: model.settings.llm).models()
            status = models.contains(model.settings.llm.model) || model.settings.llm.provider == .openAICompatible
                ? "Connected · \(models.count) models"
                : "Connected, but “\(model.settings.llm.model)” isn't installed (ollama pull \(model.settings.llm.model))"
        } catch {
            status = error.localizedDescription
        }
    }
}

struct PaloAltoSettings: View {
    @EnvironmentObject var model: AppModel
    @State private var status = ""
    @State private var seenFingerprint: String?

    var body: some View {
        Form {
            Section("Firewall") {
                Toggle("Mirror rules to a Palo Alto NGFW as shadow policies", isOn: $model.settings.pan.enabled)
                TextField("Management address", text: $model.settings.pan.host, prompt: Text("fw.example.com or 10.0.0.1"))
                SecureField("API key", text: $model.panKey)
                Picker("Target", selection: $model.settings.pan.target) {
                    Text("Firewall (vsys)").tag(PANSettings.Target.firewall)
                    Text("Panorama (device group)").tag(PANSettings.Target.panorama)
                }
                if model.settings.pan.target == .firewall {
                    TextField("vsys", text: $model.settings.pan.vsys)
                } else {
                    TextField("Device group", text: $model.settings.pan.deviceGroup)
                }
                TextField("This Mac's address", text: $model.settings.pan.macAddress,
                          prompt: Text(PolicyPlanner.primaryIPv4() ?? "auto"))
                HStack {
                    Button("Test Connection") { Task { await test() } }
                    if let fp = seenFingerprint, fp != model.settings.pan.pinnedSHA256 {
                        Button("Trust Certificate") { model.settings.pan.pinnedSHA256 = fp; Task { await test() } }
                    }
                    if model.settings.pan.pinnedSHA256 != nil {
                        Button("Forget Certificate") { model.settings.pan.pinnedSHA256 = nil }
                    }
                }
                if !status.isEmpty { Text(status).font(.caption).textSelection(.enabled) }
                if let fp = model.settings.pan.pinnedSHA256 {
                    Text("Pinned SHA-256 \(fp)").font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Section("Shadow policy") {
                Toggle("Sync automatically when rules change", isOn: $model.settings.pan.autoSync)
                Toggle("Create rules disabled (review before enabling)", isOn: $model.settings.pan.createDisabled)
                Toggle("Mirror lockdown as default-deny rules for this Mac", isOn: $model.settings.pan.mirrorLockdown)
                Toggle("Commit after syncing", isOn: $model.settings.pan.commit)
                if model.settings.pan.commit {
                    TextField("Only commit changes by admin", text: $model.settings.pan.commitAdmin,
                              prompt: Text("admin username (recommended)"))
                    Text("Without an admin name, a commit also commits everyone else's pending changes.")
                        .font(.caption).foregroundStyle(.orange)
                }
                Text("The firewall can't tell which app opened a connection, so shadow rules match this Mac's address + destination + port. When one app is allowed and another denied to the same destination, the rule is mirrored as allow.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func test() async {
        status = "Connecting…"
        let client = model.panClient
        do {
            status = "Connected: " + (try await client.systemInfo())
            seenFingerprint = client.observedSHA256
        } catch {
            seenFingerprint = client.observedSHA256
            status = error.localizedDescription
        }
    }
}
