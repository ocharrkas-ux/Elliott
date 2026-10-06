import SwiftUI

/// A secret (token, password, webhook URL) kept in the Keychain, never in Elliott's settings file.
struct SecretField: View {
    var title: String
    var account: String
    @State private var value = ""
    @State private var saved = false

    var body: some View {
        HStack {
            SecureField(title, text: $value, prompt: Text(saved ? "saved in Keychain" : "not set"))
                .onSubmit(save)
            Button("Save", action: save).disabled(value.isEmpty)
            if saved { Button("Clear") { Keychain.set(nil, for: account); saved = false } }
        }
        .onAppear { saved = !(Keychain.get(account) ?? "").isEmpty }
    }

    private func save() {
        guard !value.isEmpty else { return }
        Keychain.set(value, for: account)
        value = ""
        saved = true
    }
}

struct DetectionSettingsView: View {
    @EnvironmentObject var model: AppModel
    @ObservedObject var store: SecurityStore
    @State private var fingerprints = ""

    var body: some View {
        Form {
            Section("Network behavior") {
                Toggle("Beaconing: regular check-ins to the same destination", isOn: $model.settings.detect.beaconing)
                Toggle("DNS: generated domains and DNS tunnelling", isOn: $model.settings.detect.dnsAnalytics)
                Toggle("Unusually large uploads by an app (vs its own history)", isOn: $model.settings.detect.volumeAnomalies)
                Toggle("New devices on the local network", isOn: $model.settings.detect.newLANDevices)
                Toggle("Same threat on several Elliott devices (correlation)", isOn: $model.settings.detect.correlation)
                Toggle("Newly registered domains (looks up registration dates)", isOn: $model.settings.detect.domainAge)
                Text("Domain age sends the names of domains your apps contact to the domain registries (RDAP), at most 60 an hour. Everything else is analyzed on this Mac. DNS and TLS detections need hostname capture (the helper).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("TLS fingerprints (JA3 / JA4)") {
                Toggle("Flag connections whose TLS handshake matches known malware", isOn: $model.settings.detect.tlsFingerprints)
                Text(store.tlsFeedCount > 0 ? "\(store.tlsFeedCount) known-malicious JA3 fingerprints loaded (abuse.ch SSLBL)." : "The abuse.ch SSLBL list loads in the background.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Your own fingerprints (JA3 MD5 or JA4, comma-separated)", text: $fingerprints, axis: .vertical)
                    .onSubmit { model.settings.detect.customTLSFingerprints = fingerprints.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } }
            }
            Section("Files") {
                Toggle("Scan new programs, scripts and installers (Downloads, Desktop, temp and shared folders, launch items)", isOn: $model.settings.detect.fileScanning)
                Text("\(store.malwareHashCount > 0 ? "\(store.malwareHashCount) recent malware hashes (MalwareBazaar) checked locally. " : "")\(store.lastFileScan.map { "Last scan \($0.formatted(.relative(presentation: .named)))." } ?? "")")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Look up unsigned files on VirusTotal (key in Threat Intel settings)", isOn: $model.settings.detect.virusTotalFiles)
                Toggle("Look up unsigned files on MalwareBazaar", isOn: $model.settings.detect.malwareBazaar)
                if model.settings.detect.malwareBazaar { SecretField(title: "MalwareBazaar Auth-Key", account: "malwarebazaar-key") }
                HStack {
                    Text(model.settings.detect.yaraRulesFolder ?? "No YARA rules folder")
                        .foregroundStyle(model.settings.detect.yaraRulesFolder == nil ? Theme.dim : .primary).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Choose…") {
                        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = true
                        p.message = "Choose a folder of .yar rules (or one rules file)"
                        if p.runModal() == .OK { model.settings.detect.yaraRulesFolder = p.url?.path }
                    }
                    if model.settings.detect.yaraRulesFolder != nil { Button("Clear") { model.settings.detect.yaraRulesFolder = nil } }
                }
                Text(FileScanner.yaraPath == nil ? "YARA isn't installed (brew install yara); rules are used once it is." : "YARA found at \(FileScanner.yaraPath!).")
                    .font(.caption).foregroundStyle(.secondary)
                Button(store.fileScanning ? "Scanning…" : "Scan Files Now") { Task { await model.scanFiles() } }.disabled(store.fileScanning)
                Text("Only the SHA-256 of a file is ever sent for lookups, and only for files that aren't properly signed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onAppear { fingerprints = model.settings.detect.customTLSFingerprints.joined(separator: ", ") }
    }
}

struct IntegrationsSettingsView: View {
    @EnvironmentObject var model: AppModel
    @ObservedObject var store: SecurityStore
    @State private var testResult: [UUID: String] = [:]

    var body: some View {
        Form {
            Section("Event history") {
                Toggle("Keep a searchable history of events", isOn: $model.settings.logging.enabled)
                Toggle("Include every new connection", isOn: $model.settings.logging.logConnections)
                Stepper("Keep events for \(model.settings.logging.retentionDays) days", value: $model.settings.logging.retentionDays, in: 1...365)
                Text("Stored on this Mac (events.sqlite). Every event is signed together with the one before it, so edits or deletions show up when you verify the audit trail.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("SIEM forwarding") {
                ForEach($model.settings.integrations.forwarders) { $f in forwarderRow($f) }
                Menu("Add Destination") {
                    ForEach(Forwarder.Kind.allCases) { k in
                        Button(k.rawValue) {
                            var f = Forwarder(); f.kind = k; f.name = k.rawValue
                            if k != .syslog { f.host = "https://"; f.format = .json }
                            model.settings.integrations.forwarders.append(f)
                        }
                    }
                }
            }
            Section("Alerts off this Mac") {
                ForEach($model.settings.integrations.channels) { $c in channelRow($c) }
                Menu("Add Channel") {
                    ForEach(AlertChannel.Kind.allCases) { k in
                        Button(k.rawValue) {
                            var c = AlertChannel(); c.kind = k; c.name = k.rawValue
                            if k == .ntfy { c.target = "https://ntfy.sh/" }
                            model.settings.integrations.channels.append(c)
                        }
                    }
                }
                Stepper("At most \(model.settings.integrations.maxAlertsPerHour) alerts per channel per hour", value: $model.settings.integrations.maxAlertsPerHour, in: 1...200)
                Text("Detections, exploited vulnerabilities and other alerts at or above each channel's level are sent; the same alert isn't repeated within an hour.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func status(_ id: UUID) -> some View {
        let s = store.integrationStatus[id]
        return HStack(spacing: 6) {
            if let t = testResult[id] { Text(t).foregroundStyle(t.hasPrefix("✓") ? Theme.green : Theme.red) }
            else if let e = s?.lastError { Text("✗ \(e)").foregroundStyle(Theme.red) }
            else if let ok = s?.lastSuccess { Text("✓ delivered \(ok.formatted(.relative(presentation: .named)))").foregroundStyle(Theme.green) }
            if let q = s?.queued, q > 0 { Text("· \(q) queued").foregroundStyle(Theme.dim) }
        }
        .font(.caption).lineLimit(2)
    }

    @ViewBuilder private func forwarderRow(_ f: Binding<Forwarder>) -> some View {
        DisclosureGroup {
            TextField("Name", text: f.name)
            if f.wrappedValue.kind == .syslog {
                TextField("Host", text: f.host)
                TextField("Port", value: f.port, format: .number.grouping(.never))
                Picker("Transport", selection: f.transport) { ForEach(Forwarder.Transport.allCases) { Text($0.rawValue).tag($0) } }
                Picker("Format", selection: f.format) { ForEach(Forwarder.Format.allCases) { Text($0.rawValue).tag($0) } }
            } else {
                TextField(f.wrappedValue.kind == .splunk ? "HEC URL (https://splunk:8088)" : "Elasticsearch URL (https://es:9200)", text: f.host)
                TextField("Index", text: f.index)
                SecretField(title: f.wrappedValue.kind == .splunk ? "HEC token" : "API key (base64 id:key)", account: f.wrappedValue.secretAccount)
            }
            Picker("Minimum severity", selection: f.minSeverity) { ForEach(Severity.allCases) { Text($0.label).tag($0) } }
            HStack {
                ForEach(SecurityEvent.Kind.allCases) { k in
                    Toggle(k.rawValue, isOn: Binding(get: { f.wrappedValue.kinds.contains(k) },
                                                     set: { on in if on { f.wrappedValue.kinds.insert(k) } else { f.wrappedValue.kinds.remove(k) } }))
                        .toggleStyle(.checkbox).font(.caption)
                }
            }
            HStack {
                Button("Send Test") {
                    let fw = f.wrappedValue
                    testResult[fw.id] = "sending…"
                    Task { let e = await model.sec.integrations.test(forwarder: fw); testResult[fw.id] = e.map { "✗ \($0)" } ?? "✓ test event sent" }
                }
                Spacer()
                Button("Remove", role: .destructive) {
                    Keychain.set(nil, for: f.wrappedValue.secretAccount)
                    model.settings.integrations.forwarders.removeAll { $0.id == f.wrappedValue.id }
                }
            }
        } label: {
            HStack {
                Toggle("", isOn: f.enabled).labelsHidden()
                Text(f.wrappedValue.name.isEmpty ? f.wrappedValue.kind.rawValue : f.wrappedValue.name).fontWeight(.semibold)
                Spacer()
                status(f.wrappedValue.id)
            }
        }
    }

    @ViewBuilder private func channelRow(_ c: Binding<AlertChannel>) -> some View {
        DisclosureGroup {
            TextField("Name", text: c.name)
            switch c.wrappedValue.kind {
            case .slack, .teams, .discord, .webhook:
                SecretField(title: "Webhook URL (https://…)", account: c.wrappedValue.secretAccount)
            case .ntfy:
                TextField("Topic URL (https://ntfy.sh/your-secret-topic)", text: c.target)
                SecretField(title: "Access token (optional)", account: c.wrappedValue.secretAccount)
                Text("Anyone who knows a public ntfy topic name can read it: use a long random one, or your own server.").font(.caption).foregroundStyle(.secondary)
            case .pushover:
                TextField("Your user key", text: c.target)
                SecretField(title: "Application API token", account: c.wrappedValue.secretAccount)
            case .email:
                TextField("SMTP server (e.g. smtp.gmail.com)", text: c.target)
                TextField("Port", value: c.smtpPort, format: .number.grouping(.never))
                TextField("Username", text: c.smtpUser)
                SecretField(title: "Password (an app password)", account: c.wrappedValue.secretAccount)
                TextField("From (defaults to username)", text: c.from)
                TextField("To (comma-separated)", text: c.to)
                Text("Implicit TLS (SSL/TLS, usually port 465).").font(.caption).foregroundStyle(.secondary)
            }
            Picker("Alert at", selection: c.minSeverity) { ForEach(Severity.allCases) { Text("\($0.label) and above").tag($0) } }
            HStack {
                Button("Send Test") {
                    let ch = c.wrappedValue
                    testResult[ch.id] = "sending…"
                    Task { let e = await model.sec.integrations.test(channel: ch); testResult[ch.id] = e.map { "✗ \($0)" } ?? "✓ test alert sent" }
                }
                Spacer()
                Button("Remove", role: .destructive) {
                    Keychain.set(nil, for: c.wrappedValue.secretAccount)
                    model.settings.integrations.channels.removeAll { $0.id == c.wrappedValue.id }
                }
            }
        } label: {
            HStack {
                Toggle("", isOn: c.enabled).labelsHidden()
                Text(c.wrappedValue.name.isEmpty ? c.wrappedValue.kind.rawValue : c.wrappedValue.name).fontWeight(.semibold)
                Spacer()
                status(c.wrappedValue.id)
            }
        }
    }
}
