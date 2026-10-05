import SwiftUI

/// Start/stop a packet capture for the selected connection's app, destination, or both.
struct CaptureBox: View {
    @EnvironmentObject var model: AppModel
    var profile: Profile
    enum Scope: Hashable { case both, app, destination }
    @State private var scope: Scope = .both
    @State private var useIP = false
    @State private var error: String?
    @State private var starting = false

    var body: some View {
        let p = profile
        let running = model.captures(for: p)
        let outbound = p.key.direction == .outbound
        let fqdn = p.hostname.flatMap { RiskHeuristics.isIPLiteral($0) ? nil : $0 }
        let dest = useIP || fqdn == nil ? RuleTarget.ip(p) : fqdn!
        GroupBox("Packet capture") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(running) { c in
                    HStack {
                        Image(systemName: "record.circle").foregroundStyle(Theme.red).symbolEffect(.pulse)
                        VStack(alignment: .leading) {
                            Text(c.label).font(.callout)
                            Text("\(c.packets) packets · \(ByteCountFormatter.string(fromByteCount: Int64(c.bytes), countStyle: .file))")
                                .font(.caption).foregroundStyle(Theme.dim)
                        }
                        Spacer()
                        Button("Stop") { Task { await model.stopCapture(c.id) } }
                    }
                }
                Picker("Record", selection: $scope) {
                    Text("\(p.appName) ↔ \(dest)").tag(Scope.both)
                    Text("All of \(p.appName)'s traffic").tag(Scope.app)
                    Text("Any app ↔ \(dest)").tag(Scope.destination)
                }
                if outbound && fqdn != nil && scope != .app {
                    Toggle("Match this IP only (not every address of \(fqdn!))", isOn: $useIP).font(.caption)
                }
                HStack {
                    Button(starting ? "Starting…" : "Start Capture") { start(dest: dest) }
                        .disabled(starting || !model.helper.connected)
                    Spacer()
                    Button("All Captures") { model.section = .captures }.buttonStyle(.link)
                }
                if let error { Text(error).font(.caption).foregroundStyle(Theme.red) }
                if !model.helper.connected { Text("Needs the helper (Settings).").font(.caption).foregroundStyle(.secondary) }
            }
            .padding(4)
        }
    }

    private func start(dest: String) {
        let p = profile
        let t = CaptureTarget(appPath: scope == .destination ? nil : p.processPath,
                              appName: scope == .destination ? nil : p.appName,
                              destination: scope == .app ? nil : dest)
        starting = true
        Task {
            error = await model.startCapture(t)
            starting = false
        }
    }
}

struct CapturesView: View {
    @EnvironmentObject var model: AppModel
    @State private var showNew = false
    @State private var selection: PcapStatus.ID?

    var body: some View {
        Table(model.pcaps, selection: $selection) {
            TableColumn("Capture") { c in
                HStack {
                    if c.running { Image(systemName: "record.circle").foregroundStyle(Theme.red) }
                    VStack(alignment: .leading) {
                        Text(c.label)
                        if let e = c.error { Text(e).font(.caption).foregroundStyle(Theme.red) }
                    }
                }
            }.width(min: 200, ideal: 280)
            TableColumn("Started") { Text($0.started.formatted(date: .abbreviated, time: .shortened)).foregroundStyle(Theme.dim) }.width(140)
            TableColumn("Duration") { c in
                Text(Duration.seconds((c.ended ?? Date()).timeIntervalSince(c.started)).formatted(.time(pattern: .hourMinuteSecond)))
                    .monospacedDigit()
            }.width(80)
            TableColumn("Packets") { Text(c($0.packets)).monospacedDigit() }.width(80)
            TableColumn("Size") { Text(ByteCountFormatter.string(fromByteCount: Int64($0.bytes), countStyle: .file)).monospacedDigit() }.width(80)
            TableColumn("") { c in
                HStack {
                    if c.running {
                        Button("Stop") { Task { await model.stopCapture(c.id) } }
                    } else {
                        Button("Open") { NSWorkspace.shared.open(URL(fileURLWithPath: c.file)) }
                            .help("Opens in the app registered for .pcapng files (e.g. Wireshark)")
                        Button("Reveal") { NSWorkspace.shared.selectFile(c.file, inFileViewerRootedAtPath: "") }
                        Button("Delete", role: .destructive) {
                            guard Confirm.run(title: "Delete \((c.file as NSString).lastPathComponent)?", message: "The capture file is removed.",
                                              action: "Delete", destructive: true) else { return }
                            Task { await model.deleteCapture(c) }
                        }
                    }
                }.buttonStyle(.borderless)
            }.width(min: 170, ideal: 190)
        }
        .overlay {
            if model.pcaps.isEmpty {
                ContentUnavailableView("no captures", systemImage: "waveform.path.ecg.rectangle",
                                       description: Text("Record an application's packets, a destination's, or both. Start one here or from a connection's details."))
            }
        }
        .toolbar {
            ToolbarItem { Button("New Capture…") { showNew = true }.disabled(!model.helper.connected) }
            ToolbarItem {
                Button { NSWorkspace.shared.open(URL(fileURLWithPath: "/Library/Application Support/Elliott/Captures")) } label: {
                    Label("Captures Folder", systemImage: "folder")
                }
            }
        }
        .sheet(isPresented: $showNew) { NewCaptureSheet() }
        .task { await model.refreshCaptures() }
        .navigationTitle("pcap")
    }

    private func c(_ n: Int) -> String { n == 0 ? "—" : n.formatted() }
}

struct NewCaptureSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var appPath = ""
    @State private var otherApp = ""        // path or process name, when the app isn't in the console
    @State private var destination = ""
    private static let other = "\u{1}other"
    @State private var minutes = 60
    @State private var maxMB = 200
    @State private var error: String?
    @State private var starting = false

    private var apps: [(path: String, name: String)] {
        var seen: [String: String] = [:]
        for p in model.profiles.values { seen[p.processPath] = p.appName }
        return seen.map { ($0.key, $0.value) }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
    private var destValid: Bool {
        let d = destination.trimmingCharacters(in: .whitespaces)
        return d.isEmpty || RiskHeuristics.isIPLiteral(d) || AppModel.normalizedDomainPattern(d) != nil
    }

    var body: some View {
        Form {
            Section {
                Picker("Application", selection: $appPath) {
                    Text("Any application").tag("")
                    Text("Other application…").tag(Self.other)
                    Divider()
                    ForEach(apps, id: \.path) { Text($0.name).tag($0.path) }
                }
                if appPath == Self.other {
                    HStack {
                        TextField("Process", text: $otherApp, prompt: Text("name (curl) or path (/usr/bin/curl)"))
                        Button("Choose…", action: chooseApp)
                    }
                }
                TextField("Destination", text: $destination, prompt: Text("any — or an IP, host.example.com, *.example.com"))
                if !destValid { Text("Not an IP address or hostname.").font(.caption).foregroundStyle(Theme.red) }
            } footer: {
                Text("Choose an application, a destination, or both (then only that app's traffic to that destination is recorded). Packets are attributed to processes by macOS itself; each one is labelled with its process in the file.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Limits") {
                Stepper("Stop after \(minutes) minutes", value: $minutes, in: 1...1440, step: minutes < 10 ? 1 : 10)
                Stepper("Stop at \(maxMB) MB", value: $maxMB, in: 10...2000, step: 10)
            }
            if let error { Text(error).foregroundStyle(Theme.red) }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(starting ? "Starting…" : "Start") { start() }
                    .disabled(starting || !destValid || (appPath == Self.other && chosenApp == nil)
                              || (appPath.isEmpty && destination.trimmingCharacters(in: .whitespaces).isEmpty))
            }
        }
    }

    /// The typed process: a path, or a bare executable name (matched by the name the kernel records).
    private var chosenApp: String? {
        let t = otherApp.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? nil : t
    }

    private func chooseApp() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.treatsFilePackagesAsDirectories = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.message = "Choose an application or a command-line program"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // An .app bundle records packets under its main executable's name.
        otherApp = (url.pathExtension == "app" ? Bundle(url: url)?.executableURL?.path : nil) ?? url.path
    }

    private func start() {
        let d = destination.trimmingCharacters(in: .whitespaces)
        let dest = d.isEmpty ? nil : RiskHeuristics.isIPLiteral(d) ? d : AppModel.normalizedDomainPattern(d)
        let app = appPath == Self.other ? chosenApp : appPath.isEmpty ? nil : appPath
        let t = CaptureTarget(appPath: app,
                              appName: apps.first { $0.path == app }?.name ?? app.map { ($0 as NSString).lastPathComponent },
                              destination: dest)
        starting = true
        Task {
            error = await model.startCapture(t, minutes: minutes, maxMB: maxMB)
            starting = false
            if error == nil { dismiss() }
        }
    }
}
