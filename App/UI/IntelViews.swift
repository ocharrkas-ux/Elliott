import SwiftUI

struct IntelBadge: View {
    var intel: IntelSummary?
    var body: some View {
        switch intel?.reputation {
        case .knownBad?:
            Label("BAD", systemImage: "exclamationmark.octagon.fill").foregroundStyle(Theme.red).fontWeight(.heavy)
                .help(intel!.hits.map { "\($0.source): \($0.detail)" }.joined(separator: "\n"))
        case .suspicious?:
            Label("SUSP", systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.amber)
                .help(intel!.hits.map { "\($0.source): \($0.detail)" }.joined(separator: "\n"))
        case .clean?:
            Label("clean", systemImage: "checkmark.shield").foregroundStyle(Theme.dim)
        default:
            Text("—").foregroundStyle(.tertiary).help("Private, local or not yet checked")
        }
    }
}

struct SuggestionBadge: View {
    var suggestion: Suggestion
    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: "wand.and.stars").font(.caption2)
            Text(suggestion.verdict == .allow ? "ALLOW" : "DENY").fontWeight(.bold)
            Text("\(suggestion.confidence)%").foregroundStyle(Theme.dim).monospacedDigit()
        }
        .foregroundStyle(suggestion.verdict == .allow ? Theme.green : Theme.red)
        .opacity(suggestion.confidence < 60 ? 0.6 : 1)
    }
}

/// "Elliott thinks you'd deny this" with accept buttons and the past decisions behind it.
struct SuggestionBox: View {
    @EnvironmentObject var model: AppModel
    var profile: Profile

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if let s = profile.suggestion {
                    HStack {
                        Text("You'd probably").foregroundStyle(Theme.dim)
                        Text(s.verdict == .allow ? "ALLOW" : "DENY").fontWeight(.heavy)
                            .foregroundStyle(s.verdict == .allow ? Theme.green : Theme.red)
                        Text("this · \(s.confidence)% sure").foregroundStyle(Theme.dim)
                    }
                    Text(s.rationale).textSelection(.enabled)
                    HStack {
                        Button("Accept: \(s.verdict == .allow ? "Allow" : "Deny")") { model.acceptSuggestions([profile.id]) }
                            .buttonStyle(.borderedProminent)
                            .tint(s.verdict == .allow ? Theme.green.opacity(0.8) : Theme.red)
                        Spacer()
                        Text("from \(s.basedOn) of your decisions").font(.caption).foregroundStyle(Theme.dim)
                    }
                    DisclosureGroup("Similar past decisions") {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Advisor.examples(for: profile, in: model.decisions, limit: 5)) { d in
                                Text(d.exampleLine).font(.caption)
                                    .foregroundStyle(d.verdict == .allow ? Theme.green : Theme.red)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .font(.caption)
                } else if model.canSuggest {
                    Text(model.suggestingID == profile.id ? "Predicting your call…" : "No suggestion yet (queued).")
                        .foregroundStyle(Theme.dim)
                } else {
                    let n = model.decisions.count
                    Text(model.settings.suggestionsEnabled
                         ? "Learning your habits: \(n)/\(Advisor.minimumDecisions) decisions observed. Suggestions start after \(Advisor.minimumDecisions)."
                         : "Suggestions are off (Settings → Local LLM).")
                        .foregroundStyle(Theme.dim)
                    if model.settings.suggestionsEnabled {
                        ProgressView(value: Double(min(n, Advisor.minimumDecisions)), total: Double(Advisor.minimumDecisions))
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
        } label: {
            Label("Suggested action", systemImage: "wand.and.stars")
        }
    }
}

/// OSINT results for each remote IP, with links for manual pivoting.
struct IntelBox: View {
    @EnvironmentObject var model: AppModel
    var profile: Profile

    var body: some View {
        let ips = profile.addresses.filter(IPv4Set.isGlobal)
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if ips.isEmpty {
                    Text("Only private or local addresses: nothing to check.").foregroundStyle(Theme.dim)
                }
                ForEach(ips.prefix(8), id: \.self) { ip in
                    let entry = model.intel[ip]
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(ip).fontWeight(.semibold).textSelection(.enabled)
                            if let e = entry {
                                Text(e.reputation.label).foregroundStyle(color(e.reputation)).fontWeight(.bold)
                            } else {
                                Text("unchecked").foregroundStyle(Theme.dim)
                            }
                            Spacer()
                            Menu("Look up") {
                                link("AbuseIPDB", "https://www.abuseipdb.com/check/\(ip)")
                                link("VirusTotal", "https://www.virustotal.com/gui/ip-address/\(ip)")
                                link("GreyNoise", "https://viz.greynoise.io/ip/\(ip)")
                                link("Shodan", "https://www.shodan.io/host/\(ip)")
                                link("Talos", "https://talosintelligence.com/reputation_center/lookup?search=\(ip)")
                            }
                            .menuStyle(.borderlessButton).fixedSize()
                            .help("Opens the site in your browser (sends this IP to that site)")
                        }
                        if let e = entry {
                            ForEach(e.hits, id: \.self) { h in
                                Text("• \(h.source): \(h.detail)").font(.callout).foregroundStyle(color(h.severity))
                            }
                            if let org = e.org { Text("\(org)\(e.country.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(Theme.dim) }
                        }
                    }
                }
                Text("Checked against \(model.threatIntel.loadedFeeds) local blocklists (\(model.threatIntel.totalEntries.formatted()) ranges)\(model.onlineLookupsEnabled ? " + online lookups" : "").")
                    .font(.caption2).foregroundStyle(Theme.dim)
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
        } label: {
            Label("Threat intel (OSINT)", systemImage: "globe.badge.chevron.backward")
        }
    }

    private func color(_ r: Reputation) -> Color {
        switch r {
        case .knownBad: Theme.red
        case .suspicious: Theme.amber
        case .clean: Theme.green
        case .unknown: Theme.dim
        }
    }

    private func link(_ title: String, _ url: String) -> some View {
        Button(title) { if let u = URL(string: url) { NSWorkspace.shared.open(u) } }
    }
}

struct IntelSettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var newName = ""
    @State private var newURL = ""
    @State private var newSeverity: Reputation = .suspicious
    @State private var abuseKey = Keychain.get("abuseipdb-key") ?? ""
    @State private var vtKey = Keychain.get("virustotal-key") ?? ""
    @State private var gnKey = Keychain.get("greynoise-key") ?? ""

    var body: some View {
        Form {
            Section {
                ForEach(Feed.all) { feed in
                    let on = Binding(
                        get: { !model.settings.intel.disabledFeeds.contains(feed.id) },
                        set: { v in
                            model.settings.intel.disabledFeeds.removeAll { $0 == feed.id }
                            if !v { model.settings.intel.disabledFeeds.append(feed.id) }
                        })
                    let st = model.threatIntel.status[feed.id]
                    Toggle(isOn: on) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(feed.name)
                                Text(feed.severity == .knownBad ? "known bad" : "suspicious").font(.caption2)
                                    .foregroundStyle(feed.severity == .knownBad ? Theme.red : Theme.amber)
                            }
                            Text(feed.about).font(.caption).foregroundStyle(Theme.dim)
                            if let st {
                                Text("\(st.entries.formatted()) ranges\(st.updated.map { " · updated \($0.formatted(.relative(presentation: .named)))" } ?? "")\(st.error.map { " · ⚠︎ \($0)" } ?? "")")
                                    .font(.caption2).foregroundStyle(st.error == nil ? Theme.dim : Theme.amber)
                            }
                        }
                    }
                }
                HStack {
                    Button(model.intelRefreshing ? "Updating…" : "Update Lists Now") { Task { await model.refreshIntel(force: true) } }
                        .disabled(model.intelRefreshing)
                    Spacer()
                    Text("Refreshed automatically every 12 hours.").font(.caption).foregroundStyle(Theme.dim)
                }
                Toggle("Notify me when a connection goes to a known-bad IP", isOn: $model.settings.intel.notifyKnownBad)
            } header: {
                Text("Blocklists (matched on this Mac)")
            } footer: {
                Text("Lists are downloaded and checked locally, so no destination IPs are shared. Private, LAN and Tailscale (100.64/10) addresses are never flagged.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }

            Section {
                ForEach($model.settings.intel.customFeeds) { $feed in
                    let st = model.threatIntel.status["custom-\(feed.id)"]
                    HStack(alignment: .top) {
                        Toggle(isOn: $feed.enabled) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(feed.name)
                                    Text(feed.severity == .knownBad ? "known bad" : "suspicious").font(.caption2)
                                        .foregroundStyle(feed.severity == .knownBad ? Theme.red : Theme.amber)
                                }
                                Text(feed.url).font(.caption).foregroundStyle(Theme.dim).lineLimit(1).truncationMode(.middle)
                                if let st {
                                    Text("\(st.entries.formatted()) ranges\(st.error.map { " · ⚠︎ \($0)" } ?? "")")
                                        .font(.caption2).foregroundStyle(st.error == nil && st.entries > 0 ? Theme.dim : Theme.amber)
                                }
                            }
                        }
                        Spacer()
                        Button(role: .destructive) {
                            model.settings.intel.customFeeds.removeAll { $0.id == feed.id }
                        } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                    }
                }
                TextField("Name", text: $newName, prompt: Text("My team's blocklist"))
                TextField("URL", text: $newURL, prompt: Text("https://example.com/blocklist.txt"))
                Picker("Treat hits as", selection: $newSeverity) {
                    Text("Suspicious").tag(Reputation.suspicious)
                    Text("Known bad").tag(Reputation.knownBad)
                }
                Button("Add Feed") {
                    model.settings.intel.customFeeds.append(CustomFeed(name: newName.trimmingCharacters(in: .whitespaces),
                                                                       url: newURL.trimmingCharacters(in: .whitespaces), severity: newSeverity))
                    newName = ""; newURL = ""
                    Task { await model.refreshIntel(force: true) }
                }
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty || URL(string: newURL)?.scheme != "https")
            } header: { Text("Custom feeds") } footer: {
                Text("Any HTTPS URL serving plain-text IPs or CIDR ranges, one per line (comments with # or ;), such as a commercial feed's export or your SOC's blocklist. Downloaded and matched locally like the built-in lists.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }

            Section {
                Toggle("AbuseIPDB", isOn: $model.settings.intel.abuseIPDB)
                if model.settings.intel.abuseIPDB {
                    SecureField("AbuseIPDB API key (free tier: 1,000/day)", text: $abuseKey)
                        .onChange(of: abuseKey) { _, v in Keychain.set(v, for: "abuseipdb-key") }
                }
                Toggle("GreyNoise Community", isOn: $model.settings.intel.greyNoise)
                if model.settings.intel.greyNoise {
                    SecureField("GreyNoise API key (optional)", text: $gnKey)
                        .onChange(of: gnKey) { _, v in Keychain.set(v, for: "greynoise-key") }
                }
                Toggle("VirusTotal", isOn: $model.settings.intel.virusTotal)
                if model.settings.intel.virusTotal {
                    SecureField("VirusTotal API key (free tier: 4/minute)", text: $vtKey)
                        .onChange(of: vtKey) { _, v in Keychain.set(v, for: "virustotal-key") }
                }
            } header: {
                Text("Online lookups (opt-in)")
            } footer: {
                Text("Each public IP this Mac talks to is sent once to the services you enable, and results are cached for a week. Keys are stored in the Keychain.")
                    .font(.caption).foregroundStyle(Theme.amber)
            }
        }
        .formStyle(.grouped)
        .id(model.intelRevision)
    }
}
