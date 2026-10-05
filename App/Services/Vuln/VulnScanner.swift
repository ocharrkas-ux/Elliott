import Foundation

struct VulnSettings: Codable, Equatable {
    var enabled = true
    var projectFolders: [String] = []
    var includeApps = true
    var includeHomebrew = true
    var includeServices = true
    var autoScanDaily = true
    var lastScan: Date?
    /// Notify about newly found vulnerabilities at or above this severity (newly exploited ones always notify).
    var notifyAt: Severity = .critical
    var notify = true
    /// Look up NVD products for apps/Homebrew formulae missing from the built-in table.
    var autoMapCPE = true
    var lastExploitCheck: Date?
    var lastEPSS: Date?

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = VulnSettings()
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        projectFolders = try c.decodeIfPresent([String].self, forKey: .projectFolders) ?? d.projectFolders
        includeApps = try c.decodeIfPresent(Bool.self, forKey: .includeApps) ?? d.includeApps
        includeHomebrew = try c.decodeIfPresent(Bool.self, forKey: .includeHomebrew) ?? d.includeHomebrew
        includeServices = try c.decodeIfPresent(Bool.self, forKey: .includeServices) ?? d.includeServices
        autoScanDaily = try c.decodeIfPresent(Bool.self, forKey: .autoScanDaily) ?? d.autoScanDaily
        lastScan = try c.decodeIfPresent(Date.self, forKey: .lastScan)
        notifyAt = try c.decodeIfPresent(Severity.self, forKey: .notifyAt) ?? d.notifyAt
        notify = try c.decodeIfPresent(Bool.self, forKey: .notify) ?? d.notify
        autoMapCPE = try c.decodeIfPresent(Bool.self, forKey: .autoMapCPE) ?? d.autoMapCPE
        lastExploitCheck = try c.decodeIfPresent(Date.self, forKey: .lastExploitCheck)
        lastEPSS = try c.decodeIfPresent(Date.self, forKey: .lastEPSS)
    }
}

struct VulnScanResult {
    var components: [Component] = []
    var findings: [VulnFinding] = []
    var errors: [String] = []
    var date = Date()
}

/// One full vulnerability scan: inventory → OSV/NVD matching → KEV/EPSS → network exposure → reachability.
struct VulnScanner {
    var db: VulnDB
    var settings: VulnSettings
    var progress: @Sendable (String, Double) -> Void

    func run() async -> VulnScanResult {
        var r = VulnScanResult()

        // 1. Inventory
        progress("Inventorying installed software", 0.02)
        var components: [Component] = [Inventory.macOS()]
        if settings.includeApps { components += Inventory.apps() }
        if settings.includeHomebrew { components += Inventory.homebrew() }
        var exposures: [VulnFinding] = []
        if settings.includeServices {
            progress("Checking this Mac's listening services", 0.06)
            let (services, exp) = mapListeners(into: &components)
            components += services
            exposures = exp
        }
        for (i, folder) in settings.projectFolders.enumerated() {
            let name = (folder as NSString).lastPathComponent
            progress("Reading lockfiles in \(name)", 0.08 + 0.04 * Double(i) / Double(max(1, settings.projectFolders.count)))
            // Reading a protected folder (Documents, Desktop, iCloud) blocks until the user answers macOS's
            // permission prompt. Don't let an unanswered prompt stall the whole scan.
            guard let locks = await Self.withTimeout(seconds: 20, { Inventory.findLockfiles(under: folder) }) else {
                r.errors.append("\(name): no answer to macOS's folder-access prompt within 20 s (System Settings → Privacy & Security → Files and Folders → Elliott). Skipped this scan.")
                continue
            }
            for lock in locks { components += Inventory.packages(lockfile: lock) }
        }
        // A package seen in both a lockfile and a virtualenv is one component (keeping the dependency list and
        // "direct" from whichever source knows them).
        var firstIndex: [String: Int] = [:]
        var deduped: [Component] = []
        for c in components {
            guard c.kind == .package else { deduped.append(c); continue }
            let key = "\(c.project ?? "")|\(c.ecosystem ?? "")|\(Inventory.normalize(c.name, c.ecosystem ?? ""))|\(c.version)"
            if let i = firstIndex[key] {
                if deduped[i].requires == nil { deduped[i].requires = c.requires }
                if deduped[i].direct != true, let d = c.direct { deduped[i].direct = d }
            } else {
                firstIndex[key] = deduped.count
                deduped.append(c)
            }
        }
        components = deduped
        r.components = components

        // 2. Open-source packages → OSV
        var findings: [VulnFinding] = []
        let pkgs = components.filter { $0.kind == .package }
        if !pkgs.isEmpty {
            progress("Matching \(pkgs.count) packages against OSV", 0.15)
            do {
                let ids = try await db.osvQuery(pkgs)
                let unique = Array(Set(ids.flatMap { $0 }))
                var records: [String: [String: Any]] = [:]
                for (n, chunk) in stride(from: 0, to: unique.count, by: 8).map({ Array(unique[$0..<min($0 + 8, unique.count)]) }).enumerated() {
                    progress("Fetching advisories (\(min((n + 1) * 8, unique.count))/\(unique.count))", 0.15 + 0.2 * Double(n * 8) / Double(max(1, unique.count)))
                    await withTaskGroup(of: (String, [String: Any]?).self) { g in
                        for id in chunk { g.addTask { (id, try? await db.osvVuln(id)) } }
                        for await (id, rec) in g { records[id] = rec }
                    }
                }
                for (c, vids) in zip(pkgs, ids) {
                    var vulns = vids.compactMap { records[$0].map { VulnDB.parseOSV($0, for: c) } }
                    vulns = dedupeAliases(vulns)
                    findings += vulns.map { VulnFinding(component: c, vuln: $0) }
                }
            } catch {
                r.errors.append("OSV: \(error.localizedDescription)")
            }
        }

        // 3a. Apps and formulae missing from the built-in table: find their NVD product (cached 30 days).
        if settings.autoMapCPE {
            let unmapped = components.indices.filter {
                components[$0].cpe == nil && components[$0].version != "?" && [.app, .homebrew].contains(components[$0].kind)
            }
            for (n, i) in unmapped.enumerated() {
                let c = components[i]
                progress("Finding NVD product for \(c.name) (\(n + 1)/\(unmapped.count))", 0.35 + 0.1 * Double(n) / Double(max(1, unmapped.count)))
                let name = c.kind == .homebrew ? c.name.replacingOccurrences(of: #"@[\d.]+$"#, with: "", options: .regularExpression) : c.name
                let hint = c.kind == .app ? Self.vendorHint(appPath: c.location) : nil
                if c.kind == .app && hint == nil { continue }   // App Store / unsigned: no way to confirm the vendor
                if let cpe = await db.cpeLookup(name: name, vendorHint: hint) {
                    components[i].cpe = cpe
                    components[i].cpeAuto = true
                }
            }
            r.components = components
        }

        // 3b. Apps, Homebrew, services, macOS → NVD by CPE
        let cpeComponents = components.filter { $0.cpe != nil && $0.version != "?" }
        for (i, c) in cpeComponents.enumerated() {
            progress("NVD: \(c.display) (\(i + 1)/\(cpeComponents.count))", 0.45 + 0.3 * Double(i) / Double(max(1, cpeComponents.count)))
            do {
                var vulns: [Vulnerability]
                do { vulns = try await db.nvd(cpe: c.cpe!, version: c.version) }
                catch { try await Task.sleep(for: .seconds(30)); vulns = try await db.nvd(cpe: c.cpe!, version: c.version) }   // rate limited: back off once
                findings += vulns.map { VulnFinding(component: c, vuln: $0) }
            } catch {
                r.errors.append("NVD \(c.display): \(error.localizedDescription)")
            }
        }

        // 4. Exploitation signals
        progress("Checking CISA KEV and EPSS", 0.78)
        let kev = await db.kev()
        let cves = Array(Set(findings.compactMap(\.vuln.cve)))
        let epss = await db.epss(cves)
        for i in findings.indices {
            if let cve = findings[i].vuln.cve {
                findings[i].kev = kev.contains(cve)
                findings[i].epss = epss[cve]
            }
        }

        // 5. Reachability for project packages
        let byProject = Dictionary(grouping: findings.indices.filter { findings[$0].component.kind == .package }) {
            "\(findings[$0].component.project ?? "")|\(findings[$0].component.ecosystem ?? "")"
        }
        for (n, (key, idxs)) in byProject.enumerated() {
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { continue }
            progress("Reachability: \((parts[0] as NSString).lastPathComponent) (\(parts[1]))", 0.82 + 0.15 * Double(n) / Double(max(1, byProject.count)))
            let files = ReachabilityAnalyzer.index(project: parts[0], ecosystem: parts[1])
            // Dependency graph + what the code imports, to follow transitive use (app → fastapi → starlette).
            let projectPkgs = components.filter { $0.kind == .package && $0.project == parts[0] && $0.ecosystem == parts[1] }
            var graph: [String: [String]] = [:]
            for c in projectPkgs { if let r = c.requires { graph[Inventory.normalize(c.name, parts[1]), default: []] += r } }
            let imported = ReachabilityAnalyzer.importedPackages(projectPkgs, files: files)
            for i in idxs {
                let target = Inventory.normalize(findings[i].component.name, parts[1])
                let via = imported.contains(target) ? nil : ReachabilityAnalyzer.path(to: target, from: imported, graph: graph)
                findings[i].reachability = ReachabilityAnalyzer.analyze(findings[i].component, findings[i].vuln, files: files, via: via)
            }
        }

        r.findings = findings + exposures
        progress("Done", 1)
        return r
    }

    /// Runs blocking work off the cooperative pool; nil if it doesn't finish in time (the work is abandoned).
    static func withTimeout<T: Sendable>(seconds: Double, _ work: @escaping @Sendable () -> T) async -> T? {
        await withCheckedContinuation { (cont: CheckedContinuation<T?, Never>) in
            let lock = NSLock()
            var done = false
            func finish(_ v: T?) {
                lock.lock(); defer { lock.unlock() }
                if !done { done = true; cont.resume(returning: v) }
            }
            Thread.detachNewThread { finish(work()) }
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { finish(nil) }
        }
    }

    /// The developer behind an app, from its code signature ("apple" for Apple's apps).
    static func vendorHint(appPath: String) -> String? {
        guard let info = NSDictionary(contentsOfFile: "\(appPath)/Contents/Info.plist") as? [String: Any],
              let exe = info["CFBundleExecutable"] as? String else { return nil }
        let path = "\(appPath)/Contents/MacOS/\(exe)"
        let (_, team, apple) = PassiveMonitor.staticIdentity(path)
        if apple { return "apple" }
        let s = Signers.shared.info(path: path, teamID: team, appleSigned: false)
        return s.kind == .developer ? s.name : nil
    }

    /// GHSA, PYSEC and CVE records for the same flaw collapse into one (the one with a CVSS vector wins).
    func dedupeAliases(_ vulns: [Vulnerability]) -> [Vulnerability] {
        var out: [Vulnerability] = []
        for v in vulns.sorted(by: { ($0.cvssScore != nil ? 0 : 1, $0.id) < ($1.cvssScore != nil ? 0 : 1, $1.id) }) {
            let ids = Set([v.id] + v.aliases)
            if out.contains(where: { !ids.isDisjoint(with: Set([$0.id] + $0.aliases)) }) { continue }
            out.append(v)
        }
        return out
    }

    /// Ties listening sockets to installed software (marking it network-exposed), identifies standalone services
    /// by their banner, and flags sensitive services reachable from the network.
    func mapListeners(into components: inout [Component]) -> ([Component], [VulnFinding]) {
        var services: [Component] = []
        var exposures: [VulnFinding] = []
        // mDNS/Bonjour and SSDP discovery sockets are on every Mac; they aren't services anyone "exposed".
        for l in Inventory.listeners() where ![5353, 1900].contains(l.port) {
            let path = ProcessTable.path(l.pid) ?? ""
            var owner: Int?
            if let i = components.firstIndex(where: { ($0.kind == .app && path.hasPrefix($0.location + "/"))
                || ($0.kind == .homebrew && (path.contains("/Cellar/\($0.name)/") || path.contains("/opt/\($0.name)/"))) }) {
                owner = i
                if l.exposed && !components[i].exposedPorts.contains(l.port) { components[i].exposedPorts.append(l.port) }
            } else if l.proto == "tcp", let b = Inventory.banner(port: l.port), let id = Inventory.identify(banner: b) {
                if let j = services.firstIndex(where: { $0.cpe == id.cpe && $0.version == id.version }) {
                    if l.exposed { services[j].exposedPorts.append(l.port) }
                } else {
                    services.append(Component(kind: .service, name: id.name, version: id.version, cpe: id.cpe,
                                              location: "port \(l.port) (\(l.process))", exposedPorts: l.exposed ? [l.port] : []))
                }
            }
            // AirPlay receiver ports are normal for macOS.
            let airplay = l.process.hasPrefix("ControlCenter") && [5000, 7000].contains(l.port)
            if l.exposed, l.proto == "tcp", !airplay, let (what, score) = Inventory.sensitivePorts[l.port] {
                let comp = owner.map { components[$0] }
                    ?? Component(kind: .service, name: l.process, version: "", location: "port \(l.port)", exposedPorts: [l.port])
                let v = Vulnerability(
                    id: "EXPOSED-\(l.proto.uppercased())-\(l.port)",
                    summary: "\(what) is listening on all network interfaces (port \(l.port), \(l.process))",
                    details: "Any device on the networks this Mac joins can try to connect. If it doesn't need to be reachable from other machines, bind it to 127.0.0.1, turn the sharing service off in System Settings → General → Sharing, or deny inbound connections to it in Elliott's rules.",
                    cvssScore: score, cvssVersion: "est.")
                exposures.append(VulnFinding(component: comp, vuln: v))
            }
        }
        return (services, exposures)
    }
}
