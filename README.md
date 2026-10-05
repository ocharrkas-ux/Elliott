# Elliott

A macOS firewall and EDR with a local LLM. Elliott:

* watches every inbound and outbound connection;
* groups connections into profiles: one app talking to one destination, or one app serving one port;
* has a small local model describe each profile and rate its risk;
* lets you allow or deny each one;
* has a lockdown mode where any new connection waits for your approval;
* can mirror the rules to a Palo Alto NGFW as shadow security policies;
* checks destination IPs against threat-intelligence blocklists;
* learns from your allow/deny decisions and suggests the next ones;
* watches processes, persistence and security settings for attacker behavior (EDR);
* finds known vulnerabilities (CVE/CVSS) in macOS, apps, Homebrew, its own listening services and your projects'
  dependencies, with reachability analysis for those dependencies.

Elliott was called Bastion until October 2026. On first launch it moves the old app-support data and Keychain items
over.

## Build & run
```
cd ~/Documents/Elliott && xcodegen generate
xcodebuild -scheme Elliott -derivedDataPath ~/Library/Developer/Xcode/DerivedData/Elliott.noindex build
ditto ~/Library/Developer/Xcode/DerivedData/Elliott.noindex/Build/Products/Debug/Elliott.app /Applications/Elliott.app
```
Builds go to a `.noindex` folder so Spotlight and Launchpad only ever show the installed `/Applications/Elliott.app`
(Xcode's default build folders show up as extra copies of the app). Pass the same `-derivedDataPath` to
`xcodebuild test`.
1. **Local LLM**: `brew install ollama && ollama serve`, then `ollama pull qwen2.5:3b`. Settings → Local LLM → Test.
   Any OpenAI-compatible server on localhost (LM Studio, llama.cpp) also works. Only loopback URLs are accepted.
   Without a model, risk comes from the built-in heuristics only.
2. **Enforcement**: Settings → Filter → Install Helper, then approve it in System Settings → General → Login Items.
   Until then Elliott runs **observe-only** (it polls `nettop`, which sees every process's sockets without root).
3. Let it profile for a while. Classify connections in the Connections table (inspector, right-click menu, or select
   several to classify in bulk). Then turn on **Lockdown** in the toolbar or the menu bar. The lockdown sheet can
   first allow every unclassified connection under a risk threshold.
4. **Palo Alto**: Settings → Palo Alto: management address, API key (stored in the Keychain and sent in the
   `X-PAN-KEY` header), and vsys or Panorama device group. Test Connection. For a self-signed certificate, check the
   fingerprint and choose Trust Certificate (it gets pinned).

## Enforcement backends
| | pf helper (scheme `Elliott`) | Network Extension filter (scheme `ElliottNE`) |
|---|---|---|
| Signing | any team, including a free Personal Team | **paid Apple Developer Program team** |
| Granularity | destination IP + port (applies to every app) | per app (code-signature identity) + destination |
| Lockdown | new TCP SYNs are dropped; Elliott sees the socket stuck in SYN-SENT, asks you, and an approval opens the IP so the next SYN retry connects. Unapproved UDP is dropped. | the flow is paused (`pauseVerdict`) and resumed or dropped when you answer |
| Hostnames | IPs (no DNS visibility) | from the flow or by sniffing system DNS answers |

The helper (`Helper/main.swift`) is a root LaunchDaemon registered with `SMAppService`. It takes a structured policy
(never raw pf text) from the signed app over XPC, writes it into the pf anchor `com.apple/250.Elliott` (which stock
`/etc/pf.conf` already loads), and reloads it at boot. To remove it: Settings → Remove Helper (this flushes the
anchor and releases pf).

## Palo Alto shadow policy
A firewall can't see which app opened a connection, so the shadow rules are: this Mac's address → destination
(FQDN or IP address objects) + service (`elliott-tcp-443`, …). They're tagged `elliott-shadow` and kept at the top of
the rulebase (or of Panorama's pre-rulebase) in this order: denies, allows, then optional lockdown default-denies.
If one app is allowed and another is denied to the same destination, the shadow rule is an allow, and the Sync
view lists the conflict. Each sync deletes stale Elliott-tagged rules. By default changes stay in the candidate config;
you can turn on auto-commit (a partial commit by one admin is recommended). You can also create the rules disabled.

## EDR
Real-time process events on macOS need Apple's Endpoint Security entitlement (granted only to approved security
vendors), so Elliott polls instead. Very short-lived processes can slip between polls.
* **Processes** (every 2 s, each new process is checked once):
  * unsigned code running from temporary, download or hidden folders;
  * programs pretending to be macOS components, or whose file was deleted while running;
  * root processes running from user-writable paths;
  * known offensive tools, miners and tunnels;
  * document or mail apps (and browsers) launching shells;
  * about 20 command-line behaviors, e.g. reverse shells, `curl | sh`, base64-decoded payloads, fake password dialogs,
    Keychain dumping, quarantine stripping, disabling Gatekeeper or SIP, adding admin users, and miner arguments;
  * unsigned programs pinning the CPU.
* **Persistence and posture** (every 5 min):
  * launch agents and daemons: new items since the baseline, risky program paths, inline scripts;
  * cron, the login hook, and shell startup files;
  * SIP, Gatekeeper and FileVault status.
* **Network**: a connection to a known-bad IP becomes a critical detection on the program that made it, and a
  program's detections raise the risk of every connection it makes.
* Each detection carries MITRE ATT&CK IDs.
* **Triage**: the local LLM triages medium-and-above detections. Its advice is filtered so it never tells you to
  delete system files.
* **Responses**:
  * kill the process (the root helper handles other users' processes);
  * block the program's network access (not offered for macOS's own binaries);
  * mark a detection benign, which suppresses that exact behavior from then on.
* With the pf helper installed, Elliott sees the full command lines of root and other users' processes.

## Vulnerabilities
* **Inventory**: macOS, apps in /Applications, Homebrew formulae, this Mac's listening services, and lockfiles in the
  project folders you choose:
  * npm, yarn and pnpm;
  * pip requirements, Poetry, uv and Pipfile;
  * Cargo, Go modules, Bundler, Composer and SwiftPM.
* **Matching**:
  * Packages are checked against OSV.dev.
  * Apps, Homebrew, services and macOS are checked against NVD by CPE, using a mapping table in `Inventory.swift`;
    software it doesn't map shows as "not matched" in the inventory.
  * Every CVE gets a CVSS score (computed from the vector when only a vector is published), CISA KEV status
    (known exploited) and an EPSS exploit probability.
* **Network level, this Mac only**:
  * Which installed software listens on non-loopback interfaces. Exposed software is prioritized for
    network-vector CVEs.
  * Versions of standalone services, read from their own banner over 127.0.0.1.
  * Sensitive services open to the network, such as databases, VNC, Docker or an unauthenticated Ollama API.
  * Elliott never probes other hosts.
* **Reachability** for project packages:
  * whether the project's code imports the package at all, or it's only transitive or unused;
  * whether it calls the functions the advisory names: the authoritative lists in Go advisories, otherwise
    identifiers taken from the advisory text;
  * then the local LLM reads the call sites and judges whether the vulnerable path is plausible.
  * The result is static and best-effort, with no call graph.
* **Priority**: CVSS, plus KEV, EPSS, network exposure and reachability. An unused dependency is ranked lower.
* Your accept/reopen decisions survive rescans. Findings that disappear are marked fixed.
* **Remediation** (Settings → Vulnerabilities → Remediation: Off / Preview & confirm / Automatic after each scan):
  * **Plan**: one target version per component, the lowest that fixes all of its open vulnerabilities. Possible steps:
    * `brew upgrade`, only when Homebrew already ships the fix;
    * re-pinning `requirements*.txt`, plus `pip install` into the project's virtualenv;
    * `npm install` (or a package.json `overrides` entry for transitive dependencies);
    * `cargo update --precise`, `go get`, `bundle update --conservative`, or `composer update`;
    * for sensitive services exposed to the network, an inbound-deny firewall rule.
  * **Preview**: the sheet shows every command and file diff before anything runs.
  * **Safety**:
    * major-version upgrades are blocked unless you allow them;
    * edits are refused if a git project has uncommitted changes in those files, or a file changed after planning;
    * package names are validated and passed as process arguments, never through a shell.
  * **Verify**: afterwards Elliott re-reads the installed version (preferring the virtualenv). A finding is marked
    fixed only when its fix really landed.
  * **Undo**: from vulns → remediation, it restores edited files from backup, removes the firewall rules it added and
    reinstalls the previous pip version. Homebrew upgrades can't be rolled back.
  * Apps and macOS are never updated automatically; they update through their own updaters.
* **Privacy**: OSV and NVD receive package or product names and versions; EPSS receives CVE IDs. No code, file
  contents or IPs are sent. Responses are cached on disk.

## Layout
`Shared/` models, rule matching, pf generation, DNS parsing, process table · `App/` SwiftUI app, LLM, heuristics,
nettop monitor, threat intel, advisor, EDR (`App/Services/EDR`), vulnerabilities (`App/Services/Vuln`), PAN-OS client and planner · `Helper/` pf daemon · `Filter/` NE content filter · `Tests/` unit tests.
