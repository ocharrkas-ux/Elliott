# Bastion

A macOS firewall manager with a local LLM. Bastion:

* watches every inbound and outbound connection;
* groups connections into profiles: one app talking to one destination, or one app serving one port;
* has a small local model describe each profile and rate its risk;
* lets you allow or deny each one;
* has a lockdown mode where any new connection waits for your approval;
* can mirror the rules to a Palo Alto NGFW as shadow security policies.

## Build & run
```
cd Bastion && xcodegen generate && open Bastion.xcodeproj   # scheme "Bastion"
```
1. **Local LLM**: `brew install ollama && ollama serve`, then `ollama pull qwen2.5:3b`. Settings → Local LLM → Test.
   Any OpenAI-compatible server on localhost (LM Studio, llama.cpp) also works. Only loopback URLs are accepted.
   Without a model, risk comes from the built-in heuristics only.
2. **Enforcement**: Settings → Filter → Install Helper, then approve it in System Settings → General → Login Items.
   Until then Bastion runs **observe-only** (it polls `nettop`, which sees every process's sockets without root).
3. Let it profile for a while. Classify connections in the Connections table (inspector, right-click menu, or select
   several to classify in bulk). Then turn on **Lockdown** in the toolbar or the menu bar. The lockdown sheet can
   first allow every unclassified connection under a risk threshold.
4. **Palo Alto**: Settings → Palo Alto: management address, API key (stored in the Keychain and sent in the
   `X-PAN-KEY` header), and vsys or Panorama device group. Test Connection. For a self-signed certificate, check the
   fingerprint and choose Trust Certificate (it gets pinned).

## Enforcement backends
| | pf helper (scheme `Bastion`) | Network Extension filter (scheme `BastionNE`) |
|---|---|---|
| Signing | any team, including a free Personal Team | **paid Apple Developer Program team** |
| Granularity | destination IP + port (applies to every app) | per app (code-signature identity) + destination |
| Lockdown | new TCP SYNs are dropped; Bastion sees the socket stuck in SYN-SENT, asks you, and an approval opens the IP so the next SYN retry connects. Unapproved UDP is dropped. | the flow is paused (`pauseVerdict`) and resumed or dropped when you answer |
| Hostnames | IPs (no DNS visibility) | from the flow or by sniffing system DNS answers |

The helper (`Helper/main.swift`) is a root LaunchDaemon registered with `SMAppService`. It takes a structured policy
(never raw pf text) from the signed app over XPC, writes it into the pf anchor `com.apple/250.Bastion` (which stock
`/etc/pf.conf` already loads), and reloads it at boot. To remove it: Settings → Remove Helper (this flushes the
anchor and releases pf).

## Palo Alto shadow policy
A firewall can't see which app opened a connection, so the shadow rules are: this Mac's address → destination
(FQDN or IP address objects) + service (`bastion-tcp-443`, …). They're tagged `bastion-shadow` and kept at the top of
the rulebase (or of Panorama's pre-rulebase) in this order: denies, allows, then optional lockdown default-denies.
If one app is allowed and another is denied to the same destination, the shadow rule is an allow, and the Sync
view lists the conflict. Each sync deletes stale Bastion-tagged rules. By default changes stay in the candidate config;
you can turn on auto-commit (a partial commit by one admin is recommended). You can also create the rules disabled.

## Layout
`Shared/` models, rule matching, pf generation, DNS parsing · `App/` SwiftUI app, LLM, heuristics, nettop
monitor, PAN-OS client and planner · `Helper/` pf daemon · `Filter/` NE content filter · `Tests/` unit tests.
