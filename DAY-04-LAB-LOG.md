# Day 04 Lab Log — Phase 4 Complete: Windows, Linux, and Network Log Fundamentals

**Phase Completed:** Phase 4 — Windows, Linux, and Network Log Fundamentals
**Focus:** SOC Analyst L1 log interpretation, KQL query construction, ECS field literacy, raw telemetry review, and baseline-vs-anomaly investigation judgment

---

## Purpose

Phases 1–3 built the lab's telemetry foundation — Elastic SIEM, Suricata IDS, and Wazuh XDR all installed and validated. Phase 4 shifted from infrastructure work to actually reading the logs a SOC L1 analyst lives in day to day: Windows/Sysmon endpoint events, Windows Security/System events, Linux authentication and service logs, and network/IDS telemetry.

The goal wasn't just to run queries, but to build a personal reference for each log type — what field names actually exist in *this* environment (not just what's assumed from documentation), what normal baseline activity looks like, and how to tell routine system noise from something worth escalating.

```text
Windows 10 Victim VM -> Sysmon / Windows Event Logs -> Elastic Agent -> Elasticsearch -> Kibana Discover
Ubuntu SIEM VM -> Linux auth/service logs -> terminal review with grep, tail, and journalctl
Windows 10 Victim VM -> network activity -> Sysmon Event ID 3 and 22 -> Kibana Discover
Ubuntu SIEM VM -> Suricata IDS -> fast.log / eve.json
```

## Lab Environment Used

- **Ubuntu-SIEM** — host-only IP `192.168.56.112` (confirmed via `ip a` after a VM restart caused DHCP to reassign it — see Troubleshooting below). Hosts Elasticsearch, Kibana, Fleet Server, and Suricata.
- **windows10victim** — host-only IP `192.168.56.114`. Sysmon (SwiftOnSecurity config) + Elastic Agent enrolled through Fleet.
- **wazuh-server** — powered off for the duration of this phase to conserve host resources; not needed for log-reading work.
- **Main analysis interface** — Kibana Discover, data view `logs-*`, time ranges Last 24 hours and full history (used specifically to distinguish "nothing recent" from "nothing ever collected").

---

## Key Discovery: This Environment Normalizes to ECS, Not Raw Sysmon Field Names

Before working through individual event types, the first real finding of this phase was methodological: the raw Sysmon field names expected from documentation (`winlog.event_data.Image`, `.CommandLine`, `.ParentImage`, `.User`) don't exist in this deployment's field list at all.

Rather than assume the fields were missing or broken, I expanded a raw document into its JSON view and found the actual schema: this Elastic Agent/Windows integration version fully normalizes process telemetry into standard ECS fields instead:

- `process.executable` / `process.name` (in place of `Image`)
- `process.command_line` (in place of `CommandLine`)
- `process.parent.executable` / `process.parent.args` (in place of `ParentImage` / `ParentCommandLine`)
- `user.name` (in place of `User`)

This is actually a better outcome than expected — it means ECS enrichment is working correctly rather than leaving fields blank — but it meant every event type going forward needed its field names verified against a real document before building queries or columns, rather than assumed from memory.

---

## Log and Event Scenarios Reviewed

### Sysmon Endpoint Telemetry

**Event ID 1 — Process Creation.** Query: `winlog.channel : "Microsoft-Windows-Sysmon/Operational" and event.code : "1"`. Columns: `process.executable`, `process.name`, `process.command_line`, `process.parent.executable`, `process.parent.args`, `user.name`, `host.name`. Baseline was dominated by `svchost.exe` spawning `TiWorker.exe`/`TrustedInstaller.exe`/`taskhostw.exe` (normal Windows servicing) and `services.exe` → `TrustedInstaller.exe`. The one row that stood out from the SYSTEM-owned noise: `explorer.exe` → `mmc.exe` under `user.name : Nikola` — a genuine user-driven action, distinguishable from OS noise specifically because of the account column.

**net.exe / net1.exe drill-down.** An initial wildcard search on `process.command_line : *net*` returned mostly false matches (`netsvcs`, other unrelated substrings) — corrected by searching `process.name : "net.exe" or process.name : "net1.exe"` directly. Result: six `net user` invocations, all under `user.name : SYSTEM`, with `process.parent.executable` pointing to `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` — the Wazuh agent's own Syscollector module periodically enumerating local accounts for inventory, not an attacker. Same command (`net user`) that would be a red flag from an interactive user session turned out to be benign automated monitoring — the parent process and account context were what made the call, not the command text.

**Event ID 11 — File Created.** Query: `event.code : "11"`. As expected from the Sysmon schema, `process.command_line` and `process.parent.executable` returned `(null)` on every row — this event type never carries that data, not a mapping failure. Volume was dominated by `mousocoreworker.exe` writing to `C:\Windows\SoftwareDistribution\Download\...` (Windows Update's orchestrator). Manually checked `Temp`, `Public`, and `AppData` paths specifically, since those are the locations most likely to show a malicious drop — found nothing unusual.

**Event ID 3 — Network Connection.** Query: `event.code : "3"`, columns extended with `destination.ip` / `destination.port`. Only 26 hits in 24 hours (network events are far rarer than process/file events) — all `OneDrive.exe` / `OneDrive.Sync.Service.exe` / `OneDriveStandaloneUpdater.exe` under `Nikola`, almost entirely port 443 to various Microsoft cloud IPs. One outlier row used port 80 instead of 443 to a Microsoft-owned IP — noted as the kind of "breaks the pattern" detail worth a second look in a real investigation, even though it resolved to a known-benign Microsoft telemetry endpoint here.

**Event ID 22 — DNS Query.** Query: `event.code : "22"`, column `dns.question.name`. All resolved domains were Microsoft's own infrastructure (`ecs.office.com`, `outlook.office.com`, `m365.cloud.microsoft`, `oneclient.sfx.ms`, `default.exp-tas.com`). Two rows queried the machine's own hostname (`DESKTOP-BN86O9N`) — internal WMI/telemetry name resolution, not an actual external DNS lookup.

### Windows Security and System Events

**Event ID 4624 — Successful Logon.** Initial query (`event.code : "4624"`) returned 127 hits, entirely `winlog.logon.type : "Service"` under SYSTEM — Windows service startups, not human logons. Refining with `and not winlog.logon.type : "Service"` cut this to 7 rows: `DWM-1`/`UMFD-0`/`UMFD-1` (Windows' own auto-generated per-session virtual accounts, not real users) tied to boot-time processes, plus two genuine `Interactive` logons for `Nikola` via `svchost.exe` from loopback (`127.0.0.1`) — the actual console login for this session.

**Event ID 4625 — Failed Logon.** Empty. Confirmed as a valid, expected finding (no bad-credential attempts in this window), not a broken query — an empty result here is itself the correct baseline to have on record before ever needing to recognize a real brute-force/spray pattern.

**Event ID 4672 — Special Privileges Assigned.** 129 hits across two result pages, all `SYSTEM` / `LOCAL SERVICE` / `NETWORK SERVICE` / `DWM-1` — no real named account anywhere in the set, including `Nikola`, despite that account having logged in interactively in the 4624 check above. This is expected under Windows' UAC split-token model: a standard interactive logon only issues a standard token, and 4672 only fires when an application is actually run elevated, not simply on logon.

**Event IDs 4720, 4732, 4726, 4740** (Account Created / Added to Group / Deleted / Locked Out) and **System Event ID 7045** (New Service Installed) — all queried and confirmed empty, consistent with no account-management or service-installation activity occurring during the review window.

**Sysmon Event IDs 7 and 10 — a config limitation, not a broken pipeline.** Event ID 7 (Image/DLL Load) returned zero results even when the time range was expanded to the full history, which ruled out "just quiet right now" and pointed to a collection-level cause: the SwiftOnSecurity Sysmon configuration disables ImageLoad monitoring by default because of its extreme volume. The same verification method was applied to Event ID 10 (Process Access, the LSASS-access/credential-dumping check) — testing the bare `event.code : "10"` query with no filters first, before assuming a field-name mismatch — and it also came back empty across all time, confirming ProcessAccess monitoring is disabled in this config as well. Both are documented as known visibility gaps rather than "nothing found."

### Registry Monitoring — Sysmon Event ID 13

Baseline query (`event.code : "13"`) returned 1,652 hits. Field verification (searching "registry" in the field list) surfaced `registry.path` as the ECS equivalent of the expected `TargetObject` field. Baseline activity included `lsass.exe` writing to its own LSA configuration keys (`HKLM\...\Control\Lsa\ProductType`, `LsaCfgFlags`) — normal self-configuration by the security subsystem, distinct in meaning from anything that would *access* LSASS externally.

A targeted follow-up query scoped `registry.path` to the classic persistence locations (`*\Run\*`, `*\RunOnce\*`, `*\Services\*`) and returned 57 hits — all attributable to known, legitimate executables: `UCPDMgr.exe` (Windows User Choice Protection Driver), the Edge WebView2 updater's `setup.exe`, `WMIADAP.EXE` (WMI Performance Adapter re-registering its service keys), and `OneDriveSetup.exe` under `Nikola`'s profile registering its own auto-start entry. The last one is a useful example for future reference: the *technique* (a Run-key registry write) is identical to what malware persistence would look like, but the *executable identity and install path* are what confirm legitimacy — the mechanism alone isn't enough to judge intent.

### Linux Host Logs (Ubuntu-SIEM)

**SSH authentication** (`sudo grep sshd /var/log/auth.log | tail -n 30`) showed `sshd` restarting after the VM's reboot, followed by a single successful password login for `nikola` from `192.168.56.1` — the VirtualBox host-only gateway address, i.e. the physical host machine, not an external source.

**sudo usage** (`sudo grep sudo /var/log/auth.log | tail -n 30`) showed exactly two sudo sessions, both self-referential: the `grep sshd` command from the prior check, and the `grep sudo` command capturing its own invocation. No unexpected users or commands.

**Service health via journalctl**, run across `ssh`, `elasticsearch`, and `kibana` specifically because the VM had just rebooted (confirming a service "loaded once" isn't the same as confirming it survives a restart cleanly):

- `ssh` — clean start-and-login pattern repeated consistently across every boot going back over two weeks of lab use.
- `elasticsearch` — started successfully on every boot including the most recent one. The `WARNING: sun.misc.Unsafe...` and `WARNING: Unknown module: org.apache.arrow...` lines look concerning but are standard JVM deprecation notices from Elasticsearch's startup process, not errors.
- `kibana` — actively healthy: Fleet reporting 2/2 agents healthy, content sync tasks running every minute. One notable line, a burst of `WARN: Unable to parse panelsJSON for telemetry collection` — identified as a known low-severity Kibana quirk where a saved dashboard object has a panel definition that breaks internal telemetry-stats parsing specifically, with no effect on Discover, alerting, or actual data. Flagged and explained rather than either ignored or over-escalated.

### Network and IDS — Suricata

Confirmed the Suricata log files (`eve.json`, `stats.log`, `fast.log`) were actively updating (timestamps within minutes of the check), ruling out a stalled service. `fast.log` contained two alerts:

```text
SURICATA Applayer Mismatch protocol both directions
[Classification: Generic Protocol Command Decode] [Priority: 3]
192.168.56.1:51156 -> 192.168.56.112:5601
192.168.56.1:51164 -> 192.168.56.112:5601
```

Broken down by field: source IP is the host machine, destination is this VM's Kibana port, rule SID `2260000`, Priority 3 (Suricata's lowest/informational severity tier). This is a well-documented, generally benign Suricata signature that fires when its protocol auto-detection gets confused by Kibana's plain-HTTP traffic pattern on port 5601 — almost certainly triggered by normal browser sessions loading Kibana during this same lab session, not a real intrusion indicator. Useful confirmation that severity/priority fields matter just as much as the signature name itself when triaging an alert.

---

## Troubleshooting Notes

| Problem | What Was Checked | Root Cause | Fix |
|---|---|---|---|
| Kibana unreachable via `https://192.168.56.112:5601`, browser threw `SSL_ERROR_RX_RECORD_TOO_LONG` | Nothing configures Kibana for TLS in this lab (unlike Wazuh's dashboard) | Protocol mismatch — Kibana is serving plain HTTP, and the browser was sending a TLS handshake to a non-TLS port | Connected via `http://192.168.56.112:5601` instead |
| Forgot the Ubuntu-SIEM host-only IP after a VM restart; two different logged values existed (`.112` from earlier setup notes vs `.101` from an older reference) | `ip a` on the Ubuntu-SIEM console, checked the host-only interface specifically (not the NAT interface) | DHCP reassigns host-only addresses on restart — IPs recorded in notes are a point-in-time snapshot, not fixed | Confirmed the live IP directly with `ip a` rather than trusting either recorded value |
| Expected raw Sysmon fields (`winlog.event_data.Image`, `.CommandLine`, etc.) didn't exist anywhere in the field list | Searched the field list for "Image", found only unrelated fields (`ImagePath`, `TargetImage` — which belong to different event types entirely); expanded a document's raw JSON to see the real schema | This Elastic Agent/integration version fully normalizes Sysmon data into ECS (`process.executable`, `process.command_line`, `process.parent.*`, `user.name`) instead of leaving raw fields in place | Rebuilt every subsequent query/column set around the confirmed ECS field names instead of assumed raw names |
| Wildcard search `process.command_line : *net*` (looking for `net.exe`/`net1.exe` activity) returned mostly irrelevant noise | Reviewed the actual matched command lines | The wildcard matched any substring containing "net" (`netsvcs`, etc.), not just the `net` command specifically | Queried `process.name : "net.exe" or process.name : "net1.exe"` directly instead of wildcarding the whole command line |
| Sysmon Event IDs 7 (Image Load) and 10 (Process Access) returned zero results, even after clearing time-range and field-search filters | Re-ran each as a bare, unfiltered `event.code` query; expanded the time range to the entire history before concluding anything | The SwiftOnSecurity Sysmon config disables both event types by default due to their extreme log volume — this is a collection-level gap, not a query error or missing data | Documented both as known visibility gaps in the current Sysmon config rather than "nothing suspicious found" |
| Clicking a value inside a document's detail flyout unexpectedly narrowed the whole result set from 477 to 5 | Noticed an unfamiliar filter chip had appeared under the search bar | Clicking a field value inside the flyout adds a "filter for this value" chip automatically — a different action than intended | Removed the filter chip; switched to adding columns exclusively from the main field list in the left sidebar instead of from within the flyout |

---

## What Phase 4 Proved

- Field names cannot be assumed from documentation or from a previous phase's notes — this environment's ECS normalization meant every event type needed its actual schema confirmed against a raw document before a single query or column was built.
- An empty result set is a legitimate, useful finding when it's been properly verified (bare query, full time range, no stray filters) — not a failure state to explain away.
- Some telemetry gaps are configuration decisions, not pipeline failures: Sysmon's SwiftOnSecurity template deliberately omits Image Load and Process Access monitoring by default, which is worth knowing as a real visibility gap for any future credential-dumping or DLL-hijacking investigation in this lab.
- The same command, process name, or registry-key technique can be either completely benign or a genuine indicator depending entirely on context — parent process, account, and source path did more analytical work in this phase than any single field in isolation.
- Distinguishing SYSTEM/service-account noise from real user activity was the single most repeated skill across every log type reviewed this phase, from `net user` (Wazuh agent vs. an attacker) to 4624 logons (virtual session accounts vs. an actual person) to 4672 (UAC token behavior).

## Skills Practiced

**SOC Analyst skills:** KQL query construction and refinement (from broad to targeted), raw-document field verification, ECS schema literacy, parent/child process chain analysis, logon-type interpretation, registry persistence technique recognition, IDS alert field/severity triage, cross-referencing account context to separate automated tooling from human activity.

**Security Analyst skills:** root-cause troubleshooting under a "verify before concluding" discipline (bare queries before assuming field-name errors, full time-range checks before assuming pipeline failure), Linux service health verification via `journalctl` across multiple boots, distinguishing benign infrastructure warnings from real service failures, IDS signature/priority interpretation.

---

## Checklist

- [x] Sysmon Event ID 1 (Process Creation) reviewed, ECS field mapping confirmed
- [x] net.exe / net1.exe account-enumeration activity reviewed and attributed
- [x] Sysmon Event ID 11 (File Created) reviewed
- [x] Sysmon Event ID 3 (Network Connection) reviewed
- [x] Sysmon Event ID 22 (DNS Query) reviewed
- [x] Windows Security Event IDs 4624, 4625, 4672, 4720, 4732, 4726, 4740 reviewed
- [x] Windows System Event ID 7045 reviewed
- [x] Sysmon Event IDs 7 and 10 investigated; confirmed disabled by current Sysmon config, documented as a visibility gap
- [x] Sysmon Event ID 13 (Registry) reviewed, including a targeted persistence-key search
- [x] Linux SSH authentication log reviewed
- [x] Linux sudo usage log reviewed
- [x] Linux service health confirmed via journalctl (ssh, elasticsearch, kibana)
- [x] Suricata log files and fast.log alerts reviewed
- [x] All troubleshooting root-caused and documented

---

## Summary

Phase 4 moved the lab from infrastructure-building into actual log interpretation: reading Windows/Sysmon endpoint telemetry, Windows Security and System events, Linux authentication and service logs, and network/IDS alerts, all directly in Kibana Discover and the Ubuntu-SIEM terminal. The most significant finding wasn't any single event — it was discovering that this environment's Elastic Agent version normalizes Sysmon telemetry fully into ECS fields rather than leaving raw Sysmon field names in place, which meant every subsequent query had to be built on verified field names rather than assumptions carried over from documentation or earlier notes.

Beyond that, the phase produced a working reference for what normal looks like across this lab: SYSTEM/service-account noise dominating most event types, a small number of genuinely user-driven actions distinguishable by account context, two Sysmon event types (Image Load, Process Access) confirmed disabled by the current Sysmon configuration rather than simply quiet, and a real (if low-severity) Suricata IDS alert correctly triaged by its priority field rather than its signature name alone. Every empty result and every "normal" verdict in this log was confirmed through a deliberate check — bare queries, full time ranges, raw JSON inspection — rather than assumed, which is the habit this phase was really built to reinforce.
