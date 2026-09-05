# Day 08 Lab Log — Phase 8 Complete: Splunk Fundamentals for SOC

**Phase Completed:** Phase 8 — Splunk Fundamentals for SOC
**Focus:** Splunk Enterprise deployment, Universal Forwarder configuration, Windows Security/Sysmon ingestion troubleshooting, SPL investigation searches, SOC dashboard creation, and Splunk/Elastic platform comparison

---

## Overview

Phases 1–7 built the lab's telemetry foundation and SOC documentation habits in Elastic — collection, investigation, high-volume triage, ticket/escalation writing, and phishing analysis. Phase 8 added a second SIEM platform to the lab: a dedicated Splunk Enterprise server, connected to the existing Windows victim endpoint through the Splunk Universal Forwarder, to practice SPL investigation and dashboard-building alongside the KQL/Elastic workflow already in place.

Rather than installing Splunk on the existing Elastic SIEM VM, a new dedicated `splunk-soc` VM was built (Ubuntu Server 24.04 LTS, host-only + NAT dual-adapter, guided LVM storage). This mirrored the same architecture decision already used for `wazuh-server` in Phase 3 — protect a working telemetry pipeline, isolate new platform testing.

---

## Lab Architecture (Actual Values)

| Item | Value |
|---|---|
| Splunk server hostname | `splunk-soc` |
| Splunk host-only IP (real, DHCP-assigned) | `192.168.56.117` |
| Splunk NAT IP | `10.0.2.15` |
| Splunk Web | `http://192.168.56.117:8000` |
| Receiving port | TCP `9997` |
| Windows victim hostname | `DESKTOP-BN86O9N` |
| Splunk service account | `splunk` (Linux system account) + `NT SERVICE\SplunkForwarder` (Windows virtual account) |

Note: fixed IPs and hostnames referenced in any external walkthrough are illustrative defaults only — every lab build gets its own DHCP-assigned values, confirmed with `ip a` / `hostname` rather than assumed. This phase's actual host-only IP and Windows hostname both differed from a generic reference build, consistent with the lesson already established in Phase 1.

---

## Installation Summary

- Downloaded and installed Splunk Enterprise 10.4.0 (`.deb`) on a dedicated Ubuntu Server 24.04 VM.
- Configured a dedicated non-root service context for Splunk (the installer itself provisioned the `splunk` system account during package setup).
- Enabled systemd boot-start (`splunk enable boot-start -systemd-managed 1`) and validated full reboot persistence — Splunk came back automatically after `sudo reboot` with no manual intervention.
- Enabled the TCP 9997 receiving port in Splunk Web and confirmed it listening at the OS level (`ss -ltnp`).
- Verified forwarder-to-receiver connectivity from the Windows endpoint *before* installing any agent, isolating transport from agent configuration.
- Downloaded and verified the Splunk Universal Forwarder MSI (size + Authenticode signature) before execution, installed with **Local System** as the service account and the correct indexer/port.
- Confirmed the forwarder service running and actively connected (`splunk list forward-server`).

---

## Troubleshooting: Two Real Issues (One Anticipated, One Novel)

### Issue 1 — Windows Event Log inputs not enabled (anticipated)

**Symptom:** Forwarder showed an active connection and `_internal` housekeeping data reached Splunk, but Security/System/Application event data was not searchable.

**Root cause:** `btool inputs list --debug` confirmed no `[WinEventLog://...]` stanzas existed anywhere in the forwarder's effective configuration — a connected agent does not automatically mean the required log channels are being monitored.

**Fix:** Wrote `inputs.conf` under `etc\system\local\` enabling `Application`, `Security`, `System`, and `Microsoft-Windows-Sysmon/Operational`, then restarted the forwarder. `btool` re-confirmed all four stanzas active. Security, System, and Application data began flowing within minutes.

**Lesson:** `Agent connected ≠ required telemetry ingesting.`

### Issue 2 — Sysmon channel blocked by a restrictive `channelAccess` ACL (not anticipated)

**Symptom:** After the Issue 1 fix, Security/System/Application data flowed correctly, but the Sysmon Operational channel returned zero events — despite Sysmon itself confirmed healthy and actively logging (21,500+ historical records via `Get-WinEvent`).

**Root cause:** `splunkd.log` showed a specific error — `WinEventLogChannel::queryEvtChannel: Failed to query Windows Event Log channel=Microsoft-Windows-Sysmon/Operational`. Investigation revealed the Universal Forwarder's Windows service does not actually run as the literal `SYSTEM` account, even when "Local System" is selected during install — it runs as the Windows virtual service account `NT SERVICE\SplunkForwarder`. Standard logs (Security/System/Application) work because Windows grants built-in "Event Log Readers" access to those three specific channels, extended automatically to Splunk's virtual account by the installer. Sysmon's Operational log is an "Applications and Services" log with its own custom `channelAccess` security descriptor that does **not** extend the same access to `NT SERVICE\...` accounts by default — confirmed against comparable, documented cases from other Splunk deployments hitting the same error on the same channel.

**Fix:** Compared the Sysmon channel's ACL (`wevtutil gl "Microsoft-Windows-Sysmon/Operational"`) against a channel that already worked correctly for this account type (`Microsoft-Windows-PowerShell/Operational`), then applied that channel's working `channelAccess` descriptor to the Sysmon channel via `wevtutil sl ... /ca:...`, restarted the forwarder, and confirmed both the disappearance of the error and — more importantly — actual Sysmon data (Event IDs 1 and 22) becoming searchable in Splunk.

**Secondary snag during the fix:** The first `wevtutil sl` attempt failed with PowerShell parser errors — PowerShell interprets unquoted parentheses as its own expression syntax, so the SDDL ACL string (which is full of parentheses) needs to be passed as a single quoted argument, not typed bare on the command line.

**Lesson:** A working Windows Event Log channel does not guarantee every channel is equally accessible to the same service account — "high value" logs (Security, and apparently Sysmon's Operational channel) can carry access restrictions beyond what a standard install's default permissions cover, and diagnosing this required checking `splunkd.log` directly rather than relying on `btool`, which only shows configuration, not actual channel-open success or failure.

### Non-issue: Event ID 3 (network connections) — confirmed working, not deferred

Unlike a reference build where Sysmon Event ID 3 (network connection) telemetry was unavailable and had to be deferred as optional future tuning, this lab's Sysmon configuration already captures Event ID 3 out of the box. Verified with a live test: generating `curl.exe` traffic to `github.com` produced a real Event ID 3 record (`OneDrive.exe → 20.89.1.10:443`, TCP) within the existing dataset. No deferral was necessary for this phase — one fewer open item than a minimal build would have.

---

## SPL Investigation Searches (10 Completed)

All searches were run against `host=DESKTOP-BN86O9N`, combining `sourcetype=WinEventLog:Security` (Windows authentication) and `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` (endpoint process/DNS activity, with `rex` used to extract fields from the raw XML).

| # | Search | Finding | Verdict |
|---|---|---|---|
| 1 | Sysmon DNS → `github.com` | Cleanly attributed to `curl.exe`, known user | Benign — controlled lab lookup |
| 2 | Sysmon process creation review | Command-line, parent process, and user attribution all confirmed usable | Telemetry validated |
| 3 | PowerShell command-line triage | 256 "security policy inspection" events (`secedit`) parented by `wazuh-agent.exe`; no high-interest patterns found | Benign — security agent policy check |
| 4 | Failed authentication (4625) | 9 failures, `Logon_Type 2` (interactive), source `127.0.0.1` | Needs context — local, not remote |
| 5 | Failed authentication aggregation | Same 9 failures, single ~7-second cluster | Review-worthy volume, no brute-force evidence |
| 6 | Successful logons (4624) | Dominated by SYSTEM/service/session accounts + known user | Benign — expected identities |
| 7 | Privileged logons (4672) | No unexpected accounts among 2,911 events | Benign — no unexpected privileged account |
| 8 | Combined authentication overview | Confirms Searches 4–7 in one aggregated view | Consistent with individual findings |
| 9 | Process execution frequency | Dominated by Splunk's own forwarder helper processes + normal Windows binaries | Benign — housekeeping-heavy, no anomalies |
| 10 | DNS process attribution | OneDrive/M365 telemetry, `wpad`, local hostname resolution | Benign — expected Microsoft/Windows traffic |

---

## Dashboards Built (3)

### 1. Authentication & Privileged Access
- **Successful Logons by Account** — Event ID 4624, aggregated by account/logon type.
- **Failed Logons by Account and Source** — Event ID 4625, with a baked-in `Triage_Note` field carrying the corrected, non-overclaiming wording (*"High-volume local failures - validate lab context"*) directly into the panel output rather than leaving it as a verbal caveat.
- **Privileged Logons by Account** — Event ID 4672, with an automated `Review_Flag` field classifying every account as "Expected identity" or "Review - unexpected account."

### 2. Endpoint Process & PowerShell Triage
- **Top Executed Processes** — Sysmon Event ID 1 frequency table.
- **PowerShell Review Categories** — categorized PowerShell activity by command-line pattern and parent process, isolating the Wazuh-driven policy-inspection volume from general execution.
- **PowerShell Execution Details** — per-event detail table with an automated `Verdict` field (agent-driven / high-interest / general), operationalizing the parent-process-context lesson directly in the dashboard.

### 3. DNS Activity Investigation
- **Top Queried Domains** — Sysmon Event ID 22 frequency table.
- **DNS Queries by Process** — domain lookups attributed to the generating process.
- **GitHub DNS Investigation Details** — the `curl.exe → github.com` correlation from Search 1, with an automated benign verdict.

All nine panels reuse the validated SPL from the 10 investigation searches directly — turning one-off queries into repeatable, analyst-facing views rather than writing dashboard logic from scratch.

---

## Splunk vs. Elastic SOC Workflow Comparison

### Data Ingestion and Setup

Elastic's setup in Phase 2 involved a broader platform stack — Elasticsearch, Kibana, Fleet Server, and per-integration agent policies — which gave strong visibility into the underlying collection architecture but required more moving pieces to get right. Splunk's setup was comparatively narrower in scope (Enterprise server + Universal Forwarder + receiving port), but that narrowness didn't mean it was simpler in practice: the two real issues in this phase (missing inputs, then a channel-level ACL block) both lived specifically in getting the forwarder's Windows telemetry actually flowing, not in the initial install.

### Search Language and Investigation Workflow

KQL (Elastic) felt most natural for fast, direct filtering of known fields — `event.code`, `winlog.channel`, `winlog.event_data.CommandLine` — well suited to raw-event review. SPL felt stronger for turning raw evidence into analyst-facing conclusions: `stats`, `eval`, and `case()` made it straightforward to bucket PowerShell activity by risk pattern, attach triage wording directly to a result set, and go from investigation search to dashboard panel with minimal rework. Both platforms required the same `rex`-equivalent effort to pull structured fields out of raw Sysmon XML.

### Overall Analyst Experience

Elastic established the foundation — log collection, endpoint visibility, and high-volume triage practice. Splunk reinforced the same investigative mindset while making it easier to express analyst conclusions directly in searches and dashboards (embedded verdict fields, triage notes, review flags) rather than leaving that judgment implicit.

The most important lesson repeated across both platforms, and reinforced again in this phase:

```text
Suspicious technique does not equal confirmed malicious activity.
Context determines the verdict.
```

Examples from this phase:

| Activity | Initial Concern | Context | Verdict |
|---|---|---|---|
| PowerShell as SYSTEM | Could indicate attacker execution | Parent process was Wazuh agent performing `secedit` policy inspection | Benign by context |
| 9 failed logons | Could indicate brute force | Interactive logon type, source `127.0.0.1` (loopback), single short cluster | Review context; not confirmed brute force |
| 2,911 privileged logon events | Could indicate admin misuse | Entirely SYSTEM/service/session accounts + known user | Benign by context |
| `curl.exe` DNS activity to GitHub | Could indicate staging/download behavior | Controlled lab lookup by known user, repeated deliberately during testing | Benign by context |

---

## Issues Encountered and Troubleshooting Summary

| Issue | Diagnosis | Resolution | Lesson |
|---|---|---|---|
| Elastic VM already under memory pressure | Installing a second SIEM there risked a working pipeline | Built a dedicated `splunk-soc` VM instead | Protect stable systems; isolate new platform testing |
| Windows Event Log inputs not enabled after forwarder connected | `btool` showed no `WinEventLog://` stanzas configured | Wrote `inputs.conf` enabling Security/System/Application/Sysmon, restarted forwarder | Agent connectivity ≠ useful telemetry |
| Sysmon channel returned zero events despite healthy Sysmon logging | `splunkd.log` showed `queryEvtChannel` failure; root cause was the `NT SERVICE\SplunkForwarder` virtual account lacking access under Sysmon's custom `channelAccess` ACL | Applied a working channel's ACL (`Microsoft-Windows-PowerShell/Operational`) to the Sysmon channel via `wevtutil sl`, restarted forwarder | Standard-log access doesn't guarantee access to every Applications/Services log; verify via the actual daemon log, not just `btool` |
| `wevtutil sl` command failed with PowerShell parser errors | Unquoted parentheses in the SDDL ACL string were parsed as PowerShell syntax | Wrapped the entire `/ca:...` argument in double quotes | Command-line tool arguments with special characters need explicit quoting in PowerShell |
| Failed-logon volume could be mislabeled as brute force | Volume alone doesn't indicate attack | Corrected dashboard wording to reference local/interactive context rather than asserting an attack | Public SOC evidence must avoid overclaiming |

---

## SOC Skills Practiced

- Splunk Enterprise installation, non-root service execution, and systemd boot persistence
- Splunk receiving-port configuration and OS-level listener validation
- Splunk Universal Forwarder installation with installer integrity verification (size + Authenticode signature)
- Windows Event Log input configuration and `btool` effective-configuration troubleshooting
- Diagnosing a Windows Event Log **channel-access** failure distinct from a basic missing-input gap, including reading raw `splunkd.log` output and comparing channel ACLs via `wevtutil`
- SPL searches and raw-XML field extraction with `rex`
- Windows authentication event analysis (4624, 4625, 4672) with context-aware, non-overclaiming verdict writing
- Sysmon process-creation and DNS-query analysis (Event IDs 1 and 22)
- PowerShell triage using command-line pattern matching and parent-process context
- Dashboard creation with embedded analyst logic (`eval`/`case()`-driven verdict and triage-note fields) rather than raw tables alone
- Platform comparison: Splunk/SPL vs. Elastic/KQL
- Scope control: confirming rather than assuming a deferred-tuning item, and correctly identifying when a real blocking issue (channel ACL) required action versus when a documented outcome from elsewhere didn't apply to this build

---

## Interview Translation

### Resume / Interview Summary

In Phase 8 of my SOC home lab, I deployed Splunk Enterprise on a dedicated Ubuntu Server VM, configured non-root service execution and reboot persistence, and built a Windows Universal Forwarder pipeline into it. I diagnosed and fixed two distinct forwarder-side issues — missing Windows Event Log inputs, and a Windows Event Log channel-access restriction blocking Sysmon telemetry specifically — the second of which required comparing channel ACLs and identifying that Splunk's Windows service runs under a virtual service account with different default permissions than a literal SYSTEM login. I then wrote ten SPL investigations across authentication, process execution, PowerShell, and DNS activity, and built three SOC dashboards with embedded triage logic, before comparing the Splunk/SPL workflow against my prior Elastic/KQL experience.

### Interview Talking Points

**Why did you deploy Splunk on a separate VM instead of your existing Elastic SIEM VM?**
The Elastic server was already working and under some memory pressure. A dedicated Splunk VM protected that working pipeline and kept the platform comparison clean.

**What did you troubleshoot?**
Two separate issues, not one. First, the forwarder connected but wasn't shipping Windows Event Log data at all — fixed by explicitly enabling the Security/System/Application/Sysmon inputs. Second, after that fix, Security/System/Application data flowed but Sysmon specifically didn't — I traced that to `splunkd.log` showing a channel-query failure, found that Splunk's Windows service runs as a virtual service account rather than literal SYSTEM, and that Sysmon's event log channel has stricter default permissions than the standard logs. I fixed it by applying a working channel's access descriptor to the Sysmon channel.

**What was your most important analyst finding?**
The recurring theme across every search: volume and technique alone don't determine severity. PowerShell as SYSTEM, a cluster of failed logons, and thousands of privileged-logon events all looked review-worthy in isolation, but parent process, logon type, and source address in every case explained the activity as benign.

**Did every part of the guide's expected troubleshooting apply to your build?**
No — I confirmed Sysmon Event ID 3 (network connection telemetry), which required deferral in a reference build, was already working in mine. Rather than assuming the same gap existed, I tested it directly with real traffic before documenting anything.

---

## Phase 8 Completion Checklist

| Requirement | Status |
|---|---|
| Dedicated Splunk Enterprise VM created | Complete |
| Pre-installation and pre-forwarder snapshots taken | Complete |
| Splunk Enterprise installed | Complete |
| Splunk running under non-root service context | Complete |
| Splunk Web accessible | Complete |
| Boot-start configured and reboot validated | Complete |
| TCP 9997 receiver configured and validated | Complete |
| Universal Forwarder installer verified and signed | Complete |
| Universal Forwarder installed and actively connected | Complete |
| Windows Security/System/Application telemetry searchable | Complete |
| Sysmon telemetry searchable (channel-access issue diagnosed and fixed) | Complete |
| 10 SPL searches completed | Complete |
| 3 Splunk dashboards built (9 panels total) | Complete |
| Splunk vs. Elastic SOC workflow comparison documented | Complete |
| Event ID 3 status confirmed (working, not deferred) | Complete |

---

## Final Status

**Phase 8 complete.** Splunk added as a second working SIEM investigation environment, including two genuine troubleshooting cases beyond the anticipated scope — most notably a Windows Event Log channel-access restriction that required identifying and correcting a security descriptor mismatch between Splunk's Windows service account and Sysmon's Operational log.
