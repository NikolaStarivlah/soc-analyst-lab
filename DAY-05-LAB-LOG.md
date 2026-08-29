# Day 05 Lab Log — Phase 5 Complete

## Scripted Alert Loop, High-Volume SOC Triage, Escalation Notes, and Shift Handoff

**Status:** Phase 5 Complete
**Focus:** SOC Analyst L1 first-look triage, alert classification, false-positive decisions, escalation notes, shift handoff documentation, and hands-on Sysmon visibility-gap discovery.

---

## 1. Phase Overview

Phases 1–4 built and validated the lab's telemetry foundation — Elastic SIEM, Suricata IDS, Wazuh XDR, and a working reference for Windows/Linux/network log fundamentals. Phase 5 used that foundation to simulate a SOC alert queue: a scripted PowerShell loop generated high-volume, safe endpoint activity on the Windows 10 victim, and the resulting events were triaged in Kibana Discover using the same "verify before concluding" discipline established in Phase 4.

Main workflow practiced:

```text
Event appears -> Identify source -> Review user/process/parent/destination -> Determine context -> Decide benign/suspicious/escalate -> Document clearly
```

This phase produced two categories of result: (1) triage verdicts on expected activity, following the SOC mindset of "suspicious by technique, benign by context," and (2) a genuine, hands-on-discovered Sysmon visibility gap that went beyond what was expected going in — a stronger portfolio finding than a scripted example.

---

## 2. Lab Environment

### Ubuntu-SIEM VM

Role: Elastic/Kibana SIEM server, Fleet Server, Elasticsearch data store, Suricata IDS.

Host-only IP (confirmed live via `ip a`, not assumed from notes):

```text
192.168.56.112
```

Services involved: `elasticsearch`, `kibana`, `elastic-agent` (Fleet Server).

### Windows 10 Victim VM

Role: endpoint monitored throughout the phase; generated the Phase 5 activity loop; shipped logs to Elastic via Elastic Agent.

Host-only IP (confirmed live via `ipconfig`):

```text
192.168.56.114
```

Hostname (confirmed from live Sysmon telemetry, not assumed):

```text
DESKTOP-BN86O9N
```

User:

```text
DESKTOP-BN86O9N\Nikola
```

Telemetry sources: Windows Security logs, Windows System logs, Sysmon logs, Elastic Agent/Fleet log shipping.

### Wazuh Server VM

Powered off for the duration of Phase 5 — not needed for Elastic/Kibana-focused triage work, and kept off to conserve host resources, consistent with the Phase 4 approach.

---

## 3. Learning Objectives

- Generate repeatable, safe alert/event activity in a lab
- Review high-volume Sysmon logs in Kibana Discover
- Search for specific commands and processes using targeted `process.name` queries rather than broad wildcards
- Identify user context and distinguish user activity from SYSTEM/service noise
- Read parent-process fields to determine execution lineage
- Classify events as benign, false positive, suspicious, or escalation-worthy
- Write SOC-style triage notes, escalation notes, and a shift handoff summary
- Troubleshoot a real Elasticsearch/Kibana authentication issue
- Identify and document a genuine Sysmon event-coverage gap through direct verification, not assumption

---

## 4. Key SOC Mindset

### Suspicious by technique, benign by context

Commands like `whoami`, `hostname`, `ipconfig`, `net user`, `net localgroup administrators`, `nslookup`, `curl`, and PowerShell/cmd invocations are used by both administrators and attackers. They are not automatically malicious — they matter because attackers use them for discovery, privilege checks, environment awareness, connectivity testing, and payload retrieval.

```text
The behavior may be suspicious by technique, but the final verdict depends on context.
```

Context includes user, host, command line, parent process, process path, destination, timing, and surrounding events.

---

## 5. Pre-Phase Issue: Kibana Login Failure (Not a Service Outage)

### Problem

Elasticsearch and Kibana were both confirmed `active (running)` via `systemctl status` — no service was down. The issue was a Kibana login rejection: "Username or password is incorrect."

### Troubleshooting

Rather than apply an unrelated fix, the actual authentication path was checked first:

```bash
sudo grep -i "authenticat" /var/log/elasticsearch/elasticsearch.log | tail -n 20
```

This surfaced `ApiKeyAuthenticator` warnings tied to Fleet Server's own internal API key — unrelated to the `elastic` superuser login and not the cause of the failure. Since services were healthy and the credential itself was the only unverified variable, a straightforward password reset was used rather than modifying any service configuration:

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

### Result

New `elastic` password generated and confirmed working in Kibana on the first attempt.

### Lesson Learned

Not every login failure is a service outage, and not every red flag in the logs is the actual cause — the `ApiKeyAuthenticator` warning looked relevant but belonged to a completely different component (Fleet Server). Diagnosing the specific failure path before applying a fix (and specifically *not* reusing the Phase-4-adjacent "reset file permissions" playbook, since services were already healthy) avoided an unnecessary configuration change to a system that wasn't actually broken.

---

## 6. Scripted Activity Loop

### Script Location

```text
C:\SOC-Lab\Phase5\phase5-loop.ps1
```

### Script Content

```powershell
Write-Host "Starting Phase 5 SOC alert generation loop..."

for ($i = 1; $i -le 10; $i++) {

    Write-Host "Iteration $i"

    whoami
    hostname
    ipconfig

    nslookup google.com
    nslookup github.com
    nslookup microsoft.com

    curl.exe https://example.com
    curl.exe https://github.com

    Start-Process notepad.exe
    Start-Sleep -Seconds 2
    Start-Process calc.exe
    Start-Sleep -Seconds 2

    echo "Phase 5 test file $i" > "C:\Users\Public\phase5-test-$i.txt"
    Start-Sleep -Seconds 2
    Remove-Item "C:\Users\Public\phase5-test-$i.txt" -Force

    net user
    net localgroup administrators

    powershell.exe -Command "Get-Process | Select-Object -First 5"

    Start-Sleep -Seconds 10
}

Write-Host "Phase 5 loop complete."
```

### Execution

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\SOC-Lab\Phase5\phase5-loop.ps1
```

Ran to completion across all 10 iterations, confirmed by the `"Phase 5 loop complete."` console output. Generated process creation events, PowerShell activity, DNS lookups, command-line web requests, GUI application launches, file create/delete activity, and local account/group enumeration — 3,700+ documents ingested into `logs-*` in the run window.

---

## 7. Kibana Queries Used During Triage

```kql
agent.name : "DESKTOP-BN86O9N"

agent.name : "DESKTOP-BN86O9N" and winlog.channel : "Microsoft-Windows-Sysmon/Operational" and event.code : "1"

agent.name : "DESKTOP-BN86O9N" and process.name : "whoami.exe"

agent.name : "DESKTOP-BN86O9N" and (process.name : "net.exe" or process.name : "net1.exe")

agent.name : "DESKTOP-BN86O9N" and process.name : "curl.exe"

agent.name : "DESKTOP-BN86O9N" and process.name : "nslookup.exe"

agent.name : "DESKTOP-BN86O9N" and event.code : "22"

agent.name : "DESKTOP-BN86O9N" and event.code : "4624"

agent.name : "DESKTOP-BN86O9N" and event.code : "4624" and winlog.logon.type : "Interactive" and user.name : "Nikola"
```

**Lesson carried forward from Phase 4:** quoted phrase searches against `process.command_line` (e.g. `"net localgroup administrators"`) can silently return zero results due to field tokenization. Querying `process.name` directly is the reliable approach.

---

## 8. Parent Process vs Command Process

Across every triaged event this phase, the pattern held:

```text
Command/process: C:\Windows\system32\whoami.exe (or net.exe, curl.exe, etc.)
Parent process:  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Because the entire Phase 5 loop runs inside a `.ps1` script, every generated command shares the same parent lineage — PowerShell launching each utility in turn. This made parent-process review straightforward this phase, but the underlying lesson stands: the command/process tells what ran, the parent process tells where it came from, and an unexpected parent (e.g. an Office app spawning PowerShell) is a stronger indicator than the command itself.

---

## 9. Completed Triage Examples

### Example 1 — PowerShell `whoami`

| Field | Value |
|---|---|
| Event | Sysmon Event ID 1, Process Creation |
| User | `Nikola` |
| Command | `"C:\Windows\system32\whoami.exe"` |
| Parent | `powershell.exe` |
| Why SOC cares | Attackers commonly run `whoami` immediately post-access to confirm user context and privilege level |
| **Decision** | **Benign by context / suspicious by technique** |
| Reasoning | Expected script-driven activity under a known interactive account, not an unexplained discovery command |

10 occurrences total (one per loop iteration), identical pattern — verified one representative event in full detail rather than opening all ten individually.

### Example 2 — `net localgroup administrators`

| Field | Value |
|---|---|
| Event | Sysmon Event ID 1, Process Creation |
| Command | `net.exe localgroup administrators` |
| User | `Nikola` |
| Parent | `powershell.exe` |
| Why SOC cares | Attackers use this for local privilege-group discovery post-compromise |
| **Decision** | **Benign by context / suspicious by technique** |
| Reasoning | Script-driven lab activity; in production this event would warrant a check for nearby account/group-change activity before closing |

**Side note for interviews:** both `net.exe` and `net1.exe` fired for the same logical command — `net.exe` is a thin wrapper that hands execution off to `net1.exe`. This is expected Windows internals, not a duplicate-logging bug.

### Example 3 — `curl.exe` to GitHub

| Field | Value |
|---|---|
| Event | Sysmon Event ID 1, Process Creation |
| Command | `"C:\Windows\system32\curl.exe" https://github.com` |
| User | `Nikola` |
| Parent | `powershell.exe` |
| Why SOC cares | Command-line web tools can download payloads or beacon to attacker infrastructure |
| **Decision** | **Benign in lab / investigate if unexpected or followed by execution** |
| Reasoning | Known destination (github.com), script-driven, no follow-on execution of a downloaded artifact observed |

Same pattern confirmed for `curl.exe https://example.com`.

### Example 4 — Sysmon DNS/Network Visibility Gap (original finding, not in original script guidance)

While attempting to triage `curl.exe`'s network connections (Sysmon Event ID 3, expecting port 443 traffic), a `process.name : "curl.exe" and event.code : "3"` query returned **zero results**, verified across both a 15-minute window and a full 24-hour window. Since `curl.exe` process-creation events clearly existed in the same window, this was treated as a genuine visibility question rather than a query error, following the Phase 4 "bare query, full time range, no assumptions" method.

**Verified findings:**

- `curl.exe` generates **Process Creation (Event 1)** and **DNS Query (Event 22)**, but **never Network Connection (Event 3)**, in this environment.
- `nslookup.exe` generates **Process Creation (Event 1)** and **Network Connection (Event 3)** — to VirtualBox's internal NAT DNS proxy at `10.0.2.3:53` — but **never DNS Query (Event 22)**.

**Interpretation:** Sysmon's DNS Query event (22) appears to fire only for processes resolving names through the standard OS resolver API path. `nslookup.exe` performs its own resolution outside that path, so it surfaces only as a raw network socket to port 53, not as a DNS Query event. `curl.exe` goes through the OS resolver (hence Event 22) but its actual outbound HTTPS connection isn't independently captured as a Network Connection event in this Sysmon configuration.

**Practical takeaway:** visibility into "DNS activity" or "network activity" is tool-dependent in this environment, not a fixed mapping from activity type to event code. A real investigation correlating a suspicious `curl.exe` call to its destination IP would need to rely on DNS Query logs (which domain was resolved), not Network Connection logs — the reverse is true for `nslookup.exe`. This is a genuine, hands-on-confirmed detection gap worth carrying into future phases (e.g. Phase 9 Detection Engineering, Phase 18 Network Traffic Analysis).

### Example 5 — Windows 4624 Logons

| Metric | Result |
|---|---|
| Service logons (24h) | 44, all `SYSTEM`/`services.exe` — expected background service activity |
| Interactive logons (24h) | 0 — no fresh login occurred inside the review window |
| Interactive logons (full history) | 10 over ~2 weeks, all `svchost.exe` under `Nikola`, paired per boot/session |
| **Decision** | **Benign / close as expected baseline** |
| Reasoning | Consistent with the Phase 4 finding that this environment's real interactive logon presents via `svchost.exe` rather than a typical `winlogon.exe`-driven session; no anomalous logon type or unexpected account observed |

**Lesson:** Kibana silently widens the time range when a narrow window returns zero results (the "Search entire time range" prompt) — always confirm the actual displayed range in the date picker before drawing conclusions from a hit count, rather than assuming the original window still applies.

---

## 10. False Positive / Benign Activity List

1. PowerShell `whoami` — benign by context, suspicious by technique
2. `net user` — benign, automated inventory/script activity
3. `net localgroup administrators` — benign by context, suspicious by technique
4. `curl.exe https://github.com` — benign, known destination
5. `curl.exe https://example.com` — benign, known destination
6. `nslookup google.com` / `github.com` / `microsoft.com` — benign, expected DNS lookups
7. `notepad.exe` / `calc.exe` process creation — benign, script-triggered GUI launches
8. `net.exe` / `net1.exe` dual firing — benign, expected Windows internals (wrapper behavior)
9. Windows 4624 Service logons (`SYSTEM`) — benign, background service activity
10. Windows 4624 Interactive logons (`Nikola` via `svchost.exe`) — benign, legitimate session starts

---

## 11. Escalation-Style Notes

### Note 1 — PowerShell User Discovery

`whoami` executed under PowerShell on `DESKTOP-BN86O9N` by `Nikola`. Could indicate post-compromise discovery if the account, timing, or parent process were unexpected. **Decision: benign in lab / investigate in production if unexpected.**

### Note 2 — Local Administrator Group Enumeration

`net localgroup administrators` reveals accounts with local admin rights — a common attacker privilege-discovery step. **Decision: benign by context / suspicious by technique.**

### Note 3 — Command-Line Web Request

`curl.exe` to GitHub — command-line web tools can retrieve payloads or scripts. **Decision: benign in lab / investigate if unexpected or followed by execution of a downloaded file.**

### Note 4 — Sysmon Visibility Gap (curl/nslookup DNS asymmetry)

Not an incident, but an escalation-relevant detection gap: neither `curl.exe`'s network connections nor `nslookup.exe`'s DNS query activity are fully captured by a single Sysmon event type. **Decision: document as a known monitoring gap; do not assume network-connection or DNS-query logs alone are complete for either tool.**

### Note 5 — Successful Service/Interactive Logons (4624)

Service logons (type 5, `SYSTEM`) and the recurring `svchost.exe`/`Nikola` interactive-logon pattern are both consistent, expected baselines. **Decision: benign/tune unless an unexpected account or logon type appears.**

---

## 12. Shift Handoff Summary

### Analyst

Nikola

### Environment

Elastic/Kibana SIEM (`192.168.56.112`) with Windows 10 victim endpoint `DESKTOP-BN86O9N` (`192.168.56.114`) running Sysmon and Elastic Agent. Wazuh server powered off for the shift.

### Shift Summary

A scripted Phase 5 activity loop was executed on the Windows 10 victim to generate high-volume endpoint telemetry for SOC triage practice: process creation, PowerShell execution, DNS lookups, command-line web requests, local account/group enumeration, file create/delete activity, and GUI process launches.

Kibana login initially failed with an authentication error despite both Elasticsearch and Kibana running healthy — resolved via the built-in `elasticsearch-reset-password` tool rather than a service-level fix, since no service was actually down.

Events reviewed and triaged: PowerShell `whoami`, `net localgroup administrators` / `net user` (with `net.exe`→`net1.exe` handoff behavior noted), `curl.exe` web requests, `nslookup` DNS activity, and Windows 4624 logons (service and interactive).

### Findings

No malicious activity identified. All reviewed events were script-generated or normal Windows background/service activity, correctly classified using suspicious-by-technique/benign-by-context reasoning.

**Notable non-incident finding:** a real Sysmon visibility gap was identified and verified — `curl.exe` and `nslookup.exe` each surface through only one of {Process Creation, DNS Query, Network Connection} for their DNS/network activity, and the two tools' visible event types don't overlap. This should inform detection logic in later phases (Phase 9 onward): don't assume one event type provides complete network/DNS visibility across all tools.

### Escalation Status

```text
No events required escalation in the lab environment.
```

### Recommended Follow-Up

- Convert the strongest triage examples into formal SOC tickets in Phase 6
- Carry the curl/nslookup visibility-gap finding into Phase 9 (Detection Engineering) and Phase 18 (Network Traffic Analysis) as a known monitoring limitation
- Continue practicing targeted `process.name` queries over broad wildcard/phrase searches
- Continue verifying time-range assumptions before drawing conclusions from result counts

---

## 13. Lessons Learned

1. A running service is not the same as a working login — authentication failures need their own diagnostic path, not the nearest-looking prior fix.
2. Field tokenization can silently break phrase-based command-line searches; targeted `process.name` queries are more reliable (reconfirmed from Phase 4).
3. Event-type coverage is tool-specific, not activity-specific — two tools generating conceptually similar traffic (DNS resolution) can produce completely non-overlapping Sysmon event types.
4. Kibana silently widens time ranges on empty results; always check the actual displayed range before concluding "no data."
5. Parent-process context did the most analytical work this phase, since nearly every event shared the same script-driven PowerShell lineage — the account and command mattered more than the process name alone.
6. A verified, unexpected finding (the DNS/network visibility gap) is more valuable for a portfolio than confirming an expected one — worth actively investigating discrepancies rather than smoothing over them.

---

## 14. Interview Translation

In Phase 5, I practiced SOC Analyst first-look triage using my Elastic/Kibana SIEM and Windows 10 victim endpoint. I generated high-volume, safe endpoint activity with a PowerShell loop and reviewed the resulting Sysmon and Windows events in Kibana Discover, building queries from broad to targeted and verifying field names and event codes against raw documents rather than assuming them.

I triaged PowerShell discovery commands, local administrator group enumeration, command-line web requests, DNS lookups, and Windows logon events, classifying each using a suspicious-by-technique/benign-by-context framework. Along the way, I identified and verified a real detection gap: two different command-line tools generating DNS/network activity (`curl.exe` and `nslookup.exe`) surface through entirely different, non-overlapping Sysmon event types, meaning a single event-type filter would miss one or the other in a real investigation.

I also resolved a Kibana authentication failure by isolating whether the root cause was a service outage or a credential problem, checking Elasticsearch's own logs before applying a fix, and resetting the account password through Elasticsearch's built-in tooling rather than modifying working service configuration.

This phase reinforced the real SOC workflow of reviewing alerts, verifying assumptions against live data, documenting both expected and unexpected findings clearly, and producing a shift handoff a following analyst could act on.

---

## 15. Completion Checklist

- [x] Phase 5 activity loop created and executed to completion
- [x] High-volume endpoint events generated and confirmed ingesting into `logs-*`
- [x] Kibana authentication issue diagnosed and resolved (password reset, not a service fix)
- [x] Sysmon process creation triage practiced (`whoami`, `net localgroup administrators`, `curl.exe`)
- [x] `net.exe`/`net1.exe` wrapper behavior identified and documented
- [x] Sysmon DNS/network visibility gap identified, verified across time ranges, and documented
- [x] Windows 4624 service and interactive logons reviewed and verified across time ranges
- [x] False positive/benign list created from verified data
- [x] Escalation-style notes created from verified data
- [x] Shift handoff summary created
- [x] SOC-style decision language practiced throughout
- [x] Website/GitHub-ready writeup created with corrected environment identity (hostname, user, IPs)

## Final Status

**Phase 5 complete.**
