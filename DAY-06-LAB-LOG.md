# Day 06 Lab Log — Phase 6 Complete: SOC Ticket Writing, Escalation, and Shift Handoff

**Date:** August 29, 2026
**Phase Completed:** Phase 6 — SOC Ticket Writing, Escalation, and Shift Handoff
**Focus:** SOC ticket templates, severity reasoning, escalation summaries, shift handoff notes, and analyst documentation discipline — built from live Elastic/Kibana evidence rather than pre-written examples

---

## Phase 6 Status

**Completed for website / portfolio documentation**

This phase took alerts and events reviewed during Phase 5 and turned them into SOC-style tickets, escalation summaries, severity decisions, and shift handoff notes. Every ticket in this log was built from a real document pulled live from Kibana Discover — process IDs, parent-process chains, SHA256 hashes, and timestamps are actual values recorded in this lab, not template placeholders.

Phase 5 answered:

```text
What happened?
Who ran it?
What command/process executed?
What parent process launched it?
Was it expected?
Should I close, investigate, or escalate?
```

Phase 6 answered:

```text
How do I document this clearly in a ticket?
How do I explain severity?
How do I justify the verdict?
How do I recommend next action?
How do I hand this off to another analyst?
```

---

# 1. Phase Overview

Phase 6 built on the high-volume triage work completed in Phase 5. Instead of only reviewing alerts in Kibana, this phase focused on writing clean SOC documentation directly from live evidence: five SOC tickets, three escalation summaries, and two shift handoff notes.

---

# 2. Lab Environment Used

## Ubuntu-SIEM VM

```text
Role: Elasticsearch, Kibana, Fleet Server, Elastic Agent management
Host-only IP: 192.168.56.112 (confirmed live via `ip a`)
```

## Windows 10 Victim VM

```text
Role: Endpoint monitored throughout; source of Phase 5/6 events
Host-only IP: 192.168.56.114 (confirmed live via `ipconfig`)
Hostname: DESKTOP-BN86O9N (confirmed via `hostname`)
User: DESKTOP-BN86O9N\Nikola (confirmed via `whoami`)
```

## Tools Used

- Elastic / Kibana Discover
- Sysmon (Microsoft-Windows-Sysmon/Operational)
- Windows Security log
- Elastic Agent / Fleet
- Phase 5 activity loop events as ticket source material

**Note:** an early draft of this phase's write-up guide referenced placeholder environment values (`192.168.56.101` / `.104`, hostname `DESKTOP-3JKM5O9`, user `mmajeed`) that did not match this lab. All values above were reconfirmed live on both VMs before any ticket was written.

---

# 3. Phase 6 Goal

Deliverables completed for this log:

- 5 SOC tickets, each built from a real Kibana document
- 3 escalation summaries (1 from a live, safely simulated event; 2 from existing ticket evidence)
- 2 shift handoff notes
- Severity reasoning notes
- Ticket and escalation writing templates
- Lessons learned
- Website/GitHub-ready documentation

---

# 4. Key Concept: Triage vs Ticket vs Escalation

**Triage** — first-look analysis. Answers: What happened? Who was involved? What evidence exists? Is this expected or suspicious?

**SOC Ticket** — a formal written record. Answers: What happened? What host/user was affected? What evidence supports the analysis? What was the verdict? What should be done next?

**Escalation Summary** — shorter, written for L2/IR/security engineering. Answers: Here is the suspicious activity. Here is why it matters. Here is what I checked. Here is what I recommend next.

**Shift Handoff** — summarizes the shift so the next analyst can continue without losing context. Answers: What did I review? What did I close? What is still open? What should the next analyst watch?

---

# 5. SOC Ticket Template

```markdown
# Ticket X - <Alert Name>

## Severity
Low / Medium / High / Critical

## Status
Open / Closed as benign / False Positive / Escalated

## Alert Summary
<One to three sentences explaining what happened.>

## Affected Asset
Host:
User:
IP / Endpoint Role:

## Detection Source
Tool:
Log Source:
Event ID:

## Evidence
Command/process:
Parent process:
Parent user:
Process ID:
Parent Process ID:
Timestamp:
Relevant fields:

## Analysis
<What the event means, why SOC cares, expected or suspicious.>

## Verdict
Benign by context / Suspicious by technique / False positive / Escalate

## Recommended Action
<Close, monitor, tune, investigate further, or escalate.>
```

---

# 6. Severity Reasoning Model

Severity comes from `command + user + parent process + destination + frequency + impact + follow-on activity` — not the command name alone.

```text
Low:      Normal/noisy activity, expected behavior, little risk.
Medium:   Suspicious technique, but no proof of compromise or system change.
High:     Risky action with possible compromise, privilege change, persistence,
          suspicious source, or malicious pattern.
Critical: Confirmed compromise, active malware, ransomware, data theft,
          domain-wide impact, or production outage.
```

**Key lesson:** Severity and verdict are different. `Severity: Medium / Verdict: Benign by context` means the behavior was important enough to review, but after analysis it was authorized or expected.

---

# 7. Verification Notes From This Session

| Problem | What Was Checked | Root Cause | Fix |
|---|---|---|---|
| `curl.exe` query without an `event.code` filter returned a document missing `process.command_line`/parent fields | Expanded the JSON detail panel | The returned document was Sysmon Event ID 22 (DNS Query), not Event ID 1 (Process Creation) — Event 22 doesn't carry command-line/parent data, as established in Phase 5 | Re-ran query scoped to `event.code : "1"` to get the Process Creation document needed for the ticket |
| Unscoped `event.code : "4625"` query returned 3 hits that looked like failed logons | Inspected `winlog.channel` and the event message in each result | All 3 were from `winlog.channel: "Application"` under the `Microsoft-Windows-EventSystem` provider — a routine duplicate-log-suppression notice, unrelated to authentication | Re-ran query scoped to `winlog.channel : "Security"`; confirmed 0 real failed logons existed prior to the Escalation Summary 1 simulation |
| Needed real evidence for a "multiple failed logons" escalation scenario without an actual incident | N/A | CIS SCA review (Phase 3) confirmed no account-lockout policy is configured on this VM | Safely simulated 4 deliberate failed logon attempts via Win+L, then logged back in successfully — generated real, reversible Event ID 4625 data |

---

# 8. SOC Ticket 1 - PowerShell User Discovery Command

## Severity
Medium

## Status
Closed as benign lab activity

## Alert Summary
A PowerShell session executed `whoami.exe` on the Windows 10 victim endpoint to identify the current user context.

## Affected Asset
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
IP / Endpoint Role: 192.168.56.114 (host-only) - Windows 10 victim VM
```

## Detection Source
```text
Tool: Elastic / Kibana Discover
Log Source: Microsoft-Windows-Sysmon/Operational (windows.sysmon_operational)
Event ID: Sysmon Event ID 1 - Process Creation (event.code: 1)
```

## Evidence
```text
Command/process: C:\Windows\System32\whoami.exe
Parent process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent user: DESKTOP-BN86O9N\Nikola
Process ID: 9624
Parent Process ID: 7916
Process GUID: {133A785F-5122-6A93-DD00-0000001700}
SHA256: 1d4902a04d99e8ccbfe7085e63155955fee397449d386453f6c452ae407b743
Working directory: C:\Users\Nikola\
Timestamp: Aug 29, 2026 @ 17:37:38.333
```

## Analysis
Sysmon Event ID 1 shows `whoami.exe` launched from a PowerShell session under `Nikola`. `whoami` is a routine command used to confirm the current user context — legitimate for admin/troubleshooting use, but also a common first move for an attacker confirming what account they landed on after gaining access. In this lab, the activity is expected: it matches the Phase 5 scripted activity loop, runs under the known interactive account, and has a normal Microsoft-signed parent (`powershell.exe`). No suspicious follow-on activity observed.

## Verdict
Benign by context / suspicious by technique

## Recommended Action
Close as authorized lab activity. In production, this event would still warrant a quick check of surrounding PowerShell activity, logon events, and any privilege-related events before closing.

---

# 9. SOC Ticket 2 - Local Administrators Group Enumeration

## Severity
Medium

## Status
Closed as benign lab activity

## Alert Summary
A Windows command was executed to enumerate members of the local Administrators group on the Windows 10 victim endpoint.

## Affected Asset
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
IP / Endpoint Role: 192.168.56.114 (host-only) - Windows 10 victim VM
```

## Detection Source
```text
Tool: Elastic / Kibana Discover
Log Source: Microsoft-Windows-Sysmon/Operational (windows.sysmon_operational)
Event ID: Sysmon Event ID 1 - Process Creation (event.code: 1)
```

## Evidence
```text
Command/process: net1.exe (child, spawned by net.exe - pe.description "Net Command")
Parent process: "C:\Windows\system32\net.exe" localgroup administrators
Parent user: DESKTOP-BN86O9N\Nikola
Process ID: 2328
Parent Process ID: 8984
Process GUID (parent): {133A785F-32A8-6A92-3902-000000001500}
SHA256 (net1.exe): e62071aa18768dd88acaf97fa7b1f2fec9fcce89736c1ee9a800699328d196ea
Working directory: C:\Users\Nikola\
Timestamp: Aug 28, 2026 @ 21:15:20.236
```

## Analysis
Sysmon Event ID 1 shows `net.exe localgroup administrators` was run, which internally hands execution to `net1.exe` — expected Windows internals, not duplicate logging. This command enumerates members of the local Administrators group. It's security-relevant because attackers commonly use it post-compromise to check whether they already have elevated access or to identify high-value accounts for privilege escalation/lateral movement. In this lab, the activity is expected: it matches the Phase 5 scripted loop, runs under the known interactive account (`Nikola`), and both binaries are Microsoft-signed with normal metadata. No account creation or group-membership change was observed alongside it.

## Verdict
Benign by context / suspicious by technique

## Recommended Action
Close as authorized lab activity. In production, correlate this with nearby Event ID 4732 (added to group) or 4720 (account created) before closing, and confirm the user was authorized to run it.

---

# 10. SOC Ticket 3 - Command-Line Web Request to GitHub

## Severity
Medium

## Status
Closed as benign lab activity

## Alert Summary
A PowerShell session launched `curl.exe` to make an outbound HTTPS request to `github.com` from the Windows 10 victim endpoint.

## Affected Asset
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
IP / Endpoint Role: 192.168.56.114 (host-only) - Windows 10 victim VM
```

## Detection Source
```text
Tool: Elastic / Kibana Discover
Log Source: Microsoft-Windows-Sysmon/Operational (windows.sysmon_operational)
Event ID: Sysmon Event ID 1 - Process Creation (event.code: 1)
```

## Evidence
```text
Command/process: "C:\Windows\system32\curl.exe" https://github.com
Parent process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent user: DESKTOP-BN86O9N\Nikola
Process ID: 1444
Parent Process ID: 4576
Process GUID: {133A785F-32A1-6A92-3302-000000001500}
SHA256: 3345339164cf384eff527b6c3160fea8d849a4231e6ca80513e3a739e505168
Working directory: C:\Users\Nikola\
Timestamp: Aug 28, 2026 @ 21:15:13.858
```

## Analysis
Sysmon Event ID 1 shows `curl.exe` launched from a PowerShell session to make an outbound HTTPS request to `github.com`. Command-line web requests can be legitimate — testing, troubleshooting, tool downloads — but are also a common way attackers retrieve payloads or contact external infrastructure. In this lab the activity is expected, matching the Phase 5 scripted loop under the known interactive account. The corresponding DNS Query event (Sysmon 22) independently confirmed the destination resolved to `140.82.114.4` (GitHub's real IP), and no follow-on file execution was observed from this session.

## Verdict
Benign by context / suspicious by technique

## Recommended Action
Close as authorized lab activity. In production, review destination reputation, any downloaded content, and follow-on process execution before closing.

---

# 11. SOC Ticket 4 - DNS Lookup Using nslookup

## Severity
Low

## Status
Closed as benign lab activity

## Alert Summary
A PowerShell session launched `nslookup.exe` to query DNS resolution for `microsoft.com` from the Windows 10 victim endpoint.

## Affected Asset
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
IP / Endpoint Role: 192.168.56.114 (host-only) - Windows 10 victim VM
```

## Detection Source
```text
Tool: Elastic / Kibana Discover
Log Source: Microsoft-Windows-Sysmon/Operational (windows.sysmon_operational)
Event ID: Sysmon Event ID 1 - Process Creation (event.code: 1)
```

## Evidence
```text
Command/process: "C:\Windows\system32\nslookup.exe" microsoft.com
Parent process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent user: DESKTOP-BN86O9N\Nikola
Process ID: 6960
Parent Process ID: 4576
Process GUID: {133A785F-31EC-6A92-3102-000000001500}
SHA256: 55ab032d256adbe3fde40cf90fe83ba5eab591e04ad720161ed8e6ef059ca747
Working directory: C:\Users\Nikola\
Timestamp: Aug 28, 2026 @ 21:15:13.729
```

## Analysis
Sysmon Event ID 1 shows `nslookup.exe` launched from PowerShell to resolve `microsoft.com`. DNS lookups are routine for troubleshooting and connectivity testing, but can also appear during attacker reconnaissance or C2 domain validation. Here, the queried domain is a well-known, legitimate Microsoft domain, and the activity matches the Phase 5 scripted loop under the known interactive account. As established in Phase 5, `nslookup.exe` doesn't generate a Sysmon Event 22 (DNS Query) in this environment — it resolves outside the standard OS resolver path — so this Process Creation event is the only Sysmon record of this lookup; no separate DNS Query record independently confirms resolution success.

## Verdict
Benign by context

## Recommended Action
Close as authorized lab activity. In production, investigate further if the queried domain is unfamiliar, newly registered, or appears alongside other discovery/download activity.

---

# 12. SOC Ticket 5 - No Failed Logon Activity Observed (Security Log Baseline)

## Severity
Low

## Status
Closed - no incident, baseline confirmed

## Alert Summary
A targeted review of Windows Security Event ID 4625 (Failed Logon) on host `DESKTOP-BN86O9N` returned zero results over a 2-week window (Aug 10 - Aug 25, 2026).

## Affected Asset
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
IP / Endpoint Role: 192.168.56.114 (host-only) - Windows 10 victim VM
```

## Detection Source
```text
Tool: Elastic / Kibana Discover
Log Source: Windows Security (winlog.channel: "Security")
Event ID: Windows Security Event ID 4625 - Failed Logon
```

## Evidence
```text
Query: agent.name : "DESKTOP-BN86O9N" and event.code : "4625" and winlog.channel : "Security"
Time range checked: Aug 10, 2026 @ 13:03 - Aug 25, 2026 @ 16:33 (~2 weeks)
Result: 0 documents
```

Note: an earlier unscoped query (`event.code: "4625"` without a channel filter) returned 3 hits, but these were all from `winlog.channel: "Application"` under the `Microsoft-Windows-EventSystem` provider — unrelated COM+ duplicate-suppression notices, not authentication events. Event ID numbers are only meaningful together with their channel and provider; this was verified by inspecting `winlog.channel` and the event message before drawing any conclusion.

## Analysis
No failed logon attempts were recorded against this host's Security log across the full review window. This is a legitimate and useful baseline to have on record, consistent with the Phase 4/5 finding that an empty, properly verified result (correct channel, full time range) is itself valid evidence — not a sign of a broken query.

## Verdict
Benign - clean baseline

## Recommended Action
No action required. Retain this as the current authentication baseline for this host; any future 4625 activity in the Security channel would represent a change from established normal and should be triaged against it.

---

# 13. Escalation Summary Template

```markdown
# Escalation Summary - <Alert Name>

## Summary
<What happened in 1-3 sentences.>

## Evidence Reviewed
- Host:
- User:
- Command:
- Parent process:
- Log source:
- Event ID:
- Related fields:

## Analyst Assessment
<Why this matters. Explain whether it is suspicious by technique, benign by context, or escalation-worthy.>

## Risk
Low / Medium / High / Critical

## Recommended L2 Actions
-
-
-
```

---

# 14. Escalation Summary 1 - Repeated Failed Logon Attempts (Live Simulation)

## Summary
Four consecutive failed logon attempts were recorded for local user `Nikola` on host `DESKTOP-BN86O9N` within a 16-second window, followed by a successful logon. All attempts were Interactive (console) logons from the local machine itself. This was a deliberate, safe, reversible simulation (confirmed no account-lockout policy is configured per the Phase 3 CIS review) performed specifically to generate real evidence for this escalation summary, rather than a hypothetical.

## Evidence Reviewed
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
Command: N/A - authentication event
Parent process: N/A - authentication event
Log source: Windows Security (winlog.channel: Security)
Event ID: 4625 - Failed Logon (x4)
Timestamps: Aug 29, 2026 @ 23:34:59.447, 23:35:01.841, 23:35:10.145, 23:35:15.519
Related fields:
- winlog.event_data.TargetUserName: Nikola
- winlog.event_data.TargetDomainName: DESKTOP-BN86O9N
- winlog.logon.type / LogonType: 2 (Interactive)
- winlog.event_data.SubStatus: 0xc000006a (bad password)
- winlog.event_data.FailureReason: Unknown user name or bad password
- source.ip / winlog.event_data.IpAddress: 127.0.0.1
- winlog.computer_name / WorkstationName: DESKTOP-BN86O9N
```

## Analyst Assessment
Windows Security Event ID 4625 indicates a failed logon attempt. Four consecutive failures against the same known account in a short window would normally warrant scrutiny for password guessing or brute-force behavior. However, several fields here point away from that: the logon type is `Interactive` (a console/keyboard logon, not a network- or remote-service-based logon type like 3, 10, or 11), the source IP is the loopback address `127.0.0.1`, and the workstation name matches the target host itself — meaning these attempts originated at the physical console of the machine being logged into, not from a remote or unknown source. This pattern is consistent with a local user mistyping their own password multiple times, not an external attacker.

The same event set would be assessed very differently if the `LogonType` were network/RDP-based rather than Interactive, the source IP were external or unrecognized, the target account were unrecognized/privileged, or the attempts spanned multiple different usernames.

## Risk
```text
Low as observed - known user, console logon, loopback source, immediately followed by a successful logon.
Would be High if: LogonType were network/RDP-based, source IP were external, target account were privileged, or attempts continued without a subsequent success.
```

## Recommended L2 Actions
- Confirm `LogonType` on every 4625 before escalating — Interactive (2) from loopback is a materially different finding than Network (3) or RemoteInteractive (10) from an external IP.
- Check whether a matching 4624 (successful logon) immediately follows the failed attempts, for the same user — present here.
- If `LogonType` or source IP indicates a remote/network origin instead, treat as a possible brute-force/password-spray attempt and escalate.
- Establish a threshold (e.g., >5 failures in under a minute) for automated alerting rather than triaging every failed logon manually.

---

# 15. Escalation Summary 2 - curl.exe Launched from PowerShell

## Summary
A local user executed `curl.exe` from PowerShell to connect to `https://github.com` on host `DESKTOP-BN86O9N`. The activity should be reviewed because command-line web requests can be used for legitimate administration or for downloading files, contacting external infrastructure, or transferring data.

## Evidence Reviewed
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
Command: "C:\Windows\system32\curl.exe" https://github.com
Parent process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Log source: Microsoft-Windows-Sysmon/Operational
Event ID: Sysmon Event ID 1 - Process Creation
Process ID: 1444 | Parent Process ID: 4576
SHA256: 3345339164cf384eff527b6c3160fea8d849a4231e6ca80513e3a739e505168
Timestamp: Aug 28, 2026 @ 21:15:13.858
```

## Analyst Assessment
Sysmon Event ID 1 shows `curl.exe` launched from PowerShell to make an outbound HTTPS request to GitHub. This is security-relevant because command-line web tools can download scripts, payloads, or tools, contact external infrastructure, or transfer data. It is not automatically malicious, but should be reviewed if unexpected, repeated, associated with unknown domains, or followed by file creation or execution. In this case, the corresponding DNS Query event independently confirmed the destination resolved to a legitimate GitHub IP (`140.82.114.4`), and no follow-on file execution was observed.

## Risk
```text
Medium as observed - known destination, no downloads or follow-on execution detected.
High if: the command downloaded files, contacted an unrecognized/malicious domain, or was followed by execution of a new binary.
```

## Recommended L2 Actions
- Verify whether the user was authorized to use `curl.exe`.
- Review how many times `curl.exe` was executed in the surrounding window.
- Check the destination domain and IP reputation.
- Review whether any files were downloaded (correlate with Sysmon Event ID 11, File Created).
- Check for follow-on process execution after the curl command.
- Correlate with Sysmon Event ID 22 (DNS Query) to confirm what was actually resolved, since Event 1 alone doesn't confirm destination.

---

# 16. Escalation Summary 3 - Local Administrators Group Enumeration

## Summary
A local user executed a command to enumerate members of the local Administrators group on host `DESKTOP-BN86O9N`. This activity reveals which accounts have local administrator privileges on the endpoint.

## Evidence Reviewed
```text
Host: DESKTOP-BN86O9N
User: DESKTOP-BN86O9N\Nikola
Command: net1.exe (child of "C:\Windows\system32\net.exe" localgroup administrators)
Parent process: net.exe
Log source: Microsoft-Windows-Sysmon/Operational
Event ID: Sysmon Event ID 1 - Process Creation
Process ID: 2328 | Parent Process ID: 8984
SHA256 (net1.exe): e62071aa18768dd88acaf97fa7b1f2fec9fcce89736c1ee9a800699328d196ea
Timestamp: Aug 28, 2026 @ 21:15:20.236
```

## Analyst Assessment
Sysmon Event ID 1 indicates process creation. `net.exe localgroup administrators` enumerates local admin group membership, internally handed off to `net1.exe` (expected Windows internals, not duplicate logging). This is security-relevant because attackers commonly use it post-compromise to check for elevated access or identify high-value accounts for privilege escalation or lateral movement. The command alone does not modify the system.

## Risk
```text
Medium by default - privilege discovery, no system modification observed.
High if followed by: new user creation (4720), a user added to Administrators (4732), a suspicious successful logon, or other discovery commands in sequence.
```

## Recommended L2 Actions
- Verify whether the user was authorized to enumerate local administrator membership.
- Review how many times the command was executed.
- Check Windows Security events for user creation (4720) or group membership changes (4732) in the surrounding window.
- Review nearby successful logons and PowerShell activity for additional discovery commands.

---

# 17. Shift Handoff Note 1 - End-of-Shift Summary

## Shift Summary
During this shift, five SOC tickets were created from Phase 5 lab events using Elastic/Kibana and Sysmon/Windows Security telemetry. Reviewed activity included PowerShell user discovery, local administrator group enumeration, a command-line web request, DNS lookup activity, and a baseline check of the Security log for failed logons. One escalation summary was also produced from a live, simulated failed-logon scenario.

## Environment
```text
SIEM: Elastic / Kibana (192.168.56.112)
Endpoint: DESKTOP-BN86O9N (192.168.56.114)
User: DESKTOP-BN86O9N\Nikola
Log Sources:
- Microsoft-Windows-Sysmon/Operational
- Windows Security
```

## Tickets Created
```text
Ticket 1: PowerShell whoami - Closed as benign lab activity
Ticket 2: Local Administrators Group Enumeration - Closed as benign lab activity
Ticket 3: curl.exe to GitHub - Closed as benign lab activity
Ticket 4: nslookup to microsoft.com - Closed as benign lab activity
Ticket 5: No Failed Logon Activity Observed (2-week baseline) - Closed, clean baseline confirmed
```

## Escalation Summaries Created
```text
Escalation 1: Repeated Failed Logon Attempts (Simulated) - assessed low risk given
Interactive/loopback context; high-risk criteria documented for comparison
```

## Findings
No confirmed malicious activity was identified. All reviewed events were script-generated lab activity or normal Windows behavior. Several activities were suspicious by technique but benign by context: PowerShell `whoami`, `net localgroup administrators`, `curl.exe` to GitHub, and `nslookup` to a known Microsoft domain. A deliberate failed-logon simulation confirmed the environment correctly logs Event ID 4625 with full context fields (logon type, sub-status, failure reason), and that a 2-week pre-simulation baseline showed zero failed logons — a useful clean baseline now on record.

## Open Items
No open incidents remain from this session.

## Recommended Follow-Up
- Continue practicing SOC ticket writing with higher-risk scenarios (new user creation, user added to Administrators, remote/network-based failed logons, LSASS access).
- Carry the verified LogonType/source-IP distinction from Escalation 1 into future 4625 triage — Interactive/loopback vs. Network/external is the deciding factor, not just failure count.

---

# 18. Shift Handoff Note 2 - Next Analyst Handoff

## Summary for Next Analyst
The Phase 6 ticket-writing exercise was completed using events generated from the Phase 5 scripted activity loop, plus one live-simulated failed-logon scenario. Reviewed events were primarily benign lab-generated activity, but several map to common attacker techniques — discovery, privilege discovery, command-line web requests, and authentication failure — making them useful for practicing SOC documentation.

## Reviewed Activity
```text
PowerShell whoami:
Reviewed as user discovery. Closed as benign lab activity.

net localgroup administrators (net.exe -> net1.exe):
Reviewed as local admin enumeration. Closed as benign lab activity.

curl.exe to github.com:
Reviewed as command-line web request. Destination confirmed via DNS Query
event (140.82.114.4). Closed as benign lab activity.

nslookup microsoft.com:
Reviewed as DNS lookup activity. No Sysmon Event 22 generated for this
tool in this environment (known visibility gap from Phase 5). Closed as
benign lab activity.

4625 failed logon baseline:
2-week Security-log review returned zero failed logons prior to
simulation - confirmed as a clean baseline, not a broken query.

4625 failed logon simulation:
4 failed attempts against a known local account, Interactive logon type,
source 127.0.0.1, followed by a successful logon. Assessed as low risk
due to console/loopback context - used to build Escalation Summary 1.
```

## Watch Items
If similar activity appears in a production environment, the following conditions should increase severity:

```text
Unknown user
Repeated attempts
Privileged account targeted
Logon type Network/RemoteInteractive rather than Interactive
Source IP other than loopback/localhost
Unknown or newly-registered domain
Payload download
Follow-on process execution
New account created (4720)
User added to Administrators (4732)
Remote login after failures
```

## Recommended Next Steps
Move into the next roadmap phase after documenting Phase 6. Future practice should include tickets for higher-risk alerts (new account creation, privilege escalation, remote-based authentication failures) and escalation summaries where escalation is clearly justified rather than closed as benign.

---

# 19. Lessons Learned

**Lesson 1 – Event IDs are only meaningful with their channel and provider.** A bare `event.code: "4625"` query returned 3 irrelevant hits from the Application log (`Microsoft-Windows-EventSystem`) before the query was scoped to `winlog.channel: "Security"`. The same numeric code means something completely different depending on channel/provider.

**Lesson 2 – Sysmon event type coverage is tool-specific, not activity-specific.** `curl.exe`'s DNS activity only surfaces via Event 22, not Event 3; `nslookup.exe` generates neither Event 22 nor useful command-line detail outside Event 1. Confirmed again this phase when a `curl.exe` query without an `event.code` filter returned a DNS Query document with no `process.command_line` field — not missing data, just the wrong event type for what was needed.

**Lesson 3 – An empty, properly verified result is real evidence.** The 2-week 4625 baseline returning zero results (checked against the correct channel, full time range) was documented as a clean baseline rather than assumed broken.

**Lesson 4 – Field context decides severity, not the event type alone.** Four failed logons against a known account looks concerning by count alone, but `LogonType: Interactive` and `source.ip: 127.0.0.1` confirmed it was local console activity, not a remote attack — the same event set with a network logon type and external IP would be assessed as High.

**Lesson 5 – Command/process and parent process are different.** Reconfirmed throughout: `whoami.exe`'s parent was `powershell.exe`; `net1.exe`'s parent was `net.exe`; `curl.exe`'s parent was `powershell.exe`. The command tells what ran, the parent tells what launched it.

**Lesson 6 – Windows Security events and Sysmon events are separate pipelines.** `4625` (Security) and Sysmon Event 1 (Sysmon/Operational) required different queries, different channels, and produced different field sets throughout this phase.

---

# 20. Interview Translation

In Phase 6, I converted real SIEM evidence from my Elastic/Kibana lab into SOC-style tickets, escalation summaries, and shift handoff notes, pulling every field directly from Kibana Discover rather than working from assumed values. I wrote five tickets covering PowerShell discovery, local administrator enumeration, a command-line web request, DNS lookup activity, and Windows authentication events, documenting host, user, event source, exact process IDs, parent-process chains, and file hashes for each.

Along the way, I caught and corrected a real investigative mistake: an unscoped `event.code` query pulled irrelevant Application-log noise instead of Security-log authentication events, which reinforced that Windows event IDs must always be read together with their log channel. I also ran a safe, reversible failed-logon simulation to generate real Event ID 4625 data, then used the logon-type and source-IP fields to demonstrate why the same alert pattern can be low risk in one context and high risk in another — rather than asserting severity from the event type alone.

This phase reinforced how SOC analysts document findings with verifiable evidence, avoid overclaiming what a log proves, and distinguish genuinely suspicious indicators from benign context using the specific fields available, not assumptions.

---

# 21. Phase 6 Completion Checklist

- [x] SOC ticket template applied
- [x] 5 SOC tickets completed from real Kibana evidence (Tickets 1–5)
- [x] Severity reasoning practiced and justified per ticket
- [x] 3 escalation summaries completed (1 from a live simulation, 2 from existing ticket evidence)
- [x] 2 shift handoff notes completed
- [x] False-positive/benign context documented with supporting fields
- [x] Evidence-to-alert matching verified for every ticket
- [x] Windows Security vs. Sysmon distinction practiced and re-confirmed
- [x] Query miscategorization caught and corrected (Application vs. Security channel)
- [x] Sysmon event-type coverage gaps (curl/nslookup) carried forward from Phase 5 and reconfirmed
- [x] Recommended actions written per ticket/escalation
- [x] Environment identity corrected to match actual lab (DESKTOP-BN86O9N / Nikola / .112 / .114) instead of placeholder values

## Final Status

**Phase 6 complete.**
