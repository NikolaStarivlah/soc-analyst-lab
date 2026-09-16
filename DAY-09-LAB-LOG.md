# Phase 9 Detailed Lab Log — Detection Engineering and Rule Tuning

**Author:** Nikola Starivlah

## Status
**Completed — September 16, 2026**

## Completion Summary

Phase 9 moved my SOC home lab from manual investigation (Phase 8) into
detection engineering. I converted investigation ideas into six scheduled
Splunk alerts, safely generated controlled endpoint behavior for each,
confirmed which telemetry sources could support each rule, documented
severity and false positives, and tuned a noisy network detection so verified
benign traffic did not create unnecessary analyst work. Mid-phase, a Sysmon
telemetry pipeline failure surfaced that was not anticipated by the reference
roadmap I was following — I root-caused it to a genuine, documented Splunk
Universal Forwarder defect rather than a misconfiguration on my part, fixed
its practical impact, and hardened every detection search against its
residual behavior.

### Final Deliverables

| Requirement | Result |
|---|---|
| Practical detections | 6 enabled Splunk alerts |
| Sigma-style rules | 3 documented rules |
| Tuning write-up | 1 completed before/after analysis (52 → 0) |
| Detection platform | Splunk Enterprise |
| Endpoint telemetry used | Sysmon and Windows Security logs |
| Honest deferrals documented | LSASS access (confirmed unsupported telemetry) |
| Unplanned infrastructure investigation | Sysmon ingestion duplication — root-caused and mitigated |

---

# 1. Objective and Detection Workflow

Phase 8 focused on investigation:

```text
Event happens → Search evidence → Analyze context → Assign verdict
```

Phase 9 focused on repeatable detection logic:

```text
Select behavior → Confirm telemetry → Generate safe test activity
→ Detect evidence → Save alert → Tune noise → Document tradeoff
```

Roadmap requirement:

```text
6 detections
3 Sigma-style rules
1 tuning write-up with before/after logic
```

---

# 2. Platform and Telemetry Foundation

| Item | Configuration |
|---|---|
| SIEM | Splunk Enterprise |
| Splunk server | `splunk-soc` |
| Splunk server host-only IP | `192.168.56.117` (confirmed via `ip a`) |
| Receiver port | TCP `9997` |
| Endpoint forwarder | Splunk Universal Forwarder |
| Windows endpoint | `DESKTOP-BN8O9N` (confirmed via `hostname`) |
| Windows TA / Sysmon app | Not installed — all fields extracted manually via `rex` |

## Sysmon Availability Check

Before building any rules, I inventoried the Sysmon Event IDs actually
present in Splunk, rather than assuming the roadmap's list applied unchanged.

| Sysmon Event ID | Meaning | Available |
|---:|---|---|
| `1` | Process Creation | Yes |
| `3` | Network Connection | Yes |
| `4`, `5`, `6`, `8` | Service state / process termination / driver load / remote thread | Yes (not used this phase) |
| `11` | File Creation | Yes |
| `12` | Registry Object Create/Delete | Yes |
| `13` | Registry Value Set | Yes |
| `16` | Sysmon config state changed | Yes (not used this phase) |
| `22` | DNS Query | Yes |
| `255` | Sysmon error/status | Yes (not used this phase) |
| `10` | Process Access | **No** |

Windows Security telemetry was also confirmed available, including Event ID
`4732` for members added to a security-enabled local group.

This inventory confirmed every telemetry source the six planned detections
needed was present, and that Event ID `10` (required for LSASS access
detection) was genuinely absent — avoiding a telemetry rabbit hole before it
started.

---

# 3. Sysmon Ingestion Failure — Root-Cause Investigation and Fix

## Problem

While validating DET-001, a single controlled test action — one execution of
an encoded PowerShell command, confirmed by one printed output line — appeared
in Splunk as **17 duplicate rows**, all sharing an identical timestamp,
command line, and `EventRecordID`. Minutes later the count had grown to 21,
then 113. A whole-channel audit showed the Sysmon Operational channel had
indexed **3,460,008** events against a real event ceiling
(`max(EventRecordID)`) of only **32,336** — an average duplication factor of
roughly 100x across the entire channel.

## Investigation Timeline

Each hypothesis was tested against direct evidence before moving to the next:

| # | Hypothesis | Test | Result |
|---|---|---|---|
| 1 | Duplicate `[WinEventLog://...Sysmon...]` input stanza | `splunk.exe btool inputs list --debug` | Ruled out — exactly one stanza found |
| 2 | Duplicate `[tcpout:...]` output destination | `splunk.exe btool outputs list --debug` | Ruled out — exactly one server entry found |
| 3 | Multiple genuinely separate events | Extracted `EventRecordID` per row | Ruled out — all rows shared the same `EventRecordID` |
| 4 | Antivirus interfering with checkpoint writes | Confirmed install location | Ruled out — Malwarebytes runs on the host PC only, not the lab VMs |
| 5 | `SplunkForwarder` service crash-looping | `Get-WinEvent` for Service Control Manager Event ID 7036 across 2,000 events | Ruled out — zero service-level restarts found |
| 6 | `TcpOutputProc` warning was the cause | Pulled raw `splunkd.log` text | Ruled out — confirmed benign, unrelated Splunk internal quirk |
| 7 | Sysmon log too small, wrapping past the saved bookmark | `wevtutil gl Microsoft-Windows-Sysmon/Operational` → `maxSize: 67108864` (64 MB) against sustained volume in the hundreds of thousands of events | **Confirmed contributing cause** |
| 8 | Increasing log size alone would fix it | Set `maxSize` to 256 MB, reset checkpoints, re-monitored | Real improvement, but not sufficient alone |
| 9 | `splunk-winevtlog.exe` helper process itself unstable | `Get-Process` polled every 40s across multiple cycles | **Confirmed** — new PID roughly every 1–2 minutes |
| 10 | Windows caught this as a standard AppCrash | `Get-WinEvent` for Application log Event ID 1000 | Ruled out — no AppCrash event ever recorded |
| 11 | Known, external Splunk defect | Cross-referenced the exact symptom against Splunk's own community forums | **Confirmed** — independently reported across multiple organizations, Universal Forwarder versions 7.x–10.x, tied to `current_only=0` |

The direct trigger, found in `splunkd.log` at `ERROR` level:

```text
WinEventLogChannel::queryEvtChannel: Unable to set seek position to the given bookmark
```

## Root Cause

**Enabling condition:** an 11-day idle gap between lab sessions left the
forwarder's live-tail checkpoint frozen (`RecordId=18827`, filesystem
`LastWriteTime` of Sept 4). With the Sysmon log capped at 64 MB, activity on
resuming the VM was enough to wrap the log past that stale bookmark, producing
the seek failure above.

**Underlying defect:** once that seek fails, the input falls back to a
backward bookmark-reconstruction scan that is itself unstable in this Splunk
version — the `splunk-winevtlog.exe` helper process dies and restarts every
1–2 minutes without saving real progress, so the same window of recent
history gets re-forwarded on every cycle, indefinitely.

**Explicitly ruled out:** Windows activation status, antivirus, and any
Phase 8 configuration change. Phase 8's fixes never touched `current_only` —
it was silently inheriting Splunk's own default of `0`.

## Fix Applied

1. **Immediate containment:** disabled the Sysmon input stanza to stop
   runaway duplication while root cause was isolated.
2. **Secondary hardening:** increased the Sysmon log's `maxSize` to 256 MB.
3. **Root fix:** set `current_only = 1` on the Sysmon stanza, disabling the
   fragile historical-backfill path entirely. Re-enabled the stanza, cleared
   stale checkpoints, restarted the forwarder.

## Result

A fresh, isolated encoded-PowerShell test after the fix produced exactly one
clean event. The helper process still restarts occasionally (~5 minutes
instead of ~1–2), but each restart now costs at most one small duplicate
instead of a runaway re-scan. Every detection search from this point forward
was built with `dedup EventRecordID` (or `dedup _raw` for Security-log
searches) to guarantee accurate reporting regardless of this residual
behavior. Scheduled alerts are unaffected in practice, since `Trigger Mode =
Once` fires a single alert per run regardless of duplicate row count.

## Lesson Carried Forward

Splunk's `WinEventLog` input defaults to `current_only = 0`. Combined with a
documented, still-unpatched defect in its historical-backfill helper process,
any idle period between lab sessions can trigger runaway duplicate ingestion
once the live-tail checkpoint goes stale and the underlying event log wraps
past it. **Going forward, starting with Phase 10's Active Directory forwarding
setup:** set `current_only = 1` on every `[WinEventLog://...]` stanza at
initial configuration, and size event logs generously (256 MB+) as
defense-in-depth.

---

# 4. Alert Configuration Standard

Each validated detection was saved in Splunk as a private scheduled alert
using a consistent configuration:

| Alert Setting | Value |
|---|---|
| Permissions | Private |
| Alert Type | Scheduled |
| Schedule | Hourly, at 0 minutes past the hour |
| Lookback | Last 60 minutes |
| Trigger Condition | Number of Results is greater than 0 |
| Trigger Mode | Once |
| Trigger Action | Add to Triggered Alerts |

All six alerts were confirmed enabled after saving.

---

# 5. DET-001 — Encoded PowerShell Execution

## Why It Matters
Encoded PowerShell can hide the readable intent of a command line — a common
technique worth investigating, though also used legitimately by
administrators and automation.

## Data Source
```text
Sysmon Event ID 1 — Process Creation
```

## Safe Controlled Test
```powershell
$cmd = 'Write-Output "Phase9 Encoded PowerShell Detection Test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

## Detection SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=1
| rex field=_raw "<Data Name=[\"']User[\"']>(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']CommandLine[\"']>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']ParentImage[\"']>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| search Image="*powershell.exe" (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *")
| dedup EventRecordID
| table _time, User, Image, ParentImage, CommandLine
| sort - _time
```

## Result and Verdict
Splunk matched one distinct event (`EventRecordID 33131`) from
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` under the known
lab user, after `dedup` was added to guard against the ingestion issue
documented in Section 3.

| Item | Decision |
|---|---|
| Alert | `DET-001 Encoded PowerShell Execution` |
| Severity | Medium |
| Lab verdict | Benign by context — controlled harmless test |
| False positives | Admin scripts, automation, security tooling |
| MITRE ATT&CK | T1059.001 — PowerShell |

---

# 6. DET-002 — Registry Run Key Persistence

## Why It Matters
Run/RunOnce registry values can auto-launch software at logon. Malware abuses
this for persistence; legitimate software also uses it, making context
important.

## Data Source
```text
Sysmon Event ID 13 — Registry Value Set
```

## Safe Controlled Test
```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Phase9Test" -Value "C:\Windows\System32\notepad.exe" -PropertyType String -Force
# ... validated in Splunk ...
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Phase9Test"
```

## Detection SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=13
| rex field=_raw "<Data Name=[\"']TargetObject[\"']>(?<TargetObject>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']Details[\"']>(?<Details>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| search TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*"
| dedup EventRecordID
| table _time, Image, TargetObject, Details
| sort - _time
```

## Result and Verdict
Splunk matched the temporary `Phase9Test` value, its Notepad target path, and
the PowerShell process that created it — one clean row.

| Item | Decision |
|---|---|
| Alert | `DET-002 Registry Run Key Persistence` |
| Severity | Medium |
| Lab verdict | Benign by context — value created then removed |
| False positives | Approved startup apps, installers, update agents |
| MITRE ATT&CK | T1547.001 — Registry Run Keys / Startup Folder |

---

# 7. DET-003 — Scheduled Task Creation via Schtasks

## Why It Matters
Scheduled tasks are used legitimately, but attackers can create them for
persistence or repeated execution.

## Data Source
```text
Sysmon Event ID 1 — Process Creation
```

## Safe Controlled Test
```powershell
schtasks /Create /TN "Phase9Test" /TR "notepad.exe" /SC ONCE /ST 23:59 /F
# ... validated in Splunk ...
schtasks /Delete /TN "Phase9Test" /F
```

## Detection SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=1
| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']CommandLine[\"']>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']User[\"']>(?<User>[^<]+)</Data>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| search Image="*schtasks.exe" CommandLine="*/Create*"
| dedup EventRecordID
| table _time, User, Image, CommandLine
| sort - _time
```

## Result and Verdict
Splunk matched the full command line
(`schtasks.exe /Create /TN Phase9Test /TR notepad.exe /SC ONCE /ST 23:59 /F`)
under the known lab user — one clean row.

| Item | Decision |
|---|---|
| Alert | `DET-003 Scheduled Task Creation via Schtasks` |
| Severity | Medium |
| Lab verdict | Benign by context — future harmless task removed |
| False positives | IT automation, software updates, backup tools |
| MITRE ATT&CK | T1053.005 — Scheduled Task/Job: Scheduled Task |

---

# 8. DET-004 — New Local Administrator Activity

## Why It Matters
Adding an account to the local Administrators group grants privileged access
directly — higher risk than a generic suspicious technique.

## Data Source
```text
Windows Security Event ID 4732 — A member was added to a security-enabled local group
```

## Safe Controlled Test
```powershell
$testUser = "Phase9TempAdmin"
$testPassword = ConvertTo-SecureString ("P9!" + [Guid]::NewGuid().ToString("N") + "aA1") -AsPlainText -Force
New-LocalUser -Name $testUser -Password $testPassword -Description "Temporary Phase 9 detection test account" | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $testUser
Start-Sleep -Seconds 5
Remove-LocalGroupMember -Group "Administrators" -Member $testUser
Remove-LocalUser -Name $testUser
```

## Ingestion Troubleshooting
The guide's assumed field names (`SubjectUserName`, `Member_Name`) returned
blank. Inspecting the raw event showed why: the literal label `Account Name:`
appears twice in the raw text — once under `Subject:` (the analyst who made
the change) and once under `Member:` (the account added). Without the
official Windows Technology Add-on installed, Splunk's generic parser could
not disambiguate the two occurrences into distinct fields. `Group_Name`
worked correctly only because "Group Name:" appears exactly once in the
event. I built targeted `rex` extractions scoped to each labeled section
instead of relying on ambiguous auto-extraction.

## Detection SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="WinEventLog:Security" EventCode=4732
| rex field=_raw "(?s)Subject:.*?Account Name:\s+(?<SubjectAccountName>\S+)"
| rex field=_raw "(?s)Member:.*?Security ID:\s+(?<MemberSecurityID>\S+)"
| rex field=_raw "(?s)Group:.*?Group Name:\s+(?<GroupName>\S+)"
| search GroupName="Administrators"
| dedup _raw
| table _time, SubjectAccountName, MemberSecurityID, GroupName
| sort - _time
```

## Result and Verdict
Splunk matched `SubjectAccountName=Nikola`, `GroupName=Administrators`, and
the temporary account's Security ID under `Member` — one clean row, tied
directly to the controlled test sequence.

| Item | Decision |
|---|---|
| Alert | `DET-004 New Local Administrator Activity` |
| Severity | High |
| Lab verdict | Benign by context — temporary account cleaned up |
| False positives | Authorized admin changes, endpoint provisioning |
| MITRE ATT&CK | T1098 — Account Manipulation |

---

# 9. DET-005 — Unusual Outbound Network Connection (Tuning Exercise)

## Why It Matters
Outbound connections can be ordinary or malicious. A broad rule is too noisy
to be useful without tuning, making this an ideal false-positive reduction
exercise.

## Initial Controlled Test and Pivot
```powershell
curl.exe -I http://192.168.56.117:8000
```
The connection succeeded (`HTTP/1.1 303 See Other`), but Sysmon Event ID 3
did not capture it — the same gap encountered when this roadmap was
originally built, independent of environment. Rather than force a Sysmon
configuration change, I pivoted to real, already-flowing Event ID 3 traffic
as the tuning subject.

## Untuned Baseline SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=3
| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']DestinationIp[\"']>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']DestinationPort[\"']>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| dedup EventRecordID
| where NOT cidrmatch("10.0.0.0/8",DestinationIp)
    AND NOT cidrmatch("172.16.0.0/12",DestinationIp)
    AND NOT cidrmatch("192.168.0.0/16",DestinationIp)
    AND DestinationIp!="127.0.0.1"
| stats count as Connections values(DestinationIp) as DestinationIPs values(DestinationPort) as DestinationPorts by Image
| sort - Connections
```

## Baseline Result

| Process | Connections | Context |
|---|---:|---|
| `OneDrive.exe` | 44 | Expected Microsoft cloud sync traffic |
| `OneDriveSetup.exe` | 4 | Expected update traffic |
| `OneDrive.Sync.Service.exe` | 3 | Expected sync service traffic |
| `OneDriveStandaloneUpdater.exe` | 1 | Expected updater traffic |

```text
Untuned count: 52
```

## Final Tuned SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=3
| rex field=_raw "<Data Name=[\"']User[\"']>(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']DestinationIp[\"']>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']DestinationPort[\"']>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| dedup EventRecordID
| where NOT cidrmatch("10.0.0.0/8",DestinationIp)
    AND NOT cidrmatch("172.16.0.0/12",DestinationIp)
    AND NOT cidrmatch("192.168.0.0/16",DestinationIp)
    AND DestinationIp!="127.0.0.1"
| where NOT like(Image,"%\\Microsoft\\OneDrive\\OneDrive.exe")
    AND NOT like(Image,"%\\Microsoft\\OneDrive\\Update\\OneDriveSetup.exe")
    AND NOT like(Image,"%\\Microsoft\\OneDrive\\%\\OneDrive.Sync.Service.exe")
    AND NOT like(Image,"%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe")
| eval TriageReason="Unexpected process communicating with public destination"
| table _time, User, Image, DestinationIp, DestinationPort, TriageReason
| sort - _time
```

## Tuning Outcome

| Stage | Results | Decision |
|---|---:|---|
| Broad public-IP connection rule | 52 | Too noisy — dominated by OneDrive family |
| Exclude all 4 verified OneDrive/updater/sync paths | 0 | Known benign noise fully suppressed |

## Result and Verdict

| Item | Decision |
|---|---|
| Alert | `DET-005 Unusual Outbound Network Connection` |
| Severity | Medium |
| Validation type | Before/after false-positive tuning (52 → 0) |
| Known benign exclusions | Full-path OneDrive, updater, and sync-service executables |
| Detection tradeoff | Better signal quality, but allowlists require future review |
| MITRE ATT&CK | T1071.001 — Web Protocols |

---

# 10. DET-006 — Command-Line DNS Query Activity

## Why It Matters
Command-line DNS activity can be normal or suspicious depending on context —
this rule is intended for contextual review, not automatic escalation.

## Data Source
```text
Sysmon Event ID 22 — DNS Query
```

## Detection SPL
```spl
index=main host=DESKTOP-BN8O9N sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=22
| rex field=_raw "<Data Name=[\"']User[\"']>(?<User>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']Image[\"']>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=[\"']QueryName[\"']>(?<QueryName>[^<]+)</Data>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| dedup EventRecordID
| eval Image=replace(Image,"&lt;","<")
| eval Image=replace(Image,"&gt;",">")
| search Image="*\\curl.exe" OR Image="*\\powershell.exe" OR Image="*\\nslookup.exe"
| eval TriageReason="Command-line process generated DNS query - review domain and surrounding execution context"
| table _time, User, Image, QueryName, TriageReason
| sort - _time
```

## Validation Result
Splunk matched 24 historical events tying `curl.exe` to `github.com`,
`example.com`, and `download.splunk.com`, generated during earlier phases of
lab work. The validation search was run across all time first to prove the
data existed, then rescoped to a last-60-minutes lookback before saving the
alert, so old lab history would not repeatedly generate new alert results.

| Item | Decision |
|---|---|
| Alert | `DET-006 Command-Line DNS Query Activity` |
| Severity | Medium |
| Lab verdict | Benign by context — known GitHub/Splunk lookups |
| False positives | Admin testing, scripts, troubleshooting |
| Analyst use | Correlate command-line process activity with domain context |

---

# 11. Deferred Original Detection Concepts

## LSASS Process Access — Deferred

### Planned Detection
Unexpected process access to `lsass.exe`, potentially indicating credential
dumping.

### Expected Data Source
```text
Sysmon Event ID 10 — Process Access
```

### Evidence and Decision
The Sysmon Event ID inventory (Section 2) confirmed Event ID `10` was not
present in this endpoint's telemetry.

```text
Status: Deferred — current telemetry cannot validate this detection honestly.
```

Rather than altering Sysmon solely for this test, I completed the required
detection set using the five other supported, validated data sources.

---

# 12. Three Sigma-Style Rules

## Rule 1 — Encoded PowerShell Execution
```yaml
title: Encoded PowerShell Execution
id: phase9-det-001-encoded-powershell
status: experimental
description: Detects PowerShell execution using encoded command parameters.
author: Nikola Starivlah
date: 2026-09-16
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_commandline:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection_image and selection_commandline
falsepositives:
  - Legitimate administrative automation
  - Software deployment scripts
  - Security tooling or monitoring activity
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

## Rule 2 — Registry Run Key Persistence
```yaml
title: Registry Run Key Persistence
id: phase9-det-002-registry-run-key-persistence
status: experimental
description: Detects registry value modifications beneath Windows Run or RunOnce startup locations.
author: Nikola Starivlah
date: 2026-09-16
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce\'
  condition: selection
falsepositives:
  - Approved startup applications
  - Software installers or update agents
  - Enterprise logon utilities
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## Rule 3 — Scheduled Task Creation via Schtasks
```yaml
title: Scheduled Task Creation via Schtasks
id: phase9-det-003-scheduled-task-creation
status: experimental
description: Detects scheduled task creation using schtasks.exe with the /Create argument.
author: Nikola Starivlah
date: 2026-09-16
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith:
      - '\schtasks.exe'
  selection_commandline:
    CommandLine|contains:
      - '/Create'
  condition: selection_image and selection_commandline
falsepositives:
  - Approved IT automation
  - Software installation and update tasks
  - Backup or maintenance tooling
level: medium
tags:
  - attack.persistence
  - attack.execution
  - attack.t1053.005
```

---

# 13. Detection and Tuning Summary

| Alert | Data Source | Severity | Validation Evidence | Status |
|---|---|---:|---|---|
| DET-001 Encoded PowerShell Execution | Sysmon 1 | Medium | Encoded PowerShell matched, single event confirmed | Enabled |
| DET-002 Registry Run Key Persistence | Sysmon 13 | Medium | Temporary Notepad Run-key value matched and removed | Enabled |
| DET-003 Scheduled Task Creation via Schtasks | Sysmon 1 | Medium | Future Notepad task matched and deleted | Enabled |
| DET-004 New Local Administrator Activity | Security 4732 | High | Temporary admin membership matched and cleaned up | Enabled |
| DET-005 Unusual Outbound Network Connection | Sysmon 3 | Medium | Benign OneDrive tuning: 52 → 0 | Enabled |
| DET-006 Command-Line DNS Query Activity | Sysmon 22 | Medium | 24 historical `curl.exe` → GitHub/Splunk events matched | Enabled |

---

# 14. SOC Skills Practiced

- Detection engineering in Splunk; SPL alert creation and scheduled rule
  configuration
- Sysmon process-creation, registry, network-connection, and DNS-query
  detection
- Windows Security local administrator group monitoring
- Safe controlled behavior generation and cleanup
- MITRE ATT&CK mapping
- Sigma-style portable rule documentation
- False-positive reduction and allowlist tradeoff analysis (52 → 0)
- Telemetry validation before building detections
- Honest deferral of unsupported detection paths
- Root-cause isolation of a live ingestion-pipeline defect through systematic
  elimination of eleven competing hypotheses
- Splunk Universal Forwarder internals: `btool`, checkpoint/bookmark files,
  `current_only` semantics
- Windows Event Log internals: circular buffer wraparound, `wevtutil`,
  Service Control Manager and Application crash event auditing
- Manual field extraction (`rex`) in the absence of vendor Technology
  Add-ons, including disambiguating colliding raw-text labels

---

# 15. Interview Translation

## Portfolio / Resume Summary

Built six enabled Splunk detection alerts using Sysmon and Windows Security
telemetry, including encoded PowerShell, registry Run-key persistence,
scheduled-task creation, local administrator membership changes, unusual
outbound connections, and command-line DNS queries. Generated and cleaned up
safe controlled test behaviors, documented three Sigma-style rules with MITRE
ATT&CK mappings, and completed false-positive tuning that reduced validated
benign OneDrive network matches from 52 to zero. Independently root-caused a
live Sysmon ingestion failure to a documented, unpatched Splunk Universal
Forwarder defect — verified against Splunk's own community reports — and
mitigated it in production rather than working around symptoms.

## Strong Interview Talking Points

### How was Phase 9 different from Phase 8?
Phase 8 focused on finding and investigating endpoint events with SPL and
building dashboards. Phase 9 converted those investigation ideas into
scheduled alert rules, validated them with safe test behavior, and tuned
known benign noise so the detections became more useful.

### Tell me about a time a detection appeared to work but the results didn't add up.
A single controlled PowerShell test showed up as 17, then 21, then over 100
duplicate events in Splunk. Rather than assume the detection logic was
wrong, I verified at the `EventRecordID` level and confirmed it was one real
event being re-indexed repeatedly — an ingestion problem, not a detection
problem. I ruled out eight separate hypotheses in sequence — duplicate
config, antivirus, service crashes, log-size limits — before finding the
actual trigger in Splunk's error log and confirming, via Splunk's own
community forums, that it was a known, unpatched defect in the Universal
Forwarder's Windows Event Log helper process, worsened by an idle gap between
lab sessions that let the live-tail checkpoint go stale. I mitigated it by
disabling historical backfill (`current_only=1`) and hardened every
subsequent detection search with `dedup` so results stayed accurate
regardless of the residual ingestion behavior.

### What was the strongest tuning example?
A broad public outbound-connection search returned 52 connections across four
distinct OneDrive-family executables. I inventoried and verified each one as
benign, excluded all four full paths, and reduced known-benign results to
zero.

### Did every originally planned detection work?
LSASS process access could not be validated because Sysmon Event ID 10 was
not present in the ingested telemetry. I documented this honestly and
completed the deliverable using five other supported, validated data
sources rather than forcing a configuration change.

### Why is local administrator membership high severity?
Adding an account to the Administrators group grants privileged access
directly. Even though my temporary test account was removed and deleted, the
equivalent behavior on a production endpoint requires prompt validation.

---

# 16. Completion Checklist

| Deliverable | Status |
|---|---|
| Six enabled Splunk alerts | Complete |
| DET-001 Encoded PowerShell | Complete |
| DET-002 Registry Run Key Persistence | Complete |
| DET-003 Scheduled Task Creation via Schtasks | Complete |
| DET-004 New Local Administrator Activity | Complete |
| DET-005 Tuned Unusual Outbound Connection | Complete |
| DET-006 Command-Line DNS Query Activity | Complete |
| Sigma-style Rule 1 — Encoded PowerShell | Complete |
| Sigma-style Rule 2 — Registry Run Key Persistence | Complete |
| Sigma-style Rule 3 — Scheduled Task Creation | Complete |
| Before/after false-positive tuning write-up | Complete |
| LSASS validation limitation documented | Complete |
| Sysmon ingestion failure root-caused, documented, and mitigated | Complete |
| Test cleanup and troubleshooting documented | Complete |

---

# 17. Final Phase 9 Outcome

Phase 9 transformed the lab from a search-and-dashboard environment into a
detection-engineering environment. I created six enabled Splunk alerts from
working endpoint evidence, wrote portable Sigma-style logic, performed safe
test activity with cleanup, root-caused and fixed a genuine live ingestion
defect rather than working around it, and tuned a noisy network rule based on
verified benign behavior.

The most important professional takeaway:

```text
Validate the data source → Generate controlled behavior → Detect evidence
→ Save repeatable alert → Identify noise → Tune responsibly → Document honestly
```

Phase 9 is complete. The next roadmap milestone is Phase 10: building an
Active Directory environment for identity-focused monitoring and
investigation.
