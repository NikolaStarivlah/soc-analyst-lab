# Phase 12 Detailed Lab Log - Endpoint and EDR Investigation

## Status

**Completed - October 6, 2026**

**Track 3 - Endpoint and Identity Investigation**

## Completion Summary

Phase 12 focused on endpoint and EDR-style investigation using Windows Sysmon
telemetry in Splunk, Linux host artifacts, and a separate Wazuh agent
visibility check. I completed three controlled investigations:

1. A suspicious PowerShell process chain.
2. Scheduled-task persistence-style behavior.
3. Linux cron persistence.

For each case, I established the host and user context, reviewed process or
artifact evidence, built a timeline, documented what the evidence did and did
not prove, selected a containment action, and verified cleanup - including
verifying that persistence actually stopped, not just that files were deleted.

Before generating any activity, a pre-flight check surfaced three real
telemetry-pipeline problems that had to be understood first: Sysmon events
arriving in Splunk as raw XML with no extracted `EventCode`, a recurrence of the
Phase 9 Universal Forwarder bookmark/re-scan defect (duplicate events and
bursty ingestion lag of up to ~15 minutes), and a Splunk IOWait health warning.
I measured each one, confirmed no data was being lost, and adapted the
investigation method rather than changing forwarder configuration mid-phase.
This is documented in Section 3.

The activity was generated intentionally inside the home lab. The observed
techniques were security-relevant, but the evidence did not prove malware,
credential theft, command-and-control traffic, or endpoint compromise.

### Final Deliverables

| Requirement | Result |
|---|---|
| Windows process-chain investigation | `powershell.exe -> cmd.exe -> powershell.exe -NoProfile -ExecutionPolicy Bypass -> notepad.exe` reconstructed from Sysmon Event ID 1, linked by process ID |
| Windows persistence investigation | `\Phase12\UpdaterCheck` create/query/delete lifecycle from `schtasks.exe` telemetry, plus the Task Scheduler service's on-disk artifact (Event ID 11) |
| Linux endpoint investigation | Crontab install, script, repeated execution, journal attribution, and verified cleanup on `splunk-soc` |
| Endpoint visibility | Splunk/Sysmon pipeline measured (lag, duplicates, field extraction); Wazuh agent availability verified separately |
| Timeline building | Actor, host, process or artifact, command, time, and follow-on activity documented for each case |
| Containment decisions | Close and remove decisions tied to evidence and lab context, with production responses |
| Evidence boundaries | Each case states what was observed, what could not be concluded, and which sensor supplied the evidence |

---

# 1. Objective

The goal was to practice the endpoint-investigation workflow that follows an
EDR or SIEM alert:

```text
Receive suspicious endpoint activity
  -> Confirm endpoint visibility
  -> Identify the user, host, process, and artifact
  -> Reconstruct the timeline
  -> Review parent and child process relationships
  -> Check persistence and follow-on behavior
  -> State what the evidence proves
  -> Select containment or closure
  -> Document cleanup and remaining visibility gaps
```

Phase 12 was not designed to prove that a host had been compromised. It was
designed to show that suspicious endpoint behavior can be investigated without
overstating the conclusion.

---

# 2. Lab Environment and Evidence Sources

The phase guide used placeholder identities (`DESKTOP-3JKM5O9`,
`MAJEED\Administrator`, `/home/mmajeed/`) that do not exist in this lab, the same
situation as Phase 6. I followed the guide's structure and searches but
reconfirmed and substituted the real values before generating any activity.

| System | Role | Evidence used |
|---|---|---|
| `DESKTOP-BN86O9N` | Windows 10 domain workstation (`192.168.56.114`) | Sysmon Event IDs 1 and 11, process image, command line, parent process, user, integrity level |
| `splunk-soc` | Splunk Enterprise (`192.168.56.117`); also the Linux host for Investigation 3 | Raw XML event search, `rex` extraction, ingestion-lag measurement, timelines; crontab, script metadata, journal |
| `wazuh-server` | Wazuh manager (`192.168.56.116`) | Agent status and agent details, verified separately after the investigations |
| `DC01` | Domain controller | **Powered off all phase** - not needed, and kept off for host RAM |

All three host-only IPs were reconfirmed live (`ip addr` / `ipconfig`); no DHCP
drift this phase.

Identities used:

- `NIKOLA\soc.analyst1` (standard user, Medium integrity) - Investigation 1.
- `NIKOLA\Administrator` (built-in, RID `-500`, High integrity) - Investigation 2.
- `nikola` (UID 1000) on `splunk-soc` - Investigation 3.

With DC01 off, the elevated Administrator shell logged on with cached
credentials, so `whoami /groups` showed several domain groups as
`Unknown SID type` (no DC available to resolve names). I identified them by RID
instead: `-512` Domain Admins, `-519` Enterprise Admins, `-518` Schema Admins,
`-520` Group Policy Creator Owners, `-572` Denied RODC Password Replication
Group.

## Time Reference

Splunk displays **UTC**; the Windows clock is **EDT**. Splunk time = Windows
time + 4 hours. The Sysmon `UtcTime` field is UTC as well. All times in this log
are UTC unless marked otherwise. I left both time settings unchanged and
converted manually.

---

# 3. Pre-Flight: Telemetry Pipeline Verification

The Phase 11 carry-forward was explicit: before concluding an endpoint
technique produced no evidence, confirm the collecting channel is both enabled
and configured to ship the events. Every investigation in this phase depended
on Sysmon Event ID 1, so I verified the pipeline before generating any scenario
activity. It surfaced three separate problems.

## 3.1 `EventCode=1` Matched No Sysmon Events

The first check returned only one event:

```spl
index=* host=DESKTOP-BN86O9N EventCode=1
| stats count latest(_time) as latest by source
```

The only source was `WinEventLog:System` - a System-log event that happens to
share ID 1. That is the Phase 6 channel-vs-ID trap again. Yet Sysmon was running
(`Get-Service Sysmon64`) and the Sysmon channel *was* arriving in Splunk:

```spl
index=* host=DESKTOP-BN86O9N source="*Sysmon*" earliest=-24h
| stats count latest(_time) as latest by source
```

Breaking Sysmon events down `by EventCode` returned "No results found" despite
1,492 matching events, and a raw string search for a fresh `whoami.exe` found
the event with an **empty** `EventCode` column - while the raw XML clearly
contained `<EventID>1</EventID>`.

**Root cause:** Sysmon events arrive as raw XML and this Splunk build (no
Windows TA) does not extract `EventCode` from them. The telemetry existed; the
field did not. This is the guide's "Normalized Sysmon Fields Were Incomplete"
case exactly.

**Fix:** search with strings first, then extract with `rex`:

```spl
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
```

No configuration change.

## 3.2 The Second `whoami` Was Missing - Ingestion Lag

A fresh `whoami` run at 02:12:50 UTC still had not appeared more than five
minutes later. I measured ingestion delay directly instead of guessing:

```spl
index=* host=DESKTOP-BN86O9N source="*Sysmon*" earliest=-60m
| eval lag_sec=_indextime-_time
| bin _time span=5m
| stats count avg(lag_sec) as avg_lag max(lag_sec) as max_lag by _time
```

| Bucket (UTC) | Count | Avg lag (s) | Max lag (s) |
|---|---|---|---|
| 02:00 | 453 | 498 | 900 |
| 02:05 | 1,137 | 543 | 882 |
| 02:10 | 1,173 | 364 | 573 |
| 02:15 | 79 | 71 | 246 |

Collection was running in every bucket - including the one holding the missing
event - but lagging up to ~15 minutes after the Windows boot flood, and
draining. The delayed `whoami` arrived with `lag_sec` 403.

## 3.3 Duplicate Events - The Phase 9 Defect Recurred

The same search showed the 02:06 `whoami` **three times** (lag 410 / 812 / 1232
s) and the 02:12 `whoami` **twice** (403 / 818 s) - copies spaced ~400 seconds
apart. The forwarder's own internal logs explained it:

```spl
index=_internal host=DESKTOP-BN86O9N earliest=-60m
("winevtlog" OR "WinEventLog" OR "ExecProcessor") (log_level=WARN OR log_level=ERROR)
```

| Time (UTC) | Level | Message |
|---|---|---|
| 02:05:14 | ERROR | `splunk-winevtlog.exe` - `Unable to set seek position to the given bookmark` (x2) |
| 02:12:50 | WARN | `TcpOutputProc` - pipeline data from `splunk-winevtlog.exe` |
| 02:19:32 | WARN | same |
| 02:26:21 | WARN | same |

This is the Phase 9 signature. The VM had been off since the previous session,
the Sysmon log moved past the forwarder's saved bookmark, and after the seek
error the helper cycled roughly every 400 seconds, re-sending recent events each
time - producing both the duplicates and the bursty lag. The 02:05:14 error also
matched the "latest Sysmon event" seen in the very first check.

A per-source check confirmed all four channels (Application, Sysmon, Security,
System) were current, so nothing was stalled, and both `whoami` events had
eventually arrived. **Delay and duplication, but no data loss.**

## 3.4 Splunk Health Warning - IOWait

The health indicator cycled red -> yellow -> green during the session. The
detail was **Resource Usage / IOWait** on `splunk-soc` - host disk-I/O pressure,
consistent with the host-resource limits from Phases 10 and 11. It adds lag but
does not cause duplicates.

## 3.5 Decision - Adapt the Method, Not the Config

Phase 9's full fix included clearing checkpoint files. I did not apply it
mid-phase because the evidence was arriving intact and Phase 9 had already
established a permanent safeguard for duplicates. Instead I used two operating
rules for the whole phase:

1. Every investigation search extracts `EventRecordID` with `rex` and runs
   `dedup EventRecordID`.
2. After generating activity, wait ~7 minutes (one helper cycle) before
   concluding anything is missing.

I validated the safeguard before relying on it: 5 raw `whoami` rows collapsed to
exactly 2 unique events (`EventRecordID` 47862 and 48699).

---

# 4. Investigation 1 - Suspicious PowerShell Process Chain

## Scenario

From the existing `soc.analyst1` PowerShell window, I opened `cmd.exe` and ran a
harmless PowerShell command using security-relevant options:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-Content -Path C:\Users\Public\phase12_inv1.txt -Value 'Phase 12 Investigation 1 - benign lab marker'; Start-Process notepad.exe"
```

The command created the marker file `phase12_inv1.txt` and launched
`notepad.exe` as controlled follow-on execution. Host-side `type` confirmed the
marker content.

## Why the Behavior Matters

`-ExecutionPolicy Bypass` and `-NoProfile` are used by administrators and
legitimate automation, but they also appear frequently in malicious PowerShell
execution. The flags are suspicious by technique, not proof of malware.

## Splunk Search

The guide's raw-XML `rex` search, adapted for this lab: the real host, an
`EventID` filter extracted from XML instead of `EventCode=1`, and the dedup
safeguard.

```spl
index=* host=DESKTOP-BN86O9N source="*Sysmon*" earliest="10/07/2026:02:32:00" latest="10/07/2026:02:35:00"
("powershell.exe" OR "cmd.exe" OR "notepad.exe" OR "phase12_inv1.txt")
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| where EventID="1"
| dedup EventRecordID
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)"
| rex field=_raw "<Data Name='ParentProcessId'>(?<ParentProcessId>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| table _time User ParentProcessId ParentImage ProcessId Image CommandLine
| sort _time
```

## Process Chain Recovered

| Time (UTC) | User | Parent (PID) | Process (PID) | Command line |
|---|---|---|---|---|
| 02:33:04.591 | NIKOLA\soc.analyst1 | powershell.exe (1028) | cmd.exe (2016) | `"C:\Windows\system32\cmd.exe"` |
| 02:33:16.963 | NIKOLA\soc.analyst1 | cmd.exe (2016) | powershell.exe (2100) | `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-Content ... phase12_inv1.txt ...; Start-Process notepad.exe"` |
| 02:33:17.329 | NIKOLA\soc.analyst1 | powershell.exe (2100) | notepad.exe (4440) | `"C:\Windows\system32\notepad.exe"` |

Each `ProcessId` matches the next row's `ParentProcessId`. PID 1028 was
confirmed as the interactive PowerShell window, not assumed: the pre-flight
`whoami` events had the same parent PID.

### Noise in the Same Search

The search also returned six `splunk-powershell.exe` executions, roughly once a
minute, as `NT SERVICE\SplunkForwarder` with parent `splunkd.exe`. That is the
forwarder's own PowerShell helper, matched only because "powershell.exe" is a
substring of its name. It is benign by context: expected parent, expected
service account, fixed install path, regular schedule.

## Follow-On Activity Check

To answer the guide's questions about file, network, persistence, and registry
activity, I pulled **every** Sysmon event type from the three scenario
processes:

```spl
index=* host=DESKTOP-BN86O9N source="*Sysmon*" earliest="10/07/2026:02:32:00" latest="10/07/2026:02:40:00"
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| dedup EventRecordID
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)"
| search ProcessId IN (2016, 2100, 4440)
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)"
| rex field=_raw "<Data Name='TargetObject'>(?<TargetObject>[^<]+)"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "<Data Name='QueryName'>(?<QueryName>[^<]+)"
| table _time EventID ProcessId TargetFilename TargetObject DestinationIp QueryName
```

Result: the three Event ID 1 rows plus one Event ID 11:

| Time (UTC) | Event | Process | Target |
|---|---|---|---|
| 02:33:17.139 | 11 FileCreate | powershell.exe (2100) | `C:\Users\soc.analyst1\AppData\Local\Temp\__PSScriptPolicyTest_novkxz20.zri.ps1` |

The `__PSScriptPolicyTest_*.ps1` file is normal PowerShell startup behavior:
PowerShell writes a randomly named `.ps1` to the user's Temp folder to test
whether AppLocker/WDAC script policy applies, then deletes it. Sysmon logged it
because the SwiftOnSecurity config watches `.ps1` creation. In isolation it
looks alarming - a random `.ps1` in Temp right after `-ExecutionPolicy Bypass` -
but the name pattern, the timing (0.18 s after launch, before Notepad), and the
creating process all match that known artifact.

The `phase12_inv1.txt` marker produced **no** Event ID 11: the config does not
log ordinary `.txt` creation in `C:\Users\Public`. That is a documented
visibility gap; the file was proven by host-side evidence instead.

No Event ID 3 (network), 13 (registry), or 22 (DNS) came from any of the three
processes.

## SOC Assessment

The evidence proved that suspicious-style PowerShell execution occurred: a
standard user, at Medium integrity, launched PowerShell with flags that bypass
script restrictions and skip profile loading, from a command shell, and
PowerShell launched a further process.

The evidence did **not** prove:

- Malware execution.
- Credential theft.
- Command-and-control communication.
- Privilege escalation (Medium integrity throughout).
- Persistence.
- Unauthorized access.
- Endpoint compromise.

**Verdict:** Suspicious by technique, benign by controlled lab context.

## Containment Decision and Cleanup

**Lab decision:** Do not isolate the host. Close as a benign simulation.

```powershell
Remove-Item C:\Users\Public\phase12_inv1.txt
Test-Path C:\Users\Public\phase12_inv1.txt       # False
Get-Process notepad -ErrorAction SilentlyContinue # nothing returned
```

**Production response:**

1. Validate whether the user was authorized to run the command.
2. Review the full parent-child process chain back to the logon session.
3. Search for encoded commands, downloads, script files, registry changes, and
   network connections from the same process tree.
4. Scope the same command line or hash across other endpoints.
5. Escalate and isolate if the activity is unexplained or accompanied by
   malicious follow-on evidence.

---

# 5. Investigation 2 - Scheduled Task Persistence-Style Behavior

## Actor Verification First

Creating an `ONLOGON` task requires elevation, and Phase 11 Issue #4 showed that
the wrong actor changes the finding. Before creating anything, I opened an
elevated PowerShell as `NIKOLA\Administrator` and verified the context:

```powershell
whoami                                # nikola\administrator
whoami /groups | findstr "Mandatory"  # Mandatory Label\High Mandatory Level
```

## Scenario

```powershell
schtasks.exe /Create /TN \Phase12\UpdaterCheck /TR notepad.exe /SC ONLOGON /F
schtasks.exe /Query /TN \Phase12\UpdaterCheck /V /FO LIST
```

Key `/Query` fields:

| Field | Value |
|---|---|
| TaskName | `\Phase12\UpdaterCheck` |
| Author | `NIKOLA\Administrator` |
| Task To Run | `notepad.exe` |
| Run As User | `Administrator` |
| Schedule Type | At logon time |
| Logon Mode | Interactive only |
| Last Run Time | `1999-11-30 12:00:00 AM` (placeholder) |
| Last Result | `267011` = `0x41303` `SCHED_S_TASK_HAS_NOT_RUN` |

The last two fields prove the task was **registered but never executed**.

## Splunk Search

I removed the guide's `EventCode=1` filter deliberately so a single search would
also catch any file or registry artifacts containing the task name:

```spl
index=* host=DESKTOP-BN86O9N source="*Sysmon*" earliest="10/07/2026:02:48:00" latest="10/07/2026:03:02:00"
("schtasks.exe" OR "UpdaterCheck" OR "Phase12")
| rex field=_raw "<EventRecordID>(?<EventRecordID>\d+)</EventRecordID>"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| dedup EventRecordID
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='IntegrityLevel'>(?<IntegrityLevel>[^<]+)"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>[^<]+)"
| rex field=_raw "<Data Name='ParentProcessId'>(?<ParentProcessId>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>[^<]+)"
| table _time EventID User IntegrityLevel ParentProcessId ProcessId Image CommandLine TargetFilename
| sort _time
```

## Timeline - Full Lifecycle

| Time (UTC) | Event | Actor | Process (PID) | Detail |
|---|---|---|---|---|
| 02:48:57.566 | 1 | NIKOLA\Administrator, High | schtasks.exe (2812), parent 8104 | `/Create /TN \Phase12\UpdaterCheck /TR notepad.exe /SC ONLOGON /F` |
| 02:48:57.580 | 11 | NT AUTHORITY\SYSTEM | svchost.exe (1272) | created `C:\Windows\System32\Tasks\Phase12` |
| 02:48:57.583 | 11 | NT AUTHORITY\SYSTEM | svchost.exe (1272) | created `C:\Windows\System32\Tasks\Phase12\UpdaterCheck` |
| 02:48:57.633 | 1 | NIKOLA\Administrator, High | schtasks.exe (6284), parent 8104 | `/Query /TN \Phase12\UpdaterCheck /V /FO LIST` |
| 02:59:28.518 | 1 | NIKOLA\Administrator, High | schtasks.exe (9976), parent 8104 | `/Delete /TN \Phase12\UpdaterCheck /F` |
| 02:59:28.570 | 1 | NIKOLA\Administrator, High | schtasks.exe (296), parent 8104 | `/Query /TN \Phase12\UpdaterCheck` (cleanup verification) |

Every `schtasks.exe` process shares parent PID 8104, the elevated PowerShell.

## Key Finding - The Artifact Belongs to the Service

The task's XML definition on disk was written by **`svchost.exe` running as
SYSTEM** (the Task Scheduler service), not by `schtasks.exe` or the
Administrator. `schtasks.exe` only asks the service, over RPC, to register the
task. A hunt that looks for task creation by the creating user or process would
miss the artifact entirely. The link between the two is **time and task name** -
17 ms apart and sharing `Phase12\UpdaterCheck`.

## Visibility Gaps

- No Event ID 13 for the `TaskCache\Tree\Phase12\UpdaterCheck` registry key,
  even though the search would have matched it - the Sysmon config does not log
  that key.
- No file-delete event for the task file on cleanup.
- The COM `DeleteFolder` call used to remove the empty `\Phase12` folder runs
  inside PowerShell and left no process event.

## SOC Assessment

The evidence proved that a scheduled task was created, queried, and deleted by
the domain's built-in Administrator at High integrity, and that the Task
Scheduler service wrote it to disk. The logon trigger, administrative context,
and generic "UpdaterCheck" name make it persistence-like and worth
investigating.

The evidence did **not** prove:

- A malicious payload (the action was `notepad.exe`).
- That the task ever ran (`SCHED_S_TASK_HAS_NOT_RUN`).
- Credential theft.
- Unauthorized persistence.
- Successful attacker access.
- Endpoint compromise.

**Verdict:** Persistence-style behavior observed; benign lab simulation.

## Containment Decision and Cleanup

**Lab decision:** Remove the scheduled task and its folder, and verify both are
gone.

```powershell
schtasks.exe /Delete /TN \Phase12\UpdaterCheck /F         # SUCCESS
schtasks.exe /Query /TN \Phase12\UpdaterCheck             # ERROR: cannot find the path specified
Test-Path C:\Windows\System32\Tasks\Phase12\UpdaterCheck  # False
$s = New-Object -ComObject Schedule.Service; $s.Connect()
$s.GetFolder("\").DeleteFolder("Phase12", 0)
Test-Path C:\Windows\System32\Tasks\Phase12               # False
```

`schtasks /Delete` alone leaves the empty `\Phase12` folder behind, so the folder
was removed separately. Removal was verified on the host and in Splunk.

**Production response:**

1. Confirm whether the task has an approved owner or change record.
2. Inspect the task action, arguments, working directory, trigger, and run-as
   account.
3. Review the referenced executable or script reputation and signature.
4. Search for similar tasks across endpoints, including `Tasks\` file creations
   by the Task Scheduler service.
5. Review adjacent process, file, registry, authentication, and network
   telemetry.
6. Remove or disable the task and escalate if it is unauthorized.

---

# 6. Investigation 3 - Linux Cron Persistence Timeline

## Host Choice

The guide used an Ubuntu VM. I used `splunk-soc` (Ubuntu 24.04, user `nikola`)
because it was already running, avoiding another VM on a host already showing
IOWait pressure. The guide's Linux case uses host artifacts rather than a SIEM
alert, so the host's role did not affect the investigation.

## Scenario

```bash
crontab -l      # baseline: no crontab for nikola
mkdir -p ~/phase12_linux
cat > ~/phase12_linux/update-check.sh << 'EOF'
#!/bin/bash
echo "phase12 update-check ran at $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> /tmp/phase12_linux_marker.log
EOF
chmod +x ~/phase12_linux/update-check.sh
(crontab -l 2>/dev/null; echo "* * * * * /home/nikola/phase12_linux/update-check.sh") | crontab -
```

## Artifact Review

```bash
crontab -l
ls -la /home/nikola/phase12_linux/
stat /home/nikola/phase12_linux/update-check.sh
cat /home/nikola/phase12_linux/update-check.sh
cat /tmp/phase12_linux_marker.log
journalctl -u cron --since "15 min ago" --no-pager
journalctl -t crontab --since "20 min ago" --no-pager
sudo ls -la /var/spool/cron/crontabs/
```

### Script Metadata

| Field | Value |
|---|---|
| Owner | `nikola` (UID 1000 / GID 1000) |
| Mode | `0775` (`-rwxrwxr-x`) - **group-writable** |
| Birth / Modify | 03:08:32.42 |
| Change | 03:08:34.41 (`chmod +x` - inode change, content unchanged) |
| Access | 03:09:01.99 (first execution read the script) |

### Crontab File

`/var/spool/cron/crontabs/nikola` - owner `nikola`, group `crontab`, mode
`0600`, 228 bytes (the `crontab` command adds a "DO NOT EDIT" header), modified
03:08.

## Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 03:08:20 | `crontab` log (PID 10876) | `LIST` - baseline `crontab -l`, no crontab |
| 03:08:32 | `stat` | script created |
| 03:08:34 | `stat` | execute bit added |
| 03:08:41 | `crontab` log (PID 10914) | **`REPLACE (nikola)`** - cron entry installed |
| 03:08:41 | `crontab` log (PIDs 10915, 10916) | `LIST` - pipeline read + verification |
| 03:09:01 | cron journal + `stat` Access | first execution |
| 03:09:02, 03:10:01, 03:11:01 | marker log | repeated execution, once per minute |
| 03:10:01, 03:11:01 | cron journal | `(nikola) CMD (/home/nikola/phase12_linux/update-check.sh)` |
| 03:11:25 | `crontab` log (PID 11317) | `LIST` - analyst artifact review |
| 03:24:38 | `crontab` log (PID 14698) | **`DELETE (nikola)`** - cleanup |
| 03:25-03:28 | cron journal | no `nikola` cron session - persistence stopped |

## Findings Worth Recording

- **Install-to-execution gap:** installed 03:08:41, first run 03:09:01. Cron
  picks up crontab changes at the next minute boundary.
- **`stat` Access corroborates the marker:** the script's access time matches
  the first marker line within milliseconds - independent proof that cron read
  the script.
- **Group-writable script:** Ubuntu's default `umask 002` produced `0775`. In
  production, a group-writable script executed by cron is a tampering risk:
  anyone in that group could change what runs.
- **Where the evidence lives:** `journalctl -u cron` shows executions but not
  the crontab edit. The edit is logged by the `crontab` program under its own
  identifier, found with `journalctl -t crontab`.
- **Log gap:** the 03:09 run logged PAM session open/close but **no `CMD`
  line**, even though the marker and the access time prove it ran. A missing log
  line is not proof that activity did not occur.
- **The analyst's own commands are in the timeline:** the 03:08:20 and 03:11:25
  `LIST` entries are investigation activity, not scenario activity. Documenting
  them prevents misattribution later.
- **Baseline noise:** root's `debian-sa1` and `e2scrub_all` cron jobs are normal
  system activity.

## SOC Assessment

The crontab entry, the referenced script, the journal attribution, and the
timestamped output proved that recurring execution occurred under `nikola`. A
script launched automatically every minute from a user-writable home directory
is persistence-like and should be investigated when unexpected.

The evidence did **not** prove:

- Malware.
- Privilege escalation (user-level crontab, UID 1000).
- Credential theft.
- Command-and-control traffic.
- Unauthorized access.
- Host compromise.

**Verdict:** Linux persistence-style behavior observed; benign lab simulation.

## Containment Decision and Cleanup

**Lab decision:** Remove the cron entry, script directory, and marker file, then
verify that the persistence stopped - not just that the files are gone.

```bash
crontab -r                          # baseline was empty, so this restores it exactly
rm -r ~/phase12_linux
rm /tmp/phase12_linux_marker.log
crontab -l                          # no crontab for nikola
sudo ls -la /var/spool/cron/crontabs/   # empty
journalctl -t crontab --since "5 min ago" --no-pager   # DELETE (nikola) at 03:24:38
sleep 70; ls -la /tmp/phase12_linux_marker.log         # No such file or directory
journalctl -u cron --since "3 min ago" --no-pager      # only root debian-sa1
```

The final check crossed three minute boundaries with no `nikola` cron session
at all - a stronger check than looking for `CMD` lines, given the 03:09 gap. In
production, I would remove only the offending line so legitimate entries stay
intact.

**Production response:**

1. Review user and root crontabs.
2. Review `/etc/cron*` paths and systemd timers.
3. Inspect scripts in user-writable or temporary directories.
4. Validate file ownership, permissions, timestamps, hashes, and package
   provenance.
5. Review shell history, process telemetry, authentication logs, and network
   connections.
6. Disable the persistence mechanism and isolate the host if the activity is
   unauthorized or linked to malicious follow-on behavior.

---

# 7. Wazuh Verification and Visibility Limits

After the investigations, I shut down `splunk-soc` and started `wazuh-server` to
verify endpoint agent availability:

```bash
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/agent_control -i 001
```

```powershell
Get-Service WazuhSvc     # Running
```

| Field | Value |
|---|---|
| Agent | `001 wazuhsoclab` |
| Status | Active |
| Operating system | Microsoft Windows 10 Pro |
| Client version | Wazuh v4.14.7 |
| Last keep alive | `1791344174` = 03:36:14 UTC |
| Syscheck last started | 02:04:47 UTC |
| Syscheck last ended | 03:32:20 UTC |

`IP: any` reflects the enrollment default (accept from any source IP), not an
unknown address.

The syscheck start time (02:04:47) matches the Windows boot, the first Sysmon
data in Splunk, and the 02:05:14 forwarder seek error - three independent
sources agreeing on when the endpoint came up. The end time falls just after
`wazuh-server` came online, consistent with the agent only being able to report
completion once the manager was reachable.

**The important limit:** `wazuh-server` was powered off during all three
investigations (host RAM), and `splunk-soc` has no Wazuh agent. Wazuh was
therefore **not an evidence source for any case**. Windows process and
persistence evidence came from Sysmon via Splunk; Linux evidence came from host
artifacts and the journal. A connected agent now does not mean the events were
collected then.

This matters in a SOC because:

- A connected agent does not guarantee every desired event is collected.
- Different products normalize fields differently (raw XML in Splunk here).
- A missing alert is not proof that activity did not occur.
- Analysts should pivot to raw events, host artifacts, another sensor, or a
  different time range when visibility is incomplete.

## Visibility Gaps Documented

| Area | Gap |
|---|---|
| Sysmon config | No FileCreate for ordinary `.txt`; no TaskCache registry events; no file-delete events; Event IDs 7 and 10 still disabled (Phase 4) |
| Splunk | No Windows TA - Sysmon fields require `rex` from raw XML |
| Forwarder | Phase 9 bookmark/re-scan defect still active after idle gaps |
| Linux journal | One cron run with no `CMD` line |
| Wazuh | Manager offline during activity; no agent on the Linux host |

---

# 8. Troubleshooting and How I Fixed It

## 8.1 `EventCode=1` Returned No Sysmon Events

**Symptom:** the first visibility check returned one `WinEventLog:System` event
and no Sysmon events.

**Root cause:** Sysmon events arrive as raw XML; `EventCode` is not extracted.
The System event matched only because it shares ID 1.

**Fix:** string search plus `rex` on `<EventID>`, `<EventRecordID>`, and
`<Data Name='...'>`. No config change.

## 8.2 A Fresh Event Did Not Appear for Minutes

**Symptom:** a `whoami` run at 02:12:50 was still missing after five minutes.

**Diagnosis:** measured `_indextime - _time` per 5-minute bucket; collection was
running but lagging up to ~15 minutes and draining.

**Fix:** none needed - the event arrived with 403 s lag. Adopted a wait-one-cycle
rule before concluding absence.

## 8.3 Every Event Appeared Two or Three Times

**Symptom:** the same `EventRecordID` indexed repeatedly, with copies ~400 s
apart.

**Root cause:** the Phase 9 Universal Forwarder defect - the
`Unable to set seek position to the given bookmark` error after the idle gap,
followed by the `splunk-winevtlog.exe` helper cycling and re-sending events.

**Fix:** `dedup EventRecordID` in every search (validated 5 -> 2). Full Phase 9
remediation deferred and tracked rather than changed mid-phase.

## 8.4 Splunk Health Warning

**Symptom:** health indicator cycling red / yellow / green.

**Root cause:** IOWait on `splunk-soc` - host disk pressure.

**Fix:** kept only the two VMs needed per step; swapped `splunk-soc` for
`wazuh-server` for the final verification.

## 8.5 Administrator Groups Showed as `Unknown SID type`

**Symptom:** domain group names missing from `whoami /groups`.

**Root cause:** DC01 off; cached-credential logon cannot resolve names.

**Fix:** identified groups by well-known RID. Not a fault.

## 8.6 The Crontab Edit Was Missing From the Cron Journal

**Symptom:** `journalctl -u cron` showed executions but no `REPLACE`.

**Root cause:** the edit is logged by the `crontab` program under its own
syslog identifier, not by the cron service.

**Fix:** `journalctl -t crontab`.

## General Troubleshooting Method

When endpoint evidence was incomplete, I checked:

1. The correct host and time range (including the UTC/EDT offset).
2. The expected event source and event ID - with the channel, not the ID alone.
3. Raw telemetry before normalized fields.
4. Ingestion lag and duplication (`_indextime - _time`) before concluding absence.
5. Exact command-line strings and artifact names.
6. Parent and child process relationships by process ID.
7. Host artifacts that could confirm execution.
8. Cleanup evidence after containment - by behavior, not just file absence.

---

# 9. Endpoint Investigation Template

The structure I used, reusable for future endpoint alerts.

## Alert Summary

- Alert or behavior:
- Host:
- User and integrity level:
- First observed:
- Last observed:
- Evidence source (which sensor):

## Process and Artifact Evidence

- Parent process (PID):
- Process (PID):
- Child process (PID):
- Command line:
- File, registry, task, service, or cron artifact (and which process wrote it):
- Network activity:
- Hash or reputation:

## Evidence Assessment

- What the evidence proves:
- What the evidence does not prove:
- Known business or lab context:
- Visibility limitations:

## Analyst Decision

- Verdict:
- Severity:
- Containment action:
- Scope required:
- Escalation reason:
- Cleanup verification:

---

# 10. Skills Demonstrated

- Endpoint and EDR investigation workflow.
- Sysmon Event ID 1 and 11 analysis.
- Splunk raw XML review and `rex` field extraction.
- Ingestion-lag and duplicate-event measurement (`_indextime`, `dedup EventRecordID`).
- Forwarder internal-log review (`index=_internal`) to root-cause pipeline faults.
- Parent-child process reconstruction by process ID.
- Suspicious PowerShell investigation.
- Scheduled-task persistence investigation, including service-attributed artifacts.
- Linux cron persistence review across `crontab`, `stat`, and the journal.
- Endpoint timeline construction across Windows and Linux.
- Actor and integrity-level verification before generating telemetry.
- Evidence-safe SOC conclusions.
- Visibility-gap recognition and sensor attribution.
- Containment and verified cleanup decisions.

---

# 11. Interview-Ready Summary

In Phase 12, I completed three endpoint investigations: a suspicious PowerShell
process chain using `-NoProfile -ExecutionPolicy Bypass`, scheduled-task
persistence created by a domain administrator, and Linux cron persistence. I
reconstructed each timeline - Windows process trees by process ID from Sysmon
telemetry in Splunk, and the Linux case from crontab logs, file metadata, and
the cron journal - and documented what the evidence did and did not prove before
choosing containment and verifying cleanup.

Before I could trust the telemetry, I had to diagnose the pipeline itself.
Sysmon events were arriving as raw XML with no extracted event code, and a known
Universal Forwarder defect had resurfaced after an idle period, producing
duplicate events and up to fifteen minutes of ingestion lag. I measured the lag
with `_indextime`, confirmed in the forwarder's internal logs that it was the
same bookmark error I had documented in Phase 9, confirmed no events were being
lost, and adapted my searches with `rex` extraction and `dedup` on the event
record ID instead of changing configuration mid-investigation.

The main lessons were that suspicious techniques do not automatically prove
compromise, that a missing field or a missing log line is not missing activity,
and that a persistence artifact can be attributed to a system service rather
than to the user who caused it.

---

# 12. Phase 12 Outcome

Phase 12 is complete.

I can now:

- Reconstruct a Windows endpoint process chain from Sysmon telemetry, linked by
  process ID.
- Review suspicious PowerShell flags in context, and recognize normal PowerShell
  artifacts like `__PSScriptPolicyTest` files.
- Investigate scheduled-task persistence, including the Task Scheduler service's
  on-disk artifact.
- Build a Linux persistence timeline from crontab logs, file metadata, and the
  cron journal.
- Extract useful fields from raw Sysmon XML in Splunk.
- Measure ingestion lag and remove duplicate events before trusting a result.
- Separate suspicious behavior from confirmed compromise.
- Explain visibility limitations, and which sensor supplied which evidence.
- Choose and document containment, and verify cleanup by behavior.

## Up Next

**Phase 13 - IAM, Hardening, and Least Privilege**

The next phase uses the identity and endpoint findings from Track 3 to review
administrative exposure, stale accounts, service accounts, local and domain
privilege, logging gaps, and prioritized hardening recommendations. Inputs from
this phase:

- The built-in domain Administrator used interactively on a workstation, with
  cached credentials.
- A group-writable script executed by cron (`umask 002`).
- The logging gaps in Section 7.
- The unresolved forwarder defect, tracked as a remediation item.
