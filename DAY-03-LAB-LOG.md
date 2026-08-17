# Day 03 Lab Log — Phase 3 Complete: Wazuh XDR Deployment

**Phase Completed:** Phase 3 — Wazuh XDR (Second Detection Platform)
**Focus:** Dedicated Wazuh server build, Windows agent enrollment, endpoint telemetry validation, account/privilege-escalation detection, File Integrity Monitoring, Security Configuration Assessment, Vulnerability Detection, Elastic vs. Wazuh comparison

---

## Purpose

Phase 2 stood up a working Elastic-based SIEM pipeline (Elasticsearch, Kibana, Fleet, Sysmon, Suricata). Phase 3 added **Wazuh** as a second, XDR-style detection platform on its own dedicated VM, to compare a flexible SIEM/log-analytics workflow against a built-in endpoint-security workflow, and to enroll the same Windows 10 victim as a Wazuh-monitored endpoint alongside its existing Elastic Agent.

```text
Windows 10 Victim VM -> Wazuh Agent -> Wazuh Server / Indexer / Dashboard
```

Only wazuh-server and windows10victim needed to run for this phase — Elastic and Kali stayed powered off.

## Lab Environment Used

- **wazuh-server** (new VM) — Ubuntu Server, 8192 MB RAM, 4 CPU, 80 GB dynamic VDI. Adapter 1 = Host-only, Adapter 2 = NAT.
  - Host-only IP: `192.168.56.116` (interface `enp0s3` — note the adapter-to-interface naming came out flipped compared to Ubuntu-SIEM, where `enp0s3` was NAT. VirtualBox doesn't guarantee consistent naming across VMs.)
  - NAT IP: `10.0.2.15` (interface `enp0s8`)
  - Username: `nikola` — kept consistent with Ubuntu-SIEM's own username convention.
  - SSH: `ssh nikola@192.168.56.116`
- **windows10victim** — now dual-monitored: Elastic Agent + Sysmon (from Phase 2) plus the new Wazuh agent. Host-only IP confirmed as `192.168.56.114`, matching the IP recorded back in Phase 1/2, as expected.

## Build Steps

Installed Ubuntu Server on wazuh-server with default guided partitioning (entire disk, LVM — `/` ~39 GB ext4 logical volume, `/boot` 2 GB ext4, remaining ~39 GB left as free space in the volume group for headroom), OpenSSH enabled during install, both NICs left on DHCP.

Installed the Wazuh all-in-one stack:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget apt-transport-https unzip gnupg
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Clean install — Wazuh Manager, Indexer, Filebeat, and Dashboard (v4.14.7) all started with no errors. Dashboard reachable at `https://192.168.56.116` (self-signed cert, expected browser warning). Admin credentials generated at install time and saved to a password manager — not recorded here.

Deployed the Windows agent from the dashboard (Endpoints → Deploy new agent): MSI package, server address `192.168.56.116`, agent name `wazuhsoclab`, group `default`. Ran the generated install command in an elevated PowerShell on windows10victim, then `NET START Wazuh`. Agent confirmed **Active** in the dashboard: IP `192.168.56.114`, OS Microsoft Windows 10 Pro 10.0.19045.6456, version 4.14.7.

---

## Tests Performed

### Basic Endpoint Activity

Ran `whoami`, `ipconfig`, `net user`, `net localgroup administrators` on the Windows victim. These are all read-only and don't touch the Windows Security Log, so they didn't map to specific alerts — but two background service-state alerts (service startup type changed, VSS service state change) landed in the same window, confirming the telemetry pipeline was genuinely live.

### Account Creation and Administrator Group Change

```powershell
net user testwazuh P@ssw0rd123 /add
net localgroup administrators testwazuh /add
net localgroup administrators testwazuh /delete
net user testwazuh /delete
```

Result: 13 total alerts in the test window, 2 at Level 12+. Alert set matched expectations — Administrators Group Changed, Domain Users Group Changed, Users Group Changed, User account enabled/changed/deleted.

Drilled into the key alert's raw document: `rule.id: 60154`, `rule.level: 12`, `rule.description: "Administrators Group Changed"`, `rule.mitre.id: T1484`, `rule.mitre.tactic: Defense Evasion, Privilege Escalation`, `rule.mitre.technique: Domain Policy Modification`.

Note: other alerts in this same test sequence map to different MITRE techniques — rule 60109 ("User account enabled or created") and rule 60110 ("User account changed") map to account-creation/manipulation techniques like T1136/T1098/T1078, distinct from the T1484 mapping on the group-change alert itself. Lesson: check the MITRE mapping on the specific alert being cited, rather than assuming one mapping covers the whole test sequence.

### File Integrity Monitoring (FIM)

First attempt (default agent config) produced nothing — `C:\Users\Public` wasn't a monitored directory in `ossec.conf`'s `<syscheck>` block.

**Fix, attempt 1 (wrong):** pasted an entire new `<syscheck>...</syscheck>` block right after the existing opening tag. This left the original block's contents (real `<frequency>43200</frequency>`, default monitored directories, ignore rules, `<windows_registry>` entries) orphaned outside any `<syscheck>` element — invalid XML. Caught and undone before restarting the service.

**Fix, attempt 2 (correct):** added a single line inside the *existing* `<syscheck>` block, right after `<disabled>no</disabled>`, without touching anything else:

```xml
<directories check_all="yes" realtime="yes" report_changes="yes">C:\Users\Public</directories>
```

Confirmed via Notepad's Find that exactly one `</syscheck>` closing tag remained in the file before restarting:

```powershell
Restart-Service -Name Wazuh
```

Re-ran the FIM test (the first run had happened before the fix/restart, so it didn't count):

```powershell
echo "first test" > C:\Users\Public\wazuh-fim-test.txt
Start-Sleep -Seconds 10
echo "second test" >> C:\Users\Public\wazuh-fim-test.txt
Start-Sleep -Seconds 10
del C:\Users\Public\wazuh-fim-test.txt
```

Result: 3 `syscheck` alerts — **File added to the system**, **Integrity checksum changed**, **File deleted** — capturing the full create/modify/delete lifecycle.

### Security Configuration Assessment (SCA)

No manual trigger needed — the agent runs SCA automatically on startup. Results against CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0:

```text
Passed: 117 | Failed: 302 | Not applicable: 5 | Score: 27% | Checks: 424
```

The high failure rate is the *expected* result for a non-domain-joined, default Windows 10 VM: CIS enterprise hardening checks (password history, minimum password length, account lockout policy, etc.) simply aren't configured out of the box. This is a legitimate hardening-gap finding, not a lab problem.

### Vulnerability Detection

Populated on its own, with no manual syscollector-interval tuning needed — roughly 15 minutes after install was enough for the default sync/scan to complete.

```text
Critical: 13 | High: 561 | Medium: 179 | Low: 4 | Pending: 0
Total: 757 findings
```

This total will naturally grow over time as the CVE feed updates — not indicative of any lab issue.

---

## Troubleshooting Notes

| Problem | What Was Checked | Root Cause | Fix |
|---|---|---|---|
| Ubuntu installer's mirror check failed mid-install | N/A — installer dialog | Transient timing/DNS blip while the NAT adapter was still negotiating | Selected "Try again now" once; when still failing, selected Continue — base install completes fine from ISO media, confirmed real connectivity right after with `apt update` |
| `ping 8.8.8.8` and `ping` to the NAT gateway (`10.0.2.2`) both failed "Destination Host Unreachable" | `ip route` (showed correct `default via 10.0.2.2 dev enp0s8`), `sudo apt update` (succeeded, hit real mirrors over HTTP) | ICMP is dropped somewhere in this host's VirtualBox NAT path or host network — not a routing problem | None needed — confirmed real connectivity via `apt update`/TCP instead of ping. Noting for future reference: don't use ping as the connectivity test on this host, use apt/curl |
| FIM didn't detect the first file test | `<syscheck>` config in `ossec.conf` | `C:\Users\Public` wasn't a monitored directory | Added a single `<directories>` line inside the existing `<syscheck>` block, restarted the agent |
| First FIM config edit broke the XML structure | Reviewed the pasted block before restarting | Pasted a whole duplicate `<syscheck>...</syscheck>` block instead of one line, orphaning the original block's contents outside any element | Undid the edit, made a minimal single-line insertion instead, confirmed exactly one closing `</syscheck>` tag remained via Find |
| First FIM test run produced no alerts even after realizing the config needed a fix | Command order in PowerShell history | The test commands were run *before* the config fix and agent restart | Re-ran the FIM test after the fix was actually live |

---

## Elastic vs. Wazuh Comparison

**Hands-on, this phase:** Wazuh's built-in modules (Threat Hunting, FIM, SCA, Vulnerability Detection) gave immediate, opinionated security visibility with zero dashboard-building — the account/group-change alert fired with a rule ID, severity, and MITRE mapping automatically. Elastic, by contrast, gives raw telemetry and full control over how it's searched, filtered, and visualized (the 5-panel custom dashboard from Phase 2), but equivalent detection logic would have to be built by hand. That's the core trade-off: Wazuh = XDR-style endpoint security and compliance platform, purpose-built and ready out of the box; Elastic = flexible SIEM/log-analytics platform, more visualization power but more setup work to get security-specific detections.

**Broader context (not verified in this lab — carried over from outside research for future job-search reference):** Wazuh is commonly associated with SIEM/XDR endpoint monitoring, FIM, vulnerability detection, and compliance use cases; Elastic Security is positioned more around SIEM/analytics with AI-assisted threat detection, UEBA, and attack discovery, and shows up frequently in SOC/detection-engineering job postings alongside certification paths (Elastic Certified Engineer, etc.). Worth treating this as industry context to explore later (e.g., Elastic Security as a companion analytics layer on top of a Wazuh-monitored environment) rather than something validated hands-on in this lab — the Wazuh+Kali pairing seen often in home-lab tutorials is more likely due to both being free/open-source and easy to bundle, not a technical dependency between the two tools.

---

## What Phase 3 Proved

- A dedicated Wazuh VM can be stood up and fully installed via the all-in-one installer without disturbing the existing Elastic pipeline from Phase 2.
- A single Windows endpoint can report to two independent detection platforms (Elastic Agent + Wazuh Agent) simultaneously without conflict.
- Built-in XDR-style detections (FIM, SCA, Vulnerability Detection, MITRE mapping) work close to out of the box, but still need explicit agent-side configuration in places (FIM's monitored-directory list) before they produce results — "agent is active" and "the telemetry I want is flowing" are still two different questions.
- ICMP (ping) is not a reliable connectivity test on this host's VirtualBox NAT setup — TCP-based checks (`apt update`, `curl`) are the better validation method going forward.
- Editing XML config by pasting whole blocks instead of single targeted lines is an easy way to silently corrupt structure — always verify tag balance (e.g., via Find) before restarting a service that depends on the file.

## Skills Practiced

**SOC Analyst skills:** agent deployment, endpoint monitoring, alert triage, Threat Hunting dashboard usage, Windows event analysis, user and group change detection, privilege escalation detection, File Integrity Monitoring, MITRE ATT&CK mapping (including verifying per-alert mappings rather than trusting a summary), high-severity alert review.

**Security Analyst skills:** endpoint posture review, CIS benchmark assessment, vulnerability detection, compliance-style reporting, security configuration assessment, hardening gap identification, XML/config troubleshooting, connectivity troubleshooting (distinguishing ICMP failure from real TCP connectivity).

---

## Checklist

- [x] Dedicated Wazuh VM created and installed
- [x] SSH access configured (matching Phase 1/2 convention)
- [x] Wazuh all-in-one installed, dashboard accessible
- [x] Windows Wazuh agent enrolled and active
- [x] Basic endpoint telemetry confirmed flowing
- [x] Account creation / Administrators group change detection confirmed, with correct MITRE mapping verified
- [x] File Integrity Monitoring confirmed (add/modify/delete all captured)
- [x] Security Configuration Assessment confirmed (CIS Windows 10 benchmark)
- [x] Vulnerability Detection confirmed
- [x] Elastic vs. Wazuh comparison completed
- [x] Snapshots taken

**Snapshots:**

```text
wazuh-server:     Phase3-Wazuh-Server-Installed-Agent-Connected
windows10victim:  Phase3-Wazuh-Agent-FIM-SCA-VulnDetection-Working
```

---

## Summary

Phase 3 deployed Wazuh XDR as a second detection platform alongside the existing Elastic SIEM lab: a dedicated Ubuntu Server VM, Wazuh manager/indexer/dashboard installed via the all-in-one script, and the Windows 10 victim enrolled as a Wazuh agent in addition to its existing Elastic Agent. Every core detection module was validated hands-on — account/privilege-escalation detection with correct MITRE ATT&CK mapping, File Integrity Monitoring (full add/modify/delete lifecycle), Security Configuration Assessment against the CIS Windows 10 benchmark, and Vulnerability Detection — along with real troubleshooting along the way: a false-alarm ICMP connectivity scare (resolved by testing actual TCP connectivity instead), and a config-editing mistake caught and corrected before it could break the agent.

Comparing the two platforms directly: Wazuh delivers built-in, ready-to-use security detections and compliance checks with minimal setup, while Elastic offers more flexible, self-directed visualization and log analytics at the cost of needing to build detection logic manually. Together they give the lab both a general-purpose SIEM and a purpose-built XDR/endpoint-security platform to compare and correlate against going forward.
