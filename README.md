# SOC Analyst Lab & Roadmap

A public, end-to-end roadmap for becoming a SOC Analyst (L1/L2) and Cybersecurity Analyst — built from a real home lab and documented as the work progresses.

🔗 **Live site:** [nikolastarivlah.github.io](https://nikolastarivlah.github.io)

## About

I'm Nikola, an aspiring SOC Analyst based in Milton, Ontario, working toward SOC L1/L2 and cybersecurity analyst roles.

This repo documents my hands-on path through security operations — SIEM deployment, endpoint telemetry, IDS alerting, Wazuh XDR, phishing investigation, IOC enrichment, log analysis, high-volume triage practice, incident documentation, detection engineering, and portfolio-ready reporting.

| | |
|---|---|
| **Credentials** | CompTIA Security+ (SY0-701) — SC-300, AZ-500 in progress |
| **Education** | Honours Bachelor of Information Sciences (Cyber Security) |
| **Current role** | Building the lab full-time |
| **Previous role** | IT Security Analyst Intern, Sep–Dec 2023 — Samuel, Son & Co., Burlington, ON |

## Current Focus

The roadmap builds toward a production-style SOC practice layer:

- Scripted Kali attacker VM loop + high-volume alert queue review (Elastic + Wazuh)
- SOC ticket writing, severity reasoning, and shift handoff notes
- Splunk Enterprise + Universal Forwarder telemetry pipeline
- SPL investigations across authentication, DNS, PowerShell, and process activity
- Splunk SOC dashboards + Splunk/SPL vs Elastic/KQL workflow comparison
- Detection engineering: Sigma-style rules mapped to MITRE ATT&CK, with before/after false-positive tuning evidence
- Active Directory domain controller build (OUs, users, groups, domain join, Kerberos, DC log forwarding to Splunk)
- Controlled AD attack scenarios: password spray, AS-REP roasting exposure, Kerberoasting-relevant telemetry, privileged group changes, AD enumeration
- Endpoint/EDR-style investigations: PowerShell process chains, persistence mechanisms, Linux cron persistence
- IAM + AD hardening review with safe remediation and change-control decisions

This is designed to practice the real SOC motion: sort signal from noise, decide what deserves more time, close benign activity, tune recurring noise, write clean tickets, investigate suspicious emails, extract IOCs, search telemetry across multiple SIEMs, build dashboards, and escalate cleanly.

## Roadmap

| Track | Focus | Status |
|---|---|---|
| 1 — Build Your SOC Lab | Virtual lab setup → Elastic SIEM + Suricata IDS → Wazuh XDR | Complete |
| 2 — SOC L1 Core Workflow | Log fundamentals → attack loop/triage → ticketing → phishing → Splunk → detection tuning | Complete (Phases 4–9 of 6) |
| 3 — Endpoint & Identity Investigation | Active Directory build → AD attack sim → EDR investigation → IAM hardening | In Progress (Phase 12 of 4) |
| 4 — Cybersecurity Analyst Operations | Vulnerability management → threat intel → IR playbooks → GRC/audit | Not started |
| 5 — Deep Investigation & External Practice | Network traffic analysis → malware triage → DFIR → threat hunting → external SOC platforms | Not started |
| 6 — Cloud SOC & Microsoft Stack | AWS CloudTrail/GuardDuty → Sentinel/Defender/Entra ID | Not started |
| 7 — L2 SOC Automation | Python + SOAR case automation | Not started |
| 8 — Land the Job | Portfolio, resume, LinkedIn, interview prep | Not started |

Capstones: 01 (after Phase 9) · 02 (after Phase 13) · 03 (after Phase 17) · 04 (after Phase 22, before Track 6)

## Technical Skills

**SIEM & Detection** — Splunk, Elastic SIEM, Kibana, Wazuh XDR, Suricata IDS, Sysmon, Fleet/Elastic Agent, Splunk Universal Forwarder — KQL, SPL, raw-event field extraction (`rex`), ingestion-lag analysis, detection rule authoring, alert tuning, MITRE ATT&CK mapping

**SOC Operations** — Alert triage, queue management, ticket writing, escalation summaries, shift handoff notes, phishing triage, IOC extraction/enrichment (VirusTotal, AbuseIPDB, Shodan), incident reporting

**Endpoint & Identity** — Windows Event Logs, Sysmon, Active Directory Domain Services, DNS, OUs/users/groups, domain join, Kerberos authentication, Linux endpoint investigation (auth, cron, process, file-timestamp evidence)

**Network & Infrastructure** — Wireshark, tcpdump, Nmap, Suricata, pfSense, VirtualBox/VMware Workstation/UTM, Ubuntu Server, Kali Linux, Windows 10/11, host-only networking, NAT, VM snapshots

**Adversary Simulation & Forensics** — Kali Linux, scripted attack loops, Metasploit, Impacket, CrackMapExec, Mimikatz, Volatility, Autopsy, FTK Imager, PEStudio, YARA

## Daily Build Logs

| Day | Log | Summary |
|---|---|---|
| 01 | [DAY-01-LAB-LOG.md](./DAY-01-LAB-LOG.md) | Virtual lab foundation — NAT/host-only networking, VM roles, SSH, snapshots, troubleshooting |
| 02 | [DAY-02-LAB-LOG.md](./DAY-02-LAB-LOG.md) | Elastic SIEM (Elasticsearch/Kibana) + self-managed Fleet Server + Windows Elastic Agent/Sysmon telemetry + Suricata IDS + first 5-panel SOC dashboard, with full root-cause troubleshooting (Fleet output IP, Kibana encryption keys, stale agent policy, missing Sysmon integration) |
| 03 | [DAY-03-LAB-LOG.md](./DAY-03-LAB-LOG.md) | Wazuh XDR deployed as a second detection platform on its own dedicated VM, Windows endpoint dual-enrolled alongside the existing Elastic Agent — account/privilege-escalation detection with verified MITRE ATT&CK mapping, File Integrity Monitoring (full add/modify/delete lifecycle), Security Configuration Assessment against the CIS Windows 10 benchmark, and Vulnerability Detection, plus root-cause troubleshooting (a config-editing mistake caught and fixed before it broke the agent, and distinguishing a false-alarm ICMP connectivity issue from real TCP connectivity) |
| 04 | [DAY-04-LAB-LOG.md](./DAY-04-LAB-LOG.md) | Windows/Sysmon, Windows Security/System, Linux, and network/IDS log fundamentals — reviewed 20+ event and log scenarios across endpoint and host telemetry, discovered and documented this lab's Elastic Agent version normalizes Sysmon data into ECS fields rather than raw field names, confirmed a real Sysmon visibility gap (Image Load and Process Access disabled by the default config), and distinguished genuine user activity and IDS findings from routine SYSTEM/service-account and monitoring-agent noise across every log source reviewed |
| 05 | [DAY-05-LAB-LOG.md](./DAY-05-LAB-LOG.md) | Scripted PowerShell alert-generation loop + high-volume SOC triage in Kibana Discover — classified PowerShell discovery, local admin group enumeration, and web-request activity using suspicious-by-technique/benign-by-context reasoning; diagnosed and resolved a Kibana authentication failure by isolating it from a false-lead service warning; discovered and verified an original Sysmon visibility gap where `curl.exe` and `nslookup.exe` each surface DNS/network activity through non-overlapping event types (Process Creation, DNS Query, Network Connection), confirmed across multiple time ranges; produced false-positive/benign lists, escalation notes, and a shift handoff summary |
| 06 | [DAY-06-LAB-LOG.md](./DAY-06-LAB-LOG.md) | Converted Phase 5 evidence into 5 SOC tickets, 3 escalation summaries, and 2 shift handoffs, pulling every field live from Kibana Discover (process IDs, parent-process chains, SHA256 hashes) rather than templated placeholders; caught and corrected a real investigative mistake where an unscoped Event ID query matched an unrelated Application-log event instead of the intended Security-log authentication event; ran a safe, reversible failed-logon simulation to generate genuine Event ID 4625 data and used the logon-type/source-IP fields to demonstrate how the same alert pattern shifts from low to high severity depending on context |
| 07 | [DAY-07-LAB-LOG.md](./DAY-07-LAB-LOG.md) | Phishing and email security investigation — triaged 5 simulated SOC-mailbox reports (Microsoft 365 credential phishing, an invoice ZIP attachment, CEO/BEC impersonation, a fake Okta security alert, and a fake DocuSign request) through IOC extraction, sender/URL/attachment analysis, and social-engineering identification; caught and corrected two premature "benign, release" calls by tracing lookalike sender/URL domains (e.g. `okta-verification[.]com`, not an Okta-owned domain) back to actual domain ownership instead of how plausible the message read; produced a consolidated final incident report and phase-wide lessons learned |
| 08 | [DAY-08-LAB-LOG.md](./DAY-08-LAB-LOG.md) | Splunk Fundamentals for SOC — deployed Splunk Enterprise on a dedicated VM, configured non-root service execution and boot persistence, and built a Universal Forwarder pipeline from the Windows endpoint; diagnosed and fixed two distinct forwarder-side issues (Windows Event Log inputs not enabled by default, then a Sysmon-specific Windows Event Log channel-access restriction traced to the forwarder's `NT SERVICE\SplunkForwarder` virtual account lacking access under Sysmon's default `channelAccess` ACL, fixed by porting over a working channel's access descriptor via `wevtutil`); completed 10 SPL investigations across authentication, process execution, PowerShell, and DNS activity, and built 3 SOC dashboards with embedded triage/verdict logic; closed with a Splunk/SPL vs Elastic/KQL workflow comparison |
| 09 | [DAY-09-LAB-LOG.md](./DAY-09-LAB-LOG.md) | Detection engineering and rule tuning — built and validated 6 enabled Splunk alerts (encoded PowerShell, registry Run-key persistence, scheduled-task creation, local administrator group changes, outbound network connections, command-line DNS queries) with safe controlled test generation and cleanup for each; wrote 3 Sigma-style rules mapped to MITRE ATT&CK; ran a false-positive tuning pass that reduced a broad outbound-connection rule from 52 matches down to 0 by verifying and excluding 4 legitimate OneDrive-family executables; root-caused a live Sysmon ingestion failure (a single test event duplicating into the millions) to a documented, unpatched Splunk Universal Forwarder defect in its Windows Event Log historical-backfill path — confirmed independently via Splunk's own community reports rather than assumed — and mitigated it (`current_only=1`) rather than working around symptoms; deferred LSASS access detection after confirming required Sysmon Event ID 10 telemetry was genuinely unavailable |
| 10 | [DAY-10-LAB-LOG.md](./DAY-10-LAB-LOG.md) | Active Directory identity environment — deployed a Windows Server 2022 domain controller (DC01), promoted it to a new private forest (`nikola.local`), built out SOC-Lab OUs/users/groups, joined the existing Windows 10 endpoint to the domain, and forwarded DC01's Security/System/Application/Directory Service/DNS Server logs into Splunk; generated and investigated controlled Kerberos pre-authentication failure (Event 4771) and privileged group membership change (Event 4728) evidence, producing two SOC mini-tickets; root-caused and resolved eight distinct infrastructure issues across the build — an expired Windows Server evaluation license, a stuck VirtualBox NAT virtual adapter, a Notepad-appended hidden `.txt` extension that silently broke forwarder log collection, a stale DHCP-renewed Splunk receiver IP, host memory exhaustion that crashed the domain controller VM (Kernel-Power Event 41), and — the most involved chain — a wrong time zone on both the DC and the endpoint causing a Kerberos authentication failure that produced zero domain-controller-side evidence despite confirmed-healthy DNS, secure channel, and port connectivity, ultimately traced to a Windows Server default audit policy that only logs successful Kerberos/Credential Validation events, not failures |
| 11 | [DAY-11-LAB-LOG.md](./DAY-11-LAB-LOG.md) | Controlled AD attack simulation and alert triage — generated and investigated five identity-focused scenarios against the `nikola.local` lab in Splunk, each closed with an evidence-safe verdict: password spray (seven Event 4771 Kerberos pre-auth failures, code `0x18`, three users from one source), an AS-REP roastable service account (`svc_legacy`, `DoesNotRequirePreAuth=True`, UAC change to `0x10210` captured across the 4720/4722/4724/4738 lifecycle), Kerberoast-relevant telemetry (Event 4769 for SPN `HTTP/webapp.nikola.local` with RC4 `0x17` encryption, cross-confirmed in the `klist` cache), a privileged Domain Admins change (paired 4728/4729 with a ~9-second membership window, actor/target/group resolved by SID), and standard-user AD enumeration (Sysmon Event 1 process-creation plus Event 22 DNS-query evidence for `whoami`/`nltest`/`setspn`); wrote two formal SOC mini-tickets (password spray, Domain Admins change); pre-flight-verified time-zone and audit-policy coverage before generating activity so a missing event would signal a new fault; root-caused that new fault when Scenario 5 telemetry failed to reach Splunk — a Sysmon forwarder input left `current_only=1` (the same defect mitigation from Phase 9) silently skipping events generated before the forwarder's live watch window, diagnosed by reading `inputs.conf`/`outputs.conf` directly after confirming the service was running and the receiver IP had not drifted, then fixed by regenerating the activity live; and caught a capture recorded under the wrong actor (an elevated `Administrator` shell instead of the standard `soc.analyst1` the scenario models) by checking the shell's integrity level and SID before trusting the telemetry |
| 12 | [DAY-12-LAB-LOG.md](./DAY-12-LAB-LOG.md) | Endpoint/EDR-style investigation — reconstructed three controlled endpoint cases end to end with evidence-safe verdicts and verified cleanup: a suspicious PowerShell process chain (`powershell.exe → cmd.exe → powershell.exe -NoProfile -ExecutionPolicy Bypass → notepad.exe`, linked by process ID from Sysmon Event 1, with a normal `__PSScriptPolicyTest` startup artifact distinguished from attacker activity), scheduled-task persistence created by the domain Administrator (full create/query/delete lifecycle, plus the finding that the task's on-disk artifact is written by the Task Scheduler service as SYSTEM rather than by `schtasks.exe` or the user, and a `SCHED_S_TASK_HAS_NOT_RUN` result proving the task never executed), and Linux cron persistence (crontab REPLACE/DELETE attribution via `journalctl -t crontab`, `stat` timestamps corroborating the first execution, a group-writable script flagged as a tampering risk, and cleanup verified by confirming execution stopped rather than just that files were deleted); before generating activity, pre-flight-verified the Splunk Sysmon pipeline and root-caused three issues — Sysmon arriving as raw XML with no extracted `EventCode` (worked around with `rex`), a recurrence of the Phase 9 Universal Forwarder bookmark defect producing duplicate events and up to ~15 minutes of ingestion lag (measured with `_indextime`, confirmed in the forwarder's `_internal` logs, mitigated with `dedup EventRecordID` after confirming no data loss), and a Splunk IOWait health warning; verified Wazuh agent availability separately and documented that Wazuh was not an evidence source for any case, along with the remaining Sysmon, forwarder, and journal visibility gaps |

More logs are added after each lab session.
