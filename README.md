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
| 2 — SOC L1 Core Workflow | Log fundamentals → attack loop/triage → ticketing → phishing → Splunk → detection tuning | Not started |
| 3 — Endpoint & Identity Investigation | Active Directory build → AD attack sim → EDR investigation → IAM hardening | Not started |
| 4 — Cybersecurity Analyst Operations | Vulnerability management → threat intel → IR playbooks → GRC/audit | Not started |
| 5 — Deep Investigation & External Practice | Network traffic analysis → malware triage → DFIR → threat hunting → external SOC platforms | Not started |
| 6 — Cloud SOC & Microsoft Stack | AWS CloudTrail/GuardDuty → Sentinel/Defender/Entra ID | Not started |
| 7 — L2 SOC Automation | Python + SOAR case automation | Not started |
| 8 — Land the Job | Portfolio, resume, LinkedIn, interview prep | Not started |

Capstones: 01 (after Phase 9) · 02 (after Phase 13) · 03 (after Phase 17) · 04 (after Phase 22, before Track 6)

## Technical Skills

**SIEM & Detection** — Splunk, Elastic SIEM, Kibana, Wazuh XDR, Suricata IDS, Sysmon, Fleet/Elastic Agent, Splunk Universal Forwarder — KQL, SPL, detection rule authoring, alert tuning, MITRE ATT&CK mapping

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

More logs are added after each lab session.
