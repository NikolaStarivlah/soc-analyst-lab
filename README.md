SOC Analyst Lab & Roadmap

A public, end-to-end roadmap for becoming a SOC Analyst L1/L2 and Cybersecurity Analyst, built from a real home lab and documented as the work progresses.

Live site: nikolastarivlah.github.io/

About

I'm Nikola, an aspiring SOC Analyst based in Milton, Ontario, building toward SOC L1/L2 and cybersecurity analyst roles.

This repository documents my hands-on path through security operations: SIEM deployment, endpoint telemetry, IDS alerts, Wazuh XDR, phishing investigation, IOC enrichment, log analysis, high-volume triage practice, incident notes, detection engineering, and portfolio-ready reporting.

Current Focus

The roadmap aims to include a production-style SOC practice layer:

Scripted lab attack loop using a Kali attacker VM
Alert generation sessions and high-volume queue review (Elastic + Wazuh)
SOC ticket writing, severity reasoning, and shift handoff notes
Splunk Enterprise deployment with Universal Forwarder telemetry pipeline
SPL investigations across authentication, DNS, PowerShell, and process activity
Splunk SOC dashboards and Splunk/SPL vs Elastic/KQL workflow comparison
Detection engineering: enabled alerts, Sigma-style rules with MITRE ATT&CK mapping
False-positive tuning with before/after evidence
Active Directory domain controller build with organized OUs, users, and groups
Domain join, Kerberos authentication, and DC log forwarding into Splunk
Controlled AD security scenarios (password spray, AS-REP roasting exposure, Kerberoasting-relevant telemetry, privileged group changes, AD enumeration)
Endpoint/EDR-style investigations (PowerShell process chains, persistence mechanisms, Linux cron persistence)
IAM and Active Directory hardening review with safe remediation and change-control decisions
Case notes and lessons learned added to build logs as I go

This is designed to practice the real SOC motion: sort signal from noise, decide what deserves more time, close benign activity, tune recurring noise, write clean tickets, investigate suspicious emails, extract IOCs, search telemetry in multiple SIEMs, build dashboards, and escalate cleanly.

Credentials
CompTIA Security+ SY0-701 — earned
SC-300, AZ-500 — in progress

Education:

Honours Bachelor of Information Sciences (Cyber Security)

Current role:

Currently unemployed

Previous role:

IT Security Analyst Intern, Sep. 2023 – Dec. 2023, Samuel, Son & Co., Burlington, ON
Track 1 - Build Your SOC Lab
Set Up Your Virtual Lab Environment
Deploy Elastic SIEM + Suricata IDS
Wazuh XDR - Second Detection Platform

Status: Complete

Track 2 - SOC L1 Core Workflow
Windows, Linux, and Network Log Fundamentals
Scripted Attack Loop + High-Volume Triage
SOC Ticket Writing, Escalation, and Shift Handoff
Phishing and Email Security Investigation
Splunk Fundamentals for SOC
Detection Engineering and Rule Tuning

Status: Not started

Track 3 - Endpoint and Identity Investigation
Build an Active Directory Environment
AD Attack Simulation + Alert Triage
Endpoint / EDR Investigation (Windows + Linux)
IAM, Hardening, and Least Privilege

Status: Not started

Track 4 - Cybersecurity Analyst Operations
Vulnerability Management + Patch Prioritization
Threat Intelligence + IOC Enrichment
Incident Response Playbooks + Containment Decisions
GRC, Compliance, Audit Evidence, and Risk Reporting
Track 5 - Deep Investigation and External Practice
Network Traffic Analysis
Malware Triage + Sandbox Analysis
Digital Forensics + Memory Basics
Threat Hunting
Scale External SOC Practice + Unfamiliar Case Investigations
Track 6 - Cloud SOC and Microsoft Security Stack
AWS CloudTrail + GuardDuty + Security Hub
Microsoft Sentinel + Defender + Entra ID / M365 Investigations
Track 7 - L2 SOC Automation
Python Automation + SOAR Case Automation
Track 8 - Land the Job
Portfolio, Resume, LinkedIn, and Interview Prep
Track-End Capstone Assessments
Capstone 01 - SOC L1 Core Workflow Readiness (after Phase 9, covers Tracks 1-2)
Capstone 02 - Endpoint and Identity Investigation (after Phase 13)
Capstone 03 - Cybersecurity Analyst Operations (after Phase 17)
Capstone 04 - Deep Investigation Capstone (after Phase 22, before Track 6)
Technical Skills

SIEM and detection: Splunk, Elastic SIEM, Kibana, Wazuh XDR, Suricata IDS, Sysmon, Fleet, Elastic Agent, Splunk Universal Forwarder — KQL, SPL, detection rules, alert tuning, MITRE ATT&CK mapping

SOC operations: alert triage, queue management, ticket writing, escalation summaries, shift handoff notes, phishing triage, IOC extraction/enrichment (VirusTotal, AbuseIPDB, Shodan), incident reports

Endpoint and identity: Windows Event Logs, Sysmon, Active Directory Domain Services, DNS, OUs/users/groups, domain join, Kerberos authentication, Linux endpoint investigation (auth, cron, process, file-timestamp evidence)

Network and infrastructure: Wireshark, tcpdump, Nmap, Suricata, pfSense, VMware Workstation/VirtualBox/UTM, Ubuntu Server, Kali Linux, Windows 10/11, host-only networking, NAT, VM snapshots

Adversary simulation: Kali Linux, scripted attack loops, Metasploit, Impacket, CrackMapExec, Mimikatz, Volatility, Autopsy, FTK Imager, PEStudio, YARA

Daily Build Logs
DAY-01-LAB-LOG.md — Virtual lab foundation, NAT/host-only networking, VM roles, SSH, snapshots, and troubleshooting

More logs are added with each lab session.
