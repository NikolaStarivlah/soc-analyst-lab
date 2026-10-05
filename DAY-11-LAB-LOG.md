# Phase 11 Detailed Lab Log - AD Attack Simulation and Alert Triage

## Status

**Track 3 - Endpoint and Identity Investigation**

## Completion Summary

Phase 11 used the Active Directory environment built in Phase 10 to simulate
and investigate five identity-focused security scenarios. I generated
controlled authentication failures, created a risky AS-REP roastable
service-account condition, requested a Kerberos service ticket for a lab SPN,
performed a privileged Domain Admins membership change, and ran
domain-enumeration commands from the joined Windows 10 workstation.

I investigated the resulting DC01 and endpoint telemetry in Splunk, documented
what each event proved, identified the production context that would still need
validation, and assigned an evidence-safe verdict to each scenario. The lab
activity was deliberate and controlled. No real compromise, password cracking,
credential theft, malware execution, or domain takeover occurred.

This phase also surfaced a genuine telemetry-pipeline fault that had to be
diagnosed before Scenario 5 evidence would appear in Splunk - the Sysmon input
on the workstation forwarder was configured `current_only = 1`, so
process-creation events generated before the forwarder's live watch window were
never shipped. This is documented in Section 8.

### Final Deliverables

| Requirement | Result |
|---|---|
| Password spray simulation | Investigated Kerberos pre-authentication failures (4771) across three users from one source |
| AS-REP roastable condition | Created and documented `svc_legacy` with `DoesNotRequirePreAuth=True` |
| Kerberoast-relevant telemetry | Generated and investigated Event ID 4769 for lab SPN `HTTP/webapp.nikola.local` |
| Privileged group change | Detected addition and removal of a user from Domain Admins (4728/4729) |
| AD enumeration | Reviewed Sysmon process and command-line evidence (Event ID 1 + 22) from the workstation |
| Investigation platform | Splunk using DC01 and Windows endpoint telemetry |
| Analyst documentation | Five SOC-style assessments plus two formal mini-tickets with verdicts and follow-up |

---

# 1. Objective

The goal was to move beyond building Active Directory and practice the work a
SOC analyst performs after identity alerts appear:

```text
Generate controlled identity activity
  -> Locate the correct telemetry
  -> Establish actor, target, host, and timeline
  -> Decide what the evidence proves
  -> Identify what remains unknown
  -> Assign severity and verdict
  -> Recommend validation or escalation steps
```

The phase goal was to detect, triage, and document five Active Directory
security scenarios without overclaiming compromise.

---

# 2. Lab Environment

Only the systems required for each step were powered on at any one time. After
the host-memory crashes documented in Phase 10, VMs were deliberately sequenced
- DC01 plus Splunk for the DC-sourced scenarios, and the workstation plus
Splunk (or DC01 plus workstation) for the endpoint scenario - rather than all
three run continuously. The workstation itself failed to boot once during this
phase when three VMs plus host apps were open at the same time, consistent with
the Phase 10 host-RAM ceiling (Section 8).

| System | Role | Key evidence |
|---|---|---|
| `DC01` | Windows Server 2022 domain controller and DNS (`192.168.56.10`, static) | Security events, Kerberos events, account changes, group changes |
| `DESKTOP-BN86O9N` | Windows 10 domain workstation (`192.168.56.114`, DHCP host-only) | User activity, Sysmon process creation, command-line evidence |
| `splunk-soc` | Splunk Enterprise (`192.168.56.117`, DHCP host-only) | Central search, timeline review, field comparison, ticket evidence |
| `nikola.local` | Private lab domain (NetBIOS `NIKOLA`) | Controlled users, service accounts, groups, and authentication |

Important lab identities used this phase:

- `NIKOLA\Administrator` (built-in, SID RID `-500`)
- `NIKOLA\soc.analyst1` (standard user, SID RID `-1104`, member of `SOC Analysts` RID `-1107`)
- `NIKOLA\helpdesk.user1` (SID RID `-1105`)
- `NIKOLA\test.employee1` (SID RID `-1106`)
- `NIKOLA\svc_legacy` (service account created this phase, SID RID `-1111`)
- `NIKOLA\svc_web` (service account created this phase, SID RID `-1112`)

Well-known RIDs referenced throughout: `-500` built-in Administrator, `-512`
Domain Admins, `-519` Enterprise Admins.

The scenarios were intentionally generated inside the isolated lab. That
context affected the final verdict, but I still analyzed each as if it had
appeared unexpectedly in a production SOC queue.

---

# 3. Pre-Flight Verification (Phase 10 Lessons Applied)

Before generating any attack activity, I verified the two conditions that cost
the most time in Phase 10: time-zone alignment (Kerberos skew) and audit-policy
coverage. Both are the first suspects when an expected event is missing.

On DC01:

```powershell
Get-TimeZone | Select-Object Id
Get-Date
auditpol /get /subcategory:"Kerberos Authentication Service","Credential Validation","Kerberos Service Ticket Operations","Security Group Management","User Account Management"
```

Result - all clear, no changes required:

- Time zone `Eastern Standard Time`, clock correct (no Kerberos skew risk).
- Kerberos Authentication Service: **Success and Failure**
- Credential Validation: **Success and Failure**
- Kerberos Service Ticket Operations: **Success**
- Security Group Management: **Success**
- User Account Management: **Success**

Because all five subcategories were already covered, any missing event later in
the phase would point to a new fault rather than leftover Phase 10 config. This
was confirmed useful in Scenario 5, where the missing telemetry turned out to
be a forwarder input issue, not an audit-policy gap.

---

# 4. Scenario 1 - Password Spray Simulation

## Activity Generated

From `DESKTOP-BN86O9N`, I generated failed authentication attempts against three
NIKOLA users using `runas` with deliberately wrong passwords, repeated over a
short window to resemble spray behavior:

```text
runas /user:NIKOLA\soc.analyst1 cmd
runas /user:NIKOLA\helpdesk.user1 cmd
runas /user:NIKOLA\test.employee1 cmd
```

Each returned `error 1326` (logon failure). The set was repeated so the pattern
was one source testing several accounts in a tight window.

## Evidence Observed

- Host: `DC01`
- Event ID: `4771` (Kerberos pre-authentication failed), seven events total
- Kerberos service: `krbtgt/NIKOLA`
- Target users: `soc.analyst1` (×3), `helpdesk.user1` (×2), `test.employee1` (×2)
- Failure code: `0x18`, consistent with an incorrect password
- Source: `Client Address: ::ffff:192.168.56.114` (the workstation) on all seven
- Window: approximately 13:48 to 13:53 (~5 minutes)

## Investigation Search

```spl
index=* host=DC01 (EventCode=4771 OR EventCode=4776 OR EventCode=4625)
| table _time host EventCode Account_Name Account_Domain src_ip Workstation_Name Failure_Code _raw
| sort - _time
```

## Field-Extraction Note

`src_ip` and `Workstation_Name` were blank in the table, but the source was not
actually unknown - for Kerberos 4771 the origin is carried in the raw event as
`Client Address`, which Splunk's default field extraction does not map to
`src_ip`. The source was read from `_raw`. This is the Phase 10 lesson (read the
raw event before relying on normalized fields) recurring, and it applied again
in Scenarios 3 and 4.

## SOC Assessment

- **What it proves:** Seven 4771 failures (`0x18`) against three accounts from a
  single source inside ~5 minutes - a pattern consistent with password spraying.
- **What it does not prove:** No successful logon followed, no password was
  recovered, no account was compromised.
- **Why it could be malicious:** One source failing auth across several accounts
  in a short window is the signature of a spray attempting a common password
  across many users to avoid per-account lockout.
- **Known lab context:** The source is the lab workstation; failures were
  generated deliberately by `runas`.

**Verdict:** Suspicious by behavior, benign by controlled lab context.

**Production follow-up:** Confirm the source host and owner, count all targeted
accounts, check whether any are privileged, review for any successful logon from
`192.168.56.114` after the failures, correlate with MFA/identity-provider logs,
and watch for follow-on activity.

---

# 5. Scenario 2 - AS-REP Roastable Account Configuration

## Activity Generated

I created the service account `svc_legacy` and disabled Kerberos
pre-authentication, producing the `DoesNotRequirePreAuth=True` condition that
makes an account AS-REP roastable.

The creation took two steps because of the domain password policy (Section 8):
the first `New-ADUser` failed complexity and left a disabled, passwordless
shell; I then set a compliant password, enabled the account, and applied the
risky flag:

```powershell
Set-ADAccountPassword -Identity svc_legacy -Reset -NewPassword (Read-Host -AsSecureString "Set password")
Enable-ADAccount -Identity svc_legacy
Set-ADAccountControl -Identity svc_legacy -DoesNotRequirePreAuth $true
Get-ADUser svc_legacy -Properties DoesNotRequirePreAuth,Enabled | Select-Object Name,Enabled,DoesNotRequirePreAuth
```

Final state confirmed: `Enabled : True`, `DoesNotRequirePreAuth : True`.

## Evidence Observed

The two-step creation produced a complete account lifecycle in telemetry:

- `4720` user account created (the disabled shell) - New UAC `0x211`, `Account Disabled`, Password Last Set `<never>`
- `4724` password reset attempt
- `4738` user account changed - Password Last Set now populated
- `4722` user account enabled - UAC `0x211 -> 0x210`
- `4738` user account changed - UAC `0x210 -> 0x10210`, plain text:
  `'Don't Require Preauth' - Enabled`

All events: actor (Subject) `NIKOLA\Administrator` (RID `-500`), target
`svc_legacy` (RID `-1111`), source `DC01`.

## Investigation Search

```spl
index=* host=DC01 ("svc_legacy" OR "Legacy App Service")
| table _time host EventCode Account_Name Account_Domain _raw
| sort - _time
```

## Field-Extraction Note

The flattened `Account_Name` column stacked two values (`Administrator` and
`svc_legacy`) because 4738-family events carry both a **Subject** (who made the
change) and a **Target** (who was changed). Which is which is read from `_raw`,
not the column. This actor-vs-target distinction recurs in every
account-management event.

## SOC Assessment

- **What it proves:** `svc_legacy` was created, enabled, and modified so Kerberos
  pre-authentication is no longer required (UAC `0x10210`), by `Administrator`.
  The account is now AS-REP roastable.
- **What it does not prove:** No attacker requested AS-REP material, no hash was
  captured, no password was cracked, the account was not compromised. The
  evidence is about exposure, not exploitation.
- **Why it could be malicious:** An attacker who can modify an account may
  disable pre-auth deliberately to make it roastable, then request AS-REP data
  offline for cracking.
- **Known lab context:** The change was made deliberately by the lab
  administrator to create the condition for study.

**Verdict:** Risky configuration documented; benign lab simulation.

**Production follow-up:** Confirm whether pre-auth-disabled is actually required
(it rarely is), re-enable it, rotate the service-account password, verify
ownership and privilege level, and monitor Kerberos AS-REQ activity (4768) for
the account.

---

# 6. Scenario 3 - Kerberoast-Relevant Service Ticket Request

## Activity Generated

On DC01 I created `svc_web` (compliant password on the first attempt) and
registered the SPN:

```text
HTTP/webapp.nikola.local
```

```powershell
setspn -S HTTP/webapp.nikola.local NIKOLA\svc_web
setspn -L NIKOLA\svc_web
```

From `DESKTOP-BN86O9N`, logged in as `NIKOLA\soc.analyst1`, I purged cached
tickets and requested a fresh service ticket for the SPN:

```cmd
klist purge
klist get HTTP/webapp.nikola.local
```

`klist get` reported the ticket cached successfully. The service ticket (#1 in
the cache) came back with encryption type **RSADSI RC4-HMAC(NT)**, `Kdc Called:
DC01.nikola.local`.

## Evidence Observed

- Service account: `svc_web` (SID RID `-1112`)
- SPN: `HTTP/webapp.nikola.local`
- Event ID: `4769`
- Requesting account: `soc.analyst1@NIKOLA.LOCAL`
- `Ticket_Encryption_Type: 0x17` (RC4-HMAC) - matches the `klist` output
- `Failure Code: 0x0` (ticket issued)
- Source: `Client Address: ::ffff:192.168.56.114` (in `_raw`)
- Source: `DC01`

## Investigation Search

```spl
index=* host=DC01 EventCode=4769 ("HTTP/webapp.nikola.local" OR "svc_web" OR "webapp")
| table _time host EventCode Account_Name Service_Name Ticket_Encryption_Type Ticket_Options src_ip _raw
| sort - _time
```

## Why the RC4 Ticket Matters

The `0x17` (RC4-HMAC) encryption type is the detail that makes this a realistic
Kerberoast scenario. RC4 service tickets are derived from the service account's
NTLM password hash and are far faster to crack offline than AES. Kerberoasting
attackers specifically request RC4 tickets for this reason. `svc_web` is a plain
user account with an SPN and no AES enforcement - the common real-world weak
configuration - which is why the ticket came back RC4. In a hunt, an analyst
filters 4769 for `Ticket_Encryption_Type=0x17` against service accounts for
exactly this combination.

## SOC Assessment

- **What it proves:** A Kerberos service ticket (4769) was requested for SPN
  account `svc_web` by `soc.analyst1` from `192.168.56.114`, issued with RC4
  (`0x17`). This is Kerberoast-relevant telemetry at the request stage.
- **What it does not prove:** No ticket was exported, no offline cracking
  occurred, no service-account password was recovered, nothing was compromised.
  A single 4769 is a request, not exploitation.
- **Why it could be malicious:** RC4 service tickets are crackable offline. The
  signature to watch is one user requesting many SPN tickets, especially RC4, in
  a short window.
- **Known lab context:** A single deliberate `klist get` against one lab SPN -
  not a burst across many SPNs.

**Verdict:** Kerberoast-relevant telemetry detected; benign lab simulation.

**Production follow-up:** Validate the requesting user and host; look for bursts
of 4769s across many distinct SPNs from one source; prioritize `0x17` (RC4)
requests; confirm whether the service account is privileged; search for
suspicious authentication or lateral movement after the request. Longer term,
set AES on service accounts and use gMSAs to reduce RC4 roasting viability.

---

# 7. Scenario 4 - Domain Admins Group Membership Change

## Activity Generated

On DC01, I added `test.employee1` to Domain Admins and removed it immediately,
creating a high-impact identity event with a known start and end state:

```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members test.employee1
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name
Remove-ADGroupMember -Identity "Domain Admins" -Members test.employee1 -Confirm:$false
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name
```

First membership list included `Test Test One` (the display name for
`test.employee1`); the second returned to `Administrator` only - confirming the
full add-then-remove cycle.

## Evidence Observed

- `4728` member added to a security-enabled global group - 14:54:37
- `4729` member removed from a security-enabled global group - 14:54:46
- **Membership window: ~9 seconds**
- Actor (Subject): `Administrator` (SID RID `-500`)
- Target (Member): `test.employee1` (SID RID `-1106`, resolved to full DN
  `CN=Test Test One,OU=Users,OU=SOC-Lab,DC=nikola,DC=local`)
- Group: `Domain Admins` (SID RID `-512`)
- Source: `DC01`

The `-1106` member SID matches `test.employee1` from the Scenario 1 events -
the SID-to-account correlation an analyst performs when the Member field
reports a SID rather than a friendly name.

## Investigation Search

```spl
index=* host=DC01 (EventCode=4728 OR EventCode=4729) "Domain Admins"
| table _time host EventCode Account_Name Account_Domain Group_Name Security_ID _raw
| sort - _time
```

## SOC Assessment

- **What it proves:** `Administrator` added `test.employee1` to Domain Admins at
  14:54:37 and removed it at 14:54:46 - a 9-second privileged window bracketed by
  4728/4729.
- **What it does not prove:** It does not show why the change was made, whether
  it was authorized, or whether the target did anything with the access during
  those 9 seconds. The events bound the window; they do not reveal its contents.
- **Why it could be malicious:** Domain Admins grants broad administrative
  control. Brief add/remove cycles are a known attacker pattern - elevate, act,
  clean up - to minimize the exposure window and evade point-in-time membership
  audits. The short duration makes it more worth checking, not less.
- **Known lab context:** Deliberate add-then-remove by the lab administrator; no
  privileged action was taken in between.

**Verdict:** High severity by potential impact; benign lab simulation by known
context.

**Production follow-up:** Validate an approved change record, confirm the actor
was authorized to modify Domain Admins, verify the removal completed, review the
target account's logons and activity during the membership window, and search
for administrative actions (new accounts, GPO changes, DCSync-style activity)
tied to that account in the same timeframe.

---

# 8. Scenario 5 - AD Enumeration and Reconnaissance

## Activity Generated

From `DESKTOP-BN86O9N` as `NIKOLA\soc.analyst1`, I ran domain discovery and
enumeration commands:

```text
whoami /all
nltest /domain_trusts
nltest /dsgetdc:nikola.local
setspn -T nikola.local -Q */*
```

## Evidence Observed (Final, Correct Capture)

- Host: `DESKTOP-BN86O9N`
- Source: Sysmon `Microsoft-Windows-Sysmon/Operational` channel
- Event ID `1` (Process Create) for `whoami.exe`, `nltest.exe` (×2), `setspn.exe`
- Event ID `22` (DNS Query) for `setspn.exe`'s LDAP SRV lookups
- `User: NIKOLA\soc.analyst1`, `IntegrityLevel: Medium` (standard, non-elevated)
- `ParentImage: powershell.exe`, `ParentUser: NIKOLA\soc.analyst1`
- Full `CommandLine` captured for every process, including `setspn -T nikola.local -Q */*`

## Investigation Search

```spl
index=* host=DESKTOP-BN86O9N earliest=-15m ("whoami" OR "nltest" OR "setspn" OR "domain_trusts")
| table _time host EventCode Image CommandLine ParentImage User _raw
| sort - _time
```

## Commands Failed - Evidence Still Complete

In the final capture several commands failed to return data:
`nltest /dsgetdc` returned `1355 ERROR_NO_SUCH_DOMAIN`, and `setspn` returned
`0x51 Server Down / ldap_connect`. The Sysmon Event 22 records show the reason -
DNS queries for `_ldap._tcp.nikola.local` returned `QueryStatus 9003` (name
resolution failure) from that shell. These are the RPC/LDAP/DNS failures the
lab has hit before.

Crucially, the process-creation evidence is complete regardless: Event 1
captured the full command line and process tree for each attempt. This is the
core Scenario 5 lesson made literal - a command can fail to retrieve data and
still produce full, security-relevant endpoint evidence. An analyst sees the
intent (a standard user running domain-trust and SPN enumeration) whether or not
the commands succeeded. Event 1 shows the command; Event 22 corroborates the
failed resolution behind it.

## Link Back to Scenario 3

`setspn -T nikola.local -Q */*` is forest-wide SPN enumeration - the
reconnaissance step that precedes Kerberoasting. In the first (admin-context)
run that did resolve, the output listed `CN=svc_web ... HTTP/webapp.nikola.local`
among the domain SPNs. That is the exact Kerberoast target from Scenario 3,
making Scenario 5's recon and Scenario 3's ticket request two stages of one
attack chain.

## SOC Assessment

- **What it proves:** A standard (Medium integrity) user, `soc.analyst1`,
  executed user-context, domain-trust, DC-location, and forest-wide SPN
  enumeration from `DESKTOP-BN86O9N`, all parented to `powershell.exe`. Full
  command-line and process-tree evidence exists even though several commands
  failed.
- **What it does not prove:** No compromise, credential theft, or follow-on
  action. Discovery commands are reconnaissance signals, not exploitation.
- **Why it could be malicious:** This command set is textbook early AD
  reconnaissance, and the `setspn` enumeration specifically is how an attacker
  finds service accounts to Kerberoast.
- **Known lab context:** Deliberately run by the analyst; standard-user account,
  isolated lab, no follow-on exploitation.

**Verdict:** Suspicious by behavior, benign by controlled lab context.

**Production follow-up:** Validate the user's role and whether this fits their
job; inspect the parent process and full session; enumerate all related commands
in the window; hunt for follow-on activity - 4769 requests (especially RC4) from
the same user/host, privileged group changes, PowerShell download/execution, or
lateral movement.

---

# 9. Troubleshooting and How I Fixed It

## 9.1 Password Complexity Blocked `svc_legacy` Creation (and left a shell)

The first `New-ADUser` for `svc_legacy` failed with
`ADPasswordComplexityException` because the password was too short. The failure
did not cleanly abort - it left a **disabled, passwordless account shell**,
which caused the next two attempts to fail with "already exists".

**Fix:** Rather than re-create, I verified the real state with `Get-ADUser`
(`Enabled : False`), then finished configuring the existing object:
`Set-ADAccountPassword` (compliant password) -> `Enable-ADAccount` ->
`Set-ADAccountControl -DoesNotRequirePreAuth $true`. The two-step creation also
produced a more complete telemetry trail (4720/4724/4738/4722/4738). Lesson:
when an account "already exists" unexpectedly, confirm its actual state before
assuming creation failed outright.

## 9.2 Workstation Would Not Boot (Host RAM)

The Windows 10 VM crashed on start while DC01, Splunk, and host apps were all
open - the same host-memory exhaustion as Phase 10 (Kernel-Power / 90%+ host
RAM).

**Fix:** Sequenced VMs to the two needed per step and closed host-side apps.
Confirmed the forwarder/queue model means shutting a source VM after its events
are forwarded does not lose data - events already on `splunk-soc` persist
independently of the source.

## 9.3 Scenario 5 Telemetry Missing From Splunk - Sysmon `current_only = 1`

After running the Scenario 5 commands, the endpoint search returned zero events.
A broad check (`stats count by host`, then any `*Sysmon*`/4688 across the whole
deployment) returned nothing, confirming no process-creation telemetry was
reaching Splunk from any host - a data-path fault, not a search error.

Diagnosis, in order (Section 8 discipline - source/host, then config, then path):

1. Confirmed the search host string was the real hostname (letter `O`, not zero)
   - a broad no-host search still returned nothing, so not a typo.
2. On the workstation, `.\splunk status` showed `SplunkForwarder: Running` - the
   service was alive, so not a dead forwarder. (Note: `splunk` had to be run as
   `.\splunk` - PowerShell does not run programs from the current directory
   without the prefix. CLI login also failed because the webapp/Enterprise
   credentials are a separate store from the forwarder's own admin account.)
3. Read the config files directly (no login needed):
   - `outputs.conf` destination `192.168.56.117:9997`. Verified `splunk-soc`'s
     current host-only IP is still `192.168.56.117` with `ip addr` - so the
     destination was correct and DHCP drift was ruled out. (The other channels -
     Security/System/Application - were forwarding fine, consistent with all
     DC01 scenarios working.)
   - `inputs.conf` Sysmon stanza had `current_only = 1`, while
     Security/System/Application had `current_only = 0`. **Root cause:** with
     `current_only = 1`, the forwarder ships only events written while it is
     actively watching and does not read back events generated before that watch
     window. The commands had been run before the forwarder's current window
     (across the boot/crash/restart churn), so those Sysmon events were skipped.

**Fix:** Re-generated the activity live, with the forwarder already running and
watching. The new events were inside the watch window and forwarded
immediately. (The config-level alternative - setting `current_only = 0` on the
Sysmon stanza so it backfills - was noted but not needed; regenerating in the
correct window is the lower-risk fix and matches the guide's approach of
producing the activity in the right conditions rather than re-engineering
collection.)

## 9.4 Scenario 5 Captured Under the Wrong Actor (Elevated Shell)

The first *successful* capture showed `User: NIKOLA\Administrator`,
`IntegrityLevel: High` - the PowerShell window was elevated, not the standard
`soc.analyst1` the scenario models. Scenario 5's point is a *standard* user
running recon unexpectedly; admin recon is far more routine, so the actor
materially changes the finding.

**Fix:** Opened a new non-elevated shell as the standard user
(`runas /user:NIKOLA\soc.analyst1 powershell`) and re-ran. The final capture
shows `User: NIKOLA\soc.analyst1`, `IntegrityLevel: Medium` - the correct actor.
Both runs remain in the index, which is itself a useful contrast (identical
commands, two integrity levels, two actors). Lesson: verify the shell's user
context before generating actor-sensitive telemetry - confirm with the first
line of `whoami` (SID RID `-1104` vs `-500`) before trusting the capture.

## 9.5 General Lesson

When an expected event is missing, verify in order:

1. The correct data source and host (and exact host spelling).
2. That the service/forwarder is actually running.
3. The forwarding destination (and whether a DHCP-drifted IP broke it).
4. The input configuration - including `current_only`, which silently skips
   pre-existing events even when the channel is enabled and the pipeline is
   healthy.
5. The audit policy required to create the event (ruled out in pre-flight here).
6. The search time range.
7. The raw event before relying on normalized fields.

---

# 10. Analyst Decision Framework Used

For each scenario, I answered the same questions:

1. What activity occurred?
2. Which user, host, account, service, or group was involved?
3. What does the evidence directly prove?
4. What does the evidence not prove?
5. Why could the behavior be malicious?
6. What known lab context explains it?
7. What would a production SOC validate next?
8. Should the event be closed, monitored, tuned, or escalated?

This prevented the write-up from treating every suspicious event as a confirmed
incident, and it kept the actor/context caveats (Scenario 5) explicit rather
than hidden.

---

# 11. SOC Mini-Tickets

Two scenarios were written up as formal analyst tickets in the Phase 10 style.

## Mini-Ticket 01 - Possible Password Spray

**Title:** Multiple Kerberos Pre-Authentication Failures Across Several Users
From One Source
**Severity:** Medium
**Event source:** DC01 Security Log forwarded into Splunk
**Event ID:** `4771` - Kerberos pre-authentication failed

**Evidence:** DC01 recorded seven 4771 failures within roughly five minutes
against three accounts - `soc.analyst1`, `helpdesk.user1`, and `test.employee1`
- all with failure code `0x18` (bad password) and all originating from
`Client Address 192.168.56.114` (`DESKTOP-BN86O9N`). The source was read from
the raw event because 4771 does not populate `src_ip` by default.

**Assessment:** One source failing authentication across multiple accounts in a
short window is the defining shape of a password spray. The targeted accounts
include a standard user, a helpdesk account, and a SOC analyst account; none
showed a subsequent successful logon in the window. The source is the known
domain-joined workstation, and the activity matches deliberate controlled
testing - but the pattern itself is exactly what should be investigated before
that context is confirmed.

**Decision:** Close as benign lab activity.

**Production follow-up:**
- Confirm the source host and its owner via DHCP lease / asset records at the
  event timestamps.
- Count all accounts targeted from that source across a wider window to size the
  spray.
- Flag whether any targeted account is privileged.
- Check for any successful Kerberos TGT/service ticket (`4768`/`4769`) from the
  source shortly after the failures.
- Correlate with MFA / identity-provider logs for the same accounts.

## Mini-Ticket 02 - Domain Admins Membership Change

**Title:** `test.employee1` Added To and Removed From Domain Admins Within 9
Seconds
**Severity:** High
**Event source:** DC01 Security Log forwarded into Splunk
**Event ID:** `4728` (add) / `4729` (remove) - security-enabled global group

**Evidence:** DC01 recorded `NIKOLA\Administrator` (SID `-500`) adding
`test.employee1` (SID `-1106`) to `Domain Admins` (SID `-512`) at 14:54:37, then
removing the same account at 14:54:46 - a ~9-second membership window.

**Assessment:** Any Domain Admins membership change is high-impact because it can
grant complete administrative control of the domain. The brief add/remove window
is notable: it is both a plausible automated/administrative pattern and a known
attacker technique (elevate, act, clean up) designed to evade point-in-time
membership audits. The short duration raises, not lowers, the need to determine
what happened during the window. Here the actor is the known top-level admin and
the context is controlled lab testing, but the event type must remain fully
visible rather than suppressed so an unauthorized actor performing the same
change later would still stand out.

**Decision:** Close as benign lab activity.

**Production follow-up:**
- Confirm the change matches an approved change/access request.
- Verify the actor was authorized to modify Domain Admins specifically.
- Confirm the removal actually completed (membership returned to baseline).
- Review the target account's logons and any privileged actions during the
  9-second window (new accounts, GPO changes, DCSync-style replication).
- Review the actor account's other recent activity for anything inconsistent
  with normal admin behavior.

---

# 12. Interview-Ready Summary

In Phase 11, I used my Active Directory lab to simulate and investigate five
identity-focused security scenarios. I generated password-spray-style failed
authentication, created an AS-REP roastable service account, generated
Kerberoast-relevant service-ticket telemetry, performed a controlled Domain
Admins membership change, and ran AD enumeration commands from a domain
workstation. I investigated the activity in Splunk using DC01 Windows Security
events (4771, 4720/4722/4724/4738, 4769, 4728, 4729) and Sysmon endpoint
telemetry (Event 1 process creation, Event 22 DNS query). For each scenario I
documented what the evidence proved, what it did not prove, severity, likely
false-positive context, and what a real SOC would validate before escalation or
closure. I also diagnosed a real pipeline fault - a Sysmon forwarder input set
`current_only = 1` that silently skipped pre-existing events - and corrected a
capture that had been generated under the wrong user context, which is itself a
lesson in validating actor and integrity level before trusting telemetry.

---

# 13. Phase 11 Outcome

Phase 11 is complete.

I can now:

- Recognize password-spray patterns in domain authentication telemetry (4771,
  `0x18`, one source / many accounts).
- Explain the risk of an AS-REP roastable account (`DoesNotRequirePreAuth`,
  UAC `0x10210`) without claiming compromise.
- Investigate Kerberoast-relevant Event 4769 activity and explain why the RC4
  (`0x17`) encryption type matters.
- Triage privileged group membership changes using 4728/4729 and resolve actor
  vs target vs group by SID (`-500` / `-1106` / `-512`).
- Review AD discovery commands using Sysmon process and command-line evidence,
  including when the commands themselves failed.
- Separate suspicious behavior from a confirmed security incident.
- Diagnose a telemetry gap down to a specific forwarder input setting rather than
  assuming an attack technique failed to generate evidence.
- Write evidence-safe verdicts and practical production follow-up steps.

## Up Next

**Phase 12 - Endpoint / EDR Investigation with Wazuh, Sysmon, and
Defender-Style Telemetry**

The next phase shifts from domain identity events to process trees, device
timelines, persistence evidence, endpoint scoping, and containment decisions.
The `current_only` lesson from this phase carries directly into Phase 12: before
concluding an endpoint technique produced no evidence, confirm the collecting
channel is both enabled and configured to ship the events in question.
