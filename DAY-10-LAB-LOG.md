# Phase 10 Detailed Lab Log - Active Directory Environment and Splunk Visibility

## Status

**Track 3 - Endpoint and Identity Investigation**

## Completion Summary

Phase 10 established the identity foundation for the next part of the SOC
roadmap. I built a working Active Directory lab with a Windows Server 2022
domain controller, private lab DNS, realistic organizational units, users, and
security groups. I joined the existing Windows 10 victim endpoint to the
domain, validated domain authentication, and forwarded DC01 Windows event logs
into Splunk for centralized identity investigation.

This build surfaced significantly more real-world troubleshooting than
expected - an expired evaluation license, a stuck virtual network adapter, a
hidden file extension, a stale DHCP-assigned IP, host memory exhaustion, a
silent Kerberos time-skew failure, and a missing audit policy setting. Each is
documented in Section 12.

### Final Deliverables

| Requirement | Result |
|---|---|
| Domain controller | Windows Server 2022 host `DC01` |
| Lab domain | `nikola.local` |
| Domain services | Active Directory Domain Services and DNS |
| AD organization | `SOC-Lab`, `Users`, and `Workstations` OUs |
| Lab identities | Three domain users and three security groups |
| Domain endpoint | Windows 10 victim (`DESKTOP-BN86O9N`) joined to `nikola.local` |
| Authentication validation | Successful login as `NIKOLA\soc.analyst1` |
| Centralized logging | DC01 event logs forwarded into Splunk |
| Identity events reviewed | 4771, 4776, 4728, 4624, 4634, 4672, 4625 |
| Analyst documentation | Two SOC-style mini-tickets |

---

# 1. Objective

The goal was to move from standalone endpoint monitoring into an
enterprise-style identity environment.

```text
Build domain services
  -> Create realistic identities
  -> Join a managed endpoint
  -> Centralize domain controller logs
  -> Generate controlled identity events
  -> Investigate the evidence in Splunk
  -> Write defensible analyst conclusions
```

The core question for this phase was:

```text
Can I build the identity infrastructure, confirm where authentication evidence
lives, and investigate that evidence without overclaiming what happened?
```

---

# 2. Lab Architecture

Only the systems required for the Active Directory build were powered on at
any one time. Elastic, Wazuh, and Kali remained off throughout, and - after
host memory pressure caused a genuine VM crash (Section 12) - DC01, the
Windows 10 client, and splunk-soc were deliberately sequenced rather than all
run simultaneously for most of the build.

| System | Role | Lab address (at time of use) |
|---|---|---|
| `DC01` | Windows Server 2022 domain controller and DNS | `192.168.56.10` (static) |
| `DESKTOP-BN86O9N` | Windows 10 domain-joined victim endpoint | `192.168.56.114` (DHCP, host-only) |
| `splunk-soc` | Splunk Enterprise server and forwarder receiver | `192.168.56.117` (DHCP, host-only) |

Host: AMD Ryzen 7 5800X, 16 GB RAM. DC01 was allocated 4096 MB RAM / 2 vCPU.

The VirtualBox design used:

- A host-only adapter for isolated lab communication.
- A NAT adapter when internet access was required.
- Static addressing for the domain controller; DHCP-assigned addressing for
  the client and Splunk server (confirmed to **change between sessions** -
  see Section 12).
- DC01 as the DNS server for the domain-joined Windows client.

---

# 3. Windows Server and Domain Controller Deployment

## Server Preparation

Created a Windows Server 2022 VM in VirtualBox (Desktop Experience edition)
and prepared it for domain services:

- Renamed the server to `DC01` before installing any roles.
- Configured host-only (`Ethernet 2`) and NAT (`Ethernet`) networking,
  identified by comparing DHCP-assigned ranges with `ipconfig /all`.
- Assigned the host-only interface the static IP `192.168.56.10`, subnet
  `255.255.255.0`, DNS `127.0.0.1`.

## Active Directory Domain Services

Installed Active Directory Domain Services, promoted DC01 to a domain
controller, and created the private lab domain:

```text
nikola.local
```

DNS was installed with the domain controller because domain clients depend on
AD-integrated DNS to locate domain services.

## Validation

```powershell
hostname
whoami
Get-ADDomain
```

Confirmed: `hostname` = `DC01`; `whoami` = `nikola\administrator`;
`Get-ADDomain` returned `DNSRoot: nikola.local`, `NetBIOSName: NIKOLA`.

---

# 4. Active Directory Organization and Identity Objects

## Organizational Units

```text
nikola.local
└── SOC-Lab
    ├── Users
    └── Workstations
```

## Domain Users

| User | Intended role |
|---|---|
| `soc.analyst1` | SOC analyst account used for domain-login validation |
| `helpdesk.user1` | Help desk identity used for group-membership testing |
| `test.employee1` | Standard employee identity used for failed-login testing |

## Security Groups

- `SOC Analysts` (member: `soc.analyst1`)
- `Helpdesk` (member: `helpdesk.user1`)
- `IT Admins` (left empty initially - membership change generated later as
  deliberate, logged evidence for Mini-Ticket 02)

---

# 5. Windows 10 Domain Join and Authentication Validation

Pointed the Windows 10 host-only adapter's DNS at `192.168.56.10`, validated
with `ping` and `nslookup nikola.local` (direct server query required once -
see Section 12 for adapter-priority troubleshooting), then joined the
endpoint to `nikola.local`.

Validated domain authentication as `NIKOLA\soc.analyst1` via `whoami`. Moved
the resulting computer object from the default `Computers` container into
`SOC-Lab\Workstations`.

---

# 6. Splunk Universal Forwarder on DC01

Installed Splunk Universal Forwarder on DC01, transferred via the
`\\192.168.56.10\c$` share from the Windows 10 VM (DC01's NAT adapter was
non-functional at install time - see Section 12). Configured the Receiving
Indexer during setup, then corrected it post-install after discovering
splunk-soc's actual IP had changed (Section 12).

Created `inputs.conf` enabling:

- Windows Security
- Windows System
- Windows Application
- Directory Service
- DNS Server

Validated in Splunk:

```spl
index=* host=DC01 | stats count by sourcetype
```

| sourcetype | count |
|---|---|
| WinEventLog:Security | 8,778 |
| WinEventLog:System | 2,372 |
| WinEventLog:Application | 570 |
| WinEventLog:Directory Service | 138 |
| WinEventLog:DNS Server | 57 |

---

# 7. SPL Searches Used

```spl
index=* host=DC01
```
```spl
index=* host=DC01 (EventCode=4771 OR EventCode=4776)
```
```spl
index=* host=DC01 EventCode=4771
```
```spl
index=* host=DC01 (EventCode=4771 OR EventCode=4728)
```
```spl
index=* host=DC01 | sort -_time | head 20
```

---

# 8. Case 1 - Kerberos Pre-Authentication Failure

## Summary

Generated and investigated a controlled failed-logon event for
`test.employee1` against the domain, confirming where domain authentication
failure evidence actually lives (the domain controller, not the client) and
what conditions are required for it to be logged at all.

## Mini-Ticket 01 - Failed Kerberos Authentication

**Title:** Failed Kerberos Authentication for `NIKOLA\test.employee1`
**Severity:** Low
**Event source:** DC01 Security Log forwarded into Splunk
**Event ID:** `4771` - Kerberos pre-authentication failed

**Evidence:** DC01 recorded a Kerberos pre-authentication failure for
`test.employee1`. The event identified service `krbtgt/NIKOLA`, client
address `192.168.56.114`, and failure code `0x18`, consistent with an
incorrect password attempt.

**Assessment:** The failure originated from `192.168.56.114`, the known
domain-joined workstation `DESKTOP-BN86O9N`, not an external or unrecognized
host. `test.employee1` is a standard test account with no elevated
privileges. Volume was low, consistent with expected incorrect-password
testing rather than a brute-force pattern.

**Decision:** Close as benign lab activity.

**Production Follow-Up:** In a real SOC, I would:
- Confirm whether the user had already reported password issues or opened a
  related ticket.
- Review a wider time window for repeated failures from the same account.
- Check for a subsequent successful Kerberos ticket issuance (`4768`/`4769`)
  for the account shortly after the failure.
- Confirm the source IP genuinely maps to the expected workstation via DHCP
  lease logs (MAC address/hostname at that timestamp).
- Check for suspicious activity following any successful authentication.

---

# 9. Case 2 - Privileged Group Membership Change

## Summary

Generated and investigated a controlled privileged-group membership change
(`helpdesk.user1` added to `IT Admins`), reasoning through why an event type
can remain security-significant even when the specific instance is known to
be authorized.

## Mini-Ticket 02 - Privileged Group Membership Change

**Title:** Privileged Group Membership Change - `helpdesk.user1` Added to
`IT Admins`
**Severity:** Medium
**Event source:** DC01 Security Log forwarded into Splunk
**Event ID:** `4728` - member added to a security-enabled global group

**Evidence:** DC01 recorded `NIKOLA\Administrator` adding `helpdesk.user1` to
the `IT Admins` group.

**Assessment:** The change was performed by the domain's top-level
Administrator account, not an unexpected or lower-privileged actor. Group
membership changes affecting privileged-access groups are always worth
reviewing regardless of who makes them, since they directly affect what a
compromised or misused account could do - but in this case the actor is known
and the context (controlled lab testing) is already confirmed. The addition
itself is exactly the kind of high-value event that should stay visible even
when classified as expected, rather than suppressed, so that a similar change
by an unrecognized actor would still stand out later.

**Decision:** Close as benign lab activity.

**Production Follow-Up:** In a real SOC, I would:
- Confirm the change matches an approved change ticket or access request.
- Verify `helpdesk.user1` actually requires `IT Admins` membership for their
  role, rather than assuming the request was appropriate.
- Review the `Administrator` account's other recent activity (logon times,
  source hosts) for anything inconsistent with normal admin behavior.
- Check whether any other group or account modifications occurred around the
  same time, which could indicate broader unauthorized changes.
- If the access is temporary or test-only, confirm a plan exists to remove it
  afterward.

---

# 10. Detection and Tuning Reasoning

Built a context-aware investigation approach using Event ID `4728` to
identify accounts added to the local `Administrators`/`IT Admins` group. The
reasoning was designed to:

- Identify privileged group membership additions.
- Extract event time, host, actor account, member added, and affected group.
- Classify known lab validation activity rather than suppressing the event
  type outright.
- Preserve full visibility for analyst review regardless of actor.

**Tuning decision:** Known lab activity was classified rather than
suppressed. Local administrator/privileged-group membership changes are
high-value security events; a broad exclusion could create a blind spot if
similar behavior occurred later outside the lab context - see Interview
Defense, Question 1.

---

# 11. Interview Defense

## Why local administrator additions should stay visible even when known lab test activity is classified

> Classifying is different from suppressing. If I build a broad exclusion for
> "anything added to Administrators," I've disabled visibility into that
> event type entirely - not just for my test today, but permanently. An
> attacker who gets a foothold could add their own account the same way, and
> it would never surface, because the rule itself is blind to it now.
> Classifying the known test activity instead keeps the event visible and
> labeled, so unexpected additions still stand out.

## Why unsupported telemetry paths should be documented honestly instead of overclaimed

> A failed login only tells me an authentication attempt was denied - it
> doesn't tell me anything about what happened on the endpoint before or
> after. If I wanted to know what the user actually did on that workstation,
> I'd need to go check the workstation's own logs, not DC01's - things like
> process creation events. DC01 only has visibility into the authentication
> path itself. I wouldn't speculate past what the evidence actually covers.

## How the work maps to SOC L1 analyst responsibilities

> Identity access management matters because once an account is compromised,
> it can be used for lateral movement across systems - often a quieter and
> more effective path than malware. That's why L1 analysts spend so much time
> on authentication events like `4771` and `4625`: they're the earliest
> signal that something's wrong with an account, before it escalates into
> something bigger. Even when I recognize the account or the actor, like with
> the `helpdesk.user1` group change today, I still verify the context rather
> than assuming it's fine just because it's familiar - that's what keeps a
> known actor from becoming a blind spot.

---

# 12. Troubleshooting and Lessons Learned

This phase's actual build surfaced significantly more real troubleshooting
than a reference guide would anticipate. Each is documented below in the
order encountered.

## Windows Server Evaluation License Expired Mid-Build

DC01 powered itself off twice without warning while troubleshooting unrelated
networking issues. `Get-WinEvent` against the System log identified the
actual cause: the process `wlms.exe` (Windows License Manager Service) had
initiated a planned shutdown because the Windows Server Evaluation license's
grace period had expired. This looked at first like a crash or resource
problem, but was unrelated - a fresh VM's evaluation clock had simply run out
faster than expected.

The fix was a single command: `slmgr /rearm`, followed by a restart. This
reset the license into a new grace period (confirmed via `slmgr /dlv`, which
showed "Initial grace period" with 10 days remaining and a decremented rearm
count).

**Lesson:** An evaluation-licensed VM can force a shutdown with no visible
error beyond a generic power-off, so a silent VM shutdown isn't automatically
a crash or a resource issue - the System event log (`wlms.exe`, "license
period has expired") distinguishes license-driven shutdowns from genuine
faults before any deeper networking or hardware troubleshooting is
warranted. Rearm count is finite, so this needs tracking over a build that
spans many sessions.

## DC01's NAT Adapter Lost Connectivity After Promotion

After promoting DC01 to a domain controller and later power-cycling the VM,
the NAT adapter (`Ethernet`) could no longer reach its own gateway
(`10.0.2.2`) - `ping` and `Test-NetConnection` both failed, even though
`Get-NetAdapter` showed the interface as `Up` and the routing table and IP
configuration looked correct. Before looking at the adapter itself, DC01's
DNS forwarder setting was checked and confirmed already correctly configured
(pointing at `10.0.2.3`, auto-populated from before promotion), ruling out
DNS as the cause. ARP resolution for the gateway returned nothing at all
(`Get-NetNeighbor` showed an `Incomplete` entry), which pointed to a
lower-level adapter problem rather than a configuration issue. Since the
Windows 10 VM on the same host-only/NAT setup had working internet access at
the same time, the problem was isolated to DC01's own virtual NIC state
rather than the host or VirtualBox's NAT engine generally.

The fix was a full VM power-cycle (shutdown, not just OS restart) rather than
disabling/re-enabling the adapter in Windows, which had already been tried
and hadn't worked.

**Lesson:** A network adapter showing `Up` with a correct IP and routing
table doesn't guarantee a working link - ARP resolution is a lower-level
check that can reveal a stuck virtual NIC state invisible to `ipconfig`.
Ruling out DNS and comparing against a second VM on the same virtual network
helped narrow down the actual cause before assuming the problem was unique to
DC01.

## Splunk Forwarder Had a Destination but No Inputs

After installing Splunk Universal Forwarder on DC01 and correctly configuring
the receiving indexer, DC01's own internal/metrics logs (`index=_internal`)
appeared in Splunk, but no Windows Event Logs (`index=*`) did - confirming
the forwarder could reach the receiver but wasn't sending any Windows log
data. An `inputs.conf` file was created in `etc/system/local/` to enable
collection of Security, System, Application, Directory Service, and DNS
Server logs, but after a service restart, still nothing appeared.

Checking the file listing in File Explorer revealed the cause: the file's
**Type** column showed "Text Document" instead of "CONF File" like the other
config files in the same folder - Notepad had silently appended a `.txt`
extension, so the actual file on disk was `inputs.conf.txt`, which Splunk
never reads. Renaming it to the correct `inputs.conf` and restarting the
service fixed it immediately - all five log sources began appearing within a
minute.

**Lesson:** Notepad can silently add a `.txt` extension when saving a file
with no extension typed into the Save dialog, and Windows Explorer hides file
extensions by default, making the mistake invisible unless the **Type**
column (or "File name extensions" view option) is checked. A forwarder
having a correct output destination but no configured inputs is a distinct
failure mode from a connectivity problem - "can reach the receiver" and "has
something to send" need to be verified separately.

## Forwarder Pointed at a Stale Splunk Receiver IP

After fixing the `inputs.conf` issue, the forwarder was correctly sending
data, but `index=* host=DC01` still returned nothing in Splunk's web UI - and
the Splunk web page itself timed out when loaded at the IP used during the
original forwarder installation (`192.168.56.102`). Checking splunk-soc's
actual network configuration (`ip a`) showed its host-only adapter had a
different, DHCP-renewed address (`192.168.56.117`) than the one used when the
forwarder was first configured.

The forwarder's `outputs.conf` still had the old `192.168.56.102` address
hardcoded in two places - the `server` line and the
`[tcpout-server://...]` stanza. Editing both to the correct `192.168.56.117`
and restarting the forwarder service resolved it; DC01's events appeared in
Splunk within about a minute.

**Lesson:** VirtualBox host-only network DHCP leases aren't guaranteed to
stay fixed across VM reboots, so a server's IP address used in one session
isn't safe to assume as permanent in the next - always verify with
`ip a`/`ipconfig` rather than reusing a remembered value. A forwarder's
`outputs.conf` has the destination IP listed in two separate places, and both
need updating together.

## Host Memory Exhaustion Caused Genuine VM Crashes

DC01 powered off unexpectedly twice within about 20 minutes, separate from
the earlier license-related shutdown. `Get-WinEvent` showed Kernel-Power
Event 41 ("the system has rebooted without cleanly shutting down first...
stopped responding, crashed, or lost power unexpectedly") - a genuine abrupt
failure, not an orderly shutdown like the license issue. At the time, the
host machine's Task Manager showed memory usage at 92%+ with DC01, the
Windows 10 VM, and several host-side browser tabs all running simultaneously.

Shutting down unnecessary host applications and reducing the number of VMs
running at once (keeping only the two actually needed for the current step)
brought memory usage down to a safe range, and no further crashes occurred
afterward.

**Lesson:** Event 41 combined with high host memory pressure points to the
hypervisor/host starving a VM, not a problem inside the guest OS - worth
checking host Task Manager before troubleshooting networking or
configuration issues inside a VM that's behaving erratically. This also
validates the instruction to keep unused lab VMs (Elastic, Wazuh, Kali)
powered off during this phase - it's not just a convenience, it's what keeps
the build stable on constrained hardware.

## Wrong Time Zone Caused Silent Kerberos Authentication Failures

A deliberate failed-login test (`test.employee1` with a wrong password,
repeated multiple times) produced the expected on-screen "incorrect password"
error on the Windows 10 client, but generated no corresponding evidence at
all on DC01 - no `4771`, `4776`, or `4625` for that account, even though the
domain secure channel (`nltest /sc_query`), DNS resolution, and all relevant
ports (88, 389, 445) were all confirmed healthy. `Get-Date` on DC01 and on
the Windows 10 client revealed both machines' clocks were roughly three hours
apart from real-world time and from each other; `Get-TimeZone` showed both
had been left on `Pacific Standard Time` from the OS install defaults rather
than the actual local time zone.

Correcting both machines' time zones with
`Set-TimeZone -Id "Eastern Standard Time"` resolved the clock skew
immediately (no reboot needed, since the underlying UTC clock had been
correct all along - only the displayed local time zone was wrong).

**Lesson:** Kerberos authentication silently rejects requests when client and
domain-controller clocks differ by more than roughly 5 minutes, and this
failure can look exactly like "nothing happened" rather than producing an
obvious error - no event is logged on the DC side at all for a client whose
clock is too far out of sync to even start a valid exchange. A wrong time
zone is easy to overlook because `Get-Date` alone can look locally
self-consistent on each machine; comparing clocks *between* machines, not
just checking each one individually, is what actually surfaces this class of
problem.

## DC01's Audit Policy Only Logged Successful Authentication, Not Failures

Even after correcting the time zone mismatch, a repeated and controlled
failed-login test (using `runas /user:NIKOLA\test.employee1`, confirmed
failing with error `1326`) still produced no `4771` or `4776` events on DC01,
while successful logons for other accounts continued to appear normally.
`auditpol /get /subcategory:"Kerberos Authentication Service"` and
`auditpol /get /subcategory:"Credential Validation"` both showed `Success`
only - failure auditing for these two specific subcategories had never been
enabled, despite the general "Logon" subcategory on the Windows 10 client
showing `Success and Failure` correctly.

Running
`auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable`
and the equivalent command for `Credential Validation` enabled failure
logging immediately; the next failed authentication attempt produced a clean
`4771` event with the expected failure code (`0x18`).

**Lesson:** Windows Server's default audit policy does not uniformly enable
failure auditing across every authentication-related subcategory - "Logon"
auditing being correctly configured on a client doesn't guarantee "Kerberos
Authentication Service" or "Credential Validation" auditing is equally
configured on the domain controller, since these are separate,
independently-toggleable subcategories under Account Logon. When an event
type that should exist (per documentation or a guide) never appears despite
confirmed-working connectivity, time sync, and a genuinely failing
authentication, the audit policy itself - not the network path - is worth
checking directly with `auditpol /get`.

---

# 13. Skills Practiced

- Windows Server 2022 deployment in VirtualBox
- Active Directory Domain Services installation and domain controller
  promotion
- AD-integrated DNS dependency awareness and forwarder configuration
- Static vs. DHCP IP planning across domain services
- OU, user, and security group administration
- Windows domain join configuration and troubleshooting (DNS, adapter
  priority, network profile/firewall category)
- Domain authentication validation
- Splunk Universal Forwarder configuration on a domain controller
- Windows Security, Directory Service, and DNS Server log collection
- SPL searches for identity events
- Kerberos pre-authentication failure interpretation
- Privileged security group change investigation
- Evidence-safe severity and verdict reasoning
- SOC ticket documentation and production follow-up planning
- **Windows evaluation license diagnosis and rearming**
- **VirtualBox virtual NIC / ARP-level network troubleshooting**
- **Host resource management and VM crash root-cause analysis (Kernel-Power
  Event 41)**
- **Kerberos time-sensitivity diagnosis across client and domain controller
  clocks**
- **Windows audit policy (`auditpol`) configuration for Account Logon
  subcategories**
- **Distinguishing domain-controller identity evidence from endpoint-local
  evidence, and knowing when a symptom's absence points to configuration
  rather than connectivity**

---

# 14. SOC and Interview Mapping

Phase 10 provides practical evidence that I can explain and investigate
enterprise identity fundamentals - and, unusually, provides an equally strong
set of real troubleshooting stories across licensing, networking, logging,
resource management, and authentication timing.

## Interview Summary

> I built an Active Directory lab with a Windows Server domain controller,
> DNS, domain users, groups, OUs, and a domain-joined Windows client. I
> configured the client to use the domain controller for DNS, validated
> domain login, and forwarded DC01 Security logs into Splunk with Universal
> Forwarder. Along the way I diagnosed and fixed an expired evaluation
> license, a stuck virtual network adapter, a hidden file extension that
> silently broke log collection, a stale DHCP-assigned receiver IP, host
> memory exhaustion that was crashing the VM, and - the most instructive one
> - a Kerberos authentication failure that produced zero evidence on the
> domain controller, which I traced through DNS, the secure channel, port
> connectivity, and clock synchronization before finding the actual cause: a
> wrong time zone combined with a domain controller audit policy that only
> logged successful authentication, not failures. I investigated the
> resulting Kerberos pre-authentication failure and a privileged group
> membership change using events 4771 and 4728, and wrote evidence-based
> verdicts for both. The main lesson was that domain identity evidence lives
> on the domain controller, endpoint behavior lives on the client, and an
> event that *should* exist but doesn't is itself a diagnostic clue pointing
> at configuration, not just connectivity.

---

# 15. Scope Boundaries

Phase 10 did **not** claim completion of advanced Active Directory attack
simulation. The following are reserved for later phases:

- Password spraying at attack-simulation scale
- Kerberoasting
- AS-REP roasting
- BloodHound collection and attack-path analysis
- Pass-the-Hash
- DCSync
- Group Policy abuse
- Credential dumping
- EDR investigation of identity-driven endpoint compromise

---

# 16. Completion Checklist

| Requirement | Status |
|---|---|
| Windows Server 2022 VM deployed | Complete |
| Server renamed to DC01 | Complete |
| Stable host-only IP configured | Complete |
| Active Directory Domain Services installed | Complete |
| DC01 promoted to domain controller | Complete |
| `nikola.local` domain and DNS operational | Complete |
| SOC-Lab, Users, and Workstations OUs created | Complete |
| Domain users created | Complete |
| Security groups created | Complete |
| Windows 10 endpoint joined to domain | Complete |
| Domain authentication validated | Complete |
| Computer object moved to Workstations OU | Complete |
| Splunk Universal Forwarder configured on DC01 | Complete |
| DC01 event logs searchable in Splunk | Complete |
| Kerberos failure evidence investigated | Complete |
| Privileged group change evidence investigated | Complete |
| Two analyst mini-tickets documented | Complete |
| Eight real-world infrastructure issues diagnosed and resolved | Complete |

---

# 17. Final Phase 10 Outcome

Phase 10 completed the core Active Directory foundation for Track 3. The lab
now has a functioning Windows Server domain controller, private domain DNS,
organized identities and systems, a domain-joined Windows endpoint, and
centralized DC01 event visibility in Splunk.

The most important professional lesson came from the hardest troubleshooting
chain of the build: an event that *should* exist can be absent for reasons
that have nothing to do with connectivity - clock skew and audit policy
configuration can silently prevent evidence from ever being generated, even
when every network path is confirmed healthy.

```text
Know the authentication path
  -> Search the correct system
  -> Review the correct event IDs
  -> If expected evidence is missing, question configuration, not just connectivity
  -> Add account, source, actor, and change context
  -> Assign a defensible verdict
```

## Up Next - Phase 11

Begin controlled identity attack and detection practice against the AD lab.
The next phase will focus on safely investigating password attacks, suspicious
domain authentication, Kerberos-related activity, and identity attack paths
without overclaiming compromise.
