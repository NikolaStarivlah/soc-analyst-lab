# Phase 13 Detailed Lab Log - IAM, Hardening, and Least Privilege

## Status

**Completed - October 7, 2026**

**Track 3 - Endpoint and Identity Investigation**

## Completion Summary

Phase 13 was a defensive identity and access management review of the
`nikola.local` Active Directory lab. I collected the live state of domain
accounts, privileged group membership, service-account settings, Kerberos
pre-authentication, SPNs, sign-in context, the domain password and lockout
policy, and local Administrators membership on the Windows 10 endpoint. I then
rated each finding, separated safe fixes from access-sensitive changes, and
applied and validated the safe ones.

The review produced **11 findings**: the guide's 10 finding areas, mapped to
this lab's real accounts, plus one additional finding (IAM-11) that the same
method surfaced in this domain. Nine individual configuration changes were
made across six remediation areas, each with a before/after check. Five items
were documented for controlled change instead of being changed casually.

Two results went beyond the guide:

1. **Policy durability.** The domain password and lockout settings were also
   defined in the Default Domain Policy GPO. A direct
   `Set-ADDefaultDomainPasswordPolicy` change would have passed an immediate
   re-query but been overwritten on a later Group Policy refresh. I confirmed
   this from the GPO report, made the change in the GPO, and validated both the
   effective policy and the GPO source.
2. **A documentation discrepancy.** The Phase 10 log records `helpdesk.user1`
   being added to `IT Admins`, but AD replication metadata shows the live
   group has never held a member and was never rolled back. This is recorded
   as a documentation-integrity note with the evidence needed to close it.

No production systems or real user data were involved. The review established
configuration exposure; it did not prove credential theft, Kerberos ticket
abuse, unauthorized administrator use, or compromise.

### Final Deliverables

| Requirement | Result |
|---|---|
| Active Directory account review | All 8 domain user accounts reviewed for enabled status, `PasswordNeverExpires`, `DoesNotRequirePreAuth`, SPNs, `LastLogonDate`, `PasswordLastSet`, and `AdminCount` |
| Privileged access review | 11 privileged and custom groups enumerated recursively; built-in `Administrator` is the only privileged member |
| Kerberos and service-account review | Pre-auth exposure, SPN exposure, non-expiring passwords, and real-time `lastLogon` confirmed for `svc_legacy` and `svc_web` |
| Domain policy review | Effective policy, fine-grained policies, and the Default Domain Policy GPO source all checked |
| Endpoint privilege review | `DESKTOP-BN86O9N` local Administrators and local accounts reviewed |
| Findings register | 11 findings with risk, evidence, recommendation, lab action, and status |
| Safe remediation | 9 changes across 6 areas, each validated before and after |
| Change-control judgment | 5 access-sensitive or service-dependent items documented, not changed |

---

# 1. Objective

The goal was to practice the hardening workflow expected of a cybersecurity
analyst:

```text
Define the review scope
  -> Collect current identity and policy settings
  -> Identify unnecessary or risky access
  -> Assign risk based on likelihood and impact
  -> Separate safe fixes from disruptive changes
  -> Apply and validate approved lab changes
  -> Document remaining risk and production recommendations
```

This phase was a configuration and access review, not an attack simulation.

---

# 2. Lab Environment and Guide Substitutions

The phase guide was a finished write-up from another lab rather than a set of
instructions. It used placeholder identities that do not exist here - the same
situation as Phases 6 and 12. I followed its scope and finding structure but
collected the real state of this domain before rating anything.

| Guide value | This lab |
|---|---|
| `MAJEED` / `majeed.local` | `NIKOLA` / `nikola.local` |
| `HTTP/webapp.majeed.local` | `HTTP/webapp.nikola.local` |
| `mmajeed` (named local admin) | `DESKTOP-BN86O9N\Nikola` (Phase 1 setup account) |
| `svc_sql` | Does not exist. The same risk (non-expiring service password) was found on `svc_legacy` and `svc_web` |

I did not create `svc_sql` just to remediate it. That would have turned the
review into a reenactment of someone else's results.

| System | Role | Address |
|---|---|---|
| DC01 | Windows Server 2022 domain controller, `nikola.local` / `NIKOLA`, PDC Emulator | 192.168.56.10 (static) |
| windows10victim | `DESKTOP-BN86O9N`, domain-joined endpoint | 192.168.56.114 |

Only DC01 and the workstation were powered on (the Phase 10/11 two-VM rule for
host RAM). Splunk was not needed for this phase.

---

# 3. Pre-Flight and Rollback Point

Because this phase changes domain policy and accounts, I took a pre-change
snapshot named `Phase13-Pre-IAM-Review` on both DC01 (21:20) and
windows10victim before making any change.

DC01 pre-flight results:

| Check | Result |
|---|---|
| Shell identity | `nikola\administrator` on `DC01` |
| Time zone and clock | Eastern Standard Time, clock correct (Phase 10 issue #6 check) |
| Host-only IP | 192.168.56.10, unchanged |
| AD module and domain | Loaded; `nikola.local`, NetBIOS `NIKOLA`, PDC Emulator `DC01.nikola.local` |
| Evaluation licence (`slmgr /dlv`) | Initial grace period, 3,110 minutes remaining, 5 rearms left |

The licence check matters because an expired grace period caused DC01's silent
shutdowns in Phase 10. The remaining time was enough for the phase, so no
rearm was done mid-phase; it is tracked for the next session.

---

# 4. Collection

## 4.1 Domain User Accounts

```powershell
Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,DoesNotRequirePreAuth,ServicePrincipalName,LastLogonDate,PasswordLastSet,AdminCount |
  Select-Object SamAccountName,Enabled,PasswordNeverExpires,DoesNotRequirePreAuth,
    @{n='SPN';e={$_.ServicePrincipalName -join ';'}},LastLogonDate,PasswordLastSet,AdminCount |
  Sort-Object SamAccountName | Format-Table -AutoSize | Out-String -Width 300
```

| Account | Enabled | PwdNeverExpires | NoPreAuth | SPN | LastLogonDate | PasswordLastSet | AdminCount |
|---|---|---|---|---|---|---|---|
| Administrator | True | **True** | False | | 9/25/2026 | 9/18/2026 | 1 |
| Guest | False | True | False | | | | |
| helpdesk.user1 | True | False | False | | *(blank)* | 9/29/2026 | |
| krbtgt | False | False | False | kadmin/changepw | | 9/25/2026 | 1 |
| soc.analyst1 | True | **True** | False | | 9/30/2026 | 9/29/2026 | |
| svc_legacy | True | **True** | **True** | | *(blank)* | 10/5/2026 | |
| svc_web | True | **True** | False | **HTTP/webapp.nikola.local** | *(blank)* | 10/5/2026 | |
| test.employee1 | **True** | False | False | | 9/30/2026 | 9/29/2026 | |

No unexpected accounts were present, and both Phase 11 service accounts still
existed. `krbtgt` being disabled with an SPN and `AdminCount=1` is normal.

`test.employee1` showed a blank `AdminCount` even though Phase 11 added it to
Domain Admins. That is consistent with the evidence: it was a member for about
nine seconds, too short for the hourly SDProp process to stamp it.

## 4.2 Privileged Group Membership

```powershell
$groups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','Group Policy Creator Owners','DnsAdmins','IT Admins'
foreach ($g in $groups) {
  try {
    $m = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    $list = if ($m) { $m -join ', ' } else { '(empty)' }
  } catch { $list = "(error: $($_.Exception.Message))" }
  "{0,-28} {1}" -f $g, $list
}
```

| Group | Members |
|---|---|
| Domain Admins, Enterprise Admins, Schema Admins, Administrators, Group Policy Creator Owners | `Administrator` only |
| Account Operators, Backup Operators, Server Operators, Print Operators, DnsAdmins | empty |
| IT Admins (custom, Phase 10) | **empty** |

The try/catch was deliberate: a lookup failure prints an error instead of
looking like an empty group.

Results:

- The Phase 11 Domain Admins add/remove left no residual membership.
- Neither service account is privileged, which lowers the impact of the
  `svc_web` SPN exposure.
- The built-in `Administrator` is the only privileged identity in the domain.
  There are no separate named admin accounts. All administrative work runs
  through one predictable, high-value account.
- `IT Admins` being empty contradicted the Phase 10 log. See Section 9.1.

## 4.3 Domain Password and Lockout Policy

```powershell
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, AppliesTo, MinPasswordLength, LockoutThreshold
```

| Setting | Value |
|---|---|
| ComplexityEnabled | True |
| LockoutThreshold | **0** (lockout disabled) |
| LockoutDuration / LockoutObservationWindow | 30 min / 30 min (inert while threshold is 0) |
| MaxPasswordAge / MinPasswordAge | 42 days / 1 day |
| MinPasswordLength | **7** |
| PasswordHistoryCount | 24 |
| ReversibleEncryptionEnabled | False |
| Fine-grained password policies | None |

With no fine-grained policies, the default domain policy governs every
account. The 42-day maximum age is also why the four
`PasswordNeverExpires=True` accounts matter: they bypass that control.

## 4.4 Endpoint Local Administrators

Run on `DESKTOP-BN86O9N` as `NIKOLA\Administrator`:

```powershell
Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass, PrincipalSource
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

| Member | Class | Source | Notes |
|---|---|---|---|
| `DESKTOP-BN86O9N\Administrator` | User | Local | Built-in local admin, **disabled** (Windows default) |
| `DESKTOP-BN86O9N\Nikola` | User | Local | Phase 1 setup account, **enabled**, last logon 9/30/2026 12:33 AM |
| `NIKOLA\Domain Admins` | Group | ActiveDirectory | Domain Admins administer the workstation |

All other local accounts (`DefaultAccount`, `Guest`, `WDAGUtilityAccount`)
were disabled.

## 4.5 Real-Time Sign-In Context

`Get-LocalUser` run on DC01 by mistake (Section 9.2) returned the domain
accounts with DC01's real-time, non-replicated `lastLogon` value. It turned out
to be useful evidence:

- `soc.analyst1` showed **10/5** here but **9/30** in `LastLogonDate`,
  confirming the 9-14 day replication lag in `lastLogonTimestamp`.
- `svc_legacy` and `svc_web` were blank even here. DC01 is the only domain
  controller, so this is authoritative: neither account has ever authenticated
  as itself. Phase 11's 4769 service-ticket request was *for* `svc_web`, which
  does not count as `svc_web` logging on.

---

# 5. Findings Register

| ID | Finding | Risk | Lab action | Status |
|---|---|---:|---|---|
| IAM-01 | Built-in domain `Administrator` enabled; the only member of every privileged group and used interactively on a workstation | Medium | Document | Controlled change |
| IAM-02 | `Administrator` `PasswordNeverExpires=True` | Medium | Document | Controlled change |
| IAM-03 | `svc_legacy` and `svc_web` `PasswordNeverExpires=True` | Medium | Remediate | **Remediated** |
| IAM-04 | `svc_legacy` `DoesNotRequirePreAuth=True` | High | Remediate | **Remediated** |
| IAM-05 | `svc_web` SPN `HTTP/webapp.nikola.local`; RC4 (`0x17`) tickets issued in Phase 11 | Medium | Document | Legitimate exposure requiring management |
| IAM-06 | Account lockout threshold 0 | High | Remediate | **Remediated** |
| IAM-07 | Minimum password length 7 | Medium | Remediate | **Remediated** |
| IAM-08 | `svc_legacy` and `svc_web` enabled but have never authenticated | Medium | Document | Ownership review |
| IAM-09 | `test.employee1` enabled after earlier labs | Low/Medium | Remediate | **Remediated** |
| IAM-10 | Broad endpoint local admin membership (`Nikola`, Domain Admins) | High | Partial | **Partially remediated** |
| IAM-11 | `soc.analyst1` (standard user) `PasswordNeverExpires=True` - *not in guide* | Low/Medium | Remediate | **Remediated** |

**Documentation note (not a finding):** Phase 10 `IT Admins` membership
discrepancy - Section 9.1.

---

# 6. Detailed Findings

## IAM-01 - Built-in Administrator Enabled and Sole Privileged Identity

**Evidence:** `Administrator` enabled; the only member of Domain Admins,
Enterprise Admins, Schema Admins, Administrators, and Group Policy Creator
Owners. Used interactively on `DESKTOP-BN86O9N` in Phase 12 and again in this
phase through `runas`, which places the domain admin credential on a
workstation.

**Why it matters:** One predictable, maximum-privilege account carries all
administration, which removes accountability and makes any credential exposure
domain-wide.

**Production recommendation:** Separate named admin accounts, tiered
administration (no domain admin logons to workstations), monitoring of
built-in Administrator use, and a validated recovery path before restricting
it.

**Lab action:** Documented. Disabling it without a second admin account would
lock administration out of the lab.

## IAM-02 - Administrator Password Never Expires

**Evidence:** `PasswordNeverExpires=True`, password last set 9/18/2026.

**Lab action:** Documented. Rotation of the only privileged credential needs
planning to avoid losing access.

## IAM-03 - Service Account Passwords Never Expire

**Evidence:** `svc_legacy` and `svc_web` both `PasswordNeverExpires=True`.
The guide's equivalent was `svc_sql`, which does not exist in this lab.

**Production recommendation:** Confirm owner, rotate through change control,
remove the flag, and use a gMSA where supported.

**Lab action:** Remediated (Section 7.1).

## IAM-04 - `svc_legacy` Does Not Require Kerberos Pre-Authentication

**Evidence:** `DoesNotRequirePreAuth=True`, UAC `0x400200`. Created
deliberately in Phase 11 Scenario 2.

**Why it matters:** The account is AS-REP roastable: anyone can request
encrypted material for it and attack the password offline.

**Lab action:** Remediated (Section 7.2).

## IAM-05 - `svc_web` SPN Exposure

**Evidence:** SPN `HTTP/webapp.nikola.local`. Phase 11 showed a 4769 ticket
for this SPN issued with RC4-HMAC (`0x17`). The account is in no privileged
group.

**Why it matters:** An SPN is legitimate when a service needs Kerberos, but
any domain user can request a ticket for it. RC4 tickets are derived from the
account's NTLM hash and are the target of Kerberoasting.

**Production recommendation:** Confirm owner and purpose, use a long managed
credential or gMSA, enforce AES-only encryption types, keep it unprivileged,
and monitor 4769 activity.

**Lab action:** Documented. The SPN's presence is not a misconfiguration by
itself.

## IAM-06 - Account Lockout Disabled

**Evidence:** `LockoutThreshold 0`, also defined as `LockoutBadCount 0` in the
Default Domain Policy GPO. Phase 11's password spray could never have locked
an account.

**Lab action:** Remediated in the GPO (Section 7.4).

## IAM-07 - Minimum Password Length 7

**Evidence:** `MinPasswordLength 7` in both the effective policy and the GPO.

**Lab action:** Remediated in the GPO (Section 7.4).

## IAM-08 - Service Accounts Have Never Authenticated

**Evidence:** Blank `LastLogonDate` *and* blank real-time `lastLogon` on the
only domain controller for `svc_legacy` and `svc_web`.

**Why it matters:** An enabled account with no use is attack surface without
business value. But missing sign-in data alone is not enough to disable it -
ownership and dependent services must be confirmed first.

**Lab action:** Documented for ownership review. The real-time `lastLogon`
check makes this evidence stronger than the guide's.

## IAM-09 - Enabled Test Account

**Evidence:** `test.employee1` enabled; used for Phase 10 and 11 testing.

**Lab action:** Remediated - disabled, not deleted (Section 7.3).

## IAM-10 - Broad Endpoint Local Administrator Membership

**Evidence:** `Nikola` (enabled local account) and `NIKOLA\Domain Admins` in
the local Administrators group.

**Lab action:** Partially remediated. `Nikola` removed (Section 7.6).
Domain Admins retained to keep lab administration working.

**Recovery caveat recorded before the change:** `Nikola` was the
workstation's only enabled local admin. After removal, offline admin access
depends on cached Domain Admin credentials - and in this same session the
cached/local logon path failed in a way that was not fully explained (Section
9.3). The change went ahead with a snapshot and a one-line rollback available.

**Production recommendation:** Separate workstation admin accounts, remove
Domain Admins from endpoint administration, manage membership by policy,
deploy Windows LAPS, and monitor membership changes.

## IAM-11 - Standard User Password Never Expires (Not in Guide)

**Evidence:** `soc.analyst1`, a standard user, `PasswordNeverExpires=True`.

**Why it matters:** There is even less justification for this on a regular
user than on a service account. It was found by applying the guide's method
to this domain's real data.

**Lab action:** Remediated (Section 7.5).

---

# 7. Remediation and Validation

Every change used the same pattern: record the before state, make the change,
validate the after state with something stronger than the flag alone where
possible.

## 7.1 IAM-03 - Service Account Password Expiry

```powershell
$accts = 'svc_legacy','svc_web'
$accts | ForEach-Object { Set-ADUser -Identity $_ -PasswordNeverExpires $false }
$accts | ForEach-Object { Get-ADUser $_ -Properties PasswordNeverExpires,PasswordLastSet,'msDS-UserPasswordExpiryTimeComputed' |
  Select-Object SamAccountName, PasswordNeverExpires, PasswordLastSet,
    @{n='PasswordExpires';e={[datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')}} }
```

| Account | Before | After | Computed expiry |
|---|---|---|---|
| svc_legacy | True | False | 11/16/2026 9:23:29 AM |
| svc_web | True | False | 11/16/2026 9:29:26 AM |

The computed expiry proves the domain policy now applies to the accounts, not
just that a flag changed. The expiry shows one hour earlier than the 10:23 /
10:29 AM set times because daylight saving time ends on Nov 1: the 42 days are
counted in UTC and displayed in EST.

## 7.2 IAM-04 - Re-Enable Kerberos Pre-Authentication

```powershell
Set-ADAccountControl -Identity svc_legacy -DoesNotRequirePreAuth $false
```

| | DoesNotRequirePreAuth | UAC |
|---|---|---|
| Before | True | `0x400200` |
| After | False | `0x200` |

The raw UAC value confirms the `0x400000` flag bit was cleared.

## 7.3 IAM-09 - Disable Test Account

```powershell
Disable-ADAccount -Identity test.employee1
```

| | Enabled | UAC | LastLogonDate |
|---|---|---|---|
| Before | True | `0x200` | 9/30/2026 4:13:34 PM |
| After | False | `0x202` | 9/30/2026 4:13:34 PM |

Disabling rather than deleting keeps the change reversible and keeps the
account's SID (`-1106`) resolvable in the Phase 10 and 11 evidence.

## 7.4 IAM-06 and IAM-07 - Password and Lockout Policy (in the GPO)

### Why not just use the cmdlet

The guide says the policy was changed and re-queried but not how. Before
changing anything I checked which source controlled the policy:

```powershell
[xml]$r = Get-GPOReport -Name 'Default Domain Policy' -ReportType Xml
$r.GPO.Computer.ExtensionData.Extension.Account |
  Select-Object Name, Type, SettingNumber, SettingBoolean | Format-Table -AutoSize
```

The GPO defined `LockoutBadCount 0` and `MinimumPasswordLength 7` (plus
history 24, max age 42, min age 1, complexity on, reversible encryption off,
and the Kerberos policy). `LockoutDuration` and `ResetLockoutCount` were not
defined, which is why the effective policy showed the built-in 30-minute
defaults.

Because the GPO defines these settings, a direct
`Set-ADDefaultDomainPasswordPolicy` change would have shown correctly on an
immediate re-query and then been overwritten on a later security-policy
refresh. The hardening would have looked validated without lasting.

### Change

In `gpmc.msc` -> Default Domain Policy -> Computer Configuration -> Policies
-> Windows Settings -> Security Settings -> Account Policies:

- Password Policy -> Minimum password length: **12**
- Account Lockout Policy -> Account lockout threshold: **5**
- Account lockout duration: **15 minutes**
- Reset account lockout counter after: **15 minutes**

Then `gpupdate /force`.

### Validation - both layers

| Layer | Min length | Threshold | Duration | Reset window |
|---|---|---|---|---|
| Effective (`Get-ADDefaultDomainPasswordPolicy`) | 12 | 5 | 00:15:00 | 00:15:00 |
| Source (Default Domain Policy GPO report) | 12 | 5 | 15 | 15 |

Both layers agree, so a GPO refresh reapplies these values instead of
reverting them.

**Production nuance:** the 12-character minimum applies only at each
account's next password change. This validation proves the policy changed,
not that existing passwords comply.

## 7.5 IAM-11 - Standard User Password Expiry

```powershell
Set-ADUser -Identity soc.analyst1 -PasswordNeverExpires $false
```

| | PasswordNeverExpires | PasswordLastSet | Computed expiry |
|---|---|---|---|
| Before | True | 9/29/2026 4:48:44 PM | - |
| After | False | 9/29/2026 4:48:44 PM | 11/10/2026 3:48:44 PM |

At that date Windows will prompt for a new password, which must meet the new
12-character minimum.

## 7.6 IAM-10 - Remove Named Local Admin

Run on `DESKTOP-BN86O9N`:

```powershell
Remove-LocalGroupMember -Group Administrators -Member 'DESKTOP-BN86O9N\Nikola'
```

| | Local Administrators members |
|---|---|
| Before | `Administrator` (disabled), `Nikola`, `NIKOLA\Domain Admins` |
| After | `Administrator` (disabled), `NIKOLA\Domain Admins` |

`Nikola` remains **enabled** as a standard user - least privilege, not
deletion. The shell that made the change was running through Domain Admins,
which proved admin access still worked after the change.

Rollback, only needed if admin access to the workstation is lost:

```powershell
Add-LocalGroupMember -Group Administrators -Member 'DESKTOP-BN86O9N\Nikola'
```

## Remediation Summary

1. `svc_legacy` `PasswordNeverExpires` -> False.
2. `svc_web` `PasswordNeverExpires` -> False.
3. `svc_legacy` `DoesNotRequirePreAuth` -> False.
4. `test.employee1` disabled.
5. Minimum password length 7 -> 12 (GPO).
6. Account lockout threshold 0 -> 5 (GPO).
7. Lockout duration and reset window -> 15 minutes (GPO).
8. `soc.analyst1` `PasswordNeverExpires` -> False.
9. `Nikola` removed from endpoint local Administrators.

That is nine changes across six remediation areas: service-account
settings, the test account, password length, lockout, local admin
membership, and the standard-user password expiry. The guide's seven changes
are all covered (its `svc_sql` change maps to item 1); items 2 and 8 come
from this lab's own evidence.

---

# 8. Items Requiring Controlled Change

| Item | Reason not changed |
|---|---|
| Built-in Administrator enabled (IAM-01) | It is the only privileged account; a named admin account and recovery path must exist first |
| Administrator password never expires (IAM-02) | Rotation of the sole privileged credential needs planning |
| `svc_web` SPN (IAM-05) | SPNs can be legitimate; validate against service ownership |
| Service accounts never authenticated (IAM-08) | Ownership and dependencies must be confirmed before disablement |
| Domain Admins in endpoint Administrators (IAM-10) | Removal should follow a tested least-privilege admin design (named workstation admins, LAPS) |

---

# 9. Troubleshooting and Investigation Notes

## 9.1 `IT Admins` Was Empty Despite a Documented Addition

**Symptom:** The Phase 10 log records `helpdesk.user1` being added to
`IT Admins` (Mini-Ticket 02, Event 4728) with no recorded removal, but the live
group was empty.

**Investigation:**

```powershell
Get-ADGroup 'IT Admins' -Properties whenCreated, whenChanged, member
Get-ADReplicationAttributeMetadata -Object (Get-ADGroup 'IT Admins').DistinguishedName -Server DC01 -ShowAllLinkedValues
```

- `whenCreated` and `whenChanged` were both 9/29/2026 5:13:34 PM.
- Every attribute was at Version 1, and there was no `member` metadata row at
  all. AD keeps removed members as tombstoned links for 180 days by default,
  so a removal eight days earlier would still have been visible. The group has
  never held a member.
- A snapshot rollback was ruled out: DC01's only snapshot was the one taken
  this session, and windows10victim's newest earlier snapshot was from 9/4,
  before Phase 10.

**Conclusion:** What the Phase 10 4728 event changed cannot be determined from
DC01 alone. 4728 is logged only for domain global security groups, so it was
a domain group - but not this object. The most likely explanation is that a
Phase 10 step did not apply as documented.

**Disposition:** Documentation-integrity note, not a finding. The IAM question
- does `IT Admins` grant unexpected access now? - is answered: no.

**Evidence needed to close:** the group SID in the Phase 10 4728 event in
Splunk compared with the live `IT Admins` `objectSid`.

## 9.2 Commands Run in the DC01 Window Instead of the Workstation

**Symptom:** `Get-LocalGroupMember -Group Administrators` returned "Group
Administrators was not found", and `Get-LocalUser` listed domain accounts
including `krbtgt`.

**Root cause:** The commands ran on DC01. A domain controller has no local
account database; its "local" users are domain users.

**Fix:** Ran the commands in the workstation's admin window. Identified the
correct window by `hostname` (`DESKTOP-BN86O9N`) and by the prompt
(`C:\Windows\system32>` for the `runas` shell vs `C:\Users\Administrator>` on
DC01). The mistaken run still produced useful `lastLogon` evidence (Section
4.5).

## 9.3 Domain Administrator Could Not Log On at the Workstation Login Screen

**Symptom:** `NIKOLA\Administrator` logons at the workstation login screen
failed with "The user name or password is incorrect." The same password had
worked on DC01 that evening, and the password text was visually confirmed.

**Diagnosis, in order:**

1. **DC-side evidence.** DC01's Security log had no 4771, 4776, or 4625 in the
   prior 30 minutes (query at 22:12). Per Phase 10 issue #6, clock skew can
   produce zero DC events, so this did not yet separate skew from a
   connectivity problem.
2. **Workstation checks** (from a `soc.analyst1` session, which logged on
   normally):

   | Check | Result |
   |---|---|
   | Time offset to DC01 (`w32tm /stripchart`) | +2.54 s (Kerberos allows 300 s) |
   | Host-only IP | 192.168.56.114 |
   | DC01 port 88 (`Test-NetConnection`) | `TcpTestSucceeded True` |

   Clock skew and network were ruled out.
3. **Controlled attempt.** `runas /user:NIKOLA\Administrator powershell` from
   the `soc.analyst1` session succeeded. DC01 recorded **4768** for
   `Administrator` from `192.168.56.114` at 22:16:52, Result Code `0x0`.
   `auditpol` still showed Success and Failure on Kerberos Authentication
   Service and Credential Validation, so no logging gap.

**What the timestamps showed:** The workstation's own computer account
(`DESKTOP-BN86O9N$`) first received a ticket at 22:14:43, *after* the failed
login-screen attempts. The workstation had just booted and was not yet talking
to the domain, so those attempts were handled locally and never reached DC01.

**Not determined:** why the local check reported "incorrect" rather than "no
logon servers available." It did not affect the IAM review, so I recorded it
rather than guessing.

**Note:** All failed Administrator attempts in this window were
analyst-generated. With the new lockout policy, five such failures now lock
the account for 15 minutes.

## 9.4 The "Suggested Value Changes" Popup Would Not Reappear

**Symptom:** After setting the lockout threshold to 5, changing the value back
and forth did not bring back the popup that sets the duration and reset
window.

**Root cause:** The popup appears only once, when the threshold first goes
from Not Defined to defined. It had already appeared and been accepted.

**Fix:** Set Account lockout duration and Reset account lockout counter after
directly to 15 minutes.

## 9.5 Hypotheses That Were Ruled Out

Part of this phase was discarding explanations that did not survive the
evidence:

- **"The removed member was garbage-collected."** Wrong: the tombstone
  lifetime (180 days) far exceeds the eight days since Phase 10.
- **"DC01 was rolled back to a snapshot."** Wrong: no earlier DC01 snapshot
  existed.
- **"Clock skew would show as a 4771 with code `0x25`."** Wrong for this lab:
  Phase 10's own evidence showed skew produced no DC event at all.

Checking a hypothesis against the lab's own earlier evidence caught the third
one before it caused a wrong conclusion.

---

# 10. Carried-Forward Items

Phase 12 listed inputs for this phase. Their status after Phase 13:

| Phase 12 input | Status |
|---|---|
| Domain Administrator used interactively on a workstation | Captured in IAM-01; remains open under controlled change |
| Phase 11 service accounts | Confirmed present; IAM-03, 04, 05, 08 |
| Group-writable cron script (`umask 002`) | The script was removed in Phase 12 cleanup; the default `umask 002` on `splunk-soc` remains a file-permission hygiene note outside this guide's AD scope |
| Logging gaps (Sysmon Event 7/10, TaskCache, file delete) | Open; not in this guide's scope |
| Splunk forwarder bookmark defect | Open; tracked remediation item |

New open items:

- DC01 evaluation grace period ends around Oct 9; `slmgr /rearm` and reboot
  at the start of the next session if needed.
- Phase 10 `IT Admins` discrepancy: check the 4728 group SID in Splunk.
- Production design items: named admin accounts, LAPS, AES-only service
  accounts, gMSAs.

---

# 11. Skills Demonstrated

- Active Directory account, privilege, and policy review with PowerShell.
- Recursive privileged-group enumeration with error-safe output.
- Kerberos exposure review: pre-authentication, SPNs, RC4 encryption.
- Sign-in data interpretation: `lastLogon` vs `lastLogonTimestamp`.
- AD replication metadata (`Get-ADReplicationAttributeMetadata`) for change
  history.
- Group Policy: identifying the authoritative source of the domain password
  policy and editing the Default Domain Policy GPO.
- Two-layer validation: effective setting and policy source.
- UAC flag interpretation (`0x200`, `0x202`, `0x400200`).
- Endpoint local administrator review and least-privilege remediation.
- Kerberos logon troubleshooting with DC-side events (4768/4771/4776), time
  offset, and port checks.
- Risk rating, change-control judgment, rollback planning.
- Evidence-safe documentation, including unresolved items.

---

# 12. Interview-Ready Summary

> In Phase 13, I performed an IAM and hardening review of my Active Directory
> lab. I collected the live state of every domain account, privileged group,
> service-account setting, the password and lockout policy, and local
> administrator membership on a domain-joined workstation, and produced 11
> rated findings.
>
> I fixed the safe items with a before-and-after check for each: I removed
> non-expiring passwords from two service accounts and a standard user,
> re-enabled Kerberos pre-authentication on an AS-REP-roastable account,
> disabled a stale test account, raised the minimum password length to 12,
> enabled a five-attempt lockout, and removed an unnecessary local admin.
>
> One detail I'm glad I checked: the password policy was also defined in the
> Default Domain Policy GPO, so changing it directly with PowerShell would have
> passed validation and then silently reverted. I made the change in the GPO
> and validated both the effective policy and the GPO source.
>
> For access-sensitive findings - the built-in Administrator being the only
> privileged account, Domain Admins on workstations, and service accounts with
> unknown owners - I documented the risk and the production remediation
> instead of making a change without ownership review, alternate access, and
> rollback.

---

# 13. Phase 13 Outcome

Phase 13 is complete.

I can now:

- Review AD accounts, privileged groups, and Kerberos-related settings and
  rate the risk.
- Interpret `lastLogon`, `lastLogonTimestamp`, `AdminCount`, and UAC values
  correctly.
- Find where a domain setting is really controlled and change it there.
- Validate a change at the effective layer and at its source.
- Apply least privilege on an endpoint without losing administrative access.
- Separate safe fixes from changes that need ownership, approval, and
  rollback.
- Document discrepancies and unresolved questions with the evidence needed to
  close them.

Snapshots: `Phase13-Pre-IAM-Review` (pre-change rollback point) on DC01 and
windows10victim; `Phase13-IAM-Hardening-Complete` (post-change) as the
closeout step.

## Up Next

**Practice Checkpoint 01 and Capstone 02 - Endpoint and Identity
Investigation**

- Complete unfamiliar external cases (LetsDefend or CyberDefenders).
- Triage a mixed queue of 10 alerts from earlier phases.
- Document incomplete-evidence decisions - the Phase 10 `IT Admins` note is a
  ready example.
- Apply asset context to severity.
- Complete the Endpoint and Identity Investigation capstone.
