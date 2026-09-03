# Day 07 Lab Log — Phase 7 Complete: Phishing and Email Security Investigation

**Phase Completed:** Phase 7 — Phishing and Email Security Investigation
**Focus:** Phishing triage methodology, IOC extraction, sender/URL/attachment analysis, social engineering identification, verdict writing, and SOC response planning

---

## Overview

Phases 1–6 built the lab's telemetry foundation and SOC documentation habits — Elastic, Wazuh, log fundamentals, high-volume triage, and formal ticket/escalation writing. Phase 7 shifted into a different lane: instead of live telemetry, it worked through five simulated phishing reports the way they'd actually arrive in a SOC mailbox — a subject line, a sender, a body, and sometimes a link or attachment.

For each case, the goal was the same: figure out who the email is really from (not who it claims to be), whether any links or attachments are safe to trust, what social engineering technique is being used, what the attacker is actually after, and what a SOC analyst would do about it — then write that up as a formal ticket. The phase closed with a single incident report tying all five cases together and a set of lessons meant to carry forward into later phases (detection engineering, threat intel).

---

## Final Phishing Incident Report

### Executive Summary

Five simulated phishing scenarios were investigated using SOC analyst methodology: Microsoft 365 credential phishing, invoice attachment phishing, executive impersonation/BEC, a fake Okta security alert, and a fake DocuSign document review request. Each case was worked through sender/URL/attachment analysis, IOC extraction, social engineering identification, verdict assignment, and SOC response planning.

### Scope

Five simulated phishing reports submitted to a SOC mailbox.

### Cases Reviewed

1. Microsoft 365 password expiration phishing
2. Suspicious invoice ZIP attachment
3. CEO / executive impersonation BEC attempt
4. Fake Okta unusual sign-in alert
5. Fake DocuSign document review link

### Key Findings

- Multiple emails relied on brand impersonation — Microsoft, Okta, DocuSign, and internal executive leadership.
- Several used urgency or fear to pressure quick action: account suspension, lockout, late fees, document expiration.
- Lookalike domains were the strongest technical indicator across the credential-phishing cases — none of the "branded" senders actually used the real brand's domain.
- Several emails had no attachment at all and were still malicious — an empty attachment field doesn't mean a clean email.
- One case (the CEO/BEC email) had no link or attachment whatsoever and was still a genuine risk, since the attack was the conversation itself rather than a payload.
- The one case with an attachment used a ZIP file — a common way to wrap executables, scripts, or macro-enabled documents.
- Credential harvesting was the most common suspected goal.
- HTTPS didn't indicate safety in any case — a valid certificate says nothing about who actually controls a domain.
- Display names were consistently spoofed to look trustworthy ("IT Support," "Security Alert," "CEO," "DocuSign Notification"); the real sender address and domain were what actually decided each verdict.

### IOCs Identified

```text
support@micros0ft-security[.]com
micros0ft-security[.]com
micros0ft-security-login[.]com
hxxps://micros0ft-security-login[.]com/verify

billing@secure-invoices-payments[.]com
secure-invoices-payments[.]com
Invoice_INV-88421.zip

ceo.company.office@gmail[.]com
gmail[.]com
Subject: "Quick favor needed"

alerts@okta-verification[.]com
okta-verification[.]com
hxxps://okta-verification[.]com/security-check

notification@docusign-secure[.]net
docusign-secure[.]net
hxxps://docusign-secure[.]net/document/review?id=88421
```

### Analysis

The five cases covered typosquatting, brand impersonation, urgency/fear-based pressure, attachment-based delivery, fake security alerts, document-signing impersonation, and business email compromise.

The Microsoft and Okta-themed emails were assessed as likely credential harvesting attempts, each pairing a lookalike domain with an urgent account-security narrative. The invoice ZIP attachment was assessed as possible malware delivery, since the risk sat in an unverified file rather than a link. The CEO email was assessed as a BEC attempt — executive impersonation and urgency used to open a conversation with no payload at all, with a financial ask expected to follow a reply rather than arrive up front. The DocuSign-themed email was assessed as credential phishing through document-signing impersonation, and reinforced that a valid HTTPS certificate on the linked domain doesn't make the site trustworthy.

Across all five cases, the display name was never a reliable signal — the sender's actual domain, and where present the URL's actual domain, were what determined the verdict every time.

### Impact Assessment

No real users or production systems were affected — these were simulated lab scenarios. In a live environment, unaddressed versions of these same five cases could realistically lead to credential theft, MFA/session token theft, malware execution, initial access, account takeover, financial or vendor fraud, and sensitive data disclosure.

### Recommended SOC Actions

- Block confirmed malicious sender domains and URLs
- Search for other recipients across the mail environment (sender, subject, URL, domain)
- Quarantine or remove matching emails
- Ask reporting users whether they clicked, replied, opened attachments, or entered credentials
- Reset passwords and revoke active sessions if credentials were entered
- Review identity provider sign-in logs for suspicious authentication activity
- Submit attachments or URLs to sandbox/reputation tools when safe to do so
- Escalate to incident response if malware execution, account compromise, or financial fraud is suspected

### Final Verdict

The five cases spanned credential harvesting, possible malware delivery, business email compromise, and brand impersonation. Phase 7 exercised the full phishing triage loop — IOC extraction, sender/URL/attachment analysis, social-engineering identification, verdict writing, and SOC response planning — across delivery methods that varied from link-based to attachment-based to conversation-only.

---

## Lessons Learned

1. **Phishing doesn't require a link.** The CEO/BEC case had no URL and no attachment, but was still malicious — it tried to open a conversation as a setup for a later ask.

2. **Phishing doesn't require an attachment.** The Microsoft, Okta, and DocuSign cases all had no attachment, but were still phishing via a fake login/security/document link.

3. **HTTPS does not mean safe.** A malicious site can hold a valid certificate. The domain, sender, URL path, and context are what actually matter.

4. **Display names can lie.** "IT Support," "Security Alert," "CEO," and "DocuSign Notification" all looked legitimate on the surface — the real sender address and domain told the actual story every time.

5. **Lookalike domains are a major indicator.** The same pattern repeated across three separate cases: a domain built to *resemble* a trusted brand rather than actually belong to it.

6. **Attachments require caution by default.** A ZIP file is a common way to hide payloads, scripts, or malicious documents — it isn't something a SOC analyst clears by reading the email around it.

7. **BEC attacks often start simple.** The opening message may be nothing more than "Are you available?" — the actual malicious ask typically arrives only after the target replies.

8. **Document evidence, not assumptions.** Phrasing matters: "the email appears suspicious because…", "the likely goal is…", "if credentials were entered…" — a ticket should reflect what's actually confirmed, not what hasn't been proven yet.

---

## Final Status

**Phase 7 complete.**
