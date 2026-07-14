---
title: Account Takeover Triage Playbook
source: SOC Runbook IR-ATO-001
tags: account-takeover, login-anomaly, impossible-travel, mfa, identity
---

Treat a login anomaly as high risk when two or more signals are present:

- Impossible travel or a new country for the user.
- MFA fatigue, repeated push denials, or a push accepted after many failures.
- Login from a new ASN, proxy, VPN, hosting provider, or Tor exit node.
- Successful login followed by mailbox rule creation, OAuth consent, privilege changes, or data export.
- Failed logins against multiple users from the same IP address.

Immediate containment includes revoking refresh tokens, resetting credentials, requiring MFA re-registration,
disabling suspicious OAuth grants, and preserving identity provider logs.
