---
title: Identity Remediation Guide
source: Security Engineering Standard IR-ID-002
tags: remediation, identity, containment, recovery
---

Recommended remediation for likely identity compromise:

1. Revoke active sessions and refresh tokens.
2. Reset the account password and require MFA reset from a trusted device.
3. Remove suspicious OAuth app grants and mailbox forwarding rules.
4. Block or challenge the source IP and related infrastructure.
5. Review privileged actions, data access, and lateral movement for the next 24 hours.
6. Open a user verification task with the service desk.
