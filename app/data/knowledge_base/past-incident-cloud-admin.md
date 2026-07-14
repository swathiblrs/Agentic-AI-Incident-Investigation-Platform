---
title: Past Incident - Cloud Admin Session Hijack
source: Incident Archive 2025-11
tags: past-incident, cloud-admin, token-theft, impossible-travel
---

A cloud administrator account showed a successful login from an unfamiliar country after three MFA denials.
Within eight minutes the actor enumerated storage buckets, created a temporary access key, and added a mailbox
forwarding rule. The incident was confirmed after device logs showed no matching endpoint activity from the
administrator's managed laptop.

Lessons learned: prioritize token revocation over password reset alone, inspect OAuth grants, and verify whether
the session came from a managed device before assuming user travel.
