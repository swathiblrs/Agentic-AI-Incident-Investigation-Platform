---
title: SIEM Hunting Queries for Login Anomalies
source: Detection Engineering Query Pack
tags: siem, query, login, identity, evidence
---

Useful pivots:

- Search the source IP across all authentication events for the previous 24 hours.
- Count distinct targeted usernames from the same IP address.
- Join successful logins to cloud audit events within the next 30 minutes.
- Check whether the same user created inbox rules, changed MFA methods, consented to OAuth apps, or downloaded data.
- Compare the user agent and device ID to the user's normal login history.
