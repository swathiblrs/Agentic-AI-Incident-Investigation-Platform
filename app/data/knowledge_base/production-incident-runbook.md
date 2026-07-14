---
title: Production Incident Triage Runbook
source: SRE Runbook PROD-001
tags: production, sre, outage, latency, 503, rollback
---

Production incident triage starts with impact scope, recent changes, service health, and mitigation options.

High priority signals include customer-facing 5xx errors, elevated latency, failed dependencies, saturation,
database connection exhaustion, queue backlog, and a recent deploy or configuration change.

Recommended actions include checking deployment history, reviewing dashboards, comparing upstream and downstream
error rates, rolling back risky changes, scaling saturated components, and communicating impact and mitigation status.
