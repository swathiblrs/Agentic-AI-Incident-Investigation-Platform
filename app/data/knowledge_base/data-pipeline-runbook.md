---
title: Data Pipeline Incident Runbook
source: Data Engineering Runbook DATA-001
tags: data, pipeline, freshness, schema, quality, backfill
---

Data pipeline incidents should assess freshness, schema compatibility, source availability, transformation errors,
quality check failures, and downstream business impact.

If correctness is uncertain, pause downstream consumers, preserve failed run metadata, identify the last known good
checkpoint, and backfill only after the root cause is understood.
