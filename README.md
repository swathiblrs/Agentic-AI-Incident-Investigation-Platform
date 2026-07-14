# AI Security Alert Investigation Agent

A production-ready AI security investigation system that helps SOC and security teams investigate suspicious alerts by analyzing SIEM events, identity logs, security playbooks, MITRE ATT&CK notes, and past incident documentation using LangGraph + Retrieval Augmented Generation (RAG).

## Why this project exists

During security investigations, analysts spend valuable time searching SIEM logs, identity provider events, runbooks, threat notes, and historical incidents to decide whether an alert is benign or a real compromise.

This system acts as an AI copilot for alert investigation, helping reduce triage time and improve investigation consistency.

The agent can:

- Analyze suspicious security alerts and raw events
- Retrieve relevant playbooks, MITRE ATT&CK notes, and past incidents
- Triage alert severity with explainable risk scoring
- Enrich alerts with threat and infrastructure context
- Collect evidence into a structured investigation timeline
- Recommend containment and remediation actions

## Architecture Overview

High level workflow:

Security alert or SIEM events  
-> LangGraph orchestration  
-> RAG pipeline retrieves relevant playbooks, incidents, and ATT&CK notes  
-> Investigation nodes reason over alert context, evidence, and references  
-> Structured security investigation report

Core stack:

- FastAPI for API backend
- LangGraph for triage, enrichment, evidence collection, and remediation orchestration
- Local RAG retriever for offline development
- PostgreSQL + pgvector schema for production vector search
- Pydantic models for structured investigation reports
- Prometheus + Grafana for monitoring
- Docker for containerization
- Production-ready extension points for SIEM, EDR, IAM, and LLM integrations

## Key Features

### LangGraph Security Alert Investigation Workflow

- Submit alerts from SIEM, IAM, EDR, or cloud security tooling
- Analyze login anomalies, suspicious infrastructure, and post-authentication activity
- Semantic search across security runbooks and past incident notes
- Explainable verdicts such as benign, suspicious, likely compromise, or confirmed incident
- Recommended containment and remediation steps

### Retrieval Augmented Generation Pipeline

This project uses a RAG-style pipeline to ground investigations in security knowledge.

- Playbook and runbook knowledge base
- MITRE ATT&CK identity technique notes
- Past incident archive examples
- SIEM hunting query guidance
- Local vector-style retrieval for offline demos
- pgvector schema for production retrieval storage

### Production Backend

- FastAPI REST API
- Typed request and response models
- Health and metrics endpoints
- Input validation with Pydantic
- Structured investigation reports
- Docker Compose setup for API, Postgres, Prometheus, and Grafana

### Observability & Monitoring

- Prometheus metrics endpoint
- Investigation count by severity and verdict
- End-to-end investigation duration metrics
- Per-agent execution duration metrics
- Grafana provisioning included

### Security Workflow Coverage

- Alert triage LangGraph node
- Threat enrichment LangGraph node
- Evidence collector LangGraph node
- Remediation recommender LangGraph node
- Risk scoring and verdict generation
- Investigation timeline and evidence summary

## Example Use Cases

Example investigations:

- "Is this impossible-travel login a real account takeover?"
- "A user accepted MFA after repeated denied push prompts. Should we contain the account?"
- "A suspicious IP logged in and created a mailbox forwarding rule. What evidence matters?"
- "What remediation steps should the SOC take for likely identity compromise?"

The agent retrieves relevant playbook sections and produces structured investigation guidance with evidence, risk score, references, and recommended actions.

## Project Structure

```text
app/
 ├── api/                # FastAPI REST endpoints
 ├── agents/             # Alert triage, enrichment, evidence, remediation agents
 ├── core/               # App settings and telemetry
 ├── data/
 │    ├── knowledge_base/ # Security playbooks, MITRE notes, past incidents
 │    └── sample_alerts/  # Demo security alerts
 ├── models/             # Pydantic schemas and investigation state
 ├── rag/                # Local retrieval pipeline
 ├── services/           # Investigation orchestration
 └── storage/            # PostgreSQL + pgvector schema

scripts/                 # CLI demo scripts
docker/                  # Prometheus and Grafana configuration
```

## Getting Started

### Prerequisites

- Python 3.11+
- Docker + Docker Compose
- PostgreSQL with pgvector for production vector search

### Local Setup

Clone the repo:

```bash
git clone https://github.com/swathiblrs/AI-Security-Alert-Investigation-Agent.git
cd AI-Security-Alert-Investigation-Agent
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create environment file:

```bash
cp .env.example .env
```

Run locally:

```bash
uvicorn app.main:app --reload
```

Swagger docs available at:

```text
http://localhost:8000/docs
```

Useful endpoints:

```text
GET  /api/health
GET  /api/sample-alert
POST /api/investigate
GET  /api/metrics
```

Run the sample investigation:

```bash
python scripts/run_sample.py
```

## Run with Docker

```bash
docker compose up --build
```

Monitoring dashboards:

```text
Prometheus -> http://localhost:9090
Grafana    -> http://localhost:3000
API        -> http://localhost:8000
```

Grafana default login:

```text
admin / admin
```

## Testing

Run automated tests:

```bash
python -m pytest
```

The test suite validates:

- Sample alert investigation workflow
- FastAPI investigation endpoint
- Risk scoring and verdict generation
- Presence of references and remediation actions

## Future Improvements

- Add real SIEM integrations such as Splunk, Microsoft Sentinel, and Elastic
- Add IAM integrations such as Okta, Entra ID, and Google Workspace
- Replace local retrieval with embedding generation and pgvector search
- Add analyst feedback loops for risk scoring calibration
- Persist investigation history in PostgreSQL
- Add Slack, Jira, and PagerDuty handoff actions

## Acknowledgements

Built as a SOC-focused AI incident investigation project using FastAPI, LangGraph, RAG, pgvector-ready storage, and monitoring patterns for production security workflows.
