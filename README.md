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
- Ollama for local LLM reasoning and embeddings with deterministic fallback
- PostgreSQL + pgvector for vector search
- Redis for session memory and caching
- JWT authentication for protected investigation endpoints
- Optional Langfuse tracing for LLM and investigation observability
- Pydantic models for structured investigation reports
- Prometheus + Grafana for monitoring
- Docker for containerization
- Production-ready extension points for SIEM, EDR, IAM, and LLM integrations
- AWS-ready deployment templates that cost nothing until applied

## Key Features

### LangGraph Security Alert Investigation Workflow

- Submit alerts from SIEM, IAM, EDR, or cloud security tooling
- Analyze login anomalies, suspicious infrastructure, and post-authentication activity
- Semantic search across security runbooks and past incident notes
- Explainable verdicts such as benign, suspicious, likely compromise, or confirmed incident
- Recommended containment and remediation steps
- Conversation memory per analyst session using Redis with in-memory fallback

### Retrieval Augmented Generation Pipeline

This project uses a RAG-style pipeline to ground investigations in security knowledge.

- Playbook and runbook knowledge base
- MITRE ATT&CK identity technique notes
- Past incident archive examples
- SIEM hunting query guidance
- Local vector-style retrieval for offline demos
- Ollama embedding generation for local semantic indexing
- PostgreSQL + pgvector retrieval runtime
- Knowledge-base ingestion script for indexing playbooks and runbooks

### Production Backend

- FastAPI REST API
- JWT token endpoint and protected investigation route
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
- Optional Langfuse tracing endpoint configuration

### Performance & Reliability

- Docker Compose setup for local services
- Redis-backed session memory with in-memory fallback
- Ollama calls automatically fall back to deterministic local reasoning when Ollama is unavailable
- pytest-based evaluation framework with JSON reports
- Makefile and uv workflow for repeatable local commands

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
evals/                   # pytest-style evaluation cases and JSON reports
docker/                  # Prometheus and Grafana configuration
infra/aws/               # AWS-ready templates and deployment notes
```

## Getting Started

### Prerequisites

- Python 3.11+
- uv
- Docker + Docker Compose
- Ollama for local LLM reasoning and embeddings
- PostgreSQL with pgvector for vector search
- Redis for session memory

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
uv sync
```

Create environment file:

```bash
cp .env.example .env
```

Run locally:

```bash
make dev
```

Swagger docs available at:

```text
http://localhost:8000/docs
```

Useful endpoints:

```text
POST /api/auth/token
GET  /api/health
GET  /api/sample-alert
POST /api/investigate
GET  /api/sessions/{session_id}/memory
GET  /api/metrics
```

Run the sample investigation:

```bash
make sample
```

Index the local security knowledge base into pgvector:

```bash
make ingest
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
Ollama     -> http://localhost:11434
Redis      -> localhost:6379
```

Grafana default login:

```text
admin / admin
```

## Testing

Run automated tests:

```bash
make test
```

The test suite validates:

- Sample alert investigation workflow
- FastAPI investigation endpoint
- Risk scoring and verdict generation
- Presence of references and remediation actions
- JWT authentication and session memory
- LangGraph workflow compilation

Run evaluation cases:

```bash
make eval
```

Reports are generated in:

```text
evals/reports/
```

## AWS Deployment Setup

AWS-ready templates live in:

```text
infra/aws/
```

These files are free to keep in the repo. They only cost money if you intentionally create AWS resources, for example by running Terraform apply or deploying ECS/RDS/ElastiCache resources.

## Future Improvements

- Add real SIEM integrations such as Splunk, Microsoft Sentinel, and Elastic
- Add IAM integrations such as Okta, Entra ID, and Google Workspace
- Add larger security evaluation datasets
- Add analyst feedback loops for risk scoring calibration
- Persist investigation history in PostgreSQL
- Add Slack, Jira, and PagerDuty handoff actions

## Acknowledgements

Built as a SOC-focused AI incident investigation project using FastAPI, LangGraph, RAG, pgvector-ready storage, and monitoring patterns for production security workflows.
