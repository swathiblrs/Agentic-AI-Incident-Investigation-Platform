# 🚨 AI Incident Investigation Platform

A production-ready multi-domain incident investigation system that helps security, SRE, cloud, data, and IT teams investigate alerts, logs, metrics, traces, runbooks, and historical incidents using LangGraph + Retrieval Augmented Generation (RAG).

## 🌟 Why this project exists

During incidents, teams spend valuable time searching logs, dashboards, tickets, runbooks, security playbooks, and past incidents to understand what happened and what to do next.

This system acts as an AI copilot for incident investigation, helping reduce triage time and improve response consistency across operational domains.

The platform can:

- Analyze security alerts, production errors, cloud events, data pipeline failures, and IT incidents
- Retrieve relevant runbooks, security playbooks, MITRE ATT&CK notes, and past incidents
- Route incidents through domain-specific LangGraph workflows
- Upload logs and runbooks through the API for chunking, embeddings, and retrieval
- Collect evidence from logs, metrics, events, and alert payloads
- Produce structured reports with risk/status, timeline, evidence, references, and recommended actions
- Generate postmortems after investigations
- Maintain conversation memory across analyst sessions

## 🏗️ Architecture Overview

High level workflow:

Incident alert, logs, metrics, or SIEM events  
-> LangGraph orchestration  
-> RAG pipeline retrieves relevant runbooks, playbooks, incidents, and ATT&CK notes  
-> Domain-specific investigation nodes reason over evidence and references  
-> Structured incident response report

Core stack:

- FastAPI for API backend
- LangGraph for multi-step investigation workflows
- Ollama for local LLM reasoning and embeddings with deterministic fallback
- Optional OpenAI-compatible and Anthropic-compatible LLM provider switching
- Bounded exponential retry with jitter for transient LLM provider failures
- PostgreSQL + pgvector for vector search
- Redis for session memory and caching
- JWT authentication for protected investigation endpoints
- Optional Langfuse tracing for LLM and investigation observability
- Pydantic models for structured investigation reports
- Prometheus + Grafana for monitoring
- Docker for local containerization
- AWS-ready deployment templates that cost nothing until applied
- Lightweight built-in dashboard at `/api/dashboard`

## 🌐 Supported Domains

| Domain | Example Question | Output Focus |
|---|---|---|
| 🔐 Security | "Is this login anomaly a real account takeover?" | Verdict, risk score, evidence, containment |
| 🛠️ Production / SRE | "Why is checkout returning 503 errors?" | Status, impact, likely causes, mitigation |
| ☁️ Cloud Infrastructure | "Why did capacity drop in this cluster?" | Cloud events, quotas, routing, failover |
| 🧬 Data Engineering | "Why did this pipeline fail or drift?" | Freshness, schema, quality, backfill steps |
| 🖥️ IT Operations | "Why are users unable to access VPN or email?" | User impact, access path, workaround, escalation |

## 🤖 Key Features

### 🧭 Multi-Domain LangGraph Workflows

- Security-specific workflow for alert triage, threat enrichment, evidence collection, and remediation
- Generic incident workflow for production, cloud, data, and IT incidents
- Conditional domain routing through SOC, SRE, cloud, data, and IT graph paths
- Low-risk incidents can skip live LLM reasoning; high-risk incidents add escalation recommendations
- Domain-specific status or verdict generation
- RAG-grounded reasoning before response recommendations
- Conversation memory per analyst session using Redis with in-memory fallback

### 🧠 Retrieval Augmented Generation Pipeline

This project uses a RAG-style pipeline to ground investigations in operational knowledge.

- Security playbooks and MITRE ATT&CK notes
- Production incident runbooks
- Cloud infrastructure runbooks
- Data pipeline runbooks
- IT operations runbooks
- Past incident archive examples
- Ollama embedding generation for local semantic indexing
- PostgreSQL + pgvector retrieval runtime
- API ingestion for uploaded logs and runbooks
- Local in-memory searchable fallback for uploaded chunks when Postgres is disabled
- Knowledge-base ingestion script for indexing playbooks and runbooks

### ⚙️ Production Backend

- FastAPI REST API
- JWT token endpoint and protected investigation routes
- Role-based access control for `security_analyst`, `sre`, `data_engineer`, `it_ops`, and `admin`
- Report persistence with Postgres support and in-memory fallback
- Async Postgres connection pooling for report and ingestion writes
- Integration registry stubs for Splunk, Sentinel, Okta, CrowdStrike, Datadog, Loki, CloudWatch, Jira, ServiceNow, and Slack
- Postmortem generation from stored reports
- Typed request and response models
- Health and metrics endpoints
- Input validation with Pydantic
- Structured investigation reports
- Docker Compose setup for API, Postgres, Redis, Ollama, Prometheus, Grafana, and optional Langfuse

### 📊 Observability & Evaluation

- Prometheus metrics endpoint
- Investigation count and duration metrics
- Per-node execution duration metrics
- Grafana provisioning included
- Optional Langfuse tracing endpoint configuration
- pytest-based evaluation framework with JSON reports
- 12 cross-domain eval cases covering expected status/verdict, evidence, and actions

### ⚡ Performance & Reliability

- Docker Compose setup for local services
- Redis-backed session memory with in-memory fallback
- Ollama calls automatically fall back to deterministic local reasoning when Ollama is unavailable
- LLM provider calls use retry/backoff before falling back
- Makefile and uv workflow for repeatable local commands
- AWS-ready deployment templates under `infra/aws/`
- API dashboard for submitting incidents, viewing reports, copying actions, and browsing stored investigations

## 💡 Example Use Cases

Example investigations:

- "Is this impossible-travel login a real account takeover?"
- "Checkout is returning 503 errors after a deploy. What should we check first?"
- "A cloud autoscaling event coincided with elevated latency. What changed?"
- "A data pipeline failed quality checks. Should downstream consumers be paused?"
- "Users cannot access VPN. What evidence should IT collect?"

The platform retrieves relevant runbook sections and produces structured investigation guidance with evidence, risk or status, references, and recommended actions.

## 📂 Project Structure

```text
app/
 ├── api/                # FastAPI REST endpoints
 ├── agents/             # Security investigation agents
 ├── core/               # App settings, security, and telemetry
 ├── data/
 │    ├── knowledge_base/ # Security, production, cloud, data, and IT runbooks
 │    └── sample_alerts/  # Demo security and production incidents
 ├── models/             # Pydantic schemas and LangGraph state models
 ├── rag/                # Retrieval pipeline and uploaded in-memory document store
 ├── services/           # Workflows, ingestion, persistence, integrations, postmortems
 └── storage/            # PostgreSQL + pgvector schema and runtime adapter

scripts/                 # CLI demo and ingestion scripts
evals/                   # Evaluation cases and JSON reports
docker/                  # Prometheus and Grafana configuration
infra/aws/               # AWS-ready templates and deployment notes
```

## 🚀 Getting Started

### ✅ Prerequisites

- Python 3.11+
- uv
- Docker + Docker Compose
- Ollama for local LLM reasoning and embeddings
- PostgreSQL with pgvector for vector search
- Redis for session memory

### 🔧 Local Setup

Clone the repo:

```bash
git clone https://github.com/swathiblrs/AI-Security-Alert-Investigation-Agent.git
cd AI-Security-Alert-Investigation-Agent
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
POST /api/incidents/investigate
POST /api/ingest/document
POST /api/ingest/logs
GET  /api/reports
POST /api/reports/{investigation_id}/postmortem
POST /api/integrations
GET  /api/sessions/{session_id}/memory
GET  /api/metrics
GET  /api/dashboard
```

Run sample investigations:

```bash
make sample
```

Index the local knowledge base into pgvector:

```bash
make ingest
```

## 🐳 Run with Docker

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

## 🧪 Testing

Run automated tests:

```bash
make test
```

The test suite validates:

- Security alert investigation workflow
- Generic production incident workflow
- FastAPI investigation endpoints
- Document ingestion and local retrieval support
- Report persistence and postmortem generation
- Integration registry behavior
- Role-based access control
- Risk/status generation
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

## ☁️ AWS Deployment Setup

AWS-ready templates live in:

```text
infra/aws/
```

These files are free to keep in the repo. They only cost money if you intentionally create AWS resources, for example by running Terraform apply or deploying ECS/RDS/ElastiCache resources.

## 🔮 Future Improvements

- Replace integration stubs with live vendor adapters and OAuth/secret management
- Add larger multi-domain evaluation datasets from real incident templates
- Add analyst feedback loops for domain-specific scoring calibration
- Add richer frontend filtering, charts, and collaborative incident rooms
- Add full Terraform ECS/RDS/ElastiCache modules when ready to deploy

## 🙌 Acknowledgements

Built as a multi-domain incident investigation project using FastAPI, LangGraph, RAG, Ollama, pgvector-ready storage, Redis session memory, and monitoring patterns for security and operations workflows.
