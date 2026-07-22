from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AlertSeverity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentDomain(StrEnum):
    security = "security"
    production = "production"
    cloud = "cloud"
    data = "data"
    it = "it"


class UserRole(StrEnum):
    security_analyst = "security_analyst"
    sre = "sre"
    data_engineer = "data_engineer"
    it_ops = "it_ops"
    admin = "admin"


class IntegrationType(StrEnum):
    splunk = "splunk"
    sentinel = "sentinel"
    okta = "okta"
    crowdstrike = "crowdstrike"
    datadog = "datadog"
    grafana_loki = "grafana_loki"
    cloudwatch = "cloudwatch"
    jira = "jira"
    servicenow = "servicenow"
    slack = "slack"


class Verdict(StrEnum):
    benign = "benign"
    suspicious = "suspicious"
    likely_compromise = "likely_compromise"
    confirmed_incident = "confirmed_incident"


class IncidentStatus(StrEnum):
    informational = "informational"
    investigating = "investigating"
    degraded = "degraded"
    major_incident = "major_incident"
    resolved = "resolved"


class SecurityAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    severity: AlertSeverity = AlertSeverity.medium
    source: str = "siem"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    user: str | None = None
    host: str | None = None
    ip_address: str | None = None
    geo: str | None = None
    tactic: str | None = None
    technique: str | None = None
    raw_events: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    description: str = ""


class IncidentInput(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    domain: IncidentDomain = IncidentDomain.production
    severity: AlertSeverity = AlertSeverity.medium
    source: str = "manual"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    service: str | None = None
    environment: str | None = None
    owner_team: str | None = None
    description: str = ""
    logs: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class IngestDocumentRequest(BaseModel):
    title: str
    content: str
    source: str
    domain: IncidentDomain
    team: str | None = None
    service: str | None = None
    tags: list[str] = Field(default_factory=list)
    chunk_size: int = Field(default=900, ge=200, le=4000)
    chunk_overlap: int = Field(default=120, ge=0, le=1000)


class IngestLogsRequest(BaseModel):
    source: str
    domain: IncidentDomain
    logs: list[str]
    title: str = "Uploaded incident logs"
    team: str | None = None
    service: str | None = None
    tags: list[str] = Field(default_factory=list)
    chunk_size: int = Field(default=1200, ge=200, le=5000)
    chunk_overlap: int = Field(default=100, ge=0, le=1000)


class IngestedChunk(BaseModel):
    id: str
    document_id: str
    chunk_index: int
    title: str
    source: str
    domain: IncidentDomain
    team: str | None = None
    service: str | None = None
    created_at: datetime


class IngestionResponse(BaseModel):
    document_id: str
    chunks: list[IngestedChunk]
    stored_in_pgvector: bool


class RetrievedDocument(BaseModel):
    id: str
    title: str
    source: str
    score: float
    content: str
    tags: list[str] = Field(default_factory=list)
    domain: IncidentDomain | None = None
    team: str | None = None
    service: str | None = None
    created_at: datetime | None = None


class AgentFinding(BaseModel):
    agent: str
    summary: str
    risk_delta: int = 0
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    references: list[RetrievedDocument] = Field(default_factory=list)


class LLMReasoningResult(BaseModel):
    summary: str
    likely_causes: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.65, ge=0, le=1)


class EvidenceItem(BaseModel):
    kind: str
    description: str
    value: str
    weight: int = 0


class RemediationStep(BaseModel):
    priority: int = Field(ge=1, le=5)
    action: str
    owner: str = "SOC"
    rationale: str


class InvestigationReport(BaseModel):
    investigation_id: UUID = Field(default_factory=uuid4)
    alert: SecurityAlert
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    executive_summary: str
    timeline: list[str]
    findings: list[AgentFinding]
    evidence: list[EvidenceItem]
    recommended_actions: list[RemediationStep]
    references: list[RetrievedDocument]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IncidentReport(BaseModel):
    investigation_id: UUID = Field(default_factory=uuid4)
    incident: IncidentInput
    status: IncidentStatus
    risk_score: int = Field(ge=0, le=100)
    executive_summary: str
    timeline: list[str]
    findings: list[AgentFinding]
    evidence: list[EvidenceItem]
    recommended_actions: list[RemediationStep]
    references: list[RetrievedDocument]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StoredReportSummary(BaseModel):
    investigation_id: UUID
    domain: IncidentDomain
    title: str
    status: str
    risk_score: int
    created_at: datetime


class PostmortemReport(BaseModel):
    investigation_id: UUID
    title: str
    summary: str
    impact: str
    timeline: list[str]
    root_cause_hypothesis: str
    contributing_factors: list[str]
    corrective_actions: list[RemediationStep]
    owners: list[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IntegrationConfigRequest(BaseModel):
    integration_type: IntegrationType
    name: str
    base_url: str | None = None
    enabled: bool = True
    default_domain: IncidentDomain | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationConfigResponse(IntegrationConfigRequest):
    id: str
    status: str


class MCPToolManifest(BaseModel):
    name: str
    description: str
    domains: list[IncidentDomain]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    mode: str = "local"
    external_integration: IntegrationType | None = None


class MCPToolCallRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    incident: IncidentInput | None = None
    alert: SecurityAlert | None = None


class MCPToolCallResponse(BaseModel):
    tool_name: str
    mode: str
    status: str
    result: dict[str, Any]
    duration_ms: float


class AgentManifest(BaseModel):
    name: str
    domain: IncidentDomain
    endpoint: str
    capabilities: list[str]
    accepts: list[str]
    produces: list[str]
    mode: str = "local"


class AgentHandoffRequest(BaseModel):
    source_agent: str = "langgraph_router"
    target_agent: str
    incident: IncidentInput
    context: dict[str, Any] = Field(default_factory=dict)


class AgentHandoffResponse(BaseModel):
    source_agent: str
    target_agent: str
    domain: IncidentDomain
    status: str
    summary: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommended_actions: list[RemediationStep] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float


class PlatformMetricsSnapshot(BaseModel):
    mcp_tools_available: int
    a2a_agents_available: int
    advertised_capabilities: int
    integration_ready_tools: int
    local_tool_calls_supported: int
    operational_workflows: int
    automated_response_steps: list[str]


class InvestigationRequest(BaseModel):
    alert: SecurityAlert
    include_references: bool = True
    session_id: str | None = None
    analyst_id: str | None = None


class IncidentInvestigationRequest(BaseModel):
    incident: IncidentInput
    include_references: bool = True
    session_id: str | None = None
    analyst_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    app: str
    env: str


class SessionMemoryResponse(BaseModel):
    session_id: str
    messages: list[dict[str, str]]
