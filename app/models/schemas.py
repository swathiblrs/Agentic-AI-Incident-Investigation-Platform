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


class Verdict(StrEnum):
    benign = "benign"
    suspicious = "suspicious"
    likely_compromise = "likely_compromise"
    confirmed_incident = "confirmed_incident"


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


class RetrievedDocument(BaseModel):
    id: str
    title: str
    source: str
    score: float
    content: str
    tags: list[str] = Field(default_factory=list)


class AgentFinding(BaseModel):
    agent: str
    summary: str
    risk_delta: int = 0
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    references: list[RetrievedDocument] = Field(default_factory=list)


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


class InvestigationRequest(BaseModel):
    alert: SecurityAlert
    include_references: bool = True


class HealthResponse(BaseModel):
    status: str
    app: str
    env: str
