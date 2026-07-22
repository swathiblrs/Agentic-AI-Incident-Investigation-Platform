from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.models.schemas import (
    AgentFinding,
    EvidenceItem,
    RetrievedDocument,
    SecurityAlert,
)


class InvestigationState(BaseModel):
    alert: SecurityAlert
    risk_score: int = 0
    timeline: list[str] = Field(default_factory=list)
    findings: list[AgentFinding] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    references: list[RetrievedDocument] = Field(default_factory=list)
    enrichment: dict[str, Any] = Field(default_factory=dict)
