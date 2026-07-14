from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.schemas import AgentFinding, EvidenceItem, IncidentInput, RetrievedDocument


class GenericIncidentState(BaseModel):
    incident: IncidentInput
    risk_score: int = 0
    timeline: list[str] = Field(default_factory=list)
    findings: list[AgentFinding] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    references: list[RetrievedDocument] = Field(default_factory=list)
    enrichment: dict[str, str | int | bool | list[str]] = Field(default_factory=dict)
