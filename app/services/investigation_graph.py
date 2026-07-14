from __future__ import annotations

import time

from app.agents.enrichment import ThreatEnrichmentAgent
from app.agents.evidence import EvidenceCollectorAgent
from app.agents.remediation import RemediationRecommenderAgent
from app.agents.triage import AlertTriageAgent
from app.core.config import get_settings
from app.core.telemetry import INVESTIGATION_DURATION, INVESTIGATIONS_TOTAL
from app.models.schemas import (
    InvestigationReport,
    RemediationStep,
    SecurityAlert,
    Verdict,
)
from app.models.state import InvestigationState
from app.rag.retriever import SecurityKnowledgeRetriever


class InvestigationGraph:
    """Deterministic orchestration that mirrors a LangGraph-style state transition flow."""

    def __init__(self, retriever: SecurityKnowledgeRetriever | None = None):
        self.retriever = retriever or SecurityKnowledgeRetriever()
        self.agents = [
            AlertTriageAgent(),
            ThreatEnrichmentAgent(),
            EvidenceCollectorAgent(),
            RemediationRecommenderAgent(),
        ]

    def investigate(self, alert: SecurityAlert) -> InvestigationReport:
        started = time.perf_counter()
        state = InvestigationState(alert=alert)
        state.references = self.retriever.retrieve_for_alert(alert)
        state.timeline.append(f"Retrieved {len(state.references)} relevant knowledge base documents.")

        for agent in self.agents:
            state = agent.run(state)

        state.risk_score = max(0, min(state.risk_score, 100))
        verdict = self._verdict_for_score(state.risk_score)
        report = InvestigationReport(
            alert=alert,
            verdict=verdict,
            risk_score=state.risk_score,
            executive_summary=self._summary(alert, verdict, state.risk_score),
            timeline=state.timeline,
            findings=state.findings,
            evidence=state.evidence,
            recommended_actions=self._build_actions(state),
            references=state.references,
        )

        INVESTIGATIONS_TOTAL.labels(severity=alert.severity.value, verdict=verdict.value).inc()
        INVESTIGATION_DURATION.observe(time.perf_counter() - started)
        return report

    @staticmethod
    def _verdict_for_score(score: int) -> Verdict:
        settings = get_settings()
        if score >= settings.risk_threshold_high + 15:
            return Verdict.confirmed_incident
        if score >= settings.risk_threshold_high:
            return Verdict.likely_compromise
        if score >= settings.risk_threshold_medium:
            return Verdict.suspicious
        return Verdict.benign

    @staticmethod
    def _summary(alert: SecurityAlert, verdict: Verdict, score: int) -> str:
        target = alert.user or alert.host or "the affected asset"
        return (
            f"{alert.title} for {target} is assessed as {verdict.value.replace('_', ' ')} "
            f"with risk score {score}/100. The strongest indicators are identity anomaly, "
            "source infrastructure context, and post-authentication activity."
        )

    @staticmethod
    def _build_actions(state: InvestigationState) -> list[RemediationStep]:
        action_text = state.enrichment.get("recommended_action_text", [])
        if not isinstance(action_text, list):
            action_text = []

        actions = []
        for index, action in enumerate(action_text, start=1):
            owner = "Identity Engineering" if "MFA" in action or "password" in action else "SOC"
            actions.append(
                RemediationStep(
                    priority=min(index, 5),
                    action=action,
                    owner=owner,
                    rationale="Aligned to retrieved identity incident response playbooks and observed evidence.",
                )
            )
        return actions
