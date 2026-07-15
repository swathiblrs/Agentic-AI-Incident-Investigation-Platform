from __future__ import annotations

import time

from langgraph.graph import END, START, StateGraph

from app.agents.enrichment import ThreatEnrichmentAgent
from app.agents.evidence import EvidenceCollectorAgent
from app.agents.remediation import RemediationRecommenderAgent
from app.agents.triage import AlertTriageAgent
from app.core.config import get_settings
from app.core.telemetry import INVESTIGATION_DURATION, INVESTIGATIONS_TOTAL
from app.models.schemas import (
    AgentFinding,
    InvestigationReport,
    RemediationStep,
    SecurityAlert,
    Verdict,
)
from app.models.state import InvestigationState
from app.rag.retriever import SecurityKnowledgeRetriever
from app.services.langgraph_checkpoint import LangGraphCheckpointManager
from app.services.llm import OllamaService
from app.services.tracing import LangfuseTracer


class InvestigationGraph:
    """LangGraph orchestration for the RAG-grounded security investigation workflow."""

    def __init__(self, retriever: SecurityKnowledgeRetriever | None = None):
        self.retriever = retriever or SecurityKnowledgeRetriever()
        self.llm = OllamaService()
        self.tracer = LangfuseTracer()
        self.checkpoints = LangGraphCheckpointManager()
        self._checkpoint_graph = None
        self.triage_agent = AlertTriageAgent()
        self.enrichment_agent = ThreatEnrichmentAgent()
        self.evidence_agent = EvidenceCollectorAgent()
        self.remediation_agent = RemediationRecommenderAgent()
        self.graph = self._build_graph()

    def investigate(self, alert: SecurityAlert) -> InvestigationReport:
        started = time.perf_counter()
        state = InvestigationState(alert=alert)
        state = InvestigationState.model_validate(self.graph.invoke(state))

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

        self.tracer.trace_investigation(report)
        INVESTIGATIONS_TOTAL.labels(severity=alert.severity.value, verdict=verdict.value).inc()
        INVESTIGATION_DURATION.observe(time.perf_counter() - started)
        return report

    async def investigate_async(
        self,
        alert: SecurityAlert,
        *,
        session_id: str | None = None,
    ) -> InvestigationReport:
        if not session_id:
            return self.investigate(alert)

        started = time.perf_counter()
        if self._checkpoint_graph is None:
            self._checkpoint_graph = await self.checkpoints.compile_with_checkpointer(
                self._build_graph_builder,
                graph_name="security-investigation",
            )
        compiled_graph = self._checkpoint_graph or self.graph
        state = InvestigationState.model_validate(
            await compiled_graph.ainvoke(
                InvestigationState(alert=alert),
                config={"configurable": {"thread_id": session_id}},
            )
        )
        report = self._report_from_state(state)
        INVESTIGATION_DURATION.observe(time.perf_counter() - started)
        return report

    def _build_graph(self):
        return self._build_graph_builder().compile()

    def _build_graph_builder(self):
        graph = StateGraph(InvestigationState)
        graph.add_node("retrieve_context", self._retrieve_context)
        graph.add_node("alert_triage", self.triage_agent.run)
        graph.add_node("threat_enrichment", self.enrichment_agent.run)
        graph.add_node("evidence_collection", self.evidence_agent.run)
        graph.add_node("llm_reasoning", self._llm_reasoning)
        graph.add_node("remediation_recommendation", self.remediation_agent.run)

        graph.add_edge(START, "retrieve_context")
        graph.add_edge("retrieve_context", "alert_triage")
        graph.add_edge("alert_triage", "threat_enrichment")
        graph.add_edge("threat_enrichment", "evidence_collection")
        graph.add_edge("evidence_collection", "llm_reasoning")
        graph.add_edge("llm_reasoning", "remediation_recommendation")
        graph.add_edge("remediation_recommendation", END)
        return graph

    def _report_from_state(self, state: InvestigationState) -> InvestigationReport:
        state.risk_score = max(0, min(state.risk_score, 100))
        verdict = self._verdict_for_score(state.risk_score)
        report = InvestigationReport(
            alert=state.alert,
            verdict=verdict,
            risk_score=state.risk_score,
            executive_summary=self._summary(state.alert, verdict, state.risk_score),
            timeline=state.timeline,
            findings=state.findings,
            evidence=state.evidence,
            recommended_actions=self._build_actions(state),
            references=state.references,
        )
        self.tracer.trace_investigation(report)
        INVESTIGATIONS_TOTAL.labels(severity=state.alert.severity.value, verdict=verdict.value).inc()
        return report

    def _retrieve_context(self, state: InvestigationState) -> InvestigationState:
        state.references = self.retriever.retrieve_for_alert(state.alert)
        state.timeline.append(f"Retrieved {len(state.references)} relevant knowledge base documents.")
        return state

    def _llm_reasoning(self, state: InvestigationState) -> InvestigationState:
        analysis = self.llm.analyze_alert(state.alert, state.references)
        state.timeline.append("LLM reasoning generated a grounded investigation assessment.")
        state.findings.append(
            AgentFinding(
                agent="llm_reasoning",
                summary=analysis.summary,
                risk_delta=0,
                confidence=analysis.confidence,
                evidence=[*analysis.likely_causes, *analysis.recommended_next_steps],
                references=state.references[:3],
            )
        )
        return state

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
