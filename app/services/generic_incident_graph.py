from __future__ import annotations

import time

from langgraph.graph import END, START, StateGraph

from app.core.telemetry import INVESTIGATION_DURATION
from app.models.generic_state import GenericIncidentState
from app.models.schemas import (
    AgentFinding,
    AlertSeverity,
    EvidenceItem,
    IncidentDomain,
    IncidentInput,
    IncidentReport,
    IncidentStatus,
    RemediationStep,
)
from app.rag.retriever import SecurityKnowledgeRetriever
from app.services.langgraph_checkpoint import LangGraphCheckpointManager
from app.services.llm import OllamaService
from app.services.tracing import LangfuseTracer


class GenericIncidentGraph:
    """LangGraph + RAG workflow for non-security and multi-domain incidents."""

    def __init__(self, retriever: SecurityKnowledgeRetriever | None = None) -> None:
        self.retriever = retriever or SecurityKnowledgeRetriever()
        self.llm = OllamaService()
        self.tracer = LangfuseTracer()
        self.checkpoints = LangGraphCheckpointManager()
        self._checkpoint_graph = None
        self.graph = self._build_graph()

    def investigate(self, incident: IncidentInput) -> IncidentReport:
        started = time.perf_counter()
        state = GenericIncidentState.model_validate(
            self.graph.invoke(GenericIncidentState(incident=incident))
        )
        state.risk_score = max(0, min(state.risk_score, 100))
        status = self._status_for_score(state.risk_score)
        report = IncidentReport(
            incident=incident,
            status=status,
            risk_score=state.risk_score,
            executive_summary=self._summary(incident, status, state.risk_score),
            timeline=state.timeline,
            findings=state.findings,
            evidence=state.evidence,
            recommended_actions=self._build_actions(state),
            references=state.references,
        )
        INVESTIGATION_DURATION.observe(time.perf_counter() - started)
        return report

    async def investigate_async(
        self,
        incident: IncidentInput,
        *,
        session_id: str | None = None,
    ) -> IncidentReport:
        if not session_id:
            return self.investigate(incident)

        started = time.perf_counter()
        if self._checkpoint_graph is None:
            self._checkpoint_graph = await self.checkpoints.compile_with_checkpointer(
                self._build_graph_builder,
                graph_name=f"{incident.domain.value}-incident-investigation",
            )
        compiled_graph = self._checkpoint_graph or self.graph
        state = GenericIncidentState.model_validate(
            await compiled_graph.ainvoke(
                GenericIncidentState(incident=incident),
                config={"configurable": {"thread_id": session_id}},
            )
        )
        report = self._report_from_state(state)
        INVESTIGATION_DURATION.observe(time.perf_counter() - started)
        return report

    def _build_graph(self):
        return self._build_graph_builder().compile()

    def _build_graph_builder(self):
        graph = StateGraph(GenericIncidentState)
        graph.add_node("retrieve_context", self._retrieve_context)
        graph.add_node("classify_incident", self._classify_incident)
        graph.add_node("soc_path", self._domain_path("SOC security"))
        graph.add_node("sre_path", self._domain_path("SRE production"))
        graph.add_node("cloud_path", self._domain_path("cloud infrastructure"))
        graph.add_node("data_path", self._domain_path("data engineering"))
        graph.add_node("it_path", self._domain_path("IT operations"))
        graph.add_node("collect_evidence", self._collect_evidence)
        graph.add_node("llm_reasoning", self._llm_reasoning)
        graph.add_node("recommend_response", self._recommend_response)

        graph.add_edge(START, "retrieve_context")
        graph.add_edge("retrieve_context", "classify_incident")
        graph.add_conditional_edges(
            "classify_incident",
            self._route_domain,
            {
                "soc_path": "soc_path",
                "sre_path": "sre_path",
                "cloud_path": "cloud_path",
                "data_path": "data_path",
                "it_path": "it_path",
            },
        )
        for node in ("soc_path", "sre_path", "cloud_path", "data_path", "it_path"):
            graph.add_edge(node, "collect_evidence")
        graph.add_conditional_edges(
            "collect_evidence",
            self._route_after_evidence,
            {"llm_reasoning": "llm_reasoning", "recommend_response": "recommend_response"},
        )
        graph.add_edge("llm_reasoning", "recommend_response")
        graph.add_edge("recommend_response", END)
        return graph

    def _report_from_state(self, state: GenericIncidentState) -> IncidentReport:
        state.risk_score = max(0, min(state.risk_score, 100))
        status = self._status_for_score(state.risk_score)
        return IncidentReport(
            incident=state.incident,
            status=status,
            risk_score=state.risk_score,
            executive_summary=self._summary(state.incident, status, state.risk_score),
            timeline=state.timeline,
            findings=state.findings,
            evidence=state.evidence,
            recommended_actions=self._build_actions(state),
            references=state.references,
        )

    def _retrieve_context(self, state: GenericIncidentState) -> GenericIncidentState:
        state.references = self.retriever.retrieve_for_incident(state.incident)
        state.timeline.append(
            f"Retrieved {len(state.references)} documents for {state.incident.domain.value} incident context."
        )
        return state

    def _classify_incident(self, state: GenericIncidentState) -> GenericIncidentState:
        incident = state.incident
        score = {
            AlertSeverity.low: 10,
            AlertSeverity.medium: 25,
            AlertSeverity.high: 45,
            AlertSeverity.critical: 65,
        }[incident.severity]

        text = self._combined_text(incident)
        signals = []
        signal_weights = {
            "error": 8,
            "timeout": 10,
            "503": 15,
            "failed": 10,
            "latency": 8,
            "cpu": 8,
            "memory": 8,
            "data loss": 25,
            "customer impact": 18,
            "pipeline": 10,
            "drift": 12,
        }
        for signal, weight in signal_weights.items():
            if signal in text:
                score += weight
                signals.append(signal)

        if incident.domain == IncidentDomain.security:
            score += 10
        if incident.metrics:
            score += min(len(incident.metrics) * 3, 12)
            signals.append("metrics attached")

        state.risk_score += score
        state.enrichment["classification_signals"] = signals
        state.timeline.append(f"Classified {incident.domain.value} incident at initial risk {score}.")
        state.findings.append(
            AgentFinding(
                agent="classify_incident",
                summary=f"Detected {', '.join(signals) or 'limited explicit failure signals'}.",
                risk_delta=score,
                confidence=0.74,
                evidence=signals,
                references=state.references[:2],
            )
        )
        return state

    def _collect_evidence(self, state: GenericIncidentState) -> GenericIncidentState:
        incident = state.incident
        for index, log in enumerate(incident.logs, start=1):
            weight = 10 if any(token in log.lower() for token in ("error", "failed", "timeout", "503")) else 4
            state.evidence.append(
                EvidenceItem(kind="log", description=f"Log line {index}", value=log, weight=weight)
            )
            state.risk_score += min(weight, 10)

        for key, value in incident.metrics.items():
            state.evidence.append(
                EvidenceItem(kind="metric", description=key, value=str(value), weight=6)
            )
            state.risk_score += 4

        for event in incident.events:
            state.evidence.append(
                EvidenceItem(kind="event", description=str(event.get("event", "event")), value=str(event), weight=6)
            )
            state.risk_score += 4

        state.timeline.append(
            f"Collected {len(incident.logs)} logs, {len(incident.metrics)} metrics, and {len(incident.events)} events."
        )
        state.findings.append(
            AgentFinding(
                agent="collect_evidence",
                summary="Normalized incident evidence across logs, metrics, and events.",
                risk_delta=0,
                confidence=0.8,
                evidence=[item.description for item in state.evidence[-6:]],
                references=state.references[:2],
            )
        )
        return state

    def _llm_reasoning(self, state: GenericIncidentState) -> GenericIncidentState:
        pseudo_alert = self._incident_to_security_alert(state.incident)
        analysis = self.llm.analyze_alert(pseudo_alert, state.references, domain=state.incident.domain)
        state.timeline.append("LLM reasoning generated a grounded multi-domain assessment.")
        state.findings.append(
            AgentFinding(
                agent="llm_reasoning",
                summary=analysis.summary,
                confidence=analysis.confidence,
                evidence=[*analysis.likely_causes, *analysis.recommended_next_steps],
                references=state.references[:3],
            )
        )
        return state

    def _recommend_response(self, state: GenericIncidentState) -> GenericIncidentState:
        actions = {
            IncidentDomain.production: [
                "Check recent deploys, feature flags, and dependency changes for the affected service.",
                "Inspect dashboards for error rate, latency, saturation, and upstream/downstream failures.",
                "Mitigate customer impact through rollback, traffic shift, scaling, or circuit breaking.",
            ],
            IncidentDomain.cloud: [
                "Inspect cloud service health, quotas, autoscaling events, and infrastructure changes.",
                "Check load balancer, network, IAM, and managed database events for correlated failures.",
                "Apply temporary capacity, routing, or failover mitigation while preserving evidence.",
            ],
            IncidentDomain.data: [
                "Pause downstream consumers if data correctness is uncertain.",
                "Inspect pipeline runs, schema changes, source freshness, and quality checks.",
                "Backfill or replay from the last known good checkpoint after root cause validation.",
            ],
            IncidentDomain.it: [
                "Confirm user impact scope and affected access path.",
                "Check identity, device, VPN, email, and network service health.",
                "Publish workaround guidance and escalate to the owning IT service team.",
            ],
            IncidentDomain.security: [
                "Preserve security evidence and identify affected users, hosts, and source infrastructure.",
                "Contain suspected compromise through account, token, host, or network controls.",
                "Open a formal incident response case if attacker activity is confirmed.",
            ],
        }[state.incident.domain]
        state.enrichment["recommended_action_text"] = actions
        if state.risk_score >= 85:
            actions.insert(0, "Escalate to the incident commander and notify the owning response channel.")
        state.timeline.append("Prepared domain-specific response recommendations.")
        return state

    @staticmethod
    def _route_domain(state: GenericIncidentState) -> str:
        return {
            IncidentDomain.security: "soc_path",
            IncidentDomain.production: "sre_path",
            IncidentDomain.cloud: "cloud_path",
            IncidentDomain.data: "data_path",
            IncidentDomain.it: "it_path",
        }[state.incident.domain]

    @staticmethod
    def _domain_path(label: str):
        def route(state: GenericIncidentState) -> GenericIncidentState:
            state.timeline.append(f"Routed incident through {label} investigation path.")
            state.enrichment["domain_path"] = label
            return state

        return route

    @staticmethod
    def _route_after_evidence(state: GenericIncidentState) -> str:
        if state.risk_score < 35:
            state.timeline.append("Skipped live LLM reasoning for low-risk incident path.")
            return "recommend_response"
        return "llm_reasoning"

    @staticmethod
    def _status_for_score(score: int) -> IncidentStatus:
        if score >= 85:
            return IncidentStatus.major_incident
        if score >= 60:
            return IncidentStatus.degraded
        if score >= 35:
            return IncidentStatus.investigating
        return IncidentStatus.informational

    @staticmethod
    def _summary(incident: IncidentInput, status: IncidentStatus, score: int) -> str:
        target = incident.service or incident.owner_team or incident.domain.value
        return (
            f"{incident.title} affecting {target} is assessed as {status.value.replace('_', ' ')} "
            f"with risk score {score}/100. The report combines RAG context, logs, metrics, events, "
            "and domain-specific response guidance."
        )

    @staticmethod
    def _build_actions(state: GenericIncidentState) -> list[RemediationStep]:
        actions = state.enrichment.get("recommended_action_text", [])
        if not isinstance(actions, list):
            actions = []
        owner = state.incident.owner_team or {
            IncidentDomain.security: "SOC",
            IncidentDomain.production: "SRE",
            IncidentDomain.cloud: "Cloud Platform",
            IncidentDomain.data: "Data Engineering",
            IncidentDomain.it: "IT Operations",
        }[state.incident.domain]
        return [
            RemediationStep(
                priority=min(index, 5),
                action=action,
                owner=owner,
                rationale=f"Recommended for {state.incident.domain.value} incident response.",
            )
            for index, action in enumerate(actions, start=1)
        ]

    @staticmethod
    def _combined_text(incident: IncidentInput) -> str:
        return " ".join(
            [
                incident.title,
                incident.description,
                " ".join(incident.logs),
                " ".join(str(event) for event in incident.events),
                " ".join(str(value) for value in incident.metrics.values()),
            ]
        ).lower()

    @staticmethod
    def _incident_to_security_alert(incident: IncidentInput):
        from app.models.schemas import SecurityAlert

        return SecurityAlert(
            id=incident.id,
            title=incident.title,
            severity=incident.severity,
            source=incident.source,
            detected_at=incident.detected_at,
            host=incident.service,
            tags=[incident.domain.value, *incident.tags],
            description=incident.description,
            raw_events=incident.events,
        )
