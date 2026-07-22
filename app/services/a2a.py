from __future__ import annotations

import time

from app.core.telemetry import A2A_HANDOFF_DURATION, A2A_HANDOFFS_TOTAL, ACTIVE_AGENT_CAPABILITIES
from app.models.schemas import (
    AgentHandoffRequest,
    AgentHandoffResponse,
    AgentManifest,
    EvidenceItem,
    IncidentDomain,
    RemediationStep,
)


class LocalA2ARegistry:
    """Capability-based local agent-to-agent handoff registry."""

    def __init__(self) -> None:
        self._agents = self._build_manifests()
        for agent in self._agents.values():
            ACTIVE_AGENT_CAPABILITIES.labels(agent=agent.name, domain=agent.domain.value).set(len(agent.capabilities))

    def list_agents(self) -> list[AgentManifest]:
        return list(self._agents.values())

    def get_agent(self, name: str) -> AgentManifest | None:
        return self._agents.get(name)

    def agent_for_domain(self, domain: IncidentDomain) -> AgentManifest:
        mapping = {
            IncidentDomain.security: "soc_agent",
            IncidentDomain.production: "sre_agent",
            IncidentDomain.cloud: "cloud_agent",
            IncidentDomain.data: "data_agent",
            IncidentDomain.it: "it_agent",
        }
        return self._agents[mapping[domain]]

    def handoff(self, request: AgentHandoffRequest) -> AgentHandoffResponse:
        started = time.perf_counter()
        agent = self.get_agent(request.target_agent)
        if agent is None:
            duration = time.perf_counter() - started
            A2A_HANDOFFS_TOTAL.labels(
                source_agent=request.source_agent,
                target_agent=request.target_agent,
                domain=request.incident.domain.value,
                status="not_found",
            ).inc()
            A2A_HANDOFF_DURATION.labels(
                source_agent=request.source_agent,
                target_agent=request.target_agent,
                domain=request.incident.domain.value,
            ).observe(duration)
            return AgentHandoffResponse(
                source_agent=request.source_agent,
                target_agent=request.target_agent,
                domain=request.incident.domain,
                status="not_found",
                summary="Target agent is not registered.",
                duration_ms=round(duration * 1000, 3),
            )

        evidence = self._evidence_for(agent, request)
        actions = self._actions_for(agent, request)
        duration = time.perf_counter() - started
        A2A_HANDOFFS_TOTAL.labels(
            source_agent=request.source_agent,
            target_agent=agent.name,
            domain=agent.domain.value,
            status="ok",
        ).inc()
        A2A_HANDOFF_DURATION.labels(
            source_agent=request.source_agent,
            target_agent=agent.name,
            domain=agent.domain.value,
        ).observe(duration)
        return AgentHandoffResponse(
            source_agent=request.source_agent,
            target_agent=agent.name,
            domain=agent.domain,
            status="ok",
            summary=(
                f"{agent.name} accepted the handoff for {request.incident.title} "
                f"and produced {len(evidence)} evidence items plus {len(actions)} actions."
            ),
            evidence=evidence,
            recommended_actions=actions,
            metrics={
                "capabilities_used": min(3, len(agent.capabilities)),
                "evidence_items": len(evidence),
                "recommended_actions": len(actions),
                "cost_mode": "free_local_handoff",
            },
            duration_ms=round(duration * 1000, 3),
        )

    def capability_metrics(self) -> dict[str, int]:
        return {
            "a2a_agents_available": len(self._agents),
            "advertised_capabilities": sum(len(agent.capabilities) for agent in self._agents.values()),
            "operational_workflows": len({agent.domain for agent in self._agents.values()}),
        }

    @staticmethod
    def _build_manifests() -> dict[str, AgentManifest]:
        agents = [
            AgentManifest(
                name="soc_agent",
                domain=IncidentDomain.security,
                endpoint="/api/a2a/agents/soc_agent/handoff",
                capabilities=["account_takeover_triage", "identity_enrichment", "containment_recommendation"],
                accepts=["security_alert", "identity_log", "endpoint_signal"],
                produces=["verdict", "risk_score", "containment_actions"],
            ),
            AgentManifest(
                name="sre_agent",
                domain=IncidentDomain.production,
                endpoint="/api/a2a/agents/sre_agent/handoff",
                capabilities=["service_triage", "dependency_correlation", "rollback_guidance"],
                accepts=["service_logs", "metrics", "deployment_events"],
                produces=["status", "impact_summary", "mitigation_actions"],
            ),
            AgentManifest(
                name="cloud_agent",
                domain=IncidentDomain.cloud,
                endpoint="/api/a2a/agents/cloud_agent/handoff",
                capabilities=["capacity_analysis", "iam_change_review", "cloud_event_correlation"],
                accepts=["cloud_events", "metrics", "audit_logs"],
                produces=["risk_score", "cloud_evidence", "failover_actions"],
            ),
            AgentManifest(
                name="data_agent",
                domain=IncidentDomain.data,
                endpoint="/api/a2a/agents/data_agent/handoff",
                capabilities=["schema_drift_triage", "freshness_analysis", "backfill_planning"],
                accepts=["pipeline_logs", "quality_checks", "schema_events"],
                produces=["data_quality_status", "consumer_impact", "recovery_actions"],
            ),
            AgentManifest(
                name="it_agent",
                domain=IncidentDomain.it,
                endpoint="/api/a2a/agents/it_agent/handoff",
                capabilities=["access_path_triage", "user_impact_analysis", "workaround_recommendation"],
                accepts=["user_reports", "device_logs", "identity_events"],
                produces=["impact_scope", "workaround", "escalation_actions"],
            ),
        ]
        return {agent.name: agent for agent in agents}

    @staticmethod
    def _evidence_for(agent: AgentManifest, request: AgentHandoffRequest) -> list[EvidenceItem]:
        incident = request.incident
        base_value = incident.description or incident.title
        domain_evidence = {
            IncidentDomain.security: ("identity_signal", "Validated risky authentication and session context."),
            IncidentDomain.production: ("service_health", "Correlated logs, metrics, and deployment context."),
            IncidentDomain.cloud: ("cloud_event", "Reviewed cloud capacity, routing, and audit signals."),
            IncidentDomain.data: ("data_quality", "Checked freshness, schema, and downstream data quality signals."),
            IncidentDomain.it: ("access_impact", "Reviewed user impact, access path, and workaround evidence."),
        }[agent.domain]
        return [
            EvidenceItem(kind=domain_evidence[0], description=domain_evidence[1], value=base_value, weight=8),
            EvidenceItem(
                kind="handoff_context",
                description=f"{request.source_agent} delegated to {agent.name}.",
                value=", ".join(agent.capabilities[:3]),
                weight=4,
            ),
        ]

    @staticmethod
    def _actions_for(agent: AgentManifest, request: AgentHandoffRequest) -> list[RemediationStep]:
        owner = request.incident.owner_team or {
            IncidentDomain.security: "SOC",
            IncidentDomain.production: "SRE",
            IncidentDomain.cloud: "Cloud Platform",
            IncidentDomain.data: "Data Engineering",
            IncidentDomain.it: "IT Operations",
        }[agent.domain]
        action = {
            IncidentDomain.security: "Contain affected identity sessions and preserve authentication evidence.",
            IncidentDomain.production: "Mitigate user impact using rollback, traffic shift, scaling, or dependency isolation.",
            IncidentDomain.cloud: "Validate cloud capacity, quota, networking, and recent infrastructure changes.",
            IncidentDomain.data: "Pause affected downstream consumers and plan replay from a known-good checkpoint.",
            IncidentDomain.it: "Publish workaround guidance and escalate ownership for affected access path.",
        }[agent.domain]
        return [
            RemediationStep(
                priority=1,
                action=action,
                owner=owner,
                rationale=f"Recommended by {agent.name} after local A2A handoff.",
            )
        ]
