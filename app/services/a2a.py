from __future__ import annotations

import time

import httpx

from app.core.config import get_settings
from app.core.telemetry import (
    A2A_HANDOFF_DURATION,
    A2A_HANDOFFS_TOTAL,
    A2A_MESSAGES_TOTAL,
    ACTIVE_AGENT_CAPABILITIES,
)
from app.models.schemas import (
    AgentExchangeRequest,
    AgentExchangeResponse,
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
        self.settings = get_settings()
        self._agents = self._build_manifests()
        self._apply_cloud_endpoints()
        for agent in self._agents.values():
            ACTIVE_AGENT_CAPABILITIES.labels(agent=agent.name, domain=agent.domain.value).set(len(agent.capabilities))
        self.messages_per_investigation = 3

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
            A2A_MESSAGES_TOTAL.labels(
                source_agent=request.source_agent,
                target_agent=request.target_agent,
                task_type=request.task_type,
                status="not_found",
            ).inc()
            return AgentHandoffResponse(
                parent_message_id=request.parent_message_id,
                source_agent=request.source_agent,
                target_agent=request.target_agent,
                task_type=request.task_type,
                domain=request.incident.domain,
                status="not_found",
                summary="Target agent is not registered.",
                duration_ms=round(duration * 1000, 3),
            )

        mode = self._mode_for(agent.name)
        if mode == "cloud":
            return self._handoff_cloud(request, agent, started)

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
        A2A_MESSAGES_TOTAL.labels(
            source_agent=request.source_agent,
            target_agent=agent.name,
            task_type=request.task_type,
            status="ok",
        ).inc()
        result = self._result_for(agent, request, evidence, actions)
        return AgentHandoffResponse(
            parent_message_id=request.parent_message_id,
            source_agent=request.source_agent,
            target_agent=agent.name,
            task_type=request.task_type,
            domain=agent.domain,
            status="ok",
            summary=(
                f"{agent.name} completed {request.task_type} for {request.incident.title} "
                f"and returned {len(evidence)} evidence items plus {len(actions)} actions."
            ),
            result=result,
            evidence=evidence,
            recommended_actions=actions,
            metrics={
                "capabilities_used": min(3, len(agent.capabilities)),
                "evidence_items": len(evidence),
                "recommended_actions": len(actions),
                "cost_mode": "free_local_a2a_message",
            },
            duration_ms=round(duration * 1000, 3),
        )

    def exchange(self, request: AgentExchangeRequest) -> AgentExchangeResponse:
        primary = self.agent_for_domain(request.incident.domain)
        peer = self.peer_for_domain(request.incident.domain)
        first = self.handoff(
            AgentHandoffRequest(
                source_agent=request.source_agent,
                target_agent=primary.name,
                task_type="triage_incident",
                incident=request.incident,
                context=request.context,
                payload={"instruction": "Assess domain impact and choose supporting evidence need."},
            )
        )
        second = self.handoff(
            AgentHandoffRequest(
                source_agent=primary.name,
                target_agent=peer.name,
                task_type="collect_peer_context",
                incident=request.incident,
                context={"previous_result": first.result, **request.context},
                payload={"instruction": "Collect supporting context requested by the primary agent."},
                parent_message_id=first.message_id,
            )
        )
        third = self.handoff(
            AgentHandoffRequest(
                source_agent=peer.name,
                target_agent=primary.name,
                task_type="return_peer_context",
                incident=request.incident,
                context={"previous_result": second.result, **request.context},
                payload={"instruction": "Merge peer context into the primary investigation plan."},
                parent_message_id=second.message_id,
            )
        )
        return AgentExchangeResponse(
            domain=request.incident.domain,
            primary_agent=primary.name,
            peer_agent=peer.name,
            status="ok" if all(message.status == "ok" for message in (first, second, third)) else "degraded",
            messages=[first, second, third],
            metrics={
                "messages_exchanged": 3,
                "agents_involved": 2,
                "task_types": [first.task_type, second.task_type, third.task_type],
                "cost_mode": "free_local_a2a_exchange",
            },
        )

    def capability_metrics(self) -> dict[str, int]:
        return {
            "a2a_agents_available": len(self._agents),
            "advertised_capabilities": sum(len(agent.capabilities) for agent in self._agents.values()),
            "operational_workflows": len({agent.domain for agent in self._agents.values()}),
            "a2a_messages_per_investigation": self.messages_per_investigation,
            "a2a_provider": self.settings.a2a_provider,
            "cloud_ready_a2a_agents": len(self.settings.a2a_agent_urls),
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

    def peer_for_domain(self, domain: IncidentDomain) -> AgentManifest:
        mapping = {
            IncidentDomain.security: "it_agent",
            IncidentDomain.production: "cloud_agent",
            IncidentDomain.cloud: "sre_agent",
            IncidentDomain.data: "sre_agent",
            IncidentDomain.it: "soc_agent",
        }
        return self._agents[mapping[domain]]

    def provider(self) -> str:
        return self.settings.a2a_provider

    def _mode_for(self, agent_name: str) -> str:
        configured = bool(self.settings.a2a_agent_urls.get(agent_name))
        if self.settings.a2a_provider == "cloud":
            return "cloud" if configured else "local"
        if self.settings.a2a_provider == "auto" and configured:
            return "cloud"
        return "local"

    def _apply_cloud_endpoints(self) -> None:
        for agent_name, endpoint in self.settings.a2a_agent_urls.items():
            agent = self._agents.get(agent_name)
            if agent is not None:
                agent.endpoint = endpoint
                agent.mode = "cloud_ready"

    def _handoff_cloud(
        self,
        request: AgentHandoffRequest,
        agent: AgentManifest,
        started: float,
    ) -> AgentHandoffResponse:
        endpoint = self.settings.a2a_agent_urls.get(agent.name)
        if not endpoint:
            return self._cloud_fallback(request, agent, started, "Cloud endpoint is not configured.")

        headers = {"Content-Type": "application/json"}
        if self.settings.a2a_api_key:
            headers["Authorization"] = f"Bearer {self.settings.a2a_api_key}"

        last_error = ""
        for attempt in range(max(1, self.settings.a2a_max_retries)):
            try:
                response = httpx.post(
                    endpoint,
                    headers=headers,
                    json=request.model_dump(mode="json"),
                    timeout=self.settings.a2a_timeout_seconds,
                )
                response.raise_for_status()
                payload = response.json()
                result = AgentHandoffResponse.model_validate(payload)
                self._record_cloud_metrics(request, agent, started, "ok")
                result.metrics["cost_mode"] = "cloud_a2a_message"
                result.metrics["provider"] = "http"
                return result
            except (httpx.HTTPError, ValueError) as exc:
                last_error = str(exc)
                if attempt < self.settings.a2a_max_retries - 1:
                    time.sleep(0.25 * (attempt + 1))

        if self.settings.a2a_provider == "auto":
            fallback = self._handoff_local_after_cloud_failure(request, agent, started)
            fallback.metrics["cloud_error"] = last_error
            return fallback
        return self._cloud_fallback(request, agent, started, last_error)

    def _handoff_local_after_cloud_failure(
        self,
        request: AgentHandoffRequest,
        agent: AgentManifest,
        started: float,
    ) -> AgentHandoffResponse:
        original_provider = self.settings.a2a_provider
        self.settings.a2a_provider = "local"
        try:
            result = self.handoff(request)
            result.metrics["provider"] = "local_fallback_after_cloud_error"
            return result
        finally:
            self.settings.a2a_provider = original_provider

    def _cloud_fallback(
        self,
        request: AgentHandoffRequest,
        agent: AgentManifest,
        started: float,
        error: str,
    ) -> AgentHandoffResponse:
        duration = time.perf_counter() - started
        self._record_cloud_metrics(request, agent, started, "error")
        return AgentHandoffResponse(
            parent_message_id=request.parent_message_id,
            source_agent=request.source_agent,
            target_agent=agent.name,
            task_type=request.task_type,
            domain=agent.domain,
            status="error",
            summary=f"Cloud A2A call failed for {agent.name}.",
            result={"error": error, "provider": "http"},
            metrics={"cost_mode": "cloud_a2a_message", "provider": "http", "error": error},
            duration_ms=round(duration * 1000, 3),
        )

    def _record_cloud_metrics(
        self,
        request: AgentHandoffRequest,
        agent: AgentManifest,
        started: float,
        status: str,
    ) -> None:
        duration = time.perf_counter() - started
        A2A_HANDOFFS_TOTAL.labels(
            source_agent=request.source_agent,
            target_agent=agent.name,
            domain=agent.domain.value,
            status=status,
        ).inc()
        A2A_HANDOFF_DURATION.labels(
            source_agent=request.source_agent,
            target_agent=agent.name,
            domain=agent.domain.value,
        ).observe(duration)
        A2A_MESSAGES_TOTAL.labels(
            source_agent=request.source_agent,
            target_agent=agent.name,
            task_type=request.task_type,
            status=status,
        ).inc()

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
                rationale=f"Recommended by {agent.name} after local A2A task exchange.",
            )
        ]

    @staticmethod
    def _result_for(
        agent: AgentManifest,
        request: AgentHandoffRequest,
        evidence: list[EvidenceItem],
        actions: list[RemediationStep],
    ) -> dict[str, object]:
        return {
            "agent": agent.name,
            "task_type": request.task_type,
            "incident_id": request.incident.id,
            "domain": agent.domain.value,
            "capabilities_used": agent.capabilities[:3],
            "evidence_kinds": [item.kind for item in evidence],
            "recommended_actions": [action.action for action in actions],
            "received_from": request.source_agent,
            "parent_message_id": request.parent_message_id,
        }
