from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from app.core.telemetry import MCP_TOOL_CALLS_TOTAL, MCP_TOOL_DURATION, MCP_TOOLS_AVAILABLE
from app.models.schemas import (
    IncidentDomain,
    IncidentInput,
    IntegrationType,
    MCPToolCallRequest,
    MCPToolCallResponse,
    MCPToolManifest,
    SecurityAlert,
)


class LocalMCPToolRegistry:
    """Local MCP-style tool registry with no-cost dry-run execution.

    The API shape mirrors the important MCP ideas for this project: tools are
    discoverable through manifests and executable through a single structured
    call interface. Real vendors can be enabled later by swapping handlers when
    credentials are present.
    """

    def __init__(self) -> None:
        self._tools = self._build_manifests()
        MCP_TOOLS_AVAILABLE.labels(mode="local").set(len(self._tools))

    def list_tools(self) -> list[MCPToolManifest]:
        return list(self._tools.values())

    def get_tool(self, name: str) -> MCPToolManifest | None:
        return self._tools.get(name)

    def execute(self, request: MCPToolCallRequest) -> MCPToolCallResponse:
        started = time.perf_counter()
        manifest = self.get_tool(request.tool_name)
        if manifest is None:
            duration = time.perf_counter() - started
            MCP_TOOL_CALLS_TOTAL.labels(tool=request.tool_name, mode="local", status="not_found").inc()
            MCP_TOOL_DURATION.labels(tool=request.tool_name, mode="local").observe(duration)
            return MCPToolCallResponse(
                tool_name=request.tool_name,
                mode="local",
                status="not_found",
                result={"message": "Tool is not registered."},
                duration_ms=round(duration * 1000, 3),
            )

        result = self._execute_local(manifest, request.arguments, request.incident, request.alert)
        duration = time.perf_counter() - started
        MCP_TOOL_CALLS_TOTAL.labels(tool=manifest.name, mode=manifest.mode, status="ok").inc()
        MCP_TOOL_DURATION.labels(tool=manifest.name, mode=manifest.mode).observe(duration)
        return MCPToolCallResponse(
            tool_name=manifest.name,
            mode=manifest.mode,
            status="ok",
            result=result,
            duration_ms=round(duration * 1000, 3),
        )

    def capability_metrics(self) -> dict[str, int]:
        integration_ready = sum(1 for tool in self._tools.values() if tool.external_integration is not None)
        return {
            "mcp_tools_available": len(self._tools),
            "integration_ready_tools": integration_ready,
            "local_tool_calls_supported": len(self._tools),
        }

    @staticmethod
    def _build_manifests() -> dict[str, MCPToolManifest]:
        common_input = {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 5},
                "lookback_minutes": {"type": "integer", "default": 60},
            },
        }
        common_output = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "records": {"type": "array"},
                "source": {"type": "string"},
            },
        }
        tools = [
            MCPToolManifest(
                name="search_runbooks",
                description="Retrieve local runbook and playbook context for an incident.",
                domains=list(IncidentDomain),
                input_schema=common_input,
                output_schema=common_output,
            ),
            MCPToolManifest(
                name="search_security_logs",
                description="Collect local SIEM-style evidence for suspicious identity and endpoint alerts.",
                domains=[IncidentDomain.security],
                input_schema=common_input,
                output_schema=common_output,
                external_integration=IntegrationType.splunk,
            ),
            MCPToolManifest(
                name="query_observability",
                description="Collect local metrics, logs, and trace summaries for SRE and cloud incidents.",
                domains=[IncidentDomain.production, IncidentDomain.cloud],
                input_schema=common_input,
                output_schema=common_output,
                external_integration=IntegrationType.datadog,
            ),
            MCPToolManifest(
                name="inspect_identity_events",
                description="Inspect local identity events for MFA, session, and risky login signals.",
                domains=[IncidentDomain.security, IncidentDomain.it],
                input_schema=common_input,
                output_schema=common_output,
                external_integration=IntegrationType.okta,
            ),
            MCPToolManifest(
                name="create_ticket_dry_run",
                description="Generate a ticket payload without calling Jira or ServiceNow.",
                domains=list(IncidentDomain),
                input_schema=common_input,
                output_schema=common_output,
                external_integration=IntegrationType.jira,
            ),
            MCPToolManifest(
                name="send_escalation_dry_run",
                description="Generate a Slack escalation payload without sending a message.",
                domains=list(IncidentDomain),
                input_schema=common_input,
                output_schema=common_output,
                external_integration=IntegrationType.slack,
            ),
        ]
        return {tool.name: tool for tool in tools}

    def _execute_local(
        self,
        manifest: MCPToolManifest,
        arguments: dict[str, Any],
        incident: IncidentInput | None,
        alert: SecurityAlert | None,
    ) -> dict[str, Any]:
        title = self._title(incident, alert, arguments)
        domain = self._domain(incident, alert, manifest)
        now = datetime.now(UTC).isoformat()
        records = [
            {
                "timestamp": now,
                "source": manifest.name,
                "domain": domain.value,
                "signal": signal,
                "summary": f"Local MCP evidence for {title}: {signal}.",
            }
            for signal in self._signals_for(manifest.name, domain)
        ]
        return {
            "summary": f"{manifest.name} returned {len(records)} local evidence records for {domain.value}.",
            "records": records,
            "source": manifest.external_integration.value if manifest.external_integration else "local_knowledge_base",
            "cost_mode": "free_local_dry_run",
            "query": arguments.get("query") or title,
        }

    @staticmethod
    def _title(incident: IncidentInput | None, alert: SecurityAlert | None, arguments: dict[str, Any]) -> str:
        if incident is not None:
            return incident.title
        if alert is not None:
            return alert.title
        return str(arguments.get("query", "manual MCP tool call"))

    @staticmethod
    def _domain(
        incident: IncidentInput | None,
        alert: SecurityAlert | None,
        manifest: MCPToolManifest,
    ) -> IncidentDomain:
        if incident is not None:
            return incident.domain
        if alert is not None:
            return IncidentDomain.security
        return manifest.domains[0]

    @staticmethod
    def _signals_for(tool_name: str, domain: IncidentDomain) -> list[str]:
        signals = {
            "search_runbooks": ["matched runbook section", "past incident reference", "recommended operating procedure"],
            "search_security_logs": ["suspicious authentication event", "source IP reputation signal", "post-login activity"],
            "query_observability": ["error-rate increase", "latency saturation", "recent deployment correlation"],
            "inspect_identity_events": ["MFA challenge", "new device session", "impossible travel indicator"],
            "create_ticket_dry_run": ["ticket summary", "severity mapping", "owner assignment"],
            "send_escalation_dry_run": ["channel selection", "incident summary", "action owner mention"],
        }.get(tool_name, ["generic local evidence"])
        if domain == IncidentDomain.data:
            return ["schema change", "freshness delay", "quality check failure"]
        if domain == IncidentDomain.it:
            return ["user impact", "access path health", "workaround readiness"]
        return signals
