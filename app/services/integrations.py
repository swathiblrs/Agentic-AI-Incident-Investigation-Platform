from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.models.schemas import IncidentDomain, IntegrationConfigRequest, IntegrationConfigResponse, IntegrationType


INTEGRATION_CATALOG: dict[IntegrationType, dict[str, object]] = {
    IntegrationType.splunk: {
        "category": "security",
        "domains": [IncidentDomain.security],
        "evidence": ["SIEM notable events", "authentication logs", "network detections"],
        "required_metadata": ["index", "sourcetype"],
    },
    IntegrationType.sentinel: {
        "category": "security",
        "domains": [IncidentDomain.security, IncidentDomain.cloud],
        "evidence": ["analytics incidents", "sign-in logs", "cloud audit events"],
        "required_metadata": ["workspace_id", "tenant_id"],
    },
    IntegrationType.okta: {
        "category": "identity",
        "domains": [IncidentDomain.security, IncidentDomain.it],
        "evidence": ["user sessions", "MFA events", "risk events"],
        "required_metadata": ["org_url"],
    },
    IntegrationType.crowdstrike: {
        "category": "endpoint",
        "domains": [IncidentDomain.security],
        "evidence": ["host detections", "process trees", "containment status"],
        "required_metadata": ["cloud"],
    },
    IntegrationType.datadog: {
        "category": "observability",
        "domains": [IncidentDomain.production, IncidentDomain.cloud],
        "evidence": ["service metrics", "APM traces", "monitors"],
        "required_metadata": ["site"],
    },
    IntegrationType.grafana_loki: {
        "category": "logs",
        "domains": [IncidentDomain.production, IncidentDomain.cloud],
        "evidence": ["application logs", "infrastructure logs", "labels"],
        "required_metadata": ["tenant"],
    },
    IntegrationType.cloudwatch: {
        "category": "cloud",
        "domains": [IncidentDomain.production, IncidentDomain.cloud],
        "evidence": ["metrics", "log groups", "alarms"],
        "required_metadata": ["region"],
    },
    IntegrationType.jira: {
        "category": "ticketing",
        "domains": [IncidentDomain.security, IncidentDomain.production, IncidentDomain.cloud, IncidentDomain.data, IncidentDomain.it],
        "evidence": ["incident tickets", "owners", "status changes"],
        "required_metadata": ["project_key"],
    },
    IntegrationType.servicenow: {
        "category": "ticketing",
        "domains": [IncidentDomain.security, IncidentDomain.production, IncidentDomain.cloud, IncidentDomain.data, IncidentDomain.it],
        "evidence": ["incidents", "change records", "CMDB services"],
        "required_metadata": ["instance"],
    },
    IntegrationType.slack: {
        "category": "messaging",
        "domains": [IncidentDomain.security, IncidentDomain.production, IncidentDomain.cloud, IncidentDomain.data, IncidentDomain.it],
        "evidence": ["incident channel messages", "escalation notices", "owner updates"],
        "required_metadata": ["channel"],
    },
}


class IntegrationRegistry:
    def __init__(self) -> None:
        self._configs: dict[str, IntegrationConfigResponse] = {}

    def catalog(self) -> list[dict[str, object]]:
        return [
            {
                "integration_type": integration_type.value,
                "category": metadata["category"],
                "domains": [domain.value for domain in metadata["domains"]],
                "evidence": metadata["evidence"],
                "required_metadata": metadata["required_metadata"],
            }
            for integration_type, metadata in INTEGRATION_CATALOG.items()
        ]

    def register(self, request: IntegrationConfigRequest) -> IntegrationConfigResponse:
        status = self._status_for(request)
        integration = IntegrationConfigResponse(
            id=str(uuid4()),
            status=status,
            **request.model_dump(),
        )
        self._configs[integration.id] = integration
        return integration

    def list(self) -> list[IntegrationConfigResponse]:
        return list(self._configs.values())

    def collect_preview(self, integration_id: str) -> dict[str, str]:
        integration = self._configs.get(integration_id)
        if integration is None:
            return {"status": "not_found", "message": "Integration is not configured.", "events": "[]"}
        metadata = INTEGRATION_CATALOG[integration.integration_type]
        domain = integration.default_domain or metadata["domains"][0]
        sample_events = [
            {
                "source": integration.integration_type.value,
                "domain": domain.value,
                "kind": evidence,
                "summary": f"Dry-run {evidence} preview from {integration.name}",
                "timestamp": datetime.now(UTC).isoformat(),
            }
            for evidence in metadata["evidence"]
        ]
        return {
            "status": "preview",
            "message": (
                f"{integration.integration_type.value} connector dry-run produced "
                f"{len(sample_events)} representative evidence records without external API calls."
            ),
            "events": str(sample_events),
        }

    def health(self, integration_id: str) -> dict[str, object]:
        integration = self._configs.get(integration_id)
        if integration is None:
            return {"status": "not_found", "checks": [], "ready_for_live": False}
        metadata = INTEGRATION_CATALOG[integration.integration_type]
        required = list(metadata["required_metadata"])
        missing = [key for key in required if not integration.metadata.get(key)]
        checks = [
            {"name": "enabled", "passed": integration.enabled},
            {"name": "base_url", "passed": bool(integration.base_url)},
            {"name": "required_metadata", "passed": not missing, "missing": missing},
            {"name": "secret_management", "passed": False, "note": "Live credentials are intentionally not stored in this demo."},
        ]
        ready = integration.enabled and bool(integration.base_url) and not missing
        return {
            "status": "ready" if ready else "dry_run",
            "integration_id": integration.id,
            "integration_type": integration.integration_type.value,
            "category": metadata["category"],
            "checks": checks,
            "ready_for_live": ready,
        }

    @staticmethod
    def _status_for(request: IntegrationConfigRequest) -> str:
        if not request.enabled:
            return "disabled"
        metadata = INTEGRATION_CATALOG[request.integration_type]
        missing = [key for key in metadata["required_metadata"] if not request.metadata.get(key)]
        if not request.base_url or missing:
            return "dry_run"
        return "ready"
