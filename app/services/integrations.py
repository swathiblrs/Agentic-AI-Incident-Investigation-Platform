from __future__ import annotations

from uuid import uuid4

from app.models.schemas import IntegrationConfigRequest, IntegrationConfigResponse


class IntegrationRegistry:
    def __init__(self) -> None:
        self._configs: dict[str, IntegrationConfigResponse] = {}

    def register(self, request: IntegrationConfigRequest) -> IntegrationConfigResponse:
        integration = IntegrationConfigResponse(
            id=str(uuid4()),
            status="configured" if request.enabled else "disabled",
            **request.model_dump(),
        )
        self._configs[integration.id] = integration
        return integration

    def list(self) -> list[IntegrationConfigResponse]:
        return list(self._configs.values())

    def collect_preview(self, integration_id: str) -> dict[str, str]:
        integration = self._configs.get(integration_id)
        if integration is None:
            return {"status": "not_found", "message": "Integration is not configured."}
        return {
            "status": "preview",
            "message": (
                f"{integration.integration_type.value} connector is configured as a local-safe stub. "
                "Add credentials and a source adapter before live collection."
            ),
        }
