from __future__ import annotations

import base64

import httpx

from app.core.config import get_settings
from app.models.schemas import InvestigationReport


class LangfuseTracer:
    def __init__(self) -> None:
        self.settings = get_settings()

    def trace_investigation(self, report: InvestigationReport) -> None:
        if not self.settings.langfuse_enabled:
            return
        if not self.settings.langfuse_public_key or not self.settings.langfuse_secret_key:
            return

        auth = base64.b64encode(
            f"{self.settings.langfuse_public_key}:{self.settings.langfuse_secret_key}".encode("utf-8")
        ).decode("utf-8")
        payload = {
            "batch": [
                {
                    "type": "trace-create",
                    "body": {
                        "id": str(report.investigation_id),
                        "name": "security-alert-investigation",
                        "input": report.alert.model_dump(mode="json"),
                        "output": {
                            "verdict": report.verdict.value,
                            "risk_score": report.risk_score,
                            "summary": report.executive_summary,
                        },
                        "metadata": {"source": "agentic-ai-incident-investigation-platform"},
                    },
                }
            ]
        }
        try:
            httpx.post(
                f"{self.settings.langfuse_host.rstrip('/')}/api/public/ingestion",
                json=payload,
                headers={"Authorization": f"Basic {auth}"},
                timeout=5,
            )
        except httpx.HTTPError:
            return
