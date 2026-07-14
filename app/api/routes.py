from fastapi import APIRouter
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from app.core.config import get_settings
from app.models.schemas import HealthResponse, InvestigationReport, InvestigationRequest, SecurityAlert
from app.services.investigation_graph import InvestigationGraph

router = APIRouter()
graph = InvestigationGraph()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(status="ok", app=settings.app_name, env=settings.app_env)


@router.post("/investigate", response_model=InvestigationReport)
def investigate(request: InvestigationRequest) -> InvestigationReport:
    report = graph.investigate(request.alert)
    if not request.include_references:
        report.references = []
        for finding in report.findings:
            finding.references = []
    return report


@router.get("/sample-alert", response_model=SecurityAlert)
def sample_alert() -> SecurityAlert:
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "data" / "sample_alerts" / "login_anomaly.json"
    return SecurityAlert.model_validate(json.loads(path.read_text(encoding="utf-8")))


@router.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
