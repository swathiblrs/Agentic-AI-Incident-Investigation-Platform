from fastapi import APIRouter, Depends, HTTPException, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from app.core.config import get_settings
from app.core.security import (
    AuthRequest,
    CurrentUser,
    TokenResponse,
    authenticate_demo_user,
    create_access_token,
    get_current_user,
)
from app.models.schemas import (
    HealthResponse,
    InvestigationReport,
    InvestigationRequest,
    SecurityAlert,
    SessionMemoryResponse,
)
from app.services.investigation_graph import InvestigationGraph
from app.services.session_memory import SessionMemory

router = APIRouter()
graph = InvestigationGraph()
memory = SessionMemory()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(status="ok", app=settings.app_name, env=settings.app_env)


@router.post("/auth/token", response_model=TokenResponse)
def token(request: AuthRequest) -> TokenResponse:
    if not authenticate_demo_user(request.username, request.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return TokenResponse(access_token=create_access_token(request.username))


@router.post("/investigate", response_model=InvestigationReport)
def investigate(
    request: InvestigationRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> InvestigationReport:
    if request.session_id:
        memory.append(request.session_id, "user", request.alert.model_dump_json())
    report = graph.investigate(request.alert)
    if not request.include_references:
        report.references = []
        for finding in report.findings:
            finding.references = []
    if request.session_id:
        memory.append(request.session_id, "assistant", report.executive_summary)
    report.alert.tags = sorted(set(report.alert.tags + [f"analyst:{request.analyst_id or current_user.username}"]))
    return report


@router.get("/sessions/{session_id}/memory", response_model=SessionMemoryResponse)
def session_memory(
    session_id: str,
    _: CurrentUser = Depends(get_current_user),
) -> SessionMemoryResponse:
    return SessionMemoryResponse(session_id=session_id, messages=memory.get(session_id))


@router.get("/sample-alert", response_model=SecurityAlert)
def sample_alert() -> SecurityAlert:
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "data" / "sample_alerts" / "login_anomaly.json"
    return SecurityAlert.model_validate(json.loads(path.read_text(encoding="utf-8")))


@router.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
