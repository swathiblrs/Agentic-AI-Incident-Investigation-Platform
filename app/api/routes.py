from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from app.core.config import get_settings
from app.core.security import (
    AuthRequest,
    CurrentUser,
    TokenResponse,
    authenticate_demo_user,
    create_access_token,
    ensure_domain_access,
    get_current_user,
)
from app.models.schemas import (
    HealthResponse,
    IncidentDomain,
    IngestDocumentRequest,
    IngestLogsRequest,
    IngestionResponse,
    IntegrationConfigRequest,
    IntegrationConfigResponse,
    IncidentInvestigationRequest,
    IncidentReport,
    InvestigationReport,
    InvestigationRequest,
    PostmortemReport,
    SecurityAlert,
    SessionMemoryResponse,
    StoredReportSummary,
)
from app.services.generic_incident_graph import GenericIncidentGraph
from app.services.ingestion import IngestionService
from app.services.integrations import IntegrationRegistry
from app.services.investigation_graph import InvestigationGraph
from app.services.postmortem import PostmortemService
from app.services.report_store import ReportStore
from app.services.session_memory import SessionMemory

router = APIRouter()
graph = InvestigationGraph()
generic_graph = GenericIncidentGraph()
memory = SessionMemory()
ingestion = IngestionService()
report_store = ReportStore()
integrations = IntegrationRegistry()
postmortems = PostmortemService()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(status="ok", app=settings.app_name, env=settings.app_env)


@router.post("/auth/token", response_model=TokenResponse)
def token(request: AuthRequest) -> TokenResponse:
    if not authenticate_demo_user(request.username, request.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return TokenResponse(access_token=create_access_token(request.username, request.role))


@router.post("/investigate", response_model=InvestigationReport)
async def investigate(
    request: InvestigationRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> InvestigationReport:
    ensure_domain_access(current_user, domain=IncidentDomain.security)
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
    await report_store.save_security_report_async(report, session_id=request.session_id)
    return report


@router.post("/incidents/investigate", response_model=IncidentReport)
async def investigate_incident(
    request: IncidentInvestigationRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> IncidentReport:
    ensure_domain_access(current_user, request.incident.domain)
    if request.session_id:
        memory.append(request.session_id, "user", request.incident.model_dump_json())
    report = generic_graph.investigate(request.incident)
    if not request.include_references:
        report.references = []
        for finding in report.findings:
            finding.references = []
    if request.session_id:
        memory.append(request.session_id, "assistant", report.executive_summary)
    report.incident.tags = sorted(
        set(report.incident.tags + [f"analyst:{request.analyst_id or current_user.username}"])
    )
    await report_store.save_incident_report_async(report, session_id=request.session_id)
    return report


@router.post("/ingest/document", response_model=IngestionResponse)
async def ingest_document(
    request: IngestDocumentRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> IngestionResponse:
    ensure_domain_access(current_user, request.domain)
    return await ingestion.ingest_document_async(request)


@router.post("/ingest/logs", response_model=IngestionResponse)
async def ingest_logs(
    request: IngestLogsRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> IngestionResponse:
    ensure_domain_access(current_user, request.domain)
    return await ingestion.ingest_logs_async(request)


@router.get("/reports", response_model=list[StoredReportSummary])
def list_reports(current_user: CurrentUser = Depends(get_current_user)) -> list[StoredReportSummary]:
    summaries = []
    for summary in report_store.list_summaries():
        try:
            ensure_domain_access(current_user, summary.domain)
        except HTTPException:
            continue
        summaries.append(summary)
    return summaries


@router.get("/reports/{investigation_id}")
def get_report(investigation_id: str, current_user: CurrentUser = Depends(get_current_user)):
    report = report_store.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    ensure_domain_access(current_user, _report_domain(report))
    return report


@router.post("/reports/{investigation_id}/postmortem", response_model=PostmortemReport)
def generate_postmortem(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> PostmortemReport:
    report = report_store.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    ensure_domain_access(current_user, _report_domain(report))
    return postmortems.generate(report)


@router.post("/integrations", response_model=IntegrationConfigResponse)
def register_integration(
    request: IntegrationConfigRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> IntegrationConfigResponse:
    if current_user.role.value != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admin can configure integrations.")
    return integrations.register(request)


@router.get("/integrations", response_model=list[IntegrationConfigResponse])
def list_integrations(_: CurrentUser = Depends(get_current_user)) -> list[IntegrationConfigResponse]:
    return integrations.list()


@router.post("/integrations/{integration_id}/collect-preview")
def collect_integration_preview(
    integration_id: str,
    _: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    return integrations.collect_preview(integration_id)


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


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Incident Investigation Platform</title>
          <style>
            :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
            body { margin: 0; background: #f6f8fb; color: #172033; }
            header { padding: 24px 32px; background: #101828; color: white; }
            main { display: grid; grid-template-columns: 360px 1fr; gap: 24px; padding: 24px 32px; }
            section { background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 18px; }
            label { display: block; font-size: 13px; font-weight: 700; margin-top: 12px; }
            input, select, textarea, button { width: 100%; box-sizing: border-box; margin-top: 6px; padding: 10px 12px; border-radius: 6px; border: 1px solid #b9c5d5; font: inherit; }
            textarea { min-height: 130px; resize: vertical; }
            button { background: #2563eb; color: white; border: 0; font-weight: 700; cursor: pointer; }
            pre { white-space: pre-wrap; background: #0f172a; color: #dbeafe; border-radius: 8px; padding: 16px; overflow: auto; }
            .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
            .metric { border: 1px solid #d9e1ec; border-radius: 8px; padding: 12px; }
            .metric strong { display: block; font-size: 22px; }
            @media (max-width: 900px) { main { grid-template-columns: 1fr; padding: 16px; } header { padding: 20px 16px; } }
          </style>
        </head>
        <body>
          <header>
            <h1>🚨 AI Incident Investigation Platform</h1>
            <p>Submit incidents, inspect structured reports, and browse investigation outputs.</p>
          </header>
          <main>
            <section>
              <h2>Submit Incident</h2>
              <label>Token</label>
              <input id="token" placeholder="Paste bearer token or click demo auth" />
              <button onclick="demoAuth()">Demo Auth</button>
              <label>Domain</label>
              <select id="domain"><option>production</option><option>security</option><option>cloud</option><option>data</option><option>it</option></select>
              <label>Title</label>
              <input id="title" value="Checkout API returning elevated 503 errors" />
              <label>Description / Logs</label>
              <textarea id="description">checkout-api ERROR upstream payment-gateway timeout
checkout-api failed request status=503 route=/checkout</textarea>
              <button onclick="investigate()">Investigate</button>
            </section>
            <section>
              <h2>Report</h2>
              <div class="grid">
                <div class="metric"><span>Status</span><strong id="status">-</strong></div>
                <div class="metric"><span>Risk</span><strong id="risk">-</strong></div>
                <div class="metric"><span>Actions</span><strong id="actions">-</strong></div>
              </div>
              <pre id="output">No report yet.</pre>
              <button onclick="copyActions()">Copy Recommended Actions</button>
              <button onclick="loadReports()">Browse Past Reports</button>
            </section>
          </main>
          <script>
            let lastReport = null;
            async function demoAuth() {
              const res = await fetch('/api/auth/token', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:'analyst', password:'analyst', role:'admin'})});
              const body = await res.json();
              document.getElementById('token').value = body.access_token;
            }
            async function investigate() {
              const domain = document.getElementById('domain').value;
              const title = document.getElementById('title').value;
              const description = document.getElementById('description').value;
              const payload = {incident:{title, domain, severity:'high', source:'dashboard', service:'dashboard-input', description, logs:description.split('\\n'), tags:['dashboard']}};
              const res = await fetch('/api/incidents/investigate', {method:'POST', headers:{'Content-Type':'application/json', Authorization:'Bearer '+document.getElementById('token').value}, body: JSON.stringify(payload)});
              lastReport = await res.json();
              document.getElementById('status').textContent = lastReport.status || lastReport.verdict || '-';
              document.getElementById('risk').textContent = String(lastReport.risk_score || '-');
              document.getElementById('actions').textContent = String((lastReport.recommended_actions || []).length);
              document.getElementById('output').textContent = JSON.stringify(lastReport, null, 2);
            }
            async function loadReports() {
              const res = await fetch('/api/reports', {headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              document.getElementById('output').textContent = JSON.stringify(await res.json(), null, 2);
            }
            async function copyActions() {
              const text = (lastReport?.recommended_actions || []).map(a => `${a.priority}. ${a.action}`).join('\\n');
              await navigator.clipboard.writeText(text);
            }
          </script>
        </body>
        </html>
        """
    )


def _report_domain(report) -> IncidentDomain:
    if hasattr(report, "incident"):
        return report.incident.domain
    return IncidentDomain.security
    ensure_domain_access,
