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
    AgentHandoffRequest,
    AgentHandoffResponse,
    AgentExchangeRequest,
    AgentExchangeResponse,
    AgentManifest,
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
    MCPToolCallRequest,
    MCPToolCallResponse,
    MCPToolManifest,
    PlatformMetricsSnapshot,
    PostmortemReport,
    SecurityAlert,
    SessionMemoryResponse,
    StoredReportSummary,
)
from app.services.a2a import LocalA2ARegistry
from app.services.generic_incident_graph import GenericIncidentGraph
from app.services.ingestion import IngestionService
from app.services.integrations import IntegrationRegistry
from app.services.investigation_graph import InvestigationGraph
from app.services.mcp_tools import LocalMCPToolRegistry
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
mcp_tools = LocalMCPToolRegistry()
a2a_registry = LocalA2ARegistry()


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
    report = await graph.investigate_async(request.alert, session_id=request.session_id)
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
    report = await generic_graph.investigate_async(request.incident, session_id=request.session_id)
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


@router.get("/integrations/catalog")
def integration_catalog(_: CurrentUser = Depends(get_current_user)) -> list[dict[str, object]]:
    return integrations.catalog()


@router.get("/integrations/{integration_id}/health")
def integration_health(
    integration_id: str,
    _: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    return integrations.health(integration_id)


@router.post("/integrations/{integration_id}/collect-preview")
def collect_integration_preview(
    integration_id: str,
    _: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    return integrations.collect_preview(integration_id)


@router.get("/mcp/tools", response_model=list[MCPToolManifest])
def list_mcp_tools(_: CurrentUser = Depends(get_current_user)) -> list[MCPToolManifest]:
    return mcp_tools.list_tools()


@router.post("/mcp/tools/call", response_model=MCPToolCallResponse)
def call_mcp_tool(
    request: MCPToolCallRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> MCPToolCallResponse:
    domain = request.incident.domain if request.incident is not None else IncidentDomain.security
    ensure_domain_access(current_user, domain)
    return mcp_tools.execute(request)


@router.get("/a2a/agents", response_model=list[AgentManifest])
def list_a2a_agents(_: CurrentUser = Depends(get_current_user)) -> list[AgentManifest]:
    return a2a_registry.list_agents()


@router.post("/a2a/handoff", response_model=AgentHandoffResponse)
def a2a_handoff(
    request: AgentHandoffRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> AgentHandoffResponse:
    ensure_domain_access(current_user, request.incident.domain)
    return a2a_registry.handoff(request)


@router.post("/a2a/exchange", response_model=AgentExchangeResponse)
def a2a_exchange(
    request: AgentExchangeRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> AgentExchangeResponse:
    ensure_domain_access(current_user, request.incident.domain)
    return a2a_registry.exchange(request)


@router.post("/a2a/agents/{agent_name}/handoff", response_model=AgentHandoffResponse)
def a2a_agent_handoff(
    agent_name: str,
    request: AgentHandoffRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> AgentHandoffResponse:
    ensure_domain_access(current_user, request.incident.domain)
    request.target_agent = agent_name
    return a2a_registry.handoff(request)


@router.get("/platform/metrics-snapshot", response_model=PlatformMetricsSnapshot)
def platform_metrics_snapshot(_: CurrentUser = Depends(get_current_user)) -> PlatformMetricsSnapshot:
    mcp = mcp_tools.capability_metrics()
    a2a = a2a_registry.capability_metrics()
    return PlatformMetricsSnapshot(
        **mcp,
        **a2a,
        automated_response_steps=[
            "domain routing",
            "MCP tool discovery",
            "MCP evidence collection",
            "A2A task/result exchange",
            "RAG context retrieval",
            "risk scoring",
            "response recommendation",
            "report persistence",
            "postmortem generation",
        ],
    )


@router.get("/sessions/{session_id}/memory", response_model=SessionMemoryResponse)
def session_memory(
    session_id: str,
    _: CurrentUser = Depends(get_current_user),
) -> SessionMemoryResponse:
    return SessionMemoryResponse(session_id=session_id, messages=memory.get(session_id))


@router.delete("/sessions/{session_id}")
async def clear_session(
    session_id: str,
    _: CurrentUser = Depends(get_current_user),
) -> dict[str, bool | str]:
    memory.clear(session_id)
    checkpoints_cleared = await graph.checkpoints.clear_thread(session_id)
    await generic_graph.checkpoints.clear_thread(session_id)
    return {"session_id": session_id, "memory_cleared": True, "langgraph_checkpoints_cleared": checkpoints_cleared}


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
            body { margin: 0; background: #eef2f7; color: #172033; }
            header { display: flex; justify-content: space-between; gap: 18px; align-items: center; padding: 20px 28px; background: #101828; color: white; }
            header h1 { margin: 0; font-size: 24px; }
            header p { margin: 4px 0 0; color: #cbd5e1; }
            main { padding: 20px 28px 32px; }
            .shell { display: grid; grid-template-columns: 320px 1fr; gap: 18px; }
            .panel { background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 16px; }
            .tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
            .tab { width: auto; padding: 9px 12px; background: #e8eef7; color: #1e293b; border: 1px solid #cbd5e1; }
            .tab.active { background: #2563eb; color: white; border-color: #2563eb; }
            .view { display: none; }
            .view.active { display: block; }
            label { display: block; font-size: 12px; font-weight: 750; margin-top: 10px; color: #334155; }
            input, select, textarea, button { width: 100%; box-sizing: border-box; margin-top: 6px; padding: 10px 12px; border-radius: 6px; border: 1px solid #b9c5d5; font: inherit; }
            textarea { min-height: 116px; resize: vertical; }
            button { background: #2563eb; color: white; border: 0; font-weight: 750; cursor: pointer; }
            button.secondary { background: #475569; }
            button.ghost { background: white; color: #1e293b; border: 1px solid #cbd5e1; }
            pre { white-space: pre-wrap; background: #0f172a; color: #dbeafe; border-radius: 8px; padding: 14px; overflow: auto; min-height: 240px; }
            .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
            .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
            .metric { border: 1px solid #d9e1ec; border-radius: 8px; padding: 12px; background: #f8fafc; }
            .metric span { display: block; font-size: 12px; color: #64748b; }
            .metric strong { display: block; font-size: 22px; margin-top: 4px; }
            .list { display: grid; gap: 8px; margin-top: 10px; }
            .item { border: 1px solid #d9e1ec; border-radius: 8px; padding: 10px; background: #fbfdff; cursor: pointer; }
            .item strong { display: block; }
            .item small { color: #64748b; }
            @media (max-width: 980px) { header { display: block; } .shell, .two { grid-template-columns: 1fr; } .grid { grid-template-columns: repeat(2, 1fr); } main { padding: 16px; } }
          </style>
        </head>
        <body>
          <header>
            <div>
              <h1>🚨 AI Incident Investigation Platform</h1>
              <p>Investigate incidents, ingest knowledge, inspect reports, and validate connector readiness.</p>
            </div>
            <div>
              <input id="token" placeholder="Bearer token" />
              <button onclick="demoAuth()">Demo Admin Auth</button>
            </div>
          </header>
          <main>
            <div class="tabs">
              <button class="tab active" onclick="showView('investigate', this)">Investigate</button>
              <button class="tab" onclick="showView('reports', this); loadReports()">Reports</button>
              <button class="tab" onclick="showView('ingest', this)">Ingest</button>
              <button class="tab" onclick="showView('integrations', this); loadCatalog(); loadIntegrations()">Integrations</button>
              <button class="tab" onclick="showView('platformMetrics', this); loadPlatformMetrics()">Metrics</button>
            </div>
            <div class="shell">
              <section class="panel">
                <div class="grid">
                  <div class="metric"><span>Status</span><strong id="status">-</strong></div>
                  <div class="metric"><span>Risk</span><strong id="risk">-</strong></div>
                  <div class="metric"><span>Actions</span><strong id="actions">-</strong></div>
                  <div class="metric"><span>Refs</span><strong id="refs">-</strong></div>
                </div>
                <div id="timeline" class="list"></div>
              </section>
              <section class="panel">
                <div id="investigate" class="view active">
                  <h2>Submit Incident</h2>
                  <div class="two">
                    <div>
                      <label>Domain</label>
                      <select id="domain"><option>production</option><option>security</option><option>cloud</option><option>data</option><option>it</option></select>
                    </div>
                    <div>
                      <label>Severity</label>
                      <select id="severity"><option>high</option><option>critical</option><option>medium</option><option>low</option></select>
                    </div>
                  </div>
                  <label>Title</label>
                  <input id="title" value="Checkout API returning elevated 503 errors" />
                  <label>Description / Logs</label>
                  <textarea id="description">checkout-api ERROR upstream payment-gateway timeout
checkout-api failed request status=503 route=/checkout</textarea>
                  <button onclick="investigate()">Investigate</button>
                </div>
                <div id="reports" class="view">
                  <h2>Reports</h2>
                  <button class="ghost" onclick="loadReports()">Refresh Reports</button>
                  <div id="reportList" class="list"></div>
                </div>
                <div id="ingest" class="view">
                  <h2>Ingest Runbook or Logs</h2>
                  <label>Title</label>
                  <input id="ingestTitle" value="Checkout rollback runbook" />
                  <label>Domain</label>
                  <select id="ingestDomain"><option>production</option><option>security</option><option>cloud</option><option>data</option><option>it</option></select>
                  <label>Source</label>
                  <input id="ingestSource" value="dashboard-upload" />
                  <label>Content</label>
                  <textarea id="ingestContent">If checkout 503 errors increase after deployment, inspect payment dependencies, compare recent deploys, and rollback if customer impact continues.</textarea>
                  <button onclick="ingestDocument()">Ingest Document</button>
                </div>
                <div id="integrations" class="view">
                  <h2>Integrations</h2>
                  <div class="two">
                    <div>
                      <label>Type</label>
                      <select id="integrationType"></select>
                    </div>
                    <div>
                      <label>Domain</label>
                      <select id="integrationDomain"><option>security</option><option>production</option><option>cloud</option><option>data</option><option>it</option></select>
                    </div>
                  </div>
                  <label>Name</label>
                  <input id="integrationName" value="Primary evidence source" />
                  <label>Base URL</label>
                  <input id="integrationUrl" value="https://example.local" />
                  <label>Metadata JSON</label>
                  <textarea id="integrationMetadata">{"channel":"#incidents","project_key":"INC","region":"us-east-1","site":"us5","index":"main","sourcetype":"json"}</textarea>
                  <button onclick="registerIntegration()">Register Dry-Run Connector</button>
                  <div id="integrationList" class="list"></div>
                </div>
                <div id="platformMetrics" class="view">
                  <h2>MCP + A2A Metrics</h2>
                  <button class="ghost" onclick="loadPlatformMetrics()">Refresh Metrics</button>
                  <div id="platformMetricList" class="list"></div>
                </div>
                <pre id="output">No report yet.</pre>
                <div class="two">
                  <button class="secondary" onclick="copyActions()">Copy Actions</button>
                  <button class="secondary" onclick="generatePostmortem()">Generate Postmortem</button>
                </div>
              </section>
            </div>
          </main>
          <script>
            let lastReport = null;
            function authHeaders() { return {'Content-Type':'application/json', Authorization:'Bearer '+document.getElementById('token').value}; }
            function showView(id, button) {
              document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
              document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
              document.getElementById(id).classList.add('active');
              button.classList.add('active');
            }
            function renderOutput(value) { document.getElementById('output').textContent = JSON.stringify(value, null, 2); }
            function renderSummary(report) {
              lastReport = report;
              document.getElementById('status').textContent = report.status || report.verdict || '-';
              document.getElementById('risk').textContent = String(report.risk_score || '-');
              document.getElementById('actions').textContent = String((report.recommended_actions || []).length);
              document.getElementById('refs').textContent = String((report.references || []).length);
              document.getElementById('timeline').innerHTML = (report.timeline || []).slice(-5).map(item => `<div class="item"><small>${item}</small></div>`).join('');
              renderOutput(report);
            }
            async function demoAuth() {
              const res = await fetch('/api/auth/token', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:'analyst', password:'analyst', role:'admin'})});
              const body = await res.json();
              document.getElementById('token').value = body.access_token;
            }
            async function investigate() {
              const domain = document.getElementById('domain').value;
              const title = document.getElementById('title').value;
              const description = document.getElementById('description').value;
              const severity = document.getElementById('severity').value;
              const payload = {incident:{title, domain, severity, source:'dashboard', service:'dashboard-input', description, logs:description.split('\\n'), tags:['dashboard']}};
              const res = await fetch('/api/incidents/investigate', {method:'POST', headers:authHeaders(), body: JSON.stringify(payload)});
              renderSummary(await res.json());
            }
            async function loadReports() {
              const res = await fetch('/api/reports', {headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              const reports = await res.json();
              document.getElementById('reportList').innerHTML = reports.map(report => `<div class="item" onclick="loadReport('${report.investigation_id}')"><strong>${report.title}</strong><small>${report.domain} · ${report.status} · risk ${report.risk_score}</small></div>`).join('');
              renderOutput(reports);
            }
            async function loadReport(id) {
              const res = await fetch('/api/reports/'+id, {headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              renderSummary(await res.json());
            }
            async function ingestDocument() {
              const payload = {title:document.getElementById('ingestTitle').value, domain:document.getElementById('ingestDomain').value, source:document.getElementById('ingestSource').value, content:document.getElementById('ingestContent').value, tags:['dashboard']};
              const res = await fetch('/api/ingest/document', {method:'POST', headers:authHeaders(), body: JSON.stringify(payload)});
              renderOutput(await res.json());
            }
            async function loadCatalog() {
              const res = await fetch('/api/integrations/catalog', {headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              const catalog = await res.json();
              document.getElementById('integrationType').innerHTML = catalog.map(item => `<option value="${item.integration_type}">${item.integration_type} · ${item.category}</option>`).join('');
            }
            async function loadIntegrations() {
              const res = await fetch('/api/integrations', {headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              const items = await res.json();
              document.getElementById('integrationList').innerHTML = items.map(item => `<div class="item" onclick="selectIntegration('${item.id}')"><strong>${item.name}</strong><small>${item.integration_type} · ${item.status}</small></div>`).join('');
            }
            async function registerIntegration() {
              const payload = {integration_type:document.getElementById('integrationType').value, name:document.getElementById('integrationName').value, base_url:document.getElementById('integrationUrl').value, default_domain:document.getElementById('integrationDomain').value, metadata:JSON.parse(document.getElementById('integrationMetadata').value)};
              const res = await fetch('/api/integrations', {method:'POST', headers:authHeaders(), body: JSON.stringify(payload)});
              renderOutput(await res.json());
              await loadIntegrations();
            }
            async function selectIntegration(id) {
              const health = await fetch('/api/integrations/'+id+'/health', {headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              const preview = await fetch('/api/integrations/'+id+'/collect-preview', {method:'POST', headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              renderOutput({health: await health.json(), preview: await preview.json()});
            }
            async function loadPlatformMetrics() {
              const headers = {Authorization:'Bearer '+document.getElementById('token').value};
              const snapshot = await fetch('/api/platform/metrics-snapshot', {headers});
              const tools = await fetch('/api/mcp/tools', {headers});
              const agents = await fetch('/api/a2a/agents', {headers});
              const body = {snapshot: await snapshot.json(), mcp_tools: await tools.json(), a2a_agents: await agents.json()};
              const metrics = body.snapshot;
              document.getElementById('platformMetricList').innerHTML = [
                ['MCP tools', metrics.mcp_tools_available],
                ['A2A agents', metrics.a2a_agents_available],
                ['A2A messages/investigation', metrics.a2a_messages_per_investigation],
                ['Capabilities', metrics.advertised_capabilities],
                ['Integration-ready tools', metrics.integration_ready_tools],
                ['Workflows', metrics.operational_workflows],
                ['Automated steps', metrics.automated_response_steps.length]
              ].map(item => `<div class="item"><strong>${item[1]}</strong><small>${item[0]}</small></div>`).join('');
              renderOutput(body);
            }
            async function generatePostmortem() {
              if (!lastReport?.investigation_id) return;
              const res = await fetch('/api/reports/'+lastReport.investigation_id+'/postmortem', {method:'POST', headers:{Authorization:'Bearer '+document.getElementById('token').value}});
              renderOutput(await res.json());
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
