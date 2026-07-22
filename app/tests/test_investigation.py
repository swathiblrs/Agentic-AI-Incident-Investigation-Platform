import json
from pathlib import Path

from fastapi.testclient import TestClient
from langgraph.graph.state import CompiledStateGraph

from app.main import app
from app.models.schemas import AgentHandoffRequest, IncidentInput, IncidentStatus, SecurityAlert, Verdict
from app.services.a2a import LocalA2ARegistry
from app.services.generic_incident_graph import GenericIncidentGraph
from app.services.investigation_graph import InvestigationGraph
from app.services.llm import OllamaService


def load_sample_alert() -> SecurityAlert:
    payload = json.loads(Path("app/data/sample_alerts/login_anomaly.json").read_text(encoding="utf-8"))
    return SecurityAlert.model_validate(payload)


def load_sample_incident() -> IncidentInput:
    payload = json.loads(Path("app/data/sample_alerts/payment_503_incident.json").read_text(encoding="utf-8"))
    return IncidentInput.model_validate(payload)


def test_sample_alert_is_likely_compromise_or_higher() -> None:
    report = InvestigationGraph().investigate(load_sample_alert())

    assert report.risk_score >= 75
    assert report.verdict in {Verdict.likely_compromise, Verdict.confirmed_incident}
    assert report.references
    assert report.recommended_actions


def test_investigation_uses_compiled_langgraph() -> None:
    graph = InvestigationGraph()

    assert isinstance(graph.graph, CompiledStateGraph)


def test_generic_production_incident_workflow() -> None:
    report = GenericIncidentGraph().investigate(load_sample_incident())

    assert report.risk_score >= 60
    assert report.status in {IncidentStatus.degraded, IncidentStatus.major_incident}
    assert report.references
    assert report.recommended_actions


def test_investigate_endpoint() -> None:
    client = TestClient(app)
    token_response = client.post(
        "/api/auth/token",
        json={"username": "analyst", "password": "analyst"},
    )
    token = token_response.json()["access_token"]

    response = client.post(
        "/api/investigate",
        json={
            "alert": load_sample_alert().model_dump(mode="json"),
            "session_id": "pytest-session",
            "analyst_id": "pytest",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] >= 75
    assert body["findings"]

    memory_response = client.get(
        "/api/sessions/pytest-session/memory",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert memory_response.status_code == 200
    assert len(memory_response.json()["messages"]) >= 2

    clear_response = client.delete(
        "/api/sessions/pytest-session",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert clear_response.status_code == 200
    assert clear_response.json()["memory_cleared"] is True

    cleared_memory_response = client.get(
        "/api/sessions/pytest-session/memory",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert cleared_memory_response.status_code == 200
    assert cleared_memory_response.json()["messages"] == []


def test_generic_incident_endpoint() -> None:
    client = TestClient(app)
    token_response = client.post(
        "/api/auth/token",
        json={"username": "analyst", "password": "analyst"},
    )
    token = token_response.json()["access_token"]

    response = client.post(
        "/api/incidents/investigate",
        json={
            "incident": load_sample_incident().model_dump(mode="json"),
            "session_id": "pytest-production-session",
            "analyst_id": "pytest",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] >= 60
    assert body["recommended_actions"]


def test_ingestion_reports_postmortem_and_integrations() -> None:
    client = TestClient(app)
    token = client.post(
        "/api/auth/token",
        json={"username": "analyst", "password": "analyst", "role": "admin"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    ingest_response = client.post(
        "/api/ingest/document",
        json={
            "title": "Checkout rollback runbook",
            "content": "If 503 errors increase after deployment, inspect dashboards and rollback.",
            "source": "unit-test",
            "domain": "production",
            "team": "SRE",
            "service": "checkout-api",
            "tags": ["production", "rollback"],
        },
        headers=headers,
    )
    assert ingest_response.status_code == 200
    assert ingest_response.json()["chunks"]

    investigation_response = client.post(
        "/api/incidents/investigate",
        json={"incident": load_sample_incident().model_dump(mode="json")},
        headers=headers,
    )
    assert investigation_response.status_code == 200
    investigation_id = investigation_response.json()["investigation_id"]

    reports_response = client.get("/api/reports", headers=headers)
    assert reports_response.status_code == 200
    assert any(report["investigation_id"] == investigation_id for report in reports_response.json())

    postmortem_response = client.post(f"/api/reports/{investigation_id}/postmortem", headers=headers)
    assert postmortem_response.status_code == 200
    assert postmortem_response.json()["corrective_actions"]

    integration_response = client.post(
        "/api/integrations",
        json={
            "integration_type": "slack",
            "name": "Incident Channel",
            "base_url": "https://hooks.slack.example.local",
            "default_domain": "production",
            "metadata": {"channel": "#incidents"},
        },
        headers=headers,
    )
    assert integration_response.status_code == 200
    integration_id = integration_response.json()["id"]
    assert integration_response.json()["status"] == "ready"

    catalog_response = client.get("/api/integrations/catalog", headers=headers)
    assert catalog_response.status_code == 200
    assert any(item["integration_type"] == "slack" for item in catalog_response.json())

    health_response = client.get(f"/api/integrations/{integration_id}/health", headers=headers)
    assert health_response.status_code == 200
    assert health_response.json()["ready_for_live"] is True

    preview_response = client.post(f"/api/integrations/{integration_id}/collect-preview", headers=headers)
    assert preview_response.status_code == 200
    assert preview_response.json()["status"] == "preview"
    assert "incident channel messages" in preview_response.json()["events"]


def test_mcp_and_a2a_local_capabilities() -> None:
    client = TestClient(app)
    token = client.post(
        "/api/auth/token",
        json={"username": "analyst", "password": "analyst", "role": "admin"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tools_response = client.get("/api/mcp/tools", headers=headers)
    assert tools_response.status_code == 200
    tools = tools_response.json()
    assert len(tools) >= 6
    assert any(tool["name"] == "query_observability" for tool in tools)

    tool_call_response = client.post(
        "/api/mcp/tools/call",
        json={
            "tool_name": "query_observability",
            "arguments": {"query": "checkout 503"},
            "incident": load_sample_incident().model_dump(mode="json"),
        },
        headers=headers,
    )
    assert tool_call_response.status_code == 200
    assert tool_call_response.json()["status"] == "ok"
    assert tool_call_response.json()["result"]["cost_mode"] == "free_local_dry_run"

    agents_response = client.get("/api/a2a/agents", headers=headers)
    assert agents_response.status_code == 200
    agents = agents_response.json()
    assert len(agents) == 5
    assert any(agent["name"] == "sre_agent" for agent in agents)

    handoff_response = client.post(
        "/api/a2a/handoff",
        json={
            "source_agent": "pytest_router",
            "target_agent": "sre_agent",
            "incident": load_sample_incident().model_dump(mode="json"),
        },
        headers=headers,
    )
    assert handoff_response.status_code == 200
    assert handoff_response.json()["status"] == "ok"
    assert handoff_response.json()["metrics"]["cost_mode"] == "free_local_a2a_message"

    exchange_response = client.post(
        "/api/a2a/exchange",
        json={
            "source_agent": "pytest_router",
            "incident": load_sample_incident().model_dump(mode="json"),
        },
        headers=headers,
    )
    assert exchange_response.status_code == 200
    exchange_body = exchange_response.json()
    assert exchange_body["status"] == "ok"
    assert exchange_body["primary_agent"] == "sre_agent"
    assert exchange_body["peer_agent"] == "cloud_agent"
    assert exchange_body["metrics"]["messages_exchanged"] == 3

    snapshot_response = client.get("/api/platform/metrics-snapshot", headers=headers)
    assert snapshot_response.status_code == 200
    snapshot = snapshot_response.json()
    assert snapshot["mcp_tools_available"] >= 6
    assert snapshot["a2a_agents_available"] == 5
    assert snapshot["advertised_capabilities"] >= 15
    assert snapshot["a2a_messages_per_investigation"] == 3


def test_domain_role_access_control() -> None:
    client = TestClient(app)
    token = client.post(
        "/api/auth/token",
        json={"username": "analyst", "password": "analyst", "role": "security_analyst"},
    ).json()["access_token"]

    response = client.post(
        "/api/incidents/investigate",
        json={"incident": load_sample_incident().model_dump(mode="json")},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_llm_retry_policy_for_transient_provider_errors(monkeypatch) -> None:
    service = OllamaService()
    calls = {"count": 0}

    def flaky_provider(_: str) -> str:
        import httpx

        calls["count"] += 1
        if calls["count"] < 2:
            raise httpx.ConnectError("temporary")
        return (
            '{"summary":"ok","likely_causes":["temporary dependency"],'
            '"recommended_next_steps":["retry succeeded"],"confidence":0.8}'
        )

    monkeypatch.setattr(service, "_call_provider", flaky_provider)
    monkeypatch.setattr(service.settings, "llm_retry_base_seconds", 0)

    result = service.analyze_alert(load_sample_alert(), [])

    assert calls["count"] == 2
    assert result.summary == "ok"


def test_openai_embedding_provider_path(monkeypatch) -> None:
    service = OllamaService()
    monkeypatch.setattr(service.settings, "llm_provider", "openai")
    monkeypatch.setattr(service.settings, "openai_api_key", "test-key")

    class FakeEmbeddingResponse:
        def raise_for_status(self) -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {"data": [{"embedding": [0.1, 0.2, 0.3]}]}

    def fake_post(*args, **kwargs):
        assert args[0].endswith("/embeddings")
        assert kwargs["json"]["model"] == service.settings.openai_embed_model
        assert kwargs["json"]["dimensions"] == service.settings.openai_embed_dimensions
        return FakeEmbeddingResponse()

    monkeypatch.setattr("app.services.llm.httpx.post", fake_post)

    assert service.embed("login anomaly") == [0.1, 0.2, 0.3]


def test_openai_provider_without_key_falls_back_to_local(monkeypatch) -> None:
    service = OllamaService()
    monkeypatch.setattr(service.settings, "llm_provider", "openai")
    monkeypatch.setattr(service.settings, "openai_api_key", "")

    assert service._effective_provider() == "ollama"


def test_security_report_contains_mcp_and_a2a_verification_markers() -> None:
    report = InvestigationGraph().investigate(load_sample_alert())
    timeline = " ".join(report.timeline)

    assert "MCP tool search_security_logs collected local security evidence" in timeline
    assert "A2A exchange completed across soc_agent and it_agent" in timeline
    assert "A2A message soc_agent -> it_agent: collect_peer_context" in timeline
    assert "A2A message it_agent -> soc_agent: return_peer_context" in timeline
    assert any(item.kind == "mcp_tool" for item in report.evidence)
    assert any(item.kind == "identity_signal" for item in report.evidence)


def test_generic_report_contains_mcp_and_a2a_verification_markers() -> None:
    report = GenericIncidentGraph().investigate(load_sample_incident())
    timeline = " ".join(report.timeline)

    assert "MCP tool query_observability collected local evidence" in timeline
    assert "A2A exchange completed across sre_agent and cloud_agent" in timeline
    assert "A2A message sre_agent -> cloud_agent: collect_peer_context" in timeline
    assert "A2A message cloud_agent -> sre_agent: return_peer_context" in timeline
    assert any(item.kind == "mcp_tool" for item in report.evidence)
    assert any(item.kind == "service_health" for item in report.evidence)


def test_prometheus_exports_mcp_a2a_and_routing_metrics() -> None:
    client = TestClient(app)
    token = client.post(
        "/api/auth/token",
        json={"username": "analyst", "password": "analyst", "role": "admin"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/incidents/investigate",
        json={"incident": load_sample_incident().model_dump(mode="json")},
        headers=headers,
    )
    metrics_response = client.get("/api/metrics")

    assert metrics_response.status_code == 200
    metrics_text = metrics_response.text
    assert "incident_mcp_tool_calls_total" in metrics_text
    assert "incident_a2a_handoffs_total" in metrics_text
    assert "incident_a2a_messages_total" in metrics_text
    assert "incident_domain_routing_total" in metrics_text
    assert "incident_evidence_items_total" in metrics_text
    assert "incident_automated_steps_total" in metrics_text


def test_cloud_a2a_provider_calls_configured_agent_endpoint(monkeypatch) -> None:
    registry = LocalA2ARegistry()
    monkeypatch.setattr(registry.settings, "a2a_provider", "cloud")
    monkeypatch.setattr(
        registry.settings,
        "a2a_agent_urls",
        {"sre_agent": "https://agents.example.com/sre/handoff"},
    )
    monkeypatch.setattr(registry.settings, "a2a_api_key", "test-a2a-key")

    calls = []

    class FakeA2AResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "source_agent": "pytest_router",
                "target_agent": "sre_agent",
                "task_type": "triage_incident",
                "domain": "production",
                "status": "ok",
                "summary": "Remote SRE agent completed cloud A2A triage.",
                "result": {"provider": "remote"},
                "metrics": {"latency_source": "mock"},
                "duration_ms": 42.0,
            }

    def fake_post(url, headers, json, timeout):
        calls.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        return FakeA2AResponse()

    monkeypatch.setattr("app.services.a2a.httpx.post", fake_post)

    result = registry.handoff(
        AgentHandoffRequest(
            source_agent="pytest_router",
            target_agent="sre_agent",
            task_type="triage_incident",
            incident=load_sample_incident(),
        )
    )

    assert result.status == "ok"
    assert result.metrics["cost_mode"] == "cloud_a2a_message"
    assert calls[0]["url"] == "https://agents.example.com/sre/handoff"
    assert calls[0]["headers"]["Authorization"] == "Bearer test-a2a-key"
