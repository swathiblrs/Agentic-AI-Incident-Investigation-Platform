import json
from pathlib import Path

from fastapi.testclient import TestClient
from langgraph.graph.state import CompiledStateGraph

from app.main import app
from app.models.schemas import SecurityAlert, Verdict
from app.services.investigation_graph import InvestigationGraph


def load_sample_alert() -> SecurityAlert:
    payload = json.loads(Path("app/data/sample_alerts/login_anomaly.json").read_text(encoding="utf-8"))
    return SecurityAlert.model_validate(payload)


def test_sample_alert_is_likely_compromise_or_higher() -> None:
    report = InvestigationGraph().investigate(load_sample_alert())

    assert report.risk_score >= 75
    assert report.verdict in {Verdict.likely_compromise, Verdict.confirmed_incident}
    assert report.references
    assert report.recommended_actions


def test_investigation_uses_compiled_langgraph() -> None:
    graph = InvestigationGraph()

    assert isinstance(graph.graph, CompiledStateGraph)


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
