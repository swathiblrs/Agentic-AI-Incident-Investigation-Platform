import json
from pathlib import Path

from fastapi.testclient import TestClient

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


def test_investigate_endpoint() -> None:
    client = TestClient(app)
    response = client.post("/api/investigate", json={"alert": load_sample_alert().model_dump(mode="json")})

    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] >= 75
    assert body["findings"]
