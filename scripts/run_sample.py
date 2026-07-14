import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.schemas import SecurityAlert
from app.models.schemas import IncidentInput
from app.services.generic_incident_graph import GenericIncidentGraph
from app.services.investigation_graph import InvestigationGraph


def main() -> None:
    alert_path = Path("app/data/sample_alerts/login_anomaly.json")
    alert = SecurityAlert.model_validate(json.loads(alert_path.read_text(encoding="utf-8")))
    report = InvestigationGraph().investigate(alert)

    print(f"Verdict: {report.verdict}")
    print(f"Risk: {report.risk_score}/100")
    print(report.executive_summary)
    print("\nRecommended Actions")
    for action in report.recommended_actions:
        print(f"{action.priority}. [{action.owner}] {action.action}")

    incident_path = Path("app/data/sample_alerts/payment_503_incident.json")
    incident = IncidentInput.model_validate(json.loads(incident_path.read_text(encoding="utf-8")))
    incident_report = GenericIncidentGraph().investigate(incident)

    print("\nProduction Incident Sample")
    print(f"Status: {incident_report.status}")
    print(f"Risk: {incident_report.risk_score}/100")
    print(incident_report.executive_summary)


if __name__ == "__main__":
    main()
