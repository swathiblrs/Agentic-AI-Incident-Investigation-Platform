import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.schemas import SecurityAlert
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


if __name__ == "__main__":
    main()
