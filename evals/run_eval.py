from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.schemas import SecurityAlert
from app.services.investigation_graph import InvestigationGraph


def main() -> None:
    reports_dir = Path("evals/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    cases = [json.loads(path.read_text(encoding="utf-8")) for path in Path("evals/cases").glob("*.json")]
    graph = InvestigationGraph()
    results = []

    for case in cases:
        alert = SecurityAlert.model_validate(
            json.loads(Path(case["alert_file"]).read_text(encoding="utf-8"))
        )
        report = graph.investigate(alert)
        actions = " ".join(action.action for action in report.recommended_actions)
        passed = (
            report.risk_score >= case["min_risk_score"]
            and report.verdict.value in case["allowed_verdicts"]
            and all(required in actions for required in case["required_actions"])
        )
        results.append(
            {
                "name": case["name"],
                "passed": passed,
                "risk_score": report.risk_score,
                "verdict": report.verdict.value,
            }
        )

    output = {
        "created_at": datetime.now(UTC).isoformat(),
        "total": len(results),
        "passed": sum(1 for result in results if result["passed"]),
        "results": results,
    }
    report_path = reports_dir / "latest.json"
    report_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
