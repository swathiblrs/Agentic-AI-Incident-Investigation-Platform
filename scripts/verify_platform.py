from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.schemas import IncidentInput, SecurityAlert
from app.services.a2a import LocalA2ARegistry
from app.services.generic_incident_graph import GenericIncidentGraph
from app.services.investigation_graph import InvestigationGraph
from app.services.mcp_tools import LocalMCPToolRegistry


def main() -> None:
    reports_dir = Path("evals/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    alert = SecurityAlert.model_validate(
        json.loads(Path("app/data/sample_alerts/login_anomaly.json").read_text(encoding="utf-8"))
    )
    incident = IncidentInput.model_validate(
        json.loads(Path("app/data/sample_alerts/payment_503_incident.json").read_text(encoding="utf-8"))
    )

    security_report = InvestigationGraph().investigate(alert)
    incident_report = GenericIncidentGraph().investigate(incident)
    mcp_metrics = LocalMCPToolRegistry().capability_metrics()
    a2a_metrics = LocalA2ARegistry().capability_metrics()

    checks = {
        "mcp_tools_available": mcp_metrics["mcp_tools_available"] >= 6,
        "a2a_agents_available": a2a_metrics["a2a_agents_available"] == 5,
        "advertised_capabilities": a2a_metrics["advertised_capabilities"] >= 15,
        "security_mcp_timeline": any("MCP tool" in item for item in security_report.timeline),
        "security_a2a_timeline": any("A2A handoff" in item for item in security_report.timeline),
        "generic_mcp_timeline": any("MCP tool" in item for item in incident_report.timeline),
        "generic_a2a_timeline": any("A2A handoff" in item for item in incident_report.timeline),
        "security_evidence_complete": len(security_report.evidence) >= 4,
        "generic_evidence_complete": len(incident_report.evidence) >= 6,
        "actions_generated": bool(security_report.recommended_actions and incident_report.recommended_actions),
    }
    output = {
        "created_at": datetime.now(UTC).isoformat(),
        "passed": all(checks.values()),
        "checks": checks,
        "metrics": {
            **mcp_metrics,
            **a2a_metrics,
            "automated_response_steps": 9,
            "sample_security_risk_score": security_report.risk_score,
            "sample_incident_risk_score": incident_report.risk_score,
        },
    }
    report_path = reports_dir / "platform_verification.json"
    report_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))
    raise SystemExit(0 if output["passed"] else 1)


if __name__ == "__main__":
    main()
