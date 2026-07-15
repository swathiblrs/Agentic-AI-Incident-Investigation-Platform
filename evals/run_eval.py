from __future__ import annotations

import json
import sys
import time
import base64
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from app.core.config import get_settings
from app.models.schemas import IncidentInput, IncidentReport, InvestigationReport, SecurityAlert
from app.services.generic_incident_graph import GenericIncidentGraph
from app.services.investigation_graph import InvestigationGraph


def main() -> None:
    settings = get_settings()
    reports_dir = Path("evals/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    cases = [json.loads(path.read_text(encoding="utf-8")) for path in Path("evals/cases").glob("*.json")]
    security_graph = InvestigationGraph()
    generic_graph = GenericIncidentGraph()
    openai_eval_enabled = _openai_eval_enabled(settings)
    langfuse_eval_enabled = _langfuse_eval_enabled(settings)
    results = []

    for case in cases:
        if "alert_file" in case or "alert" in case:
            payload = (
                json.loads(Path(case["alert_file"]).read_text(encoding="utf-8"))
                if "alert_file" in case
                else case["alert"]
            )
            alert = SecurityAlert.model_validate(payload)
            report = security_graph.investigate(alert)
            actions = " ".join(action.action for action in report.recommended_actions)
            evidence = " ".join(item.value for item in report.evidence)
            passed = (
                report.risk_score >= case["min_risk_score"]
                and report.verdict.value in case["allowed_verdicts"]
                and all(required in actions for required in case["required_actions"])
                and all(required.lower() in evidence.lower() for required in case.get("required_evidence", []))
            )
            result = {
                "name": case["name"],
                "passed": passed,
                "risk_score": report.risk_score,
                "verdict": report.verdict.value,
            }
        else:
            payload = (
                json.loads(Path(case["incident_file"]).read_text(encoding="utf-8"))
                if "incident_file" in case
                else case["incident"]
            )
            incident = IncidentInput.model_validate(payload)
            report = generic_graph.investigate(incident)
            actions = " ".join(action.action.lower() for action in report.recommended_actions)
            evidence = " ".join(item.value.lower() for item in report.evidence)
            passed = (
                report.risk_score >= case["min_risk_score"]
                and report.status.value in case["allowed_statuses"]
                and all(required.lower() in actions for required in case["required_actions"])
                and all(required.lower() in evidence for required in case.get("required_evidence", []))
            )
            result = {
                "name": case["name"],
                "passed": passed,
                "risk_score": report.risk_score,
                "status": report.status.value,
            }

        if openai_eval_enabled:
            result["openai_judge"] = _judge_with_openai(case, report, settings)
        else:
            result["openai_judge"] = {"enabled": False, "reason": "OPENAI_API_KEY not configured"}

        result["langfuse_trace_sent"] = (
            _send_langfuse_eval_trace(case, report, result, settings) if langfuse_eval_enabled else False
        )
        results.append(result)

    output = {
        "created_at": datetime.now(UTC).isoformat(),
        "evaluation_mode": "openai_langfuse" if openai_eval_enabled and langfuse_eval_enabled else "local",
        "total": len(results),
        "passed": sum(1 for result in results if result["passed"]),
        "openai_judged": sum(1 for result in results if result["openai_judge"].get("enabled")),
        "langfuse_traces_sent": sum(1 for result in results if result["langfuse_trace_sent"]),
        "results": results,
    }
    report_path = reports_dir / "latest.json"
    report_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


def _openai_eval_enabled(settings: Any) -> bool:
    return settings.evaluation_provider in {"auto", "openai"} and bool(settings.openai_api_key)


def _langfuse_eval_enabled(settings: Any) -> bool:
    return (
        settings.langfuse_enabled
        and bool(settings.langfuse_public_key)
        and bool(settings.langfuse_secret_key)
    )


def _judge_with_openai(
    case: dict[str, Any],
    report: InvestigationReport | IncidentReport,
    settings: Any,
) -> dict[str, Any]:
    prompt = (
        "You are evaluating an AI incident investigation report. "
        "Return only JSON with keys: score, passed, rationale. "
        "score must be a number from 0 to 1. passed must be boolean. "
        "Evaluate whether the report reached the expected status/verdict, used required evidence, "
        "and recommended required actions.\n\n"
        f"Evaluation case:\n{json.dumps(case, default=str)}\n\n"
        f"Generated report:\n{report.model_dump_json()}"
    )
    last_error = ""
    for attempt in range(max(1, settings.evaluation_max_retries)):
        try:
            response = httpx.post(
                f"{settings.openai_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                json={
                    "model": settings.evaluation_model,
                    "response_format": {"type": "json_object"},
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            payload = json.loads(content)
            return {
                "enabled": True,
                "model": settings.evaluation_model,
                "score": float(payload.get("score", 0)),
                "passed": bool(payload.get("passed", False)),
                "rationale": str(payload.get("rationale", "")),
            }
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            if attempt < settings.evaluation_max_retries - 1:
                time.sleep(1 + attempt)
    return {"enabled": True, "model": settings.evaluation_model, "error": last_error}


def _send_langfuse_eval_trace(
    case: dict[str, Any],
    report: InvestigationReport | IncidentReport,
    result: dict[str, Any],
    settings: Any,
) -> bool:
    auth = base64.b64encode(
        f"{settings.langfuse_public_key}:{settings.langfuse_secret_key}".encode("utf-8")
    ).decode("utf-8")
    payload = {
        "batch": [
            {
                "type": "trace-create",
                "body": {
                    "id": str(report.investigation_id),
                    "name": "incident-investigation-eval",
                    "input": case,
                    "output": report.model_dump(mode="json"),
                    "metadata": {
                        "local_passed": result["passed"],
                        "openai_judge": result.get("openai_judge", {}),
                        "source": "hybrid-eval-runner",
                    },
                },
            }
        ]
    }
    try:
        response = httpx.post(
            f"{settings.langfuse_host.rstrip('/')}/api/public/ingestion",
            json=payload,
            headers={"Authorization": f"Basic {auth}"},
            timeout=10,
        )
        response.raise_for_status()
        return True
    except httpx.HTTPError:
        return False


if __name__ == "__main__":
    main()
