from app.agents.base import InvestigationAgent
from app.models.schemas import AgentFinding, AlertSeverity, EvidenceItem
from app.models.state import InvestigationState


class AlertTriageAgent(InvestigationAgent):
    name = "alert_triage"

    def _run(self, state: InvestigationState) -> InvestigationState:
        alert = state.alert
        score = {
            AlertSeverity.low: 10,
            AlertSeverity.medium: 25,
            AlertSeverity.high: 45,
            AlertSeverity.critical: 60,
        }[alert.severity]

        signals = []
        if "impossible-travel" in alert.tags or "new-country" in alert.tags:
            score += 20
            signals.append("new geography or impossible travel")
        if "mfa-fatigue" in alert.tags:
            score += 20
            signals.append("MFA fatigue pattern")
        if alert.technique:
            score += 10
            signals.append(f"mapped to ATT&CK {alert.technique}")

        state.risk_score += score
        state.timeline.append(f"Triage classified alert '{alert.title}' at initial risk {score}.")
        state.evidence.extend(
            EvidenceItem(kind="triage_signal", description=signal, value=alert.id, weight=10)
            for signal in signals
        )
        state.findings.append(
            AgentFinding(
                agent=self.name,
                summary=f"Initial triage found {', '.join(signals) or 'limited high-risk context'}.",
                risk_delta=score,
                confidence=0.78,
                evidence=signals,
                references=state.references[:2],
            )
        )
        return state
