from app.agents.base import InvestigationAgent
from app.models.schemas import AgentFinding, EvidenceItem
from app.models.state import InvestigationState


class EvidenceCollectorAgent(InvestigationAgent):
    name = "evidence_collector"

    def _run(self, state: InvestigationState) -> InvestigationState:
        alert = state.alert
        collected = []
        risk_delta = 0

        for event in alert.raw_events:
            event_name = str(event.get("event", "unknown"))
            timestamp = str(event.get("timestamp", "unknown time"))
            description = f"{event_name} at {timestamp}"
            weight = 5
            if "succeeded" in event_name:
                weight += 5
            if "mailbox_rule" in event_name or "oauth" in event_name:
                weight += 15
            if "failed" in event_name and "mfa" in str(event).lower():
                weight += 8

            risk_delta += min(weight, 15)
            collected.append(description)
            state.evidence.append(
                EvidenceItem(
                    kind="raw_event",
                    description=description,
                    value=str(event),
                    weight=weight,
                )
            )

        state.risk_score += risk_delta
        state.timeline.append(f"Evidence collector normalized {len(alert.raw_events)} source events.")
        state.findings.append(
            AgentFinding(
                agent=self.name,
                summary=f"Collected {len(collected)} evidence items from source telemetry.",
                risk_delta=risk_delta,
                confidence=0.84,
                evidence=collected,
                references=state.references[:2],
            )
        )
        return state
