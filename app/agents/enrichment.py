from ipaddress import ip_address

from app.agents.base import InvestigationAgent
from app.models.schemas import AgentFinding, EvidenceItem
from app.models.state import InvestigationState


class ThreatEnrichmentAgent(InvestigationAgent):
    name = "threat_enrichment"

    def _run(self, state: InvestigationState) -> InvestigationState:
        alert = state.alert
        risk_delta = 0
        observations = []

        if alert.ip_address:
            try:
                parsed = ip_address(alert.ip_address)
                if not parsed.is_private:
                    observations.append(f"{alert.ip_address} is an external source address")
                    risk_delta += 8
            except ValueError:
                observations.append(f"{alert.ip_address} is not a valid IP address")

        raw_text = " ".join(str(event).lower() for event in alert.raw_events)
        if "hosting-provider" in raw_text or "tor" in raw_text or "vpn" in raw_text:
            observations.append("source infrastructure resembles anonymized or hosted access")
            risk_delta += 15
        if "oauth" in raw_text or "mailbox_rule" in raw_text or "forward" in raw_text:
            observations.append("post-login cloud activity indicates possible persistence or collection")
            risk_delta += 22

        state.risk_score += risk_delta
        state.enrichment["threat_observations"] = observations
        state.timeline.append(f"Threat enrichment added {risk_delta} risk points.")
        state.evidence.extend(
            EvidenceItem(kind="threat_enrichment", description=obs, value=alert.ip_address or "n/a", weight=8)
            for obs in observations
        )
        state.findings.append(
            AgentFinding(
                agent=self.name,
                summary="Threat enrichment correlated infrastructure and cloud activity.",
                risk_delta=risk_delta,
                confidence=0.72,
                evidence=observations,
                references=state.references[:3],
            )
        )
        return state
