from app.agents.base import InvestigationAgent
from app.models.schemas import AgentFinding
from app.models.state import InvestigationState


class RemediationRecommenderAgent(InvestigationAgent):
    name = "remediation_recommender"

    def _run(self, state: InvestigationState) -> InvestigationState:
        actions = [
            "Revoke active sessions and refresh tokens for the affected user.",
            "Reset password and require MFA re-registration from a trusted device.",
            "Inspect and remove suspicious mailbox rules or OAuth grants.",
            "Search the source IP across identity, endpoint, and cloud audit logs.",
        ]

        if state.risk_score >= 75:
            actions.insert(0, "Temporarily disable the account until user verification is complete.")

        state.enrichment["recommended_action_text"] = actions
        state.timeline.append("Remediation recommender prepared containment and recovery actions.")
        state.findings.append(
            AgentFinding(
                agent=self.name,
                summary="Recommended containment focuses on token revocation, identity reset, and cloud persistence review.",
                risk_delta=0,
                confidence=0.81,
                evidence=actions,
                references=state.references,
            )
        )
        return state
