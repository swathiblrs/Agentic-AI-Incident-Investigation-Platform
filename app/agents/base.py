from __future__ import annotations

import time
from abc import ABC, abstractmethod

from app.core.telemetry import AGENT_DURATION
from app.models.state import InvestigationState


class InvestigationAgent(ABC):
    name: str

    def run(self, state: InvestigationState) -> InvestigationState:
        started = time.perf_counter()
        try:
            return self._run(state)
        finally:
            AGENT_DURATION.labels(agent=self.name).observe(time.perf_counter() - started)

    @abstractmethod
    def _run(self, state: InvestigationState) -> InvestigationState:
        raise NotImplementedError
