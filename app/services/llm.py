from __future__ import annotations

import hashlib
import json
import random
import time
from collections.abc import Callable

import httpx

from app.core.config import get_settings
from app.models.schemas import IncidentDomain, LLMReasoningResult, RetrievedDocument, SecurityAlert


class OllamaService:
    def __init__(self) -> None:
        self.settings = get_settings()

    def embed(self, text: str) -> list[float]:
        if self.settings.llm_provider != "ollama":
            return self._deterministic_embedding(text)

        try:
            response = self._with_retries(
                lambda: httpx.post(
                    f"{self.settings.ollama_base_url}/api/embeddings",
                    json={"model": self.settings.ollama_embed_model, "prompt": text},
                    timeout=10,
                )
            )
            response.raise_for_status()
            embedding = response.json().get("embedding")
            if isinstance(embedding, list) and embedding:
                return [float(value) for value in embedding]
        except httpx.HTTPError:
            pass
        return self._deterministic_embedding(text)

    def analyze_alert(
        self,
        alert: SecurityAlert,
        references: list[RetrievedDocument],
        domain: IncidentDomain = IncidentDomain.security,
    ) -> LLMReasoningResult:
        prompt = self._build_prompt(alert, references, domain)
        if self.settings.llm_provider not in {"ollama", "openai", "anthropic"}:
            return self._fallback_analysis(alert, domain)

        try:
            text = self._with_retries(lambda: self._call_provider(prompt))
            return self._parse_reasoning(text)
        except httpx.HTTPError:
            pass
        except ValueError:
            pass
        return self._fallback_analysis(alert, domain)

    def _call_provider(self, prompt: str) -> str:
        if self.settings.llm_provider == "ollama":
            response = httpx.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json={
                    "model": self.settings.ollama_llm_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
                timeout=30,
            )
            response.raise_for_status()
            text = response.json().get("response")
            if isinstance(text, str) and text.strip():
                return text.strip()
        if self.settings.llm_provider == "openai" and self.settings.openai_api_key:
            response = httpx.post(
                f"{self.settings.openai_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {self.settings.openai_api_key}"},
                json={
                    "model": self.settings.openai_model,
                    "response_format": {"type": "json_object"},
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        if self.settings.llm_provider == "anthropic" and self.settings.anthropic_api_key:
            response = httpx.post(
                f"{self.settings.anthropic_base_url.rstrip('/')}/messages",
                headers={
                    "x-api-key": self.settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": self.settings.anthropic_model,
                    "max_tokens": 800,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            response.raise_for_status()
            parts = response.json().get("content", [])
            if parts and isinstance(parts[0].get("text"), str):
                return parts[0]["text"]
        raise ValueError("No supported live provider configured.")

    def _with_retries(self, operation: Callable[[], object]):
        attempts = max(1, self.settings.llm_max_retries)
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                return operation()
            except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError, httpx.TransportError) as exc:
                last_error = exc
                if attempt == attempts - 1:
                    break
                delay = min(
                    self.settings.llm_retry_max_seconds,
                    self.settings.llm_retry_base_seconds * (2**attempt),
                )
                time.sleep(delay + random.uniform(0, delay / 4))
        if last_error is not None:
            raise last_error
        raise ValueError("Retry operation failed without an exception.")

    @staticmethod
    def _parse_reasoning(text: str) -> LLMReasoningResult:
        payload = json.loads(text)
        return LLMReasoningResult.model_validate(payload)

    @staticmethod
    def _build_prompt(
        alert: SecurityAlert,
        references: list[RetrievedDocument],
        domain: IncidentDomain,
    ) -> str:
        context = "\n\n".join(f"{doc.title}: {doc.content[:800]}" for doc in references[:4])
        return (
            f"You are a {domain.value} incident investigation assistant. Analyze the incident using the context. "
            "Return only valid JSON with keys: summary, likely_causes, recommended_next_steps, confidence. "
            "confidence must be a number from 0 to 1.\n\n"
            f"Incident: {alert.model_dump_json()}\n\nContext:\n{context}"
        )

    @staticmethod
    def _fallback_analysis(alert: SecurityAlert, domain: IncidentDomain) -> LLMReasoningResult:
        if domain == IncidentDomain.security:
            summary = (
                f"{alert.title} should be treated as high priority when identity anomaly, MFA fatigue, "
                "new infrastructure, or post-login persistence activity are present."
            )
            causes = ["credential compromise", "MFA fatigue", "suspicious post-authentication activity"]
            steps = ["preserve logs", "revoke sessions", "verify the user", "review persistence changes"]
        else:
            summary = (
                f"{alert.title} needs domain-specific triage using logs, metrics, events, and runbook context."
            )
            causes = ["recent change", "dependency failure", "capacity or configuration issue"]
            steps = ["inspect recent changes", "review dashboards", "mitigate user impact", "open owner follow-up"]
        return LLMReasoningResult(
            summary=summary,
            likely_causes=causes,
            recommended_next_steps=steps,
            confidence=0.62,
        )

    @staticmethod
    def _deterministic_embedding(text: str, dimensions: int = 384) -> list[float]:
        vector = [0.0] * dimensions
        for token in text.lower().split():
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:2], "big") % dimensions
            vector[index] += 1.0
        norm = sum(value * value for value in vector) ** 0.5 or 1.0
        return [value / norm for value in vector]
