from __future__ import annotations

import hashlib

import httpx

from app.core.config import get_settings
from app.models.schemas import RetrievedDocument, SecurityAlert


class OllamaService:
    def __init__(self) -> None:
        self.settings = get_settings()

    def embed(self, text: str) -> list[float]:
        if self.settings.llm_provider != "ollama":
            return self._deterministic_embedding(text)

        try:
            response = httpx.post(
                f"{self.settings.ollama_base_url}/api/embeddings",
                json={"model": self.settings.ollama_embed_model, "prompt": text},
                timeout=10,
            )
            response.raise_for_status()
            embedding = response.json().get("embedding")
            if isinstance(embedding, list) and embedding:
                return [float(value) for value in embedding]
        except httpx.HTTPError:
            pass
        return self._deterministic_embedding(text)

    def analyze_alert(self, alert: SecurityAlert, references: list[RetrievedDocument]) -> str:
        prompt = self._build_prompt(alert, references)
        if self.settings.llm_provider != "ollama":
            return self._fallback_analysis(alert)

        try:
            response = httpx.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json={"model": self.settings.ollama_llm_model, "prompt": prompt, "stream": False},
                timeout=30,
            )
            response.raise_for_status()
            text = response.json().get("response")
            if isinstance(text, str) and text.strip():
                return text.strip()
        except httpx.HTTPError:
            pass
        return self._fallback_analysis(alert)

    @staticmethod
    def _build_prompt(alert: SecurityAlert, references: list[RetrievedDocument]) -> str:
        context = "\n\n".join(f"{doc.title}: {doc.content[:800]}" for doc in references[:4])
        return (
            "You are a SOC investigation assistant. Analyze the alert using the context, "
            "state likely compromise indicators, and recommend immediate next steps.\n\n"
            f"Alert: {alert.model_dump_json()}\n\nContext:\n{context}"
        )

    @staticmethod
    def _fallback_analysis(alert: SecurityAlert) -> str:
        return (
            f"{alert.title} should be treated as high priority when identity anomaly, MFA fatigue, "
            "new infrastructure, or post-login persistence activity are present. Preserve logs, "
            "revoke active sessions, and verify the user before closure."
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
