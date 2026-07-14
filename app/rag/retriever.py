from pathlib import Path

from app.core.config import get_settings
from app.models.schemas import RetrievedDocument, SecurityAlert
from app.rag.vector_store import LocalVectorStore
from app.storage.pgvector_store import PgVectorStore


class SecurityKnowledgeRetriever:
    def __init__(self, knowledge_dir: Path | None = None):
        base_dir = Path(__file__).resolve().parents[1]
        settings = get_settings()
        self.knowledge_dir = knowledge_dir or base_dir / "data" / "knowledge_base"
        self.store = LocalVectorStore(self.knowledge_dir)
        self.pgvector_store = PgVectorStore(settings.database_url) if settings.use_postgres else None

    def retrieve_for_alert(self, alert: SecurityAlert) -> list[RetrievedDocument]:
        settings = get_settings()
        query = " ".join(
            part
            for part in [
                alert.title,
                alert.description,
                alert.user or "",
                alert.host or "",
                alert.ip_address or "",
                alert.geo or "",
                alert.tactic or "",
                alert.technique or "",
                " ".join(alert.tags),
                " ".join(str(event) for event in alert.raw_events),
            ]
            if part
        )
        if self.pgvector_store is not None:
            try:
                return self.pgvector_store.search(query=query, top_k=settings.rag_top_k)
            except Exception:
                pass
        return self.store.search(query=query, top_k=settings.rag_top_k)
