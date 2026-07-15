from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.core.config import get_settings
from app.models.schemas import (
    IncidentDomain,
    IngestDocumentRequest,
    IngestLogsRequest,
    IngestedChunk,
    IngestionResponse,
)
from app.rag.uploaded_store import UPLOADED_DOCUMENTS
from app.services.llm import OllamaService
from app.storage.db import get_database_pool


class IngestionService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.embeddings = OllamaService()
        self.memory_chunks: dict[str, IngestedChunk] = {}

    def ingest_document(self, request: IngestDocumentRequest) -> IngestionResponse:
        return self._ingest(
            title=request.title,
            content=request.content,
            source=request.source,
            domain=request.domain,
            team=request.team,
            service=request.service,
            tags=request.tags,
            chunk_size=request.chunk_size,
            chunk_overlap=request.chunk_overlap,
        )

    async def ingest_document_async(self, request: IngestDocumentRequest) -> IngestionResponse:
        return await self._ingest_async(
            title=request.title,
            content=request.content,
            source=request.source,
            domain=request.domain,
            team=request.team,
            service=request.service,
            tags=request.tags,
            chunk_size=request.chunk_size,
            chunk_overlap=request.chunk_overlap,
        )

    def ingest_logs(self, request: IngestLogsRequest) -> IngestionResponse:
        content = "\n".join(request.logs)
        return self._ingest(
            title=request.title,
            content=content,
            source=request.source,
            domain=request.domain,
            team=request.team,
            service=request.service,
            tags=["logs", *request.tags],
            chunk_size=request.chunk_size,
            chunk_overlap=request.chunk_overlap,
        )

    async def ingest_logs_async(self, request: IngestLogsRequest) -> IngestionResponse:
        content = "\n".join(request.logs)
        return await self._ingest_async(
            title=request.title,
            content=content,
            source=request.source,
            domain=request.domain,
            team=request.team,
            service=request.service,
            tags=["logs", *request.tags],
            chunk_size=request.chunk_size,
            chunk_overlap=request.chunk_overlap,
        )

    def _ingest(
        self,
        title: str,
        content: str,
        source: str,
        domain: IncidentDomain,
        team: str | None,
        service: str | None,
        tags: list[str],
        chunk_size: int,
        chunk_overlap: int,
    ) -> IngestionResponse:
        document_id = str(uuid4())
        chunks = self._chunk_text(content, chunk_size, chunk_overlap)
        created_at = datetime.now(UTC)
        ingested = [
            IngestedChunk(
                id=f"{document_id}-{index}",
                document_id=document_id,
                chunk_index=index,
                title=title,
                source=source,
                domain=domain,
                team=team,
                service=service,
                created_at=created_at,
            )
            for index, _ in enumerate(chunks)
        ]
        stored = self._store_chunks(ingested, chunks, tags)
        return IngestionResponse(document_id=document_id, chunks=ingested, stored_in_pgvector=stored)

    async def _ingest_async(
        self,
        title: str,
        content: str,
        source: str,
        domain: IncidentDomain,
        team: str | None,
        service: str | None,
        tags: list[str],
        chunk_size: int,
        chunk_overlap: int,
    ) -> IngestionResponse:
        document_id = str(uuid4())
        chunks = self._chunk_text(content, chunk_size, chunk_overlap)
        created_at = datetime.now(UTC)
        ingested = [
            IngestedChunk(
                id=f"{document_id}-{index}",
                document_id=document_id,
                chunk_index=index,
                title=title,
                source=source,
                domain=domain,
                team=team,
                service=service,
                created_at=created_at,
            )
            for index, _ in enumerate(chunks)
        ]
        self._store_memory_chunks(ingested, chunks, tags)
        stored = await self._store_chunks_async(ingested, chunks, tags)
        return IngestionResponse(document_id=document_id, chunks=ingested, stored_in_pgvector=stored)

    def _store_chunks(self, chunks: list[IngestedChunk], contents: list[str], tags: list[str]) -> bool:
        self._store_memory_chunks(chunks, contents, tags)

        if not self.settings.use_postgres:
            return False

        try:
            import psycopg

            with psycopg.connect(self.settings.database_url) as connection:
                with connection.cursor() as cursor:
                    for chunk, content in zip(chunks, contents, strict=True):
                        embedding = self.embeddings.embed(content)[:384]
                        vector = "[" + ",".join(str(value) for value in embedding) + "]"
                        cursor.execute(
                            """
                            INSERT INTO security_documents
                              (id, title, source, content, tags, embedding, domain, team, service, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s::vector, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                              title = EXCLUDED.title,
                              source = EXCLUDED.source,
                              content = EXCLUDED.content,
                              tags = EXCLUDED.tags,
                              embedding = EXCLUDED.embedding,
                              domain = EXCLUDED.domain,
                              team = EXCLUDED.team,
                              service = EXCLUDED.service
                            """,
                            (
                                chunk.id,
                                chunk.title,
                                chunk.source,
                                content,
                                tags,
                                vector,
                                chunk.domain.value,
                                chunk.team,
                                chunk.service,
                                chunk.created_at,
                            ),
                        )
                connection.commit()
            return True
        except Exception:
            return False

    async def _store_chunks_async(
        self,
        chunks: list[IngestedChunk],
        contents: list[str],
        tags: list[str],
    ) -> bool:
        if not self.settings.use_postgres:
            return False
        try:
            pool = await get_database_pool().open()
            if pool is None:
                return False
            async with pool.connection() as connection:
                async with connection.cursor() as cursor:
                    for chunk, content in zip(chunks, contents, strict=True):
                        embedding = self.embeddings.embed(content)[:384]
                        vector = "[" + ",".join(str(value) for value in embedding) + "]"
                        await cursor.execute(
                            """
                            INSERT INTO security_documents
                              (id, title, source, content, tags, embedding, domain, team, service, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s::vector, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                              title = EXCLUDED.title,
                              source = EXCLUDED.source,
                              content = EXCLUDED.content,
                              tags = EXCLUDED.tags,
                              embedding = EXCLUDED.embedding,
                              domain = EXCLUDED.domain,
                              team = EXCLUDED.team,
                              service = EXCLUDED.service
                            """,
                            (
                                chunk.id,
                                chunk.title,
                                chunk.source,
                                content,
                                tags,
                                vector,
                                chunk.domain.value,
                                chunk.team,
                                chunk.service,
                                chunk.created_at,
                            ),
                        )
                await connection.commit()
            return True
        except Exception:
            return False

    def _store_memory_chunks(
        self,
        chunks: list[IngestedChunk],
        contents: list[str],
        tags: list[str],
    ) -> None:
        for chunk, content in zip(chunks, contents, strict=True):
            self.memory_chunks[chunk.id] = chunk
            UPLOADED_DOCUMENTS.append(
                {
                    "id": chunk.id,
                    "title": chunk.title,
                    "source": chunk.source,
                    "content": content,
                    "tags": [chunk.domain.value, *(tags or [])],
                }
            )

    @staticmethod
    def _chunk_text(text: str, chunk_size: int, chunk_overlap: int) -> list[str]:
        text = text.strip()
        if not text:
            return [""]
        chunks = []
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            chunks.append(text[start:end])
            if end == len(text):
                break
            start = max(end - chunk_overlap, start + 1)
        return chunks
