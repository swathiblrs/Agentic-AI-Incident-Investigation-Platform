from __future__ import annotations

from app.models.schemas import RetrievedDocument
from app.services.llm import OllamaService


class PgVectorStore:
    def __init__(self, database_url: str, embeddings: OllamaService | None = None) -> None:
        self.database_url = database_url
        self.embeddings = embeddings or OllamaService()

    def search(self, query: str, top_k: int = 5) -> list[RetrievedDocument]:
        import psycopg

        embedding = self.embeddings.embed(query)
        vector = "[" + ",".join(str(value) for value in embedding[:384]) + "]"
        sql = """
            SELECT id, title, source, content, tags, 1 - (embedding <=> %s::vector) AS score,
                   domain, team, service, created_at
            FROM security_documents
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, (vector, vector, top_k))
                rows = cursor.fetchall()

        return [
            RetrievedDocument(
                id=row[0],
                title=row[1],
                source=row[2],
                content=row[3],
                tags=list(row[4] or []),
                score=round(float(row[5] or 0), 4),
                domain=row[6],
                team=row[7],
                service=row[8],
                created_at=row[9],
            )
            for row in rows
        ]
