from __future__ import annotations

import sys
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.rag.vector_store import LocalVectorStore
from app.services.llm import OllamaService


def main() -> None:
    settings = get_settings()
    store = LocalVectorStore(Path("app/data/knowledge_base"))
    embeddings = OllamaService()

    with psycopg.connect(settings.database_url) as connection:
        with connection.cursor() as cursor:
            for document in store.documents:
                content = str(document["content"])
                embedding = embeddings.embed(f"{document['title']} {content}")[:384]
                vector = "[" + ",".join(str(value) for value in embedding) + "]"
                cursor.execute(
                    """
                    INSERT INTO security_documents (id, title, source, content, tags, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s::vector)
                    ON CONFLICT (id) DO UPDATE SET
                      title = EXCLUDED.title,
                      source = EXCLUDED.source,
                      content = EXCLUDED.content,
                      tags = EXCLUDED.tags,
                      embedding = EXCLUDED.embedding
                    """,
                    (
                        document["id"],
                        document["title"],
                        document["source"],
                        content,
                        document["tags"],
                        vector,
                    ),
                )
        connection.commit()
    print(f"Ingested {len(store.documents)} documents into pgvector.")


if __name__ == "__main__":
    main()
