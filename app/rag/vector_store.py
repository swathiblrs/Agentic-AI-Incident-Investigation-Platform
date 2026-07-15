from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from app.models.schemas import RetrievedDocument
from app.rag.uploaded_store import UPLOADED_DOCUMENTS

TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:-]+")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


class LocalVectorStore:
    """Small dependency-free retrieval store for local demos and tests."""

    def __init__(self, knowledge_dir: Path):
        self.knowledge_dir = knowledge_dir
        self.documents = self._load_documents()
        self._doc_vectors = {
            doc["id"]: Counter(tokenize(f"{doc['title']} {doc['content']} {' '.join(doc['tags'])}"))
            for doc in self.documents
        }

    def search(self, query: str, top_k: int = 5) -> list[RetrievedDocument]:
        query_vector = Counter(tokenize(query))
        scored = []
        all_documents = [*self.documents, *UPLOADED_DOCUMENTS]
        doc_vectors = {
            **self._doc_vectors,
            **{
                doc["id"]: Counter(tokenize(f"{doc['title']} {doc['content']} {' '.join(doc['tags'])}"))
                for doc in UPLOADED_DOCUMENTS
            },
        }
        for doc in all_documents:
            score = self._cosine_similarity(query_vector, doc_vectors[doc["id"]])
            if score > 0:
                scored.append((score, doc))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            RetrievedDocument(
                id=doc["id"],
                title=doc["title"],
                source=doc["source"],
                score=round(score, 4),
                content=doc["content"],
                tags=doc["tags"],
            )
            for score, doc in scored[:top_k]
        ]

    def _load_documents(self) -> list[dict[str, str | list[str]]]:
        docs = []
        for path in sorted(self.knowledge_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            metadata, content = self._split_frontmatter(text)
            docs.append(
                {
                    "id": path.stem,
                    "title": metadata.get("title", path.stem.replace("-", " ").title()),
                    "source": metadata.get("source", str(path)),
                    "tags": [tag.strip() for tag in metadata.get("tags", "").split(",") if tag.strip()],
                    "content": content.strip(),
                }
            )
        return docs

    @staticmethod
    def _split_frontmatter(text: str) -> tuple[dict[str, str], str]:
        if not text.startswith("---"):
            return {}, text

        _, frontmatter, content = text.split("---", 2)
        metadata = {}
        for line in frontmatter.strip().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip()
        return metadata, content

    @staticmethod
    def _cosine_similarity(left: Counter[str], right: Counter[str]) -> float:
        if not left or not right:
            return 0.0

        intersection = set(left) & set(right)
        numerator = sum(left[token] * right[token] for token in intersection)
        left_norm = math.sqrt(sum(value * value for value in left.values()))
        right_norm = math.sqrt(sum(value * value for value in right.values()))
        if left_norm == 0 or right_norm == 0:
            return 0.0
        return numerator / (left_norm * right_norm)
