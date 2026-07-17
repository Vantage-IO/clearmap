"""Retrieval with scoring, ranking, thresholding, and source provenance."""

from dataclasses import dataclass
from typing import Any

_INDEX: list[dict[str, Any]] = []

# Only sources at or above this similarity are treated as usable evidence.
RELEVANCE_THRESHOLD = 0.75


@dataclass
class Evidence:
    source_id: str
    text: str
    score: float
    authoritative: bool  # e.g. formulary/guideline vs. free-text note


def retrieve(query: str, k: int = 5) -> list[Evidence]:
    """Return scored, ranked, thresholded evidence with source ids.

    Authoritative sources are preferred and low-relevance hits are dropped, so
    the caller can reason about evidence strength and trace each chunk to a
    source.
    """
    scored = [
        Evidence(
            source_id=doc["id"],
            text=doc["text"],
            score=_similarity(query, doc["text"]),
            authoritative=doc.get("authoritative", False),
        )
        for doc in _INDEX
    ]
    usable = [e for e in scored if e.score >= RELEVANCE_THRESHOLD]
    usable.sort(key=lambda e: (e.authoritative, e.score), reverse=True)
    return usable[:k]


def _similarity(query: str, text: str) -> float:
    """Placeholder similarity; a real app uses vector cosine similarity."""
    q = set(query.lower().split())
    t = set(text.lower().split())
    return len(q & t) / len(q) if q else 0.0
