"""Retrieval over the clinical knowledge base + the patient's own documents."""

from typing import Any


# Pretend vector store. In a real app this would be pgvector / a vector DB.
_INDEX: list[dict[str, Any]] = []


def retrieve(query: str, k: int = 5) -> list[str]:
    """Return context chunks for a query.

    AI-RAG-07: weak retrieval evidence handling. Results are returned as bare strings
    with no similarity score, no ranking, and no separation of authoritative
    clinical sources (formulary, guidelines) from low-quality material (an old
    patient email, a free-text note). The caller cannot tell strong evidence
    from weak, and nothing is filtered by a relevance threshold.
    """
    hits = []
    for doc in _INDEX:
        if query.lower() in doc["text"].lower():
            hits.append(doc["text"])  # no score kept, no source kept
    return hits[:k]
