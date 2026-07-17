"""Endpoint exposing the clinical RAG assistant — returns cited answers."""

from fastapi import APIRouter, Depends

from auth import current_user
from rag import assistant

router = APIRouter()


@router.post("/assistant/ask")
def ask(payload: dict, user=Depends(current_user)):
    """Answer a clinician's question with citations and confidence.

    The response carries the source ids that grounded the answer, whether the
    assistant abstained, and a confidence label so the clinician can verify it.
    """
    answer = assistant.answer_question(
        actor_id=user["sub"],
        patient=payload["patient"],
        question=payload["question"],
        external_docs=payload.get("external_docs", []),
    )
    return {
        "answer": answer.text,
        "citations": answer.citations,
        "abstained": answer.abstained,
        "confidence": answer.confidence,
    }
