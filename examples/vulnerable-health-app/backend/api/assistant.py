"""Endpoint that exposes the clinical RAG assistant."""

from fastapi import APIRouter, Depends

from auth import current_user
from rag import assistant

router = APIRouter()


@router.post("/assistant/ask")
def ask(payload: dict, user=Depends(current_user)):
    """Answer a clinician's question about a patient.

    AI-RAG-03: no source traceability in the response. The API returns only the raw
    answer string. The response carries no `citations` / `sources` field, so
    the clinician sees a confident answer with no way to verify which documents
    (if any) it was grounded in.
    """
    answer = assistant.answer_question(
        patient=payload["patient"],
        question=payload["question"],
        external_docs=payload.get("external_docs", []),
    )
    return {"answer": answer}
