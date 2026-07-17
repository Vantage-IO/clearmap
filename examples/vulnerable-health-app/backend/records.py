"""Persistence for clinical notes, including AI-generated summaries."""

from typing import Any

# Pretend table of clinical notes keyed by note id.
_NOTES: dict[str, dict[str, Any]] = {}


def save_ai_summary(note_id: str, patient_id: str, ai_text: str, sources: list[str]) -> None:
    """Persist an AI-generated summary into the patient's clinical record.

    INTEGRITY-02: AI output stored as fact without a review state. The record is written
    with no `reviewed_by`, `review_status`, or `confidence` field — once saved
    it is indistinguishable from a clinician-authored, verified note.

    AI-RAG-05: AI output written as fact. The generated text is persisted directly to
    the clinical record and immediately treated as authoritative downstream
    (other views render `text` with no "AI-generated, unverified" badge).

    AUDIT-04: no source-to-output trace. The `sources` that produced the summary are
    accepted but never stored — the persisted record keeps no provenance, so
    you cannot later trace which documents the AI output was derived from.
    """
    _NOTES[note_id] = {
        "patient_id": patient_id,
        "text": ai_text,
        # note: sources argument is dropped on the floor (AUDIT-04)
    }


def attach_source_context(note_id: str, retrieved_context: str) -> None:
    """Attach the supporting source context to a note.

    INTEGRITY-03: source-context overwrite. Each call replaces the stored context wholesale
    instead of appending/versioning, so the evidence trail for an earlier
    revision of the note is silently destroyed when the note is regenerated.
    """
    _NOTES[note_id]["context"] = retrieved_context
