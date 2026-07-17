"""Persistence for clinical notes — AI output stored as reviewable drafts."""

import time
from typing import Any

_NOTES: dict[str, dict[str, Any]] = {}


def save_ai_summary(note_id: str, patient_id: str, ai_text: str, sources: list[str]) -> None:
    """Persist an AI-generated summary as an unverified draft with provenance.

    The record is explicitly marked AI-generated and unreviewed, carries a
    confidence + review_status, and stores the source ids that produced it so
    the output can be traced back to its inputs.
    """
    _NOTES[note_id] = {
        "patient_id": patient_id,
        "text": ai_text,
        "author": "ai-assistant",
        "review_status": "unverified",   # requires clinician sign-off before clinical use
        "reviewed_by": None,
        "confidence": "model-generated",
        "source_ids": list(sources),     # provenance retained
        "context_revisions": [],
    }


def attach_source_context(note_id: str, retrieved_context: str) -> None:
    """Append (never overwrite) a versioned snapshot of the supporting context."""
    _NOTES[note_id]["context_revisions"].append({"ts": time.time(), "context": retrieved_context})
