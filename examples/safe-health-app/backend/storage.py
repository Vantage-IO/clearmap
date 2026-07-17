"""Patient document storage access — audited."""

import os

import audit
from config import DOCUMENT_ROOT


def read_document(actor_id: str, patient_id: str, filename: str) -> bytes:
    """Read a stored patient document and record an audit event for the access."""
    path = os.path.join(DOCUMENT_ROOT, patient_id, filename)
    audit.record_event(actor_id, "document.read", f"patient:{patient_id}/{filename}")
    with open(path, "rb") as fh:
        return fh.read()
