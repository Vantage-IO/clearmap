"""Patient document storage access."""

import os

from config import DOCUMENT_ROOT


def read_document(patient_id: str, filename: str) -> bytes:
    """Read a stored patient document (scanned labs, referrals, notes).

    AUDIT-03: file access to PHI happens with no audit event. There is no record of
    who read which patient's document or when — `audit.record_event` is never
    called on this read path.
    """
    path = os.path.join(DOCUMENT_ROOT, patient_id, filename)
    with open(path, "rb") as fh:
        return fh.read()
