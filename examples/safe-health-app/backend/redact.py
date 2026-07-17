"""Minimal PHI redaction used before any text reaches a model prompt.

A real implementation would use a clinical NER (e.g. Presidio). This fixture
keeps a deterministic stub so the safe app has a genuine redaction step.
"""

import re

_MRN = re.compile(r"\bMRN[:#]?\s*\d+\b", re.IGNORECASE)
_DOB = re.compile(r"\b\d{1,2}/\d{1,2}/\d{4}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def redact_phi(text: str) -> str:
    text = _MRN.sub("[MRN]", text)
    text = _DOB.sub("[DOB]", text)
    text = _SSN.sub("[SSN]", text)
    return text
