"""Redaction.

No raw PHI-like value or secret may appear in findings.json or the report.
`redact()` runs on every captured code snippet before it leaves the scanner.
Only code *structure* is retained; literal values that look like PHI or secrets
are replaced with typed placeholders.
"""
from __future__ import annotations

import re

# Order matters: most specific first.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Secrets / keys
    (re.compile(r'sk-[A-Za-z0-9_-]{16,}'), "[REDACTED_API_KEY]"),
    (re.compile(r'\behr_(live|test)_[A-Za-z0-9]{8,}'), "[REDACTED_API_KEY]"),
    (re.compile(r'\b[A-Za-z0-9_-]*(secret|token|passwd|password|apikey|api_key)[A-Za-z0-9_-]*\s*[:=]\s*["\'][^"\']+["\']',
                re.IGNORECASE), lambda m: re.sub(r'(["\']).+(["\'])', r'\1[REDACTED]\2', m.group(0))),
    # Credentials embedded in connection strings: scheme://user:pass@host
    (re.compile(r'(\w+://[^:/\s]+:)[^@/\s]+(@)'), r'\1[REDACTED]\2'),
    # PHI carried in a named field: patient_name = "...", dob: '...'
    (re.compile(r'\b(first_?name|last_?name|full_?name|patient_?name|'
                r'dob|date_of_birth|birth_?date|home_?address|street_?address)'
                r'\s*[:=]\s*["\'][^"\']+["\']', re.IGNORECASE),
     lambda m: re.sub(r'(["\']).+(["\'])', r'\1[REDACTED_PHI]\2', m.group(0))),
    # Direct PHI-ish literals
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "[SSN]"),                    # SSN
    (re.compile(r'\bMRN[:#=]?\s*\d+\b', re.IGNORECASE), "[MRN]"),       # MRN (incl. mrn=123 URL form)
    (re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'), "[DATE]"),               # DOB-like, US format
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'), "[DATE]"),                   # DOB-like, ISO format
    (re.compile(r'(?<![\d.])(\+?1[-. ]?)?(\(\d{3}\)[-. ]?|\d{3}[-. ])\d{3}[-. ]\d{4}(?![\d.])'),
     "[PHONE]"),                                                        # US phone, incl. (NNN)NNN-NNNN
    (re.compile(r'\b\d+\s+[A-Za-z][\w.]*(\s[A-Za-z][\w.]*)?\s+'
                r'(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|'
                r'Court|Ct|Way|Place|Pl)\b\.?', re.IGNORECASE), "[ADDRESS]"),
    (re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b'), "[EMAIL]"),           # email
]


def redact(text: str) -> str:
    """Return `text` with PHI-like values and secrets replaced by placeholders."""
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


if __name__ == "__main__":
    import sys
    for line in sys.stdin:
        sys.stdout.write(redact(line))
