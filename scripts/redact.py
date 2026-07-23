"""Redaction.

No raw PHI-like value or secret may appear in findings.json or the report.
`redact()` runs on every captured code snippet before it leaves the scanner.
Only code *structure* is retained; literal values that look like PHI or secrets
are replaced with typed placeholders.
"""
from __future__ import annotations

import re

# Inputs to redact() are code snippets and short free text, never whole files.
# The assignment/email patterns can be O(n^2) on a pathologically long single
# line, so redact() bounds the work here. This is a hard safety net for every
# call site (presidio_check, merge_reasoning, scan) that might feed an unbounded
# line into redact(): content past the cap is dropped, never emitted, so a long
# line can neither leak a tail value nor hang the scanner.
MAX_REDACT_CHARS = 10_000

# Assignment value forms shared by the secret and PHI patterns:
#   (a) a full quoted string  "..."  '...'
#   (b) a quoted string missing its closing quote at end of input  "...
#   (c) a bare token up to whitespace / comma / semicolon (unquoted YAML/env).
_ASSIGN_VALUE = r'''("[^"]*"?|'[^']*'?|[^\s,;"']+)'''
_SECRET_WORD = r'(?:secret|token|passwd|password|apikey|api[_-]?key)'
# Bounded runs around the keyword ({0,64}, not *): a realistic key name is short,
# and bounding the repetition keeps the match linear instead of catastrophically
# backtracking across a long run of word characters that has no ':'/'='.
_SECRET_KEY = r'[A-Za-z0-9_-]{0,64}' + _SECRET_WORD + r'[A-Za-z0-9_-]{0,64}'
_PHI_KEY = (r'(?:first_?name|last_?name|full_?name|patient_?name|'
            r'dob|date_of_birth|birth_?date|home_?address|street_?address)')

# A bare (unquoted) value that is obviously not a literal secret/PHI value:
# language keywords, a bare type name, a template/env reference, or any
# expression with a call. These keep code structure instead of over-redacting.
_BARE_SKIP = re.compile(
    r'^(?:none|null|nil|true|false|undefined|str|string|int|integer|'
    r'bool|boolean|float|number|any|object)$'
    r'|\$\{|^\$|process\.env|os\.environ|getenv|\(', re.IGNORECASE)


def _assign_redactor(placeholder: str):
    """Replacement for a `key <op> value` match: keep the key + operator prefix,
    replace only the value with `placeholder`. Handles quoted, truncated-quoted,
    and bare values; leaves an empty value or obvious non-secret code untouched."""
    def _sub(m: re.Match[str]) -> str:
        prefix, val = m.group(1), m.group(2)
        quote = val[:1]
        if quote in ('"', "'"):
            closed = len(val) > 1 and val.endswith(quote)
            body = val[1:-1] if closed else val[1:]
            if not body:                       # empty string: nothing to hide
                return m.group(0)
            return f"{prefix}{quote}{placeholder}" + (quote if closed else "")
        if _BARE_SKIP.search(val):             # keep obvious non-secret code
            return m.group(0)
        return f"{prefix}{placeholder}"
    return _sub


# Order matters: most specific first.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Secrets / keys
    (re.compile(r'sk-[A-Za-z0-9_-]{16,}'), "[REDACTED_API_KEY]"),
    (re.compile(r'\behr_(live|test)_[A-Za-z0-9]{8,}'), "[REDACTED_API_KEY]"),
    # Secret assignment: optional quotes around the key, then a quoted,
    # truncated-quoted, or bare value.
    (re.compile(r'(["\']?' + _SECRET_KEY + r'["\']?\s*[:=]\s*)' + _ASSIGN_VALUE,
                re.IGNORECASE), _assign_redactor("[REDACTED]")),
    # Credentials embedded in connection strings: scheme://user:pass@host.
    # Bounded runs keep the match linear on long delimiter-free lines.
    (re.compile(r'(\w{1,32}://[^:/\s]{1,255}:)[^@/\s]{1,255}(@)'), r'\1[REDACTED]\2'),
    # PHI carried in a named field: patient_name = "...", dob: '...', name: bare
    (re.compile(r'(["\']?' + _PHI_KEY + r'["\']?\s*[:=]\s*)' + _ASSIGN_VALUE,
                re.IGNORECASE), _assign_redactor("[REDACTED_PHI]")),
    # Direct PHI-ish literals
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "[SSN]"),                    # SSN
    (re.compile(r'\bMRN[:#=]?\s*\d+\b', re.IGNORECASE), "[MRN]"),       # MRN (incl. mrn=123 URL form)
    (re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'), "[DATE]"),               # DOB-like, US format
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'), "[DATE]"),                   # DOB-like, ISO format
    (re.compile(r'(?<![\d.])(\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\d.])'),
     "[PHONE]"),                                                        # US phone
    (re.compile(r'\b\d+\s+[A-Za-z][\w.]*(\s[A-Za-z][\w.]*)?\s+'
                r'(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|'
                r'Court|Ct|Way|Place|Pl)\b\.?', re.IGNORECASE), "[ADDRESS]"),
    # Email. Bounded runs ({1,64}/{1,255}, not +) so a long delimiter-free line
    # cannot force O(n^2) backtracking while the local part hunts for an '@'.
    (re.compile(r'\b[\w.+-]{1,64}@[\w-]{1,255}\.[\w.-]{1,255}\b'), "[EMAIL]"),
]


def redact(text: str) -> str:
    """Return `text` with PHI-like values and secrets replaced by placeholders.

    Input is bounded to MAX_REDACT_CHARS first: a snippet longer than that is
    truncated (its tail dropped, never emitted) so redact() stays linear on
    pathological single lines and no caller can feed it unbounded text."""
    out = text if len(text) <= MAX_REDACT_CHARS else text[:MAX_REDACT_CHARS]
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


if __name__ == "__main__":
    import sys
    for line in sys.stdin:
        sys.stdout.write(redact(line))
