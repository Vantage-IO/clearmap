"""Optional Presidio-powered PHI-literal check (opt-in, never required).

Looks for raw PHI identifiers (names, SSNs, phone numbers, NPI/medical-license
style values) committed into the files where teams habitually paste real
patient data: seeds, fixtures, prompt templates, sample payloads.

Strictly opt-in via `scan.py --presidio`. If presidio-analyzer is not
installed, the scan continues unchanged (zero-dependency default preserved) —
a note goes to stderr. Findings are redacted before they leave this module.

    pip install presidio-analyzer && python -m spacy download en_core_web_lg
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import redact  # noqa: E402

# Only these path shapes are scanned — bounded runtime + FP surface.
TARGET_PATH_RE = re.compile(
    r"(seed|fixture|sample|mock|prompt|template)", re.IGNORECASE)
TARGET_EXT = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".csv", ".txt",
              ".jinja", ".jinja2", ".j2", ".md"}

# Entities worth flagging in committed files; scores below threshold dropped.
ENTITIES = ["PERSON", "US_SSN", "PHONE_NUMBER", "US_DRIVER_LICENSE",
            "MEDICAL_LICENSE", "EMAIL_ADDRESS"]
SCORE_THRESHOLD = 0.6
MAX_FILE_BYTES = 200_000
MAX_FINDINGS_PER_FILE = 5


def presidio_available() -> str | None:
    """Return the presidio version string, or None when not installed."""
    try:
        import presidio_analyzer
        return getattr(presidio_analyzer, "__version__", "unknown")
    except ImportError:
        return None


def run_presidio(target: Path, paths: list[str] | None) -> list[dict]:
    """Scan candidate files for raw PHI literals. Returns ClearMap findings."""
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError:
        print("clearmap: --presidio requested but presidio-analyzer is not "
              "installed; skipping (pip install presidio-analyzer)", file=sys.stderr)
        return []

    candidates: list[Path] = []
    if paths:
        candidates = [Path(p) for p in paths]
    else:
        candidates = [p for p in target.rglob("*") if p.is_file()]
    candidates = sorted(
        p for p in candidates
        if p.suffix in TARGET_EXT and TARGET_PATH_RE.search(str(p))
        and ".git" not in p.parts and "node_modules" not in p.parts)

    engine = AnalyzerEngine()
    findings: list[dict] = []
    for fp in candidates:
        try:
            text = fp.read_text(errors="ignore")[:MAX_FILE_BYTES]
        except OSError:
            continue
        results = engine.analyze(text=text, entities=ENTITIES, language="en")
        results = [r for r in results if r.score >= SCORE_THRESHOLD]
        results.sort(key=lambda r: (r.start, r.entity_type))
        for r in results[:MAX_FINDINGS_PER_FILE]:
            line = text.count("\n", 0, r.start) + 1
            snippet_line = text.splitlines()[line - 1].strip() if text else ""
            try:
                rel = str(fp.resolve().relative_to(target.resolve()))
            except ValueError:
                rel = str(fp)
            findings.append({
                "rule_id": "presidio-phi-literal",
                "category": "SECRETS",
                "severity": "high",
                "source": "deterministic",
                "engine": "presidio",
                "hipaa_ref": "164.312(a)(1)",
                "file": rel,
                "line": line,
                "title": f"Possible raw PHI literal ({r.entity_type}) in a "
                         "seed/fixture/template file",
                "structural_snippet": redact(snippet_line)[:300],
                "why": "Real-looking personal/health identifiers committed in source "
                       "spread PHI to every clone and backup of the repo.",
                "remediation": "Replace with synthetic values (e.g. faker) and purge "
                               "the literal from git history if it was real.",
            })
    return findings
