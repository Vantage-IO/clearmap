#!/usr/bin/env python3
"""ClearMap scoring.

Each category starts at 100 and deducts by severity, floored at 0. The headline
composite is computed from the DETERMINISTIC layer only, so it is reproducible.
A blended composite that also reflects reasoning findings is reported
separately; reasoning's contribution per category is capped so it cannot tank a
category or swing wildly run-to-run (rubric-bound, "agent-identified, verify").

Importable (`score_findings`) and runnable:
    python3 scripts/scoring.py findings.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Severity -> points deducted from a category's 100.
DEDUCTION = {"critical": 25, "high": 15, "medium": 8, "low": 3}

# Relative category weights (renormalized across the applicable categories, so
# the absolute sum need not be 1.0). AI/RAG and Audit weighted highest.
# Access (orig 0.15) is split into ACCESS (authz) 0.10 + AUTH (authn) 0.05.
WEIGHTS = {
    "AI-RAG": 0.25,
    "AUDIT": 0.20,
    "ACCESS": 0.10,
    "AUTH": 0.05,
    "TRANSIT": 0.10,
    "TRACKING": 0.10,
    "APPSEC": 0.10,
    "INTEGRITY": 0.08,
    "SESSION": 0.07,
    "SECRETS": 0.05,
}

# Cap on how much the reasoning layer can deduct from any single category, so an
# agent-identified set can't dominate the (verify-required) blended score.
REASONING_CAP = 40

# --- Severity ceilings (worst finding dominates — the "weakest-link" principle).
# ClearMap covers technical safeguards only, so it never reports a perfect score.
# Rationale + sources in references/scoring-methodology.md.
SCORE_CEILING = 95      # no critical/high (never perfect)
HIGH_CEILING = 85       # any high present
MEDIUM_CEILING = 90     # any medium present (no high/critical)

# Criticals dominate AND compound with diminishing returns (noisy-OR / saturation):
# one critical caps the score at 75; each additional critical lowers the cap
# further by a shrinking amount, asymptoting to a floor. This is a noisy-OR shape:
#   cap(n) = FLOOR + (CAP_ONE - FLOOR) * DECAY**(n-1)
# (equivalently 1-(1-p)^n risk with p = 1-DECAY = 0.45 per critical).
CRIT_CAP_ONE = 75       # exactly one critical -> 75
CRIT_FLOOR = 40         # asymptote as criticals pile up
CRIT_DECAY = 0.55       # each extra critical retains 55% of the remaining gap


def critical_ceiling(n: int) -> int:
    """Saturating cap for n>=1 criticals: 75, 59, 51, 46, 43, ... -> 40."""
    return round(CRIT_FLOOR + (CRIT_CAP_ONE - CRIT_FLOOR) * (CRIT_DECAY ** (n - 1)))


def severity_ceiling(findings: list[dict]) -> tuple[int, str]:
    """Return (ceiling, reason) from the worst severity present (worst dominates)."""
    n_crit = sum(1 for f in findings if f.get("severity") == "critical")
    if n_crit:
        return critical_ceiling(n_crit), (
            f"{n_crit} critical finding{'s' if n_crit > 1 else ''}")
    if any(f.get("severity") == "high" for f in findings):
        return HIGH_CEILING, "a high-severity finding"
    if any(f.get("severity") == "medium" for f in findings):
        return MEDIUM_CEILING, "a medium-severity finding"
    return SCORE_CEILING, "ClearMap covers technical safeguards only"

CATEGORY_NAME = {
    "ACCESS": "Access Control", "AUTH": "Authentication", "AUDIT": "Audit Controls",
    "INTEGRITY": "Integrity", "TRANSIT": "Transmission Security",
    "SESSION": "Frontend / Session", "TRACKING": "Tracking / Analytics",
    "AI-RAG": "AI / LLM / RAG", "SECRETS": "Secrets / Config",
    "APPSEC": "Application Security",
}


def _clamp(n: float) -> int:
    return max(0, min(100, round(n)))


# Categories with NO deterministic rules: their entire signal comes from the
# AI-assisted reasoning layer. If that layer did not run, they cannot be scored
# and must NOT be reported as a clean 100 (that would inflate the topline of an
# AI/healthcare repo into a falsely reassuring "low risk").
REASONING_ONLY = {"AI-RAG", "AUDIT"}


def score_findings(findings: list[dict], applicability: dict | None = None,
                   source_layer: str | None = None) -> dict:
    """Return per-category + composite scores. Non-applicable categories (no such
    surface in the codebase) are marked N/A and EXCLUDED from the composite —
    their weight is renormalized across the applicable categories, so a category
    that doesn't apply never contributes a misleading 100. A category with any
    finding is always treated as applicable.

    If `source_layer` is given and does NOT include the reasoning layer, any
    applicable REASONING_ONLY category with no findings is marked `not_reviewed`
    and EXCLUDED from the composite (we have no basis to score it). The report
    surfaces this as an incomplete assessment. `source_layer=None` means "assume
    fully reviewed" (back-compat: no behavior change)."""
    applicability = applicability or {}
    reasoning_ran = source_layer is None or "reasoning" in source_layer
    cats = {}
    for code in WEIGHTS:
        det = [f for f in findings if f.get("category") == code and f.get("source") == "deterministic"]
        rea = [f for f in findings if f.get("category") == code and f.get("source") == "reasoning"]
        det_deduct = sum(DEDUCTION.get(f.get("severity", "medium"), 8) for f in det)
        rea_deduct = min(REASONING_CAP, sum(DEDUCTION.get(f.get("severity", "medium"), 8) for f in rea))
        applicable = bool(det or rea) or applicability.get(code, True)
        not_reviewed = (applicable and not reasoning_ran and code in REASONING_ONLY
                        and not det and not rea)
        if not_reviewed:
            applicable = False  # excluded from composite, but labeled distinctly
        cats[code] = {
            "name": CATEGORY_NAME[code],
            "weight": WEIGHTS[code],
            "applicable": applicable,
            "not_reviewed": not_reviewed,
            "deterministic_score": _clamp(100 - det_deduct),
            "blended_score": _clamp(100 - det_deduct - rea_deduct),
            "deterministic_findings": len(det),
            "reasoning_findings": len(rea),
        }

    # Composite over APPLICABLE categories only, with renormalized weights.
    applic = {c: v for c, v in cats.items() if v["applicable"]}
    wsum = sum(v["weight"] for v in applic.values()) or 1.0
    for v in cats.values():
        v["effective_weight"] = round(v["weight"] / wsum, 3) if v["applicable"] else 0.0
    det_composite = _clamp(sum(v["deterministic_score"] * v["weight"] for v in applic.values()) / wsum)
    blended_raw = _clamp(sum(v["blended_score"] * v["weight"] for v in applic.values()) / wsum)
    # Topline = blended, then capped by the worst-severity ceiling (worst dominates;
    # criticals compound with diminishing returns). The lower of the two governs.
    ceiling, reason = severity_ceiling(findings)
    score = _clamp(min(blended_raw, ceiling))

    return {
        "score": score,                        # THE topline number
        "ceiling_applied": ceiling,
        "ceiling_reason": reason,
        "composite_blended_raw": blended_raw,   # weighted composite before ceiling (disclosure)
        "composite_deterministic": det_composite,  # deterministic-only (disclosure)
        "n_critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "n_high": sum(1 for f in findings if f.get("severity") == "high"),
        "n_medium": sum(1 for f in findings if f.get("severity") == "medium"),
        "n_low": sum(1 for f in findings if f.get("severity") == "low"),
        "posture": posture(score),
        "categories": cats,
        "reasoning_ran": reasoning_ran,
        "not_reviewed_categories": [c for c, v in cats.items() if v["not_reviewed"]],
    }


# Posture bands, aligned so a single critical (cap 75) reads "Elevated" — the
# number and the words agree, and a critical/high can never read "Low".
_LEVELS = [
    (90, "Low technical risk in the areas ClearMap checks."),
    (76, "Moderate technical risk: some gaps to address."),
    (50, "Elevated technical risk: multiple significant gaps."),
    (0,  "High technical risk: substantial gaps; prioritize remediation."),
]


def posture(score: int) -> str:
    """Plain-language posture from the (already ceiling-capped) score. Avoids any
    compliance claim."""
    return next(label for threshold, label in _LEVELS if score >= threshold)


def main() -> int:
    ap = argparse.ArgumentParser(description="ClearMap scoring")
    ap.add_argument("findings", type=Path)
    args = ap.parse_args()
    data = json.loads(args.findings.read_text())
    scores = score_findings(data.get("findings", []), data.get("applicability"),
                            data.get("source_layer"))
    print(json.dumps(scores, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
