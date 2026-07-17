#!/usr/bin/env python3
"""Merge & validate reasoning-layer findings into the deterministic findings.json.

ClearMap's reasoning layer is executed by the host agent (it reads the code and
evaluates references/clinical-checks.md + references/audit-checks.md). The agent
writes its findings to a JSON file; this script validates them, re-applies
redaction (a safety net: no raw PHI may ever reach output), and merges them
with the deterministic findings into one combined findings.json.

Usage:
    python3 scripts/merge_reasoning.py findings.json reasoning.json --out combined.json

reasoning.json shape:
    {"findings": [ {reasoning finding}, ... ]}

Each reasoning finding MUST have:
    id, category, severity, source="reasoning", confidence in {high,medium,low},
    file, line, structural_snippet, why
Optional: hipaa_ref, remediation, reviewer_question
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import redact  # noqa: E402
import taxonomy  # noqa: E402

VALID_SEVERITY = {"critical", "high", "medium", "low"}
VALID_CONFIDENCE = {"high", "medium", "low"}
REQUIRED = ["id", "category", "severity", "source", "confidence", "file", "line",
            "title", "structural_snippet", "why"]


def validate(f: dict, i: int, repo_root: Path | None = None) -> list[str]:
    """Validate one agent-produced reasoning finding against the canonical
    taxonomy registry and the scanned repo. Untrusted input: reject unknown check
    ids, non-canonical severities (unless explicitly overridden), category drift,
    unsafe/traversal file paths, PHI-like paths, and out-of-range line numbers."""
    errs = []
    for k in REQUIRED:
        if k not in f or f[k] in (None, ""):
            errs.append(f"finding[{i}] missing required field: {k}")
    if f.get("source") != "reasoning":
        errs.append(f"finding[{i}] source must be 'reasoning' (got {f.get('source')!r})")
    if f.get("severity") not in VALID_SEVERITY:
        errs.append(f"finding[{i}] invalid severity: {f.get('severity')!r}")
    if f.get("confidence") not in VALID_CONFIDENCE:
        errs.append(f"finding[{i}] invalid/missing confidence: {f.get('confidence')!r}")

    fid = f.get("id")
    reg = taxonomy.entry(fid) if fid else None
    if reg is None:
        errs.append(f"finding[{i}] unknown check id {fid!r} (not in the taxonomy registry)")
    else:
        if reg["layer"] != "reasoning":
            errs.append(f"finding[{i}] {fid} is a {reg['layer']} check, not a reasoning check")
        if f.get("category") != reg["category"]:
            errs.append(f"finding[{i}] {fid} category {f.get('category')!r} "
                        f"!= canonical {reg['category']!r}")
        if f.get("severity") != reg["severity"] and not f.get("severity_override_reason"):
            errs.append(f"finding[{i}] {fid} severity {f.get('severity')!r} != canonical "
                        f"{reg['severity']!r} (set severity_override_reason to override)")

    # File path safety: relative, no traversal, no PHI/secret-like content.
    raw = str(f.get("file", ""))
    p = Path(raw)
    if not raw:
        pass  # already flagged by REQUIRED
    elif p.is_absolute() or ".." in p.parts:
        errs.append(f"finding[{i}] file must be a repo-relative path without '..': {raw!r}")
    elif redact(raw) != raw:
        errs.append(f"finding[{i}] file path contains PHI/secret-like content; rejected")
    else:
        line = f.get("line")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            errs.append(f"finding[{i}] line must be a positive integer (got {line!r})")
        elif repo_root is not None:
            fp = repo_root / p
            if not fp.is_file():
                errs.append(f"finding[{i}] file not found in the scanned repo: {raw!r}")
            else:
                try:
                    n = len(fp.read_text(errors="ignore").splitlines())
                    if line > n:
                        errs.append(f"finding[{i}] line {line} is past end of {raw} ({n} lines)")
                except OSError:
                    pass
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description="Merge reasoning findings into findings.json")
    ap.add_argument("deterministic", type=Path, help="findings.json from scan.py")
    ap.add_argument("reasoning", type=Path, help="agent-produced reasoning findings json")
    ap.add_argument("--out", type=Path, default=Path("findings.json"))
    ap.add_argument("--repo-path", type=Path, default=None,
                    help="scanned repo root; enables file-exists + line-in-file checks")
    args = ap.parse_args()

    det = json.loads(args.deterministic.read_text())
    rea = json.loads(args.reasoning.read_text())
    rfindings = rea.get("findings", rea if isinstance(rea, list) else [])
    repo_root = args.repo_path.resolve() if args.repo_path else None

    provider = rea.get("provider", "host-agent")
    model = rea.get("model")
    run_id = rea.get("run_id")
    manifest = rea.get("manifest") or {}

    errors: list[str] = []
    cleaned = []
    for i, f in enumerate(rfindings):
        errors.extend(validate(f, i, repo_root))
        # Redaction safety net on ALL user-visible free text, including the title
        # (rendered prominently, never redacted before). The file path is validated
        # above (rejected if PHI/secret-like), not rewritten.
        for field in ("title", "structural_snippet", "why", "remediation", "reviewer_question"):
            if isinstance(f.get(field), str):
                f[field] = redact(f[field])
        # Category, citation, and authority come from the registry, not agent input.
        reg = taxonomy.entry(f.get("id"))
        if reg:
            f["category"] = reg["category"]
            f["hipaa_ref"] = reg["hipaa_ref"]
            f["authority_type"] = reg["authority_type"]
        f.setdefault("source", "reasoning")
        f.setdefault("engine", provider)
        cleaned.append(f)

    if errors:
        print("clearmap: reasoning findings INVALID — not merged:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        return 1

    # Overlap dedupe: when the deterministic layer already flagged the same flaw
    # (same category + file, nearby line — det route rules anchor on the
    # decorator while the agent cites the body, hence the wide tolerance), drop
    # the reasoning duplicate so the score never double-deducts one flaw.
    DEDUPE_TOL = 8
    det_findings = det.get("findings", [])
    det_locs = [(f.get("category"), Path(str(f.get("file", ""))).as_posix(),
                 int(f.get("line", 0))) for f in det_findings]
    deduped, dropped = [], 0
    for f in cleaned:
        loc = (f.get("category"), Path(str(f.get("file", ""))).as_posix(),
               int(f.get("line", 0)))
        if any(c == loc[0] and p == loc[1] and abs(ln - loc[2]) <= DEDUPE_TOL
               for c, p, ln in det_locs):
            dropped += 1
            continue
        deduped.append(f)
    if dropped:
        print(f"clearmap: dropped {dropped} reasoning finding(s) already "
              f"covered deterministically")
    cleaned = deduped

    combined = det.get("findings", []) + cleaned
    combined.sort(key=lambda x: (x.get("file", ""), x.get("line", 0),
                                 x.get("category", ""), x.get("id", "")))
    det["findings"] = combined
    # Completion gating: only claim the reasoning layer ran if a manifest confirms
    # it (no failed batches) or, for a legacy manifest-less reasoning.json, if the
    # agent actually produced findings. An empty, manifest-less file leaves
    # source_layer deterministic, so the "Assessment incomplete" banner stays.
    if manifest:
        reasoning_complete = int(manifest.get("batches_failed", 0) or 0) == 0
    else:
        reasoning_complete = len(rfindings) > 0
    det["reasoning"] = {
        "provider": provider,
        "model": model,
        "run_id": run_id,
        "complete": reasoning_complete,
        "manifest": manifest or None,
    }
    if reasoning_complete:
        det["source_layer"] = "deterministic+reasoning"
    args.out.write_text(json.dumps(det, indent=2) + "\n")

    by_src: dict[str, int] = {}
    for f in combined:
        by_src[f.get("source", "?")] = by_src.get(f.get("source", "?"), 0) + 1
    print(f"clearmap: merged {len(cleaned)} reasoning + {len(det.get('findings', [])) - len(cleaned)} "
          f"deterministic = {len(combined)} findings -> {args.out}")
    print(f"  by source: {by_src}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
