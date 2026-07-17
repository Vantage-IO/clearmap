#!/usr/bin/env python3
"""ClearMap calibration — measure findings against the corpus ground truth.

Compares one or more candidate findings files against a fixture's
expected-findings.json and reports recall, precision, false positives, and
(for multiple candidate runs) variance on high/critical findings.

A candidate "matches" an expected finding when they share category + file and
the line is within a tolerance (rules/agents may report a nearby line). Each
expected finding is matched at most once.

    # recall/precision of one run
    python3 scripts/calibrate.py --expected EXP.json --candidate run1.json --source reasoning
    # + variance across runs
    python3 scripts/calibrate.py --expected EXP.json --candidate r1.json r2.json r3.json --source reasoning
"""
from __future__ import annotations

import argparse
import json
from itertools import combinations
from pathlib import Path

LINE_TOL = 3


def _key_loc(f: dict) -> tuple:
    return (f.get("category"), Path(str(f.get("file", ""))).as_posix())


def _findings(path: Path, source: str | None) -> list[dict]:
    data = json.loads(path.read_text())
    items = data.get("findings", data.get("must_catch", data if isinstance(data, list) else []))
    if source and source != "all":
        out = []
        for f in items:
            if f.get("source") == source:
                out.append(f)
            elif source in f.get("also_detectable_by", []):
                # Expected primarily for the other layer but also catchable by
                # this one; det rules may anchor on a different line (e.g. the
                # route decorator instead of the body) — use det_line if given.
                g = dict(f)
                if source == "deterministic" and f.get("det_line"):
                    g["line"] = f["det_line"]
                out.append(g)
        items = out
    return items


def _same_file(a: dict, b: dict) -> bool:
    return Path(str(a.get("file", ""))).as_posix() == Path(str(b.get("file", ""))).as_posix()


def match(cands: list[dict], exps: list[dict]) -> tuple[set[int], set[int]]:
    """Greedy match: return (matched expected idxs, matched candidate idxs).

    A candidate matches an expected when, in the same file, EITHER they carry the
    same check id (the reasoning layer classifies to a check id — the right metric)
    OR they share category and a nearby line (handles deterministic/no-id cases).
    """
    matched_exp: set[int] = set()
    matched_cand: set[int] = set()
    for ci, c in enumerate(cands):
        for ei, e in enumerate(exps):
            if ei in matched_exp or not _same_file(c, e):
                continue
            id_match = c.get("id") and e.get("id") and c["id"] == e["id"]
            loc_match = (c.get("category") == e.get("category")
                         and abs(int(c.get("line", 0)) - int(e.get("line", 0))) <= LINE_TOL)
            if id_match or loc_match:
                matched_exp.add(ei)
                matched_cand.add(ci)
                break
    return matched_exp, matched_cand


def _hi_crit_keys(findings: list[dict]) -> set[tuple]:
    return {_key_loc(f) for f in findings if f.get("severity") in ("critical", "high")}


def main() -> int:
    ap = argparse.ArgumentParser(description="ClearMap calibration metrics")
    ap.add_argument("--expected", type=Path, required=True)
    ap.add_argument("--candidate", type=Path, nargs="+", required=True)
    ap.add_argument("--source", default="all", help="deterministic | reasoning | all")
    ap.add_argument("--label", default="")
    ap.add_argument("--min-recall", type=float, default=None,
                    help="exit 1 if mean recall falls below this gate (CI)")
    ap.add_argument("--min-precision", type=float, default=None,
                    help="exit 1 if mean precision falls below this gate (CI)")
    args = ap.parse_args()

    exps = _findings(args.expected, args.source)
    runs = [_findings(c, args.source) for c in args.candidate]

    print(f"== Calibration {args.label} (source={args.source}) ==")
    print(f"expected findings: {len(exps)}")

    recalls, precisions = [], []
    for path, cands in zip(args.candidate, runs, strict=True):
        m_exp, m_cand = match(cands, exps)
        recall = len(m_exp) / len(exps) if exps else 1.0
        precision = len(m_cand) / len(cands) if cands else 1.0
        fp = [c for i, c in enumerate(cands) if i not in m_cand]
        recalls.append(recall)
        precisions.append(precision)
        missed = [str(e.get("id", _key_loc(e))) for i, e in enumerate(exps) if i not in m_exp]
        fp_labels = [f"{_key_loc(c)}@{c.get('line')}" for c in fp]
        print(f"\n  {path.name}: candidates={len(cands)}  "
              f"recall={recall:.2f} ({len(m_exp)}/{len(exps)})  "
              f"precision={precision:.2f}  false_positives={len(fp)}")
        if missed:
            print(f"    missed: {', '.join(missed[:20])}")
        if fp_labels:
            print(f"    FP: {', '.join(fp_labels[:20])}")

    if len(runs) > 1:
        print(f"\n  mean recall={sum(recalls)/len(recalls):.2f}  "
              f"mean precision={sum(precisions)/len(precisions):.2f}")
        # Variance: pairwise Jaccard overlap on high/critical finding locations.
        keysets = [_hi_crit_keys(r) for r in runs]
        overlaps = []
        for a, b in combinations(keysets, 2):
            union = a | b
            overlaps.append(len(a & b) / len(union) if union else 1.0)
        if overlaps:
            mean_ov = sum(overlaps) / len(overlaps)
            gate = "PASS" if mean_ov >= 0.80 else "FAIL"
            print(f"  variance (high/critical 3-run mean pairwise Jaccard) = {mean_ov:.2f}  "
                  f"[stability gate >=0.80: {gate}]")

    # CI gates: fail loudly when the measured baseline regresses.
    failed = []
    mean_recall = sum(recalls) / len(recalls) if recalls else 1.0
    mean_precision = sum(precisions) / len(precisions) if precisions else 1.0
    if args.min_recall is not None and mean_recall < args.min_recall:
        failed.append(f"recall {mean_recall:.2f} < gate {args.min_recall:.2f}")
    if args.min_precision is not None and mean_precision < args.min_precision:
        failed.append(f"precision {mean_precision:.2f} < gate {args.min_precision:.2f}")
    if failed:
        print(f"\n  GATE FAILED: {'; '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
