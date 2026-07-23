#!/usr/bin/env python3
"""ClearMap open-issues list.

Compact, terminal-friendly view of the open findings in the latest scan:
severity, title, location, citation, and verification status. Reuses the
report model (report.build_model) so the list can never disagree with the
report.

Default input discovery: ./.clearmap/findings.json, then ./findings.json.
Exit code 1 when any critical or high finding is open (usable as a gate).

    python3 scripts/issues.py [findings.json] [--severity critical,high]
        [--format table|md|json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402

DEFAULT_PATHS = (Path(".clearmap/findings.json"),
                 Path(".clearmap/findings-deterministic.json"),
                 Path("findings.json"))
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _discover() -> Path | None:
    for p in DEFAULT_PATHS:
        if p.is_file():
            return p
    return None


def _rows(model: dict, severities: set[str] | None) -> list[dict]:
    rows = []
    for v in model["ordered"]:
        if severities and v["severity"] not in severities:
            continue
        rows.append({
            "severity": v["severity"],
            "title": report._normalize_dashes(v["title"]),
            "location": v["location"],
            "citation": v["citation"]["short"] if v["citation"] else "",
            "status": v["verification_short"],
        })
    return rows


def _fmt_table(rows: list[dict], score: dict) -> str:
    if not rows:
        return "No open findings."
    headers = ("SEVERITY", "FINDING", "LOCATION", "CITATION", "STATUS")
    cells = [(r["severity"].upper(), r["title"], r["location"],
              r["citation"], r["status"]) for r in rows]
    widths = [max(len(h), *(len(c[i]) for c in cells)) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    lines.append("  ".join("-" * w for w in widths))
    lines += ["  ".join(c[i].ljust(widths[i]) for i in range(len(headers)))
              for c in cells]
    lines.append("")
    lines.append(f"{len(rows)} open finding(s) · HIPAA Risk Score "
                 f"{score['score']}/100: {score['posture']}")
    return "\n".join(lines)


def _fmt_md(rows: list[dict], score: dict) -> str:
    if not rows:
        return "No open findings."
    out = ["| Severity | Finding | Location | Citation | Status |",
           "|----------|---------|----------|----------|--------|"]
    out += [f"| {r['severity'].capitalize()} | {r['title']} | `{r['location']}` | "
            f"{r['citation']} | {r['status']} |" for r in rows]
    out.append("")
    out.append(f"{len(rows)} open finding(s) · HIPAA Risk Score "
               f"{score['score']}/100: {score['posture']}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="List open ClearMap findings")
    ap.add_argument("findings", type=Path, nargs="?", default=None,
                    help="findings.json (default: .clearmap/findings.json, ./findings.json)")
    ap.add_argument("--severity", default=None,
                    help="comma-separated filter, e.g. critical,high")
    ap.add_argument("--format", choices=["table", "md", "json"], default="table")
    args = ap.parse_args()

    path = args.findings or _discover()
    if not path or not Path(path).is_file():
        print("clearmap: no findings file found. Run an audit first "
              "(scan.py, or /clearmap:audit in Claude Code).", file=sys.stderr)
        return 2

    severities = None
    if args.severity:
        severities = {s.strip().lower() for s in args.severity.split(",") if s.strip()}
        bad = severities - set(SEV_RANK)
        if bad:
            print(f"clearmap: unknown severity: {', '.join(sorted(bad))}", file=sys.stderr)
            return 2

    data = json.loads(Path(path).read_text())
    model = report.build_model(data, repo=str(path), date="")
    rows = _rows(model, severities)

    if args.format == "json":
        print(json.dumps({"score": model["scores"]["score"],
                          "posture": model["scores"]["posture"],
                          "findings": rows}, indent=2))
    elif args.format == "md":
        print(_fmt_md(rows, model["scores"]))
    else:
        print(_fmt_table(rows, model["scores"]))

    # The exit-1 gate reflects the WHOLE open-finding set, never the --severity
    # display filter: a critical/high open finding must trip the gate even when
    # the view hides it. Uses the scored counts (unfiltered, acknowledged risks
    # excluded, consistent with the score).
    s = model["scores"]
    return 1 if (s["n_critical"] or s["n_high"]) else 0


if __name__ == "__main__":
    sys.exit(main())
