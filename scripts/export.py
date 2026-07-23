#!/usr/bin/env python3
"""Export findings.json to machine-readable formats.

  SARIF 2.1.0 — GitHub code scanning, VS Code SARIF viewer, Azure DevOps.
                hipaa_ref travels in rule properties.tags; severity maps to
                SARIF level (critical/high -> error, medium -> warning,
                low -> note) plus a numeric security-severity property.
  CSV         — flat findings table for GRC spreadsheets.

Both outputs are a deterministic function of the input (stable ordering, no
timestamps), matching scan.py's byte-stability guarantee.

    python3 scripts/export.py findings.json --format sarif --out clearmap.sarif
    python3 scripts/export.py findings.json --format csv   --out clearmap.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _version import __version__  # noqa: E402

SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json")
REPO_URL = "https://github.com/vantage-io/clearmap"

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub-style numeric security severity (0-10).
SECURITY_SEVERITY = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "2.0"}

CSV_COLUMNS = ["rule_id", "id", "category", "severity", "source", "confidence",
               "engine", "file", "line", "title", "hipaa_ref", "authority_type",
               "why", "remediation"]


def _rule_key(f: dict) -> str:
    return f.get("rule_id") or f.get("id") or "unknown"


def to_sarif(data: dict) -> dict:
    findings = data.get("findings", [])
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = _rule_key(f)
        if rid not in rules:
            tags = ["hipaa", f.get("category", "UNKNOWN")]
            if f.get("hipaa_ref"):
                tags.append(f["hipaa_ref"])
            if f.get("authority_type"):
                tags.append(f["authority_type"])
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.get("title") or rid},
                "helpUri": f"{REPO_URL}/blob/main/references/regulatory-map.md",
                "properties": {
                    "tags": tags,
                    "security-severity": SECURITY_SEVERITY.get(f.get("severity"), "2.0"),
                },
            }
        message = f.get("why") or f.get("title") or rid
        if f.get("remediation"):
            message += f" Remediation: {f['remediation']}"
        results.append({
            "ruleId": rid,
            "level": LEVEL.get(f.get("severity"), "note"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("file", "")).replace("\\", "/")},
                    "region": {"startLine": max(1, int(f.get("line", 1) or 1))},
                },
            }],
            "properties": {
                "clearmap_category": f.get("category", ""),
                "source": f.get("source", ""),
                **({"authority_type": f["authority_type"]} if f.get("authority_type") else {}),
                **({"confidence": f["confidence"]} if f.get("confidence") else {}),
            },
        })
    engines = data.get("engines", {})
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ClearMap",
                    "informationUri": REPO_URL,
                    "version": __version__,
                    "rules": [rules[k] for k in sorted(rules)],
                },
            },
            "properties": {
                "source_layer": data.get("source_layer", ""),
                "regulatory_baseline": data.get("regulatory_baseline", {}),
                "engines": engines,
                "suppressed_count": data.get("suppressed_count", 0),
            },
            "results": results,
        }],
    }


def to_csv(data: dict) -> str:
    import io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore",
                       lineterminator="\n")
    w.writeheader()
    for f in data.get("findings", []):
        w.writerow({k: f.get(k, "") for k in CSV_COLUMNS})
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description="Export ClearMap findings")
    ap.add_argument("findings", type=Path)
    ap.add_argument("--format", choices=["sarif", "csv"], required=True)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    data = json.loads(args.findings.read_text())
    out = args.out or args.findings.with_suffix(
        ".sarif" if args.format == "sarif" else ".csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "sarif":
        out.write_text(json.dumps(to_sarif(data), indent=2) + "\n")
    else:
        out.write_text(to_csv(data))
    n = len(data.get("findings", []))
    print(f"clearmap: exported {n} findings ({args.format}) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
