#!/usr/bin/env python3
"""List ClearMap suppressions from a findings.json.

Audits the false-positive layer: every suppression and downgrade is recorded in
the scan output with its source, reason, and optional expiry. This command
groups them (active / expired / downgraded) so a reviewer can see exactly what
was hidden and why. Expiry is evaluated against --as-of (default: today);
--fail-on-expired exits non-zero if any explicit suppression has lapsed.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path


def classify(ledger: list[dict], as_of: str) -> dict:
    active, expired, downgraded = [], [], []
    for r in ledger:
        if r.get("disposition") == "downgraded":
            downgraded.append(r)
            continue
        exp = r.get("expires")
        (expired if (exp and exp < as_of) else active).append(r)
    return {"active": active, "expired": expired, "downgraded": downgraded}


def _fmt(r: dict) -> str:
    loc = f"{r.get('file', '?')}:{r.get('line', '?')}"
    rule = r.get("rule_id") or r.get("category") or "?"
    reason = r.get("reason") or "(no reason)"
    exp = f" expires {r['expires']}" if r.get("expires") else ""
    return f"  {loc}  [{r.get('source', '?')}] {rule}: {reason}{exp}"


def main() -> int:
    ap = argparse.ArgumentParser(description="List ClearMap suppressions")
    ap.add_argument("findings", type=Path, nargs="?",
                    default=Path(".clearmap/findings.json"))
    ap.add_argument("--as-of", default=None, help="date YYYY-MM-DD to evaluate expiry (default: today)")
    ap.add_argument("--fail-on-expired", action="store_true",
                    help="exit 1 if any explicit suppression has expired")
    args = ap.parse_args()

    path = args.findings
    if not path.exists():
        alt = Path("findings.json")
        if alt.exists():
            path = alt
        else:
            print(f"clearmap: no findings file at {args.findings}", file=sys.stderr)
            return 2
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"clearmap: could not read {path} ({e}); not a valid findings file.",
              file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print(f"clearmap: {path} is not a valid findings file "
              "(expected a JSON object, not a top-level array).", file=sys.stderr)
        return 2
    ledger = data.get("suppressions", [])
    if not isinstance(ledger, list):
        print(f"clearmap: {path} has a malformed 'suppressions' field (expected a list).",
              file=sys.stderr)
        return 2
    as_of = args.as_of or date.today().isoformat()
    groups = classify(ledger, as_of)

    if not ledger:
        print("clearmap: no suppressions recorded.")
        return 0
    print(f"clearmap suppressions (as of {as_of}): {len(groups['active'])} active, "
          f"{len(groups['expired'])} expired, {len(groups['downgraded'])} downgraded")
    for label, key in (("Active", "active"), ("EXPIRED", "expired"), ("Downgraded", "downgraded")):
        if groups[key]:
            print(f"\n{label}:")
            for r in groups[key]:
                print(_fmt(r))
    if args.fail_on_expired and groups["expired"]:
        print(f"\nclearmap: {len(groups['expired'])} suppression(s) expired.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
