#!/usr/bin/env python3
"""Acknowledgments: user-documented, accepted technical risks.

Some findings are technically valid but already mitigated by controls ClearMap
cannot see in the code, for example PHI sent to an LLM under a signed Business
Associate Agreement with zero data retention. The user records these in a small
JSON file at the repository root (`clearmap-acknowledgments.json`, or
`.clearmap/acknowledgments.json`). Each acknowledgment names the finding it
accepts, an owner, a date, and a plain explanation; an optional `expires` date
makes the acceptance lapse so it must be reviewed again.

An acknowledged finding stays visible in the report, clearly marked as an
accepted risk with its owner and reason, but does not deduct from the score
(scoring.py skips findings flagged `acknowledged`). This is a governance record,
not a way to hide a finding: the acknowledgment text and provenance are printed
in a dedicated report appendix.

Format is JSON, not YAML: ClearMap's core is stdlib-only (no PyYAML). File shape:

    {
      "acknowledgments": [
        {
          "reference": "AI-RAG-01",
          "file": "backend/ai.py",          // optional: narrow to one file
          "owner": "sam@example.com",
          "date": "2026-07-20",
          "expires": "2027-07-20",          // optional
          "reason": "PHI sent to our LLM provider is covered by a signed BAA "
                    "with zero data retention."
        }
      ]
    }

`reference` is the Reference shown under each finding in the report (a reasoning
check id like AI-RAG-01, or a deterministic rule id), without the "(... rule)"
note. An acknowledgment with no `file` matches every finding with that reference.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import redact  # noqa: E402

# Where we look, in order. The first that exists wins. The root file is the
# recommended, committed location (the audit gitignores `.clearmap/`); it is also
# where `clearmap acknowledge add` writes.
WRITE_NAME = "clearmap-acknowledgments.json"
CANDIDATES = (WRITE_NAME, ".clearmap/acknowledgments.json")

REQUIRED = ("reference", "owner", "date", "reason")
_MIN_REASON = 8


def _valid_date(s: str) -> bool:
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except (ValueError, TypeError):
        return False


def _validate(e: dict) -> list[str]:
    """Return a list of human-readable errors for one acknowledgment entry, empty
    if it is well-formed. Shared by load() and `acknowledge add` so the file and
    the CLI enforce exactly the same rules."""
    from report import check_banned  # lazy: avoids an import cycle
    errs: list[str] = []
    if not isinstance(e, dict):
        return ["not an object"]
    for k in REQUIRED:
        if not str(e.get(k, "")).strip():
            errs.append(f"missing {k}")
    if e.get("date") and not _valid_date(str(e["date"])):
        errs.append("date must be YYYY-MM-DD")
    if e.get("expires") and not _valid_date(str(e["expires"])):
        errs.append("expires must be YYYY-MM-DD")
    if e.get("reason") and len(str(e["reason"]).strip()) < _MIN_REASON:
        errs.append("reason is too short to be a real explanation")
    text = f"{e.get('reason', '')} {e.get('owner', '')}".lower()
    banned = check_banned(text)
    if banned:
        errs.append(f"reason/owner contains a phrase ClearMap will not reproduce ({banned!r})")
    elif "hipaa compliant" in text or "hipaa-compliant" in text:
        # Stricter than the report guard: no compliance ASSERTION may ride in on a
        # user note (a neutral noun like "HIPAA compliance program" is fine).
        errs.append("reason/owner must not assert HIPAA compliance")
    return errs


def _find_file(target: Path) -> Path | None:
    for name in CANDIDATES:
        p = target / name
        if p.is_file():
            return p
    return None


def load(target: Path) -> list[dict]:
    """Read and validate the acknowledgments file from `target`. Returns a list of
    normalized (and redacted) acknowledgments; malformed entries are skipped with a
    stderr warning. Never raises for a missing or broken file (acknowledgments are
    optional)."""
    path = _find_file(target)
    if not path:
        return []
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"clearmap: could not read {path.name} ({e}); ignoring acknowledgments.",
              file=sys.stderr)
        return []

    entries = raw.get("acknowledgments") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        print(f"clearmap: {path.name} must contain an 'acknowledgments' list; ignoring.",
              file=sys.stderr)
        return []

    out: list[dict] = []
    for i, e in enumerate(entries):
        errs = _validate(e)
        if errs:
            print(f"clearmap: acknowledgment[{i}] ignored: {'; '.join(errs)}", file=sys.stderr)
            continue
        out.append({
            "reference": str(e["reference"]).strip(),
            "file": str(e["file"]).strip() if e.get("file") else None,
            # Owner is an accountability identifier (who accepted the risk), like a
            # git commit author, so it is shown verbatim. The reason is free text and
            # is redacted as a safety net against pasted PHI or secrets.
            "owner": str(e["owner"]).strip(),
            "date": str(e["date"]).strip(),
            "expires": str(e["expires"]).strip() if e.get("expires") else None,
            "reason": redact(str(e["reason"]).strip()),
        })
    return out


def _finding_ref(f: dict) -> str:
    return str(f.get("id") or f.get("rule_id") or "")


def _matches(ack: dict, f: dict) -> bool:
    if ack["reference"] != _finding_ref(f):
        return False
    if ack.get("file") and ack["file"] != f.get("file"):
        return False
    return True


def apply(findings: list[dict], acks: list[dict], today: str) -> dict:
    """Annotate `findings` in place. A finding matched by an active acknowledgment
    gets `f['acknowledged']` (and is skipped by scoring). A finding matched only by
    an EXPIRED acknowledgment gets `f['acknowledgment_expired']` and still counts,
    so a lapsed acceptance re-surfaces as live risk. Returns appendix + count data.

    `today` is the report date (YYYY-MM-DD); expiry compares lexically, which is
    correct for ISO dates and keeps output deterministic for a given date."""
    applied: list[dict] = []
    n_ack = n_expired = 0
    for ack in acks:
        expired = bool(ack.get("expires") and ack["expires"] < today)
        matched = [f for f in findings if _matches(ack, f)]
        for f in matched:
            if expired:
                f.setdefault("acknowledgment_expired", ack)
            else:
                f.setdefault("acknowledged", ack)
        if expired:
            n_expired += len(matched)
        else:
            n_ack += len(matched)
        applied.append({
            "reference": ack["reference"],
            "file": ack.get("file"),
            "owner": ack["owner"],
            "date": ack["date"],
            "expires": ack.get("expires"),
            "reason": ack["reason"],
            "status": "expired" if expired else "active",
            "matched": len(matched),
        })
    return {"applied": applied, "n_acknowledged": n_ack, "n_expired": n_expired}


# --------------------------------------------------------------------- CLI --
# `clearmap acknowledge` writes/reads the acknowledgments file for a repo so an
# agent (the /clearmap:exclusions command) or a user never has to hand-edit JSON.

def _git_email(target: Path) -> str:
    try:
        r = subprocess.run(["git", "-C", str(target), "config", "user.email"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _read_entries(path: Path) -> tuple[list, str | None]:
    """Return (entries, comment) from an existing file, tolerating a bare list or a
    missing file. `comment` preserves any `_comment` key so a template stays intact."""
    if not path.is_file():
        return [], None
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return [], None
    if isinstance(raw, dict):
        entries = raw.get("acknowledgments")
        return (entries if isinstance(entries, list) else []), raw.get("_comment")
    return (raw if isinstance(raw, list) else []), None


def _write_entries(path: Path, entries: list, comment: str | None) -> None:
    doc: dict = {}
    if comment:
        doc["_comment"] = comment
    doc["acknowledgments"] = entries
    path.write_text(json.dumps(doc, indent=2) + "\n")


def _same_key(a: dict, b: dict) -> bool:
    return (str(a.get("reference")) == str(b.get("reference"))
            and (a.get("file") or None) == (b.get("file") or None))


def _add(args: argparse.Namespace) -> int:
    target = args.target.resolve()
    entry = {
        "reference": (args.reference or "").strip(),
        "owner": (args.owner or _git_email(target) or "").strip(),
        "date": (args.date or date.today().isoformat()).strip(),
        "reason": (args.reason or "").strip(),
    }
    if args.file:
        entry["file"] = args.file.strip()
    if args.expires:
        entry["expires"] = args.expires.strip()
    errs = _validate(entry)
    if not entry["owner"]:
        errs.append("missing owner (pass --owner or set git user.email)")
    if errs:
        print("clearmap: cannot add acknowledgment: " + "; ".join(errs), file=sys.stderr)
        return 2
    path = target / WRITE_NAME
    entries, comment = _read_entries(path)
    entries = [e for e in entries if not _same_key(e, entry)]  # replace on same key
    entries.append(entry)
    _write_entries(path, entries, comment)
    scope = f" for {entry['file']}" if entry.get("file") else ""
    print(f"clearmap: acknowledged {entry['reference']}{scope} in {path.name}. "
          "Regenerate the report to apply it (clearmap report or /clearmap:report).")
    return 0


def _remove(args: argparse.Namespace) -> int:
    target = args.target.resolve()
    path = target / WRITE_NAME
    entries, comment = _read_entries(path)
    key = {"reference": (args.reference or "").strip(), "file": args.file}
    kept = [e for e in entries if not _same_key(e, key)]
    if len(kept) == len(entries):
        print(f"clearmap: no acknowledgment matching {key['reference']!r}"
              + (f" for {args.file}" if args.file else ""), file=sys.stderr)
        return 1
    _write_entries(path, kept, comment)
    print(f"clearmap: removed {len(entries) - len(kept)} acknowledgment(s) for "
          f"{key['reference']}.")
    return 0


def _list(args: argparse.Namespace) -> int:
    acks = load(args.target.resolve())
    if not acks:
        print("No acknowledgments recorded. Add one with `clearmap acknowledge add "
              "--reference <ref> --reason \"...\"` or /clearmap:exclusions.")
        return 0
    for a in acks:
        scope = a["file"] or "all matching findings"
        exp = f", expires {a['expires']}" if a.get("expires") else ""
        print(f"- {a['reference']} ({scope}) by {a['owner']} on {a['date']}{exp}\n    {a['reason']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="clearmap acknowledge",
                                 description="Record findings accepted as documented risk")
    sub = ap.add_subparsers(dest="action", required=True)

    a = sub.add_parser("add", help="add or replace an acknowledgment")
    a.add_argument("--reference", required=True,
                   help="the Reference shown under a finding (a check id or rule id)")
    a.add_argument("--reason", required=True, help="why this risk is accepted")
    a.add_argument("--owner", help="who accepts it (defaults to git user.email)")
    a.add_argument("--file", help="narrow to one file (repo-relative)")
    a.add_argument("--date", help="acceptance date YYYY-MM-DD (defaults to today)")
    a.add_argument("--expires", help="expiry date YYYY-MM-DD (optional)")
    a.add_argument("--target", type=Path, default=Path("."))
    a.set_defaults(fn=_add)

    r = sub.add_parser("remove", help="remove an acknowledgment")
    r.add_argument("--reference", required=True)
    r.add_argument("--file")
    r.add_argument("--target", type=Path, default=Path("."))
    r.set_defaults(fn=_remove)

    ls = sub.add_parser("list", help="list recorded acknowledgments")
    ls.add_argument("--target", type=Path, default=Path("."))
    ls.set_defaults(fn=_list)

    args = ap.parse_args()
    return int(args.fn(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
