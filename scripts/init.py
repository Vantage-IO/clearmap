#!/usr/bin/env python3
"""ClearMap installer.

  install   — drop the ClearMap agent entrypoint + a starter .clearmapignore
              into a target repo. Records every created file (with sha256) in
              <target>/.clearmap/install-manifest.json. Never touches
              application code; refuses to overwrite existing files unless
              --force.
  uninstall — remove exactly the manifest-listed files; refuses when a file
              was modified after install (sha mismatch) unless --force.
              Reversible by construction.
  doctor    — verify engines (semgrep, gitleaks) are installed and match the
              pinned versions ClearMap was calibrated against.

    python3 scripts/init.py install /path/to/repo
    python3 scripts/init.py doctor  /path/to/repo
    python3 scripts/init.py uninstall /path/to/repo
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

CLEARMAP_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_REL = Path(".clearmap") / "install-manifest.json"

# Engines this build is calibrated against (pinned versions).
ENGINE_PINS = {"semgrep": "1.164", "gitleaks": "8.30"}
ENGINE_INSTALL_HINTS = {
    "semgrep": "pip install semgrep==1.164.0  (or: brew install semgrep)",
    "gitleaks": "brew install gitleaks  (or: https://github.com/gitleaks/gitleaks/releases)",
}

SKILL_TEMPLATE = """---
name: clearmap
description: Local-first HIPAA technical-risk guardrail. Use for "clearmap plan",
  "clearmap audit", "clearmap check", or when writing healthcare/PHI code.
---

# ClearMap (installed entrypoint)

ClearMap home: `{root}`

- **Plan** — follow `{root}/agent-adapters/claude/plan-mode.md`
- **Companion** — follow `{root}/agent-adapters/claude/companion-mode.md`
- **Audit** — outputs live in `.clearmap/` (add it to .gitignore):
  ```bash
  mkdir -p .clearmap
  python3 {root}/scripts/scan.py . --out .clearmap/findings-deterministic.json
  # reasoning pass per {root}/references/clinical-checks.md + audit-checks.md
  # -> .clearmap/reasoning.json, then:
  python3 {root}/scripts/merge_reasoning.py .clearmap/findings-deterministic.json \\
      .clearmap/reasoning.json --out .clearmap/findings.json
  python3 {root}/scripts/report.py .clearmap/findings.json --format both \\
      --out .clearmap/clearmap-report.md
  ```
- **Open issues** — `python3 {root}/scripts/issues.py` (reads `.clearmap/findings.json`)

Suppressions: `.clearmapignore` at the repo root (`pattern [rule-id]` per
line) or inline `# clearmap:allow <rule-id>` on/above the flagged line.
"""

CLEARMAPIGNORE_TEMPLATE = """# ClearMap suppressions — one glob per line, optional rule-id second column.
# Examples:
#   generated/*
#   src/legacy/*  generic-api-key
"""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install(target: Path, force: bool) -> int:
    manifest_path = target / MANIFEST_REL
    if manifest_path.exists() and not force:
        print(f"clearmap: already installed (manifest at {manifest_path}); "
              "use --force to reinstall", file=sys.stderr)
        return 1
    files = {
        target / ".claude" / "skills" / "clearmap" / "SKILL.md":
            SKILL_TEMPLATE.format(root=CLEARMAP_ROOT),
        target / ".clearmapignore": CLEARMAPIGNORE_TEMPLATE,
    }
    created: list[dict] = []
    for path in files:
        if path.exists() and not force:
            print(f"clearmap: refusing to overwrite existing {path} "
                  "(use --force)", file=sys.stderr)
            return 1
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        created.append({"path": str(path.relative_to(target)), "sha256": _sha(path)})
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(
        {"clearmap_root": str(CLEARMAP_ROOT), "files": created}, indent=2) + "\n")
    print(f"clearmap: installed {len(created)} file(s) into {target}")
    for c in created:
        print(f"  + {c['path']}")
    return doctor(target)


def uninstall(target: Path, force: bool) -> int:
    manifest_path = target / MANIFEST_REL
    if not manifest_path.exists():
        print("clearmap: nothing to uninstall (no manifest)", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())
    entries = manifest.get("files", [])
    troot = target.resolve()
    # Path safety FIRST: the manifest is data from the target repo and is
    # untrusted. An absolute path (pathlib join replaces target entirely) or one
    # that escapes target via '..' must abort the WHOLE uninstall before anything
    # is deleted. --force only skips the sha check; it never bypasses this guard.
    resolved: list[tuple[dict, Path]] = []
    for e in entries:
        rel = str(e.get("path", ""))
        candidate = (target / rel).resolve()
        safe = (rel and not Path(rel).is_absolute()
                and candidate != troot and candidate.is_relative_to(troot))
        if not safe:
            print(f"clearmap: refusing to uninstall: manifest entry {rel!r} "
                  "resolves outside the target directory (hostile manifest?)",
                  file=sys.stderr)
            return 2
        resolved.append((e, candidate))
    # Verify shas second, delete third — uninstall is all-or-nothing.
    for e, path in resolved:
        if path.exists() and _sha(path) != e["sha256"] and not force:
            print(f"clearmap: {e['path']} was modified after install; "
                  "use --force to remove anyway", file=sys.stderr)
            return 1
    for e, path in resolved:
        if path.exists():
            path.unlink()
            print(f"  - {e['path']}")
    manifest_path.unlink()
    # Remove any now-empty directories we may have created.
    for rel in (".clearmap", ".claude/skills/clearmap", ".claude/skills", ".claude"):
        d = target / rel
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()
    print(f"clearmap: uninstalled from {target}")
    return 0


def doctor(target: Path) -> int:
    ok = True
    for engine, pin in ENGINE_PINS.items():
        exe = shutil.which(engine)
        if not exe:
            ok = False
            print(f"  ✗ {engine}: NOT INSTALLED — {ENGINE_INSTALL_HINTS[engine]}")
            continue
        ver = subprocess.run([engine, "--version"] if engine == "semgrep"
                             else [engine, "version"],
                             capture_output=True, text=True, check=False).stdout.strip()
        mark = "✓" if ver.startswith(pin) else "~"
        note = "" if ver.startswith(pin) else f"  (calibrated against {pin}.x — scores may drift)"
        print(f"  {mark} {engine}: {ver}{note}")
    ignore = target / ".clearmapignore"
    print(f"  {'✓' if ignore.exists() else '·'} .clearmapignore "
          f"{'present' if ignore.exists() else 'absent (optional)'}")
    return 0 if ok else 2


def main() -> int:
    ap = argparse.ArgumentParser(description="ClearMap installer")
    ap.add_argument("command", choices=["install", "uninstall", "doctor"])
    ap.add_argument("target", type=Path)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    target = args.target.resolve()
    if not target.is_dir():
        print(f"clearmap: target is not a directory: {target}", file=sys.stderr)
        return 1
    return {"install": lambda: install(target, args.force),
            "uninstall": lambda: uninstall(target, args.force),
            "doctor": lambda: doctor(target)}[args.command]()


if __name__ == "__main__":
    sys.exit(main())
