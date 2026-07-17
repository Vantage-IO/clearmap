#!/usr/bin/env python3
"""Install ClearMap's canonical Agent Skills into a project or user skills
directory, for agents that support the Agent Skills folder standard but not a
native plugin.

Self-contained: alongside the two skills it copies the scanner, rules, and
references into `clearmap-engine/`, so the audit skill can run without a source
checkout or a pip install. Removes only ClearMap-managed files on uninstall.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plugin_root  # noqa: E402

ROOT = plugin_root.plugin_root()
SKILLS = ("clearmap-development", "clearmap-audit")
ENGINE_DIRS = ("scripts", "rules", "references")
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")


def _base(scope: str, target: Path) -> Path:
    root = Path.home() if scope == "user" else Path(target)
    return root / ".agents" / "skills"


def _managed(base: Path) -> list[Path]:
    return [base / s for s in SKILLS] + [base / "clearmap-engine"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Install ClearMap Agent Skills")
    ap.add_argument("--target", type=Path, default=Path("."))
    ap.add_argument("--scope", choices=("project", "user"), default="project")
    ap.add_argument("--agent", choices=("codex", "generic"), default="generic")
    ap.add_argument("--dest", type=Path, default=None,
                    help="explicit skills directory to install into (overrides --scope/--target)")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    base = args.dest.expanduser() if args.dest else _base(args.scope, args.target)
    tag = "[dry-run] " if args.dry_run else ""

    if args.uninstall:
        for p in _managed(base):
            if p.exists():
                print(f"{tag}remove {p}")
                if not args.dry_run:
                    shutil.rmtree(p)
        return 0

    targets = _managed(base)
    if not args.force:
        existing = [p for p in targets if p.exists()]
        if existing:
            print("clearmap: refusing to overwrite (use --force): "
                  + ", ".join(str(p) for p in existing), file=sys.stderr)
            return 1

    for skill in SKILLS:
        dest = base / skill
        print(f"{tag}install skill {skill} -> {dest}")
        if not args.dry_run:
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(ROOT / "skills" / skill, dest, ignore=_IGNORE)

    engine = base / "clearmap-engine"
    print(f"{tag}install engine -> {engine}")
    if not args.dry_run:
        if engine.exists():
            shutil.rmtree(engine)
        engine.mkdir(parents=True)
        for d in ENGINE_DIRS:
            shutil.copytree(ROOT / d, engine / d, ignore=_IGNORE)
        launcher = ROOT / "bin" / "clearmap"
        if launcher.is_file():
            # Preserve the bin/ subdirectory so the launcher's "root is my
            # parent's parent" logic resolves to clearmap-engine, not above it.
            (engine / "bin").mkdir(exist_ok=True)
            shutil.copy2(launcher, engine / "bin" / "clearmap")

    print(f"\nClearMap skills installed under {base}")
    print("The audit skill finds the bundled engine at ./clearmap-engine next to "
          "the skills; no environment variable is required. To use it directly: "
          f"{engine / 'bin' / 'clearmap'} audit <path>  (or "
          f"python3 {engine / 'scripts'}/audit.py <path>).")
    if args.agent == "codex":
        print("For Codex, invoke the skills explicitly with $clearmap-development "
              "and $clearmap-audit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
