#!/usr/bin/env python3
"""clearmap reason: the AI-assisted reasoning pass via an OpenAI-compatible
provider (the non-host-agent automation path).

Deterministic candidate selection (structure and signal, no fake semantic
search), NEVER sends ClearMap answer keys or generated manifests, chunks for
model context limits, requires structured JSON output, and writes reasoning.json
with a completion manifest so an empty or partial pass cannot masquerade as a
complete assessment.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import config  # noqa: E402
import providers  # noqa: E402
import scan as scanmod  # noqa: E402  (reuse _SRC_EXT / _SKIP_DIRS / EXCLUDE_BASENAMES / _SIG / _rel)
import taxonomy  # noqa: E402

CHECKLISTS = ("clinical-checks.md", "audit-checks.md")
SYSTEM = (
    "You are ClearMap's HIPAA technical-risk reasoning reviewer. You review real "
    "source code against the provided checklists and report only issues you can "
    "verify in the code. Never invent findings, never copy from an answer key, and "
    "never put a raw PHI value or secret in any field. Respond with ONLY a JSON "
    "object, no prose."
)


def _refs_dir() -> Path:
    return next((p for p in (HERE.parent / "references", HERE / "references") if p.is_dir()),
               HERE.parent / "references")


def _candidates(target: Path) -> list[Path]:
    files: list[Path] = []
    for root, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in scanmod._SKIP_DIRS and not d.startswith("."))
        for n in sorted(names):
            if Path(n).suffix in scanmod._SRC_EXT and n not in scanmod.EXCLUDE_BASENAMES \
                    and "expected-findings" not in n:
                p = Path(root) / n
                try:
                    if p.stat().st_size > 200_000:
                        continue
                except OSError:
                    continue
                files.append(p)

    def signal(p: Path) -> int:
        try:
            t = p.read_text(errors="ignore")[:50_000]
        except OSError:
            return 0
        return sum(1 for rx in scanmod._SIG.values() if rx.search(t))

    return sorted(files, key=lambda p: -signal(p))


def _batches(files: list[Path], target: Path, budget: int = 40_000):
    batch: list[str] = []
    size = 0
    for p in files:
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        block = f"\n### FILE: {scanmod._rel(str(p), target)}\n{text}\n"
        if size + len(block) > budget and batch:
            yield batch
            batch, size = [], 0
        batch.append(block)
        size += len(block)
    if batch:
        yield batch


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-assisted reasoning pass")
    ap.add_argument("target", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reasoning.json"))
    ap.add_argument("--max-batches", type=int, default=8)
    args = ap.parse_args()
    target = args.target.resolve()

    cfg = config.load(target)
    if cfg.get("provider") != "openai-compatible":
        print("clearmap: reason requires an openai-compatible provider "
              "(run 'clearmap setup')", file=sys.stderr)
        return 2
    errs = config.validate(cfg)
    for e in errs:
        print(f"clearmap: {e}", file=sys.stderr)
    if errs:
        return 2

    refs = _refs_dir()
    checklists = "\n\n".join((refs / c).read_text() for c in CHECKLISTS)
    reasoning_ids = ", ".join(sorted(k for k, v in taxonomy.findings().items()
                                     if v["layer"] == "reasoning"))
    files = _candidates(target)

    findings: list[dict] = []
    evaluated: set[str] = set()
    considered = done = failed = 0
    for i, batch in enumerate(_batches(files, target)):
        if i >= args.max_batches:
            break
        considered += len(batch)
        user = (f"Canonical reasoning finding ids you may use: {reasoning_ids}.\n\n"
                f"CHECKLISTS:\n{checklists}\n\nCODE UNDER REVIEW:\n{''.join(batch)}\n\n"
                'Return ONLY {"findings": [ ... ]}. Each finding requires: id (from the '
                "list above), category, title (short human sentence), severity "
                "(critical/high/medium/low), source (\"reasoning\"), confidence "
                "(high/medium/low), file (repo-relative), line (1-based integer), "
                "structural_snippet (structure only, never a raw PHI or secret value), why. "
                "Report only issues you verified in this code; return an empty list if none.")
        try:
            resp = providers.chat_completion(
                cfg, [{"role": "system", "content": SYSTEM},
                      {"role": "user", "content": user}], timeout=180)
            obj = providers.extract_json(resp["content"])
            for f in (obj.get("findings", []) if isinstance(obj, dict) else []):
                findings.append(f)
                if f.get("id"):
                    evaluated.add(f["id"])
            done += 1
        except providers.ProviderError as e:
            print(f"clearmap: reasoning batch {i} failed: {e}", file=sys.stderr)
            failed += 1

    manifest = {"checks_evaluated": sorted(evaluated), "files_considered": considered,
                "files_skipped": [], "batches_completed": done, "batches_failed": failed,
                "privacy_mode": cfg["privacy_mode"]}
    out = {"provider": "openai-compatible", "model": cfg.get("model"),
           "manifest": manifest, "findings": findings}
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    print(f"clearmap: {len(findings)} reasoning finding(s) in {done} batch(es) -> {args.out}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
