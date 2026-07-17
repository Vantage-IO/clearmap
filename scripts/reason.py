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
    """Yield batches, each a list of (repo_rel_path, prompt_block) tuples."""
    batch: list[tuple[str, str]] = []
    size = 0
    for p in files:
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        rel = scanmod._rel(str(p), target)
        block = f"\n### FILE: {rel}\n{text}\n"
        if size + len(block) > budget and batch:
            yield batch
            batch, size = [], 0
        batch.append((rel, block))
        size += len(block)
    if batch:
        yield batch


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-assisted reasoning pass")
    ap.add_argument("target", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reasoning.json"))
    ap.add_argument("--max-batches", type=int, default=8)
    ap.add_argument("--deterministic", type=Path, default=None,
                    help="the scan's findings-deterministic.json; binds the manifest to it")
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
    reasoning_ids = sorted(k for k, v in taxonomy.findings().items() if v["layer"] == "reasoning")
    ids_str = ", ".join(reasoning_ids)

    # Bind the manifest to the scan it reviews, so a reasoning.json for a
    # different revision cannot be accepted downstream as complete.
    scan_fp = None
    if args.deterministic and args.deterministic.is_file():
        try:
            scan_fp = (json.loads(args.deterministic.read_text()).get("scan") or {}).get("fingerprint")
        except (OSError, json.JSONDecodeError):
            pass

    all_batches = list(_batches(_candidates(target), target))
    process = all_batches[:args.max_batches]
    skipped = [rel for b in all_batches[args.max_batches:] for rel, _ in b]
    files_considered = sum(len(b) for b in process)

    findings: list[dict] = []
    done = failed = 0
    for i, batch in enumerate(process):
        code = "".join(block for _, block in batch)
        user = (f"Canonical reasoning finding ids you may use: {ids_str}.\n\n"
                f"CHECKLISTS:\n{checklists}\n\nCODE UNDER REVIEW:\n{code}\n\n"
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
            done += 1
        except providers.ProviderError as e:
            print(f"clearmap: reasoning batch {i} failed: {e}", file=sys.stderr)
            failed += 1

    truncated = bool(skipped)
    manifest = {
        "checks_in_scope": reasoning_ids,
        "files_considered": files_considered,
        "files_skipped": skipped,
        "batches_completed": done,
        "batches_failed": failed,
        "truncated": truncated,
        "privacy_mode": cfg["privacy_mode"],
        "scan_fingerprint": scan_fp,
    }
    out = {"provider": "openai-compatible", "model": cfg.get("model"),
           "manifest": manifest, "findings": findings}
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    note = " (TRUNCATED: raise --max-batches for a full review)" if truncated else ""
    print(f"clearmap: {len(findings)} reasoning finding(s) in {done} batch(es){note} "
          f"-> {args.out}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
