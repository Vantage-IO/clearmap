#!/usr/bin/env python3
"""clearmap audit: run the full pipeline and print an inline status summary.

Orchestrates scan -> reasoning (per provider) -> merge -> report, then prints the
ClearMap HIPAA Technical Risk Score and top findings in the terminal. Fails
closed: a required-engine failure yields "Score unavailable" and a non-zero exit;
a run without a completed reasoning pass is an explicit automated-layer-only
result (never a clean bill of health).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import config  # noqa: E402
import report as report_mod  # noqa: E402


def _run(module: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HERE / f"{module}.py"), *args])


def _summary(findings_path: Path, repo: str, out_dir: Path, provider: str) -> None:
    data = json.loads(findings_path.read_text())
    m = report_mod.build_model(data, repo, date.today().isoformat())
    s, state = m["scores"], m["score_state"]
    print("\nClearMap audit complete.\n")
    if state == "unavailable":
        print(f"{m['score_label']}: unavailable")
        print(f"Reason: {m['score_reason']}")
    else:
        q = " (automated layer only)" if state == "incomplete" else ""
        print(f"{m['score_label']}: {s['score']}{q}")
        print(f"Assessment: {'Complete' if state == 'complete' else 'Automated layer only'}")
    print(f"Findings: {s['n_critical']} critical, {s['n_high']} high, "
          f"{m['n_medium']} medium, {m['n_low']} low")
    if m["exec"]["top"]:
        print("\nTop issues:")
        for i, v in enumerate(m["exec"]["top"], 1):
            print(f"{i}. {v['title']}" + (f" ({v['location']})" if v.get("location") else ""))
    if s.get("not_reviewed_categories"):
        print("\nNot reviewed: " + ", ".join(s["not_reviewed_categories"]))
    print(f"\nReasoning provider: {m['assessment'].get('reasoning_provider') or provider}")
    print(f"Regulatory baseline: {m['assessment'].get('baseline_version')}")
    print(f"\nReports:\n{out_dir / 'clearmap-report.md'}\n{out_dir / 'clearmap-report.html'}")
    print("\nTechnical code-risk signal only. Not a compliance score, certification, "
          "formal HIPAA risk analysis, or legal determination.")
    print("\nThis is a partial, automated technical review, not a full audit. For a deeper "
          "reliability assessment beyond the technical layer, visit vantageio.com.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a full ClearMap audit")
    ap.add_argument("target", type=Path, nargs="?", default=Path("."))
    ap.add_argument("--provider", choices=config.PROVIDERS)
    ap.add_argument("--skip-reasoning", action="store_true")
    ap.add_argument("--require-complete", action="store_true")
    ap.add_argument("--format", choices=["md", "html", "json", "both", "all"], default="both")
    ap.add_argument("--diff", action="store_true")
    ap.add_argument("--history", action="store_true")
    args = ap.parse_args()

    target = args.target.resolve()
    out_dir = target / ".clearmap"
    out_dir.mkdir(parents=True, exist_ok=True)
    gi = target / ".gitignore"
    if gi.exists() and ".clearmap/" not in gi.read_text():
        gi.write_text(gi.read_text().rstrip("\n") + "\n.clearmap/\n")
    cfg = config.load(target, overrides={"provider": args.provider} if args.provider else None)
    provider = cfg["provider"]

    det = out_dir / "findings-deterministic.json"
    scan_args = [str(target), "--out", str(det)]
    if args.diff:
        scan_args.append("--diff")
    if args.history:
        scan_args.append("--history")
    if _run("scan", *scan_args).returncode != 0:
        _run("report", str(det), "--repo", target.name, "--repo-path", str(target),
             "--format", args.format, "--out", str(out_dir / "clearmap-report.md"))
        print("\nClearMap audit: Score unavailable. A required scanning engine did not "
              "complete. Run 'clearmap doctor' to diagnose.", file=sys.stderr)
        return 2

    findings_path, reasoning_done = det, False
    reasoning_json = out_dir / "reasoning.json"
    if args.skip_reasoning:
        pass
    elif provider == "openai-compatible":
        if _run("reason", str(target), "--out", str(reasoning_json)).returncode == 0:
            if _run("merge_reasoning", str(det), str(reasoning_json), "--repo-path",
                    str(target), "--out", str(out_dir / "findings.json")).returncode == 0:
                findings_path, reasoning_done = out_dir / "findings.json", True
    elif reasoning_json.exists():  # host-agent (agent wrote it) or manual
        if _run("merge_reasoning", str(det), str(reasoning_json), "--repo-path",
                str(target), "--out", str(out_dir / "findings.json")).returncode == 0:
            findings_path, reasoning_done = out_dir / "findings.json", True
    elif provider == "manual":
        print("clearmap: --provider manual needs .clearmap/reasoning.json", file=sys.stderr)
        return 2

    _run("report", str(findings_path), "--repo", target.name, "--repo-path", str(target),
         "--format", args.format, "--out", str(out_dir / "clearmap-report.md"))
    _summary(findings_path, target.name, out_dir, provider)

    if not reasoning_done and provider == "host-agent" and not args.skip_reasoning:
        print("\nAI-assisted review not completed (no .clearmap/reasoning.json). This is an "
              "automated-layer-only result. To complete it: run inside a coding agent that "
              "writes reasoning.json, `clearmap setup` an OpenAI-compatible provider, or use "
              "--provider manual with a supplied reasoning.json.")
    if args.require_complete and not reasoning_done:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
