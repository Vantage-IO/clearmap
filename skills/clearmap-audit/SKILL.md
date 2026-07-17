---
name: clearmap-audit
description: Run a ClearMap HIPAA technical-risk audit of a repository and summarize the result in the agent. Use when the user asks to audit a project, run ClearMap, scan a repository for HIPAA or PHI issues, get the HIPAA technical-risk status, or review code before sending it to a hospital or health system. It runs the bundled deterministic scanners, performs the AI-assisted reasoning review, merges and validates findings, generates Markdown and HTML reports, and reports the score inline. Do NOT run a full audit merely because the user is implementing a small healthcare feature. ClearMap is a technical-risk signal, not a HIPAA certification or a complete audit.
---

# ClearMap: on-demand audit

Run the full ClearMap audit and summarize the result directly in the agent. The user should not need how `scan.py`, `merge_reasoning.py`, `scoring.py`, or `report.py` work, and should not have to open the HTML report to understand the basic result.

Resolve the plugin root from `$CLEARMAP_PLUGIN_ROOT`, else `$CLAUDE_PLUGIN_ROOT`, else `$PLUGIN_ROOT` (in Claude Code this is set for you). Call it `ROOT`. Run every script as `python3 "$ROOT/scripts/<name>.py"` (or `"$ROOT/bin/clearmap" <cmd>` when `bin/` is on PATH). Do not assume ClearMap is pip-installed or that the source repo exists elsewhere.

## Steps

1. **Target.** Use the path the user gave, else the current project. Call it `TARGET`.
2. **Output dir.** `mkdir -p "$TARGET/.clearmap"`. If `$TARGET/.gitignore` does not list `.clearmap/`, append it and say so.
3. **Doctor + engines.** Run `python3 "$ROOT/scripts/init.py" doctor "$TARGET"`. If a required engine (Semgrep, Gitleaks) is missing or the wrong version, relay the install hints and stop; do not fabricate a score.
4. **Deterministic scan.**
   ```bash
   python3 "$ROOT/scripts/scan.py" "$TARGET" --out "$TARGET/.clearmap/findings-deterministic.json"
   ```
   If this exits non-zero (a required engine failed), STOP. Report `Score unavailable`, name the failed engine from `engine_status`, give the exact next action, and do not show a number or zero findings.
5. **AI-assisted review.** Read `"$ROOT/references/clinical-checks.md"` and `"$ROOT/references/audit-checks.md"`. Read the applicable source under `TARGET` and evaluate each check yourself. Write `"$TARGET/.clearmap/reasoning.json"` following `"$ROOT/references/reasoning-schema.json"`:
   ```json
   {
     "provider": "host-agent",
     "model": "<the model you are running as, if known>",
     "manifest": {"checks_evaluated": ["AUDIT-01", "AI-RAG-01"], "files_considered": 0,
                  "files_skipped": [], "batches_completed": 1, "batches_failed": 0,
                  "privacy_mode": "local-only"},
     "findings": [ { ...one reasoning finding... } ]
   }
   ```
   Each finding needs: `id` (a canonical reasoning id from `references/taxonomy.json`, e.g. `AUDIT-01`, `AI-RAG-03`), `category`, `title` (a short human sentence, no rule slugs), `severity`, `source` = `"reasoning"`, `confidence` (high/medium/low), `file` (repo-relative, no `..`), `line` (1-based), `structural_snippet` (structure only, never a raw PHI or secret value), `why`. Optional: `remediation`, `reviewer_question`. Report only what you verified in the code; never invent findings or copy an answer key. If you found nothing, still write the manifest with `"findings": []`.
6. **Merge + validate.**
   ```bash
   python3 "$ROOT/scripts/merge_reasoning.py" \
     "$TARGET/.clearmap/findings-deterministic.json" \
     "$TARGET/.clearmap/reasoning.json" \
     --repo-path "$TARGET" --out "$TARGET/.clearmap/findings.json"
   ```
   If it reports validation errors, fix `reasoning.json` and re-run.
7. **Report.**
   ```bash
   python3 "$ROOT/scripts/report.py" "$TARGET/.clearmap/findings.json" \
     --repo "<repo name>" --repo-path "$TARGET" --format both \
     --out "$TARGET/.clearmap/clearmap-report.md"
   ```
8. **Summarize inline** (see below), then suggest the next step: `clearmap-audit` to list open findings, or fixing the critical/high findings.

## Inline summary (always show this)

```
ClearMap audit complete.

ClearMap HIPAA Technical Risk Score: <score> (or "unavailable")
Assessment: Complete | Automated layer only | Score unavailable
Findings: <c> critical, <h> high, <m> medium, <l> low

Top issues:
1. ...
2. ...
3. ...

Not reviewed: <categories, if any>
Reasoning provider: <provider>
Regulatory baseline: <version>

Reports:
.clearmap/clearmap-report.md
.clearmap/clearmap-report.html
```

Always include the qualification: a technical code-risk signal only, not a compliance score, certification, formal HIPAA risk analysis, or legal determination. Never say software is HIPAA compliant because ClearMap found no issues.

## Failed vs incomplete

- **Failed** (Semgrep/Gitleaks/baseline/a required step failed): show `Score unavailable`, name the failed component, give the next action, and return non-zero. Never a number, never zero findings.
- **Incomplete** (deterministic scan succeeded but the reasoning pass did not complete): show the qualified automated-layer-only score, mark AI-RAG and other reasoning-only categories `Not reviewed`, display `Assessment incomplete`, and do not call the repository clean.

## Fixing findings

When asked to fix findings: read the actual code, confirm the finding is valid, implement the narrowest safe correction, update tests, rerun relevant tests, then rerun ClearMap. Never suppress a finding just to raise the score; any suppression needs a reason (`clearmap:allow <rule> reason="..."`). Summarize which findings were fixed, disputed, or still open. Do not refactor unrelated architecture solely to raise the score.
