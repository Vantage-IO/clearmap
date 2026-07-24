---
name: clearmap-audit
description: Run a ClearMap HIPAA technical-risk audit of a repository and summarize the result in the agent. Use when the user asks to audit a project, run ClearMap, scan a repository for HIPAA or PHI issues, get the HIPAA technical-risk status, or review code before sending it to a hospital or health system. It runs the bundled deterministic scanners, performs the AI-assisted reasoning review, merges and validates findings, generates Markdown and HTML reports, and reports the score inline. Do NOT run a full audit merely because the user is implementing a small healthcare feature. ClearMap is a technical-risk signal, not a HIPAA certification or a complete audit.
---

# ClearMap: on-demand audit

Run the full ClearMap audit and summarize the result directly in the agent. The user should not need how `scan.py`, `merge_reasoning.py`, `scoring.py`, or `report.py` work, and should not have to open the HTML report to understand the basic result.

Resolve the engine root, call it `ROOT`, in this order: `$CLEARMAP_PLUGIN_ROOT`, else `$CLAUDE_PLUGIN_ROOT`, else `$PLUGIN_ROOT` (Claude Code sets one for you); else, for a skills-only install, the `clearmap-engine` directory next to this skill (its sibling: `<this skill dir>/../clearmap-engine`). Run every script as `python3 "$ROOT/scripts/<name>.py"` (or `"$ROOT/bin/clearmap" <cmd>`). The engine's scripts self-resolve their own rules and references from `ROOT`, so no environment variable is required for a skills-only install. Do not assume ClearMap is pip-installed or that the source repo exists elsewhere.

## Steps

1. **Target.** Use the path the user gave, else the current project. Call it `TARGET`.
2. **Output dir.** `mkdir -p "$TARGET/.clearmap"`. Keep it out of git by writing a self-ignore inside the output directory: if `$TARGET/.clearmap/.gitignore` is absent, create it containing a single `*`. Never modify the scanned repo's own `.gitignore`; ClearMap writes only inside `.clearmap/`.
3. **Doctor + engines.** Run `python3 "$ROOT/scripts/init.py" doctor "$TARGET"`. If a required engine (Semgrep, Gitleaks) is missing or the wrong version, relay the install hints and stop; do not fabricate a score.
4. **Deterministic scan.**
   ```bash
   python3 "$ROOT/scripts/scan.py" "$TARGET" --out "$TARGET/.clearmap/findings-deterministic.json"
   ```
   If this exits non-zero (a required engine failed), STOP. Report `Score unavailable`, name the failed engine from `engine_status`, give the exact next action, and do not show a number or zero findings.
5. **AI-assisted review.** Read `"$ROOT/references/clinical-checks.md"` and `"$ROOT/references/audit-checks.md"`. Read every applicable source file under `TARGET` and evaluate each reasoning check yourself. Write `"$TARGET/.clearmap/reasoning.json"` following `"$ROOT/references/reasoning-schema.json"`. The **manifest is what makes the assessment count as Complete**, so fill it truthfully:
   ```json
   {
     "provider": "host-agent",
     "model": "<the model you are running as, if known>",
     "manifest": {
       "scan_fingerprint": "<copy the `scan.fingerprint` value from findings-deterministic.json>",
       "checks_in_scope": ["AUDIT-01", "AUDIT-02", "AI-RAG-01", "..."],
       "files_considered": 12,
       "files_skipped": [],
       "batches_completed": 1,
       "batches_failed": 0,
       "truncated": false,
       "privacy_mode": "local-only"
     },
     "findings": [ { ...one reasoning finding... } ]
   }
   ```
   The result is marked **Complete** only if you reviewed every applicable file (`files_skipped` empty), `truncated` is false, `batches_failed` is 0, and `scan_fingerprint` matches this scan. If you could not review some files, list them in `files_skipped` and set `truncated: true` honestly; the report will then show an automated-layer-only result rather than a false Complete.
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
8. **Summarize inline** (see below), then suggest the next step: `/clearmap:issues` to list open findings, or fixing the critical/high findings.

## Inline summary (always show this)

```
ClearMap audit complete.

ClearMap HIPAA Technical Risk Score: <score> (or "unavailable")
Assessment: Complete | Automated layer only | Score unavailable
Findings: <c> critical, <h> high, <m> medium, <l> low
Acknowledged: <n> accepted as documented risk (only if any; excluded from the score)

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

## Acknowledged risks

The report reads `clearmap-acknowledgments.json` from the repo root (or `.clearmap/acknowledgments.json`) each time it is generated. An acknowledgment accepts a valid finding as documented risk (for example PHI to an LLM under a signed BAA with zero data retention): it stays visible and listed in the Acknowledgments appendix but does not deduct from the score. When a finding cannot be judged from code alone and the user says it is covered by a control ClearMap cannot see (a BAA, a VPC boundary, an upstream gateway), tell them they can acknowledge it. Do not invent acknowledgments; acknowledging a finding is the user's decision, on the record, and needs their reason in their words.

Write it for them with the CLI (never hand-edit the JSON). This is what `/clearmap:exclusions` drives:

```bash
python3 "$ROOT/scripts/acknowledgments.py" list --target "$TARGET"
python3 "$ROOT/scripts/acknowledgments.py" add --reference "<Reference from the finding>" \
    --reason "<the user's explanation>" [--file "<path>"] [--expires "YYYY-MM-DD"] --target "$TARGET"
python3 "$ROOT/scripts/acknowledgments.py" remove --reference "<ref>" --target "$TARGET"
```

`add` defaults owner to git `user.email` and date to today, validates the entry, and refuses any wording that asserts HIPAA compliance. After adding or removing, regenerate the report so the score reflects it.
