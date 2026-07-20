# Auditing a repository

```
/clearmap:audit .
```

or, in Codex or another agent:

```
Use $clearmap-audit to audit this repository.
```

or from the terminal: `clearmap audit .`

## What runs

1. **Doctor + engines.** Confirms `semgrep` and `gitleaks` are installed and on the calibrated versions. A missing or failed required engine stops the audit.
2. **Deterministic scan.** Semgrep (ClearMap rules) + Gitleaks, byte-stable output. Fails closed: if a required engine errors, times out, or returns unusable output, the audit reports `Score unavailable` rather than a clean-looking zero.
3. **AI-assisted review.** The host agent (or a configured OpenAI-compatible model) reviews the code against the clinical-AI and audit checklists and writes reasoning findings with a completion manifest.
4. **Merge + validate.** Reasoning findings are validated against the canonical taxonomy, redacted, and merged with the deterministic findings.
5. **Report.** Markdown and self-contained HTML are written to `.clearmap/`.
6. **Summary.** The score, assessment state, counts, and top issues print in the agent.

## The report

![Sample ClearMap report](report-sample.png)

The report opens with the ClearMap HIPAA Technical Risk Score and its qualification, a severity breakdown, the top findings, scope and coverage, the full findings with their regulatory citations and authority basis, and a closing note. No raw PHI-like value ever appears in it.

## Generating the report

The audit writes the report automatically, but you can regenerate it in any format from your agent without re-scanning:

```
/clearmap:report html      # self-contained HTML (open in a browser)
/clearmap:report md        # Markdown
/clearmap:report json      # machine-readable JSON of the issues
/clearmap:report both       # md + html
/clearmap:report all        # md + html + json
```

In Codex or another agent, ask in natural language: "Generate the ClearMap report as JSON." From the terminal:

```bash
clearmap report .clearmap/findings.json --repo-path . --format all
# writes .clearmap/clearmap-report.{md,html,json}
```

The `json` output is the machine-readable report (score, assessment, findings, suppressions, and closing note) for dashboards or further processing.

## Output locations

- `.clearmap/clearmap-report.md`, `.clearmap/clearmap-report.html`, `.clearmap/clearmap-report.json` (gitignored, fixed filenames).
- Machine-readable exports: `clearmap export .clearmap/findings.json --format sarif|csv`.

## Complete vs automated-layer-only

- **Complete:** engines ran and the reasoning review completed. Full score.
- **Automated layer only:** engines ran but the reasoning review did not (for example a bare terminal with no agent). A real, qualified score with an "Assessment incomplete" banner; AI-RAG and AUDIT show as Not reviewed. Never a clean bill of health.
- **Score unavailable:** a required engine failed, the baseline could not load, or nothing applies. No number is shown, and the exact failed component is named.

## Acknowledging accepted risks

Some findings are technically valid but already mitigated by controls ClearMap cannot see in the code, for example PHI sent to an LLM under a signed Business Associate Agreement with zero data retention. ClearMap has no way to know a BAA exists, so it keeps flagging the risk. You can acknowledge such a finding: it stays visible in the report, clearly marked as an accepted risk with your owner and reason, but it no longer deducts from the score.

The easiest way is to let the agent do it. Run:

```
/clearmap:exclusions
```

The agent shows the current findings, asks which one to accept and why, and writes the file for you (owner defaults to your git email, date to today), then regenerates the report. From the terminal the same thing is:

```bash
clearmap acknowledge add --reference AI-RAG-01 --reason "Covered by a signed BAA with zero data retention." [--file backend/ai.py] [--expires 2027-07-20]
clearmap acknowledge list
clearmap acknowledge remove --reference AI-RAG-01
```

Or edit `clearmap-acknowledgments.json` in your repository root directly (see [clearmap-acknowledgments.example.json](../clearmap-acknowledgments.example.json)):

```json
{
  "acknowledgments": [
    {
      "reference": "AI-RAG-01",
      "owner": "you@example.com",
      "date": "2026-07-20",
      "expires": "2027-07-20",
      "reason": "PHI sent to our LLM provider is covered by a signed BAA with zero data retention."
    }
  ]
}
```

- `reference` is the **Reference** shown under each finding in the report (a check id like `AI-RAG-01`, or a rule id), without the `(... rule)` note. Omit `file` to accept every finding with that reference, or set it to narrow the acknowledgment to one file.
- `owner`, `date`, and `reason` are required; `expires` (YYYY-MM-DD) is optional. When an acknowledgment expires, the finding is scored again and the appendix marks it expired, so acceptances get reviewed rather than living forever.
- The file is read the next time the report is generated. Acknowledged findings are listed in an **Acknowledgments** appendix so the decision, its owner, and its date are on the record. It is JSON, not YAML, because ClearMap's core uses no third-party packages. This records a decision; it does not remove the finding, and it can never assert HIPAA compliance (such wording is rejected). Keep the file committed so the acceptances travel with the code.

## Fixing and rerunning

```
/clearmap:issues
```

Ask the agent to fix the critical and high findings. It confirms each finding, applies the narrowest safe correction, updates tests, and reruns ClearMap. A finding is never suppressed just to raise the score; any suppression needs a reason and is recorded in the report's suppression appendix (`clearmap suppressions` lists active, expired, and downgraded entries).

## Options

```
clearmap audit <target> --provider host-agent | openai-compatible | manual
clearmap audit <target> --skip-reasoning     explicitly automated-layer-only
clearmap audit <target> --require-complete    non-zero exit if not complete
clearmap audit <target> --diff                only changed files
clearmap audit <target> --history             also scan git history for secrets
clearmap audit <target> --format md | html | both
```
