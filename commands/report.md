---
description: Generate the ClearMap report (HTML, Markdown, or JSON) from the latest audit
argument-hint: "[md | html | json | both | all]"
allowed-tools: Bash, Read
---

# ClearMap report

Generate the report from the most recent audit's findings in the requested
format. Use the format in `$ARGUMENTS` if given, otherwise `both` (markdown +
HTML). Valid formats: `md`, `html`, `json`, `both`, `all`.

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/report.py" .clearmap/findings.json \
    --repo-path . --format both --out .clearmap/clearmap-report.md
```

Replace `both` with the requested format. Outputs go to `.clearmap/`:
`clearmap-report.md`, `clearmap-report.html`, and/or `clearmap-report.json`.

- If `.clearmap/findings.json` does not exist, tell the user to run
  `/clearmap:audit` first.
- After generating, relay the output paths and the score line.
- The `json` format is the machine-readable report (score, assessment, findings,
  suppressions, and the closing note) for dashboards or further processing.

ClearMap is a technical-risk signal, not a compliance certification.
