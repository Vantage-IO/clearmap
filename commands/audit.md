---
description: Run a ClearMap HIPAA technical-risk audit (scan + AI review + report)
argument-hint: "[path]"
allowed-tools: Bash, Read, Write, Glob, Grep
---

# ClearMap audit

Run the full ClearMap audit on `$ARGUMENTS` (or the current project if no path is given) by following the `clearmap-audit` skill: doctor and engine check, deterministic scan, AI-assisted reasoning review against the bundled checklists, merge and validate, generate the Markdown and HTML reports under `.clearmap/`, and summarize the ClearMap HIPAA Technical Risk Score, assessment state, finding counts, and top issues inline. Run every script from the plugin root (`${CLAUDE_PLUGIN_ROOT}/scripts/...`). If a required engine fails, show `Score unavailable`, name the failed engine, and stop. ClearMap is a technical-risk signal, not a compliance certification or a complete audit.
