---
description: List open ClearMap findings from the latest audit
argument-hint: "[--severity critical,high]"
allowed-tools: Bash, Read
---

# ClearMap open issues

Show the open findings from the most recent ClearMap audit of the current repository:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/issues.py" $ARGUMENTS
```

- It reads `.clearmap/findings.json` (falling back to `./findings.json`). Exit code 2 means no audit has run yet: tell the user to run `/clearmap:audit` first.
- Exit code 1 means critical or high findings remain: that is expected and works as a gate, not an error.
- Relay the table as-is, then point at the full report (`.clearmap/clearmap-report.html`) if it exists.
- To review what the scan filtered, run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/suppressions.py"`.

When the user asks to fix findings, follow the `clearmap-audit` skill's remediation guidance: confirm each finding, apply the narrowest safe fix, update tests, and rerun ClearMap. Never suppress a finding merely to raise the score.
