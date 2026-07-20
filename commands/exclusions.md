---
description: Acknowledge findings as accepted risk (exclusions) without editing JSON
argument-hint: "[list | add | remove]"
allowed-tools: Bash, Read
---

# ClearMap exclusions (acknowledged accepted risks)

Interactively manage the findings the user has accepted as documented risk, for
example PHI sent to an LLM under a signed BAA with zero data retention. An
acknowledged finding stays visible in the report and is listed in its
Acknowledgments appendix, but does not deduct from the score. You write the file
for the user through the `clearmap acknowledge` CLI; never hand-edit the JSON.

The file lives at `clearmap-acknowledgments.json` in the repo root (committed, so
the acceptances travel with the code).

## Decide the action from `$ARGUMENTS`

- `list` (or empty, when the user just wants to see them): show current entries.
- `add`: add a new acknowledgment (the common case, interactive).
- `remove`: remove one.

## List

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/acknowledgments.py" list --target .
```

## Add (interactive)

1. Make sure an audit exists. Read `.clearmap/findings.json`; if it is missing,
   tell the user to run `/clearmap:audit` first and stop.
2. Show the current findings the user could acknowledge, each with its
   **Reference** (the `id` or `rule_id` field), title, severity, and location.
   Prefer critical and high findings. This Reference is what the acknowledgment
   points at.
3. Ask the user, in plain language:
   - which finding (its Reference) they want to acknowledge;
   - why it is an accepted risk (the reason, for example the BAA + zero-retention
     arrangement, or a VPC/gateway boundary ClearMap cannot see);
   - optionally, whether it applies to one file only, and an expiry date.
   Do NOT invent a reason. Acknowledging a finding is the user's decision; capture
   their own words.
4. Write it (owner defaults to git `user.email`; date defaults to today):

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/acknowledgments.py" add \
       --reference "<REFERENCE>" \
       --reason "<the user's explanation>" \
       [--file "<repo-relative path>"] \
       [--expires "YYYY-MM-DD"] \
       --target .
   ```

   The CLI validates the entry (owner, date, a real reason) and refuses any
   wording that asserts HIPAA compliance. If it exits non-zero, relay the reason
   and ask the user to reword.
5. Regenerate the report so the score reflects the acknowledgment:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/report.py" .clearmap/findings.json \
       --repo-path . --format both --out .clearmap/clearmap-report.md
   ```

   Then relay the new score and confirm the finding now shows as Acknowledged.

## Remove

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/acknowledgments.py" remove \
    --reference "<REFERENCE>" [--file "<path>"] --target .
```

Regenerate the report afterward, as above.

An acknowledgment records a decision; it does not remove or hide the finding.
ClearMap is a technical-risk signal, not a compliance certification.
