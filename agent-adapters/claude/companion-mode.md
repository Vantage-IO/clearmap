# ClearMap companion mode (passive, during generation)

The companion-mode content is the plugin skill at
`skills/clearmap-development/SKILL.md` and its `references/safe-patterns.md`. In
Claude Code the development skill loads automatically while healthcare or
PHI-handling code is being written.

For any other coding agent (Codex, Cursor, Copilot, and similar), apply the
risk / safe-alternative table from that skill: when you generate code in a
healthcare context, prefer the safe form for each risky pattern and note the
category code briefly.
