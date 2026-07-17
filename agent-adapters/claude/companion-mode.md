# ClearMap companion mode (passive, during generation)

The companion-mode content is the plugin skill at
`skills/clearmap-companion/SKILL.md`. In Claude Code it loads automatically
while healthcare or PHI-handling code is being written.

For any other coding agent (Codex, Cursor, Copilot, and similar), apply the
risk / safe-alternative table from that skill file: when you generate code in a
healthcare context, prefer the safe form for each risky pattern and note the
category code briefly.
