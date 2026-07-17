# ClearMap in Codex

The reliable way, which works on any Codex version, installs the ClearMap skills directly.

## Install (recommended)

```bash
git clone https://github.com/Vantage-IO/clearmap
python3 clearmap/scripts/install_agent_skills.py --scope user --agent codex
```

This installs `clearmap-development`, `clearmap-audit`, and a self-contained `clearmap-engine/` (scanner, rules, references) into `~/.agents/skills/`, so the audit runs without a source checkout. Options:

```
--scope project --target /path/to/project   # install into <project>/.agents/skills/ instead
--dest ~/.codex/skills                       # or an explicit skills directory your Codex reads
--uninstall                                  # remove only ClearMap's files
--dry-run                                    # preview
```

If your Codex version reads skills from a directory other than `~/.agents/skills/`, pass it with `--dest`. Check its docs or `codex --help` for the path.

## Native plugin (optional)

ClearMap also ships `.codex-plugin/plugin.json` and a Codex marketplace. If your Codex version exposes plugin commands (`codex plugin --help`), you can add the marketplace and install from it. Confirm the exact commands against your version first; do not run a command your CLI does not expose.

## Use

Describe healthcare work and the development skill activates, or invoke explicitly:

```
Use $clearmap-development to implement a patient results endpoint.
Use $clearmap-audit to audit this repository.
Generate the ClearMap report as JSON.
```

Codex runs the bundled scanner through the local shell and prints the score summary in the session. Reports are written to `.clearmap/`.

## Requirements

- Python 3.10+, plus `semgrep` 1.164.x and `gitleaks` 8.30.x on PATH.
- The AI-assisted review runs in Codex by default; to use a local or remote model instead, run `python3 clearmap-engine/scripts/setup.py` (see [advanced.md](advanced.md)).
