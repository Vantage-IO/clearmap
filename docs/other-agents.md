# ClearMap in other coding agents (Agent Skills)

ClearMap ships two portable Agent Skills, `clearmap-development` and `clearmap-audit`, plus the scanner engine. Any agent that supports the Agent Skills folder standard and can run a shell can use them, even without a native plugin format.

## Install

From a ClearMap checkout or an installed plugin, run the installer. It copies the two skills and a self-contained `clearmap-engine/` (scanner, rules, references) into the target skills directory, so the audit skill runs without a source checkout or a pip install.

```bash
# into a project's .agents/skills/
python3 scripts/install_agent_skills.py --target /path/to/project --scope project

# into the user-level ~/.agents/skills/
python3 scripts/install_agent_skills.py --scope user
```

Options:

```
--scope project | user     where to install (default: project)
--agent codex | generic    tailor the closing hint (default: generic)
--uninstall                remove only ClearMap-managed files
--dry-run                  print what would happen, change nothing
--force                    overwrite an existing install
```

The installer never overwrites an existing ClearMap install without `--force`, and `--uninstall` removes only the `clearmap-development`, `clearmap-audit`, and `clearmap-engine` directories it created.

## How the skills find the engine

The skills resolve the engine through `CLEARMAP_PLUGIN_ROOT` / `CLAUDE_PLUGIN_ROOT` / `PLUGIN_ROOT`, else the bundled engine's own location. For a plain Agent Skills install, point your agent at the bundle:

```bash
export CLEARMAP_PLUGIN_ROOT=/path/to/project/.agents/skills/clearmap-engine
```

Then the audit skill runs `"$CLEARMAP_PLUGIN_ROOT/scripts/audit.py"`, and the scanner finds its rules and references.

## Requirements to actually run an audit

- Python 3.10+ (standard library only; no runtime pip dependencies for the core).
- `semgrep` 1.164.x and `gitleaks` 8.30.x on PATH for the deterministic scan.
- For AI-assisted review: either the host agent performs it (default), or configure an OpenAI-compatible provider with `python3 clearmap-engine/scripts/setup.py`.

## Compatibility matrix

| Environment         | Development skill | Audit skill | Native plugin | Agent Skills |
|---------------------|-------------------|-------------|---------------|--------------|
| Claude Code         | Yes               | Yes         | Yes           | Yes          |
| Codex               | Yes               | Yes         | Yes (manifest built, verify locally) | Yes |
| Generic skills CLI  | Yes               | Yes         | No            | Yes          |
| Plain terminal      | No agent reasoning | Deterministic scan + report | No | No |

In a plain terminal with no agent, the deterministic scanner and report run (`clearmap audit` produces an automated-layer-only result); the AI-assisted development and reasoning review need a compatible agent or a configured model provider.
