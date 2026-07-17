# ClearMap in Codex

ClearMap ships a Codex plugin manifest (`.codex-plugin/plugin.json`), a Codex marketplace (`.agents/plugins/marketplace.json`), and the same two portable skills used everywhere else.

> Note: the exact `codex` plugin and marketplace commands vary by Codex CLI version. Verify against your installed version before relying on a specific flow:
>
> ```bash
> codex --help
> codex plugin --help
> codex plugin marketplace --help
> ```
>
> Do not assume a command that your CLI does not expose. The manifests here follow the documented Codex plugin schema; confirm installation on your machine.

## Install (native plugin, where supported)

When your Codex version exposes plugin and marketplace commands, add the ClearMap marketplace and enable the plugin through that flow. ClearMap is offered for installation, not silently enabled.

## Fallback: install the Agent Skills

If your Codex version does not expose native plugin installation, install the portable skills directly. This is fully supported and self-contained:

```bash
python3 scripts/install_agent_skills.py --scope user --agent codex
# or, per project:
python3 scripts/install_agent_skills.py --target /path/to/project --scope project --agent codex
```

See [other-agents.md](other-agents.md) for what this installs and how the skills find the engine.

## Use

Codex discovers both skills from their descriptions. Invoke them implicitly by describing healthcare work, or explicitly:

```
Use $clearmap-development to implement a patient results endpoint.
Use $clearmap-audit to audit this repository.
Fix the critical and high ClearMap findings.
```

Codex executes the bundled scanner through the local shell, resolves the plugin/engine root, finds the bundled rules and references, and renders the audit summary in the session.

## Configure the reasoning provider

The default is the host agent (Codex itself). To use a local or remote model instead, run `python3 scripts/setup.py` (or the bundled `clearmap-engine/scripts/setup.py` for a skills-only install). See [first-run.md](first-run.md).
