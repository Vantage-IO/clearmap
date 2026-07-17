# ClearMap in Claude Code

## Install

In a Claude Code session:

```
/plugin marketplace add Vantage-IO/clearmap
/plugin install clearmap@vantage-io
/clearmap:setup
```

Terminal equivalent:

```bash
claude plugin marketplace add Vantage-IO/clearmap
claude plugin install clearmap@vantage-io
```

The plugin installs from the repository root into the plugin cache; you do not need to clone ClearMap or `pip install` anything. `/clearmap:setup` checks the scanner engines (`semgrep` 1.164.x, `gitleaks` 8.30.x) and lets you set the AI-assisted reasoning provider (default: this agent).

## Commands

```
/clearmap:setup            configure engines + reasoning provider
/clearmap:plan <task>      HIPAA-aware planning questions before code
/clearmap:develop <task>   implement a healthcare feature with guidance
/clearmap:audit [path]     full audit + inline score summary
/clearmap:issues           open findings from the latest audit
```

## Skills

Two skills load automatically from their descriptions when relevant:

- `clearmap-development` for building healthcare software safely.
- `clearmap-audit` for running the technical-risk audit.

A small SessionStart hook adds one line reminding the agent to load the development skill for healthcare work. It makes no network calls, writes no files, and is safe to disable; the skill still auto-activates from its own description.

## Update and uninstall

```bash
claude plugin update clearmap
claude plugin uninstall clearmap
claude plugin marketplace remove vantage-io
```

## Contributors: local development copy

To test an unreleased local copy without the marketplace:

```bash
claude --plugin-dir /path/to/clearmap
```

`--plugin-dir` is for contributors testing a local checkout only; normal users install through the marketplace above.
