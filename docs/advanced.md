# ClearMap advanced

Everything beyond the basic plugin install. Most users need none of this: the AI-assisted review runs in your coding agent by default, with no setup.

## Choosing where the AI review runs

`/clearmap:setup` (or `python3 scripts/setup.py`) lets you pick:

- **Host agent (default).** Your coding agent does the review. No API key, no network. Nothing to configure.
- **Local model.** Point at a local OpenAI-compatible server (Ollama at `http://127.0.0.1:11434/v1`, LM Studio at `http://127.0.0.1:1234/v1`). Nothing leaves your machine.
- **Remote model (OpenRouter and similar).** An explicit opt-in; the files under review are sent to the endpoint you set. ClearMap stores the endpoint, the model, and the name of the env var holding the key, never the key itself.

Under the default `local-only` privacy mode, only loopback endpoints are allowed; a remote endpoint is refused until you switch to `provider-managed`. Override anything with env vars: `CLEARMAP_REASONING_PROVIDER`, `CLEARMAP_MODEL_BASE_URL`, `CLEARMAP_MODEL_NAME`, `CLEARMAP_MODEL_API_KEY_ENV`, `CLEARMAP_PRIVACY_MODE`. Precedence: CLI flags > env > repo config > user config > defaults. Check readiness with `clearmap doctor .` and see effective config with `clearmap config show`.

## Standalone CLI (no agent)

ClearMap also runs as a plain scanner. Standalone mode runs the deterministic scan and reports; the AI-assisted review needs an agent or a configured model.

```bash
pip install -e .            # adds the `clearmap` command (Python 3.10+, stdlib only)

clearmap audit /path/to/repo               # scan + report + summary
clearmap scan  /path/to/repo --out .clearmap/findings.json
clearmap report .clearmap/findings.json --format all   # md + html + json
clearmap issues                            # open findings (exit 1 while critical/high remain)
clearmap suppressions                      # what the scan filtered, and why
clearmap export .clearmap/findings.json --format sarif  # or csv
clearmap doctor /path/to/repo
```

Engines: `semgrep` 1.164.x and `gitleaks` 8.30.x. Scan only changed files with `--diff`, or include git history for secrets with `--history`. Suppress a finding with a reason: `# clearmap:allow <rule-id> reason="..."`, or a line in `.clearmapignore`.

## Other coding agents (Agent Skills)

Any agent that supports the Agent Skills folder standard can use ClearMap. Install the two skills plus a self-contained engine into a skills directory:

```bash
python3 scripts/install_agent_skills.py --target /path/to/project --scope project
# or user-level:   --scope user
# or an explicit dir:   --dest ~/.some-agent/skills
```

It installs `clearmap-development`, `clearmap-audit`, and `clearmap-engine/` (scanner, rules, references) so the audit runs without a source checkout. `--uninstall` removes only those; `--dry-run` previews; `--force` overwrites.

| Environment        | Development | Audit | Native plugin | Agent Skills |
|--------------------|-------------|-------|---------------|--------------|
| Claude Code        | Yes         | Yes   | Yes           | Yes          |
| Codex              | Yes         | Yes   | Manifest built (verify locally) | Yes |
| Generic skills CLI | Yes         | Yes   | No            | Yes          |
| Plain terminal     | Deterministic scan + report only | | No | No |
