# ClearMap standalone CLI

The recommended way to use ClearMap is as a plugin inside a coding agent (see the [README](../README.md)). This page documents running the engine directly, without an agent. Standalone mode runs the deterministic scanner and reports; agent-assisted development and the AI-assisted reasoning review require a compatible agent or a configured model provider.

## Run from the repository

```bash
# audit a repo (deterministic layer + report), automated-layer-only result
python3 scripts/scan.py /path/to/repo --out .clearmap/findings.json
python3 scripts/report.py .clearmap/findings.json --format both \
    --out .clearmap/clearmap-report.md

# orchestrated audit (scan -> reasoning-by-provider -> merge -> report -> summary)
python3 scripts/audit.py /path/to/repo

# open-findings list from the latest audit (exit 1 while critical/high remain)
python3 scripts/issues.py

# review what the scan filtered
python3 scripts/suppressions.py

# machine-readable exports (GitHub code scanning / GRC spreadsheets)
python3 scripts/export.py .clearmap/findings.json --format sarif --out clearmap.sarif
python3 scripts/export.py .clearmap/findings.json --format csv   --out clearmap.csv

# only changed + untracked files (both engines), or scan git history for secrets
python3 scripts/scan.py /path/to/repo --diff
python3 scripts/scan.py /path/to/repo --history

# check engines + provider config
python3 scripts/doctor.py /path/to/repo
```

## Install the console command

Core has zero runtime dependencies (Python 3.10+ standard library only).

```bash
pip install -e .            # dev/editable; adds the `clearmap` command
clearmap scan /path/to/repo --out .clearmap/findings.json
clearmap audit /path/to/repo
clearmap report .clearmap/findings.json --format both
clearmap issues
clearmap suppressions
```

Engines: `semgrep` 1.164.x and `gitleaks` 8.30.x (`clearmap doctor /path/to/repo` checks them). Optional deep PHI-literal pass: `pip install "clearmap[presidio]"` then `scan.py --presidio`.

Suppressions: `.clearmapignore` (`glob [rule-id] reason="..." expires="YYYY-MM-DD"` per line) or inline `# clearmap:allow <rule-id> reason="..."`. A wildcard `clearmap:allow *` requires a reason.

## AI-assisted review in standalone mode

The reasoning layer needs a model. Configure a provider once:

```bash
python3 scripts/setup.py            # host-agent (default), local, or remote
python3 scripts/audit.py /path/to/repo --provider openai-compatible
```

See [first-run.md](first-run.md). Without a provider or an agent, `audit` produces an explicit automated-layer-only result, never a clean bill of health.
