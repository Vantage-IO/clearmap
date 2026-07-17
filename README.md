# ClearMap

[![CI](https://github.com/vantage-io/clearmap/actions/workflows/ci.yml/badge.svg)](https://github.com/vantage-io/clearmap/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**ClearMap by Vantage IO** is a HIPAA-aware plugin for AI coding agents. It helps Claude Code and Codex build safer healthcare software, then audits a repository when you ask. Everything runs on your machine. It is a technical-risk signal, not a HIPAA compliance certification.

## Install in Claude Code

Run these two lines in a Claude Code session:

```
/plugin marketplace add Vantage-IO/clearmap
/plugin install clearmap@vantage-io
```

That's it. (You won't see ClearMap under `/plugin` until you add the marketplace with the first line.) Nothing else to configure: the AI-assisted review runs in Claude itself by default.

Then just build healthcare features normally, or audit a repo:

```
/clearmap:audit .
```

## Install in Codex

The simplest way, which works on any Codex version, installs the ClearMap skills into your project:

```bash
git clone https://github.com/Vantage-IO/clearmap
python3 clearmap/scripts/install_agent_skills.py --scope user --agent codex
```

Then in Codex: "Use $clearmap-audit to audit this repository." Full details and the native-plugin option: [docs/codex.md](docs/codex.md).

## What it does

**Builds safer healthcare code.** Ask for something ordinary ("Add symptoms and SSN to the patient record") and ClearMap still ships the feature, but questions whether the full SSN is needed, separates identity from clinical data, keeps PHI out of logs and prompts, and adds authentication and audit events.

**Audits a repository.** `/clearmap:audit .` runs the scanners, reviews the code, and prints the score inline:

```
ClearMap HIPAA Technical Risk Score: 68 (Assessment: Complete)
Findings: 2 critical, 4 high, 7 medium, 3 low
Reports: .clearmap/clearmap-report.md, .clearmap/clearmap-report.html
```

Findings map to HIPAA Security Rule technical safeguards (45 CFR 164.312) plus extensions (clinical AI/RAG, tracking, secrets, and application-security). See [docs/auditing.md](docs/auditing.md) for the report and how to generate it as HTML, Markdown, or JSON.

## The report

![Sample ClearMap report](docs/report-sample.png)

Generate it in any format from your agent: `/clearmap:report html | md | json | all`.

## What ClearMap does not replace

Not a HIPAA compliance certification, and a score does not mean a product is or is not HIPAA compliant. Not a full or formal HIPAA audit. It does not cover administrative (164.308) or physical (164.310) safeguards, BAAs, policy, or a full risk analysis, and does not replace a security review, a penetration test, or counsel.

## More

- [docs/codex.md](docs/codex.md): Codex install and use
- [docs/auditing.md](docs/auditing.md): the audit, the report, and generating it
- [docs/advanced.md](docs/advanced.md): local/remote model setup, standalone CLI, other agents
- [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
