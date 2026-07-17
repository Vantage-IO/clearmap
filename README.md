# ClearMap

[![CI](https://github.com/vantage-io/clearmap/actions/workflows/ci.yml/badge.svg)](https://github.com/vantage-io/clearmap/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**ClearMap by Vantage IO** is a HIPAA-aware development and technical-risk plugin for AI coding agents. It helps Claude Code, Codex, and compatible coding agents make safer decisions while building healthcare software, then audits the repository when you ask. Everything runs on your machine.

ClearMap is a *technical risk signal*, not a HIPAA compliance certification. Finding no issues never means a product is HIPAA compliant.

## What ClearMap does

### 1. Build safer healthcare software

While your agent plans and writes healthcare code, ClearMap steers the design. Ask for something ordinary:

```
Add symptoms and SSN to the patient record.
```

ClearMap keeps you productive and ships the feature, but it:

- questions whether the full SSN is actually necessary, and prefers a token or last-four when it is not,
- separates identity data from clinical observations and isolates it behind stricter access,
- keeps raw PHI out of logs, analytics, URLs, browser storage, prompts, and tests,
- adds authentication, authorization, and audit events, and
- generates the models, migration, and tests.

### 2. Audit the repository

```
/clearmap:audit .
```

```
ClearMap audit complete.

ClearMap HIPAA Technical Risk Score: 68 (Assessment: Complete)
Findings: 2 critical, 4 high, 7 medium, 3 low

Top issues:
1. Patient endpoint permits access without a resource-level authorization check.
2. Raw patient content is included in an external LLM request.
3. Audit events omit the acting user.

Reports: .clearmap/clearmap-report.md, .clearmap/clearmap-report.html
```

## Install in Claude Code

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

See [docs/claude-code.md](docs/claude-code.md) for details.

## Use it during normal development

```
/clearmap:plan Add AI-assisted patient-note summarization
/clearmap:develop Implement the approved design
/clearmap:audit .
/clearmap:issues
```

You can also just make ordinary requests. ClearMap can activate when the task clearly involves healthcare or PHI (patient data, symptoms, diagnoses, medications, labs, records, clinical AI/RAG, healthcare APIs, or auth/audit/storage of health data). It will not activate for generic, non-healthcare work. More workflows in [docs/normal-development.md](docs/normal-development.md).

## Install in Codex

ClearMap ships a Codex plugin manifest and marketplace, plus portable Agent Skills. Add the marketplace and enable ClearMap through your Codex version's supported flow (see [docs/codex.md](docs/codex.md)), then:

```
Use $clearmap-development to implement this patient workflow.
Use $clearmap-audit to audit this repository.
```

## Other coding agents

Any agent that supports the Agent Skills folder standard can use ClearMap. See [docs/other-agents.md](docs/other-agents.md) and the compatibility matrix.

## What ClearMap reviews

Findings are grouped into categories, each mapped to a HIPAA Security Rule technical safeguard (45 CFR 164.312) or a documented extension: `ACCESS` `AUTH` `AUDIT` `INTEGRITY` `TRANSIT` `SESSION` `TRACKING` `AI-RAG` `SECRETS` `APPSEC`. Two layers produce them: a deterministic scan (Semgrep rules + Gitleaks, byte-stable output) and an AI-assisted review of the clinical-AI and audit checks that pattern matching cannot judge. Every citation resolves against a versioned [regulatory baseline](references/regulatory-baseline.json), and no raw PHI-like value ever appears in output.

## What ClearMap does not replace

- **Not** a legal HIPAA compliance certification, and a score does not mean a product is or is not HIPAA compliant.
- **Not** a full or formal HIPAA audit or risk assessment.
- It does **not** cover administrative (164.308) or physical (164.310) safeguards, BAAs, organizational policy, or a full risk analysis, and does **not** replace a security review, a penetration test, or counsel.

## Reports and exports

Audit outputs go to `.clearmap/` in the target repo (gitignored, fixed filenames): `clearmap-report.md` and `.html`. Machine-readable exports (SARIF for GitHub code scanning, CSV for GRC) are available via `clearmap export`.

## Additional documentation

- [docs/claude-code.md](docs/claude-code.md), [docs/codex.md](docs/codex.md), [docs/other-agents.md](docs/other-agents.md)
- [docs/normal-development.md](docs/normal-development.md), [docs/auditing.md](docs/auditing.md), [docs/first-run.md](docs/first-run.md)
- [docs/standalone-cli.md](docs/standalone-cli.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

Need to run ClearMap without an agent? See [docs/standalone-cli.md](docs/standalone-cli.md). Standalone mode runs the deterministic scanner and reports, but agent-assisted development and the reasoning review require a compatible agent or a configured model provider.
