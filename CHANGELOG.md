# Changelog

All notable changes to ClearMap are documented here. The format is based on
Keep a Changelog, and ClearMap follows semantic versioning.

## [0.3.0] (unreleased)

Plugin-first release: ClearMap becomes an installable agent-native plugin
(Claude Code, Codex, and Agent Skills) on top of a hardened engine.

### Added: agent plugin
- Installable Claude Code plugin + `vantage-io` marketplace (`clearmap@vantage-io`),
  validated with `claude plugin validate --strict`. Codex plugin manifest +
  `.agents` marketplace, and a self-contained Agent Skills installer for other
  agents (`scripts/install_agent_skills.py`).
- Two canonical skills: `clearmap-development` (HIPAA-aware healthcare
  development) and `clearmap-audit` (agent-executable audit with an inline score
  summary). Commands `setup`, `plan`, `develop`, `audit`, `issues`; a small
  SessionStart routing hook; a plugin-root resolver and `bin/clearmap` launcher.
- Configurable AI-assisted reasoning providers: host agent (default, no key/no
  network), an OpenAI-compatible endpoint (local model or remote such as
  OpenRouter, loopback-enforced under `local-only`), or manual reasoning JSON.

### Added: engine hardening
- Canonical taxonomy registry (`references/taxonomy.json`) as the single source
  of truth for every finding id.
- Fail-closed scanning with per-engine status; a missing/errored/timed-out/
  malformed required engine now yields a non-zero exit and an unusable output.
- APPSEC security-rule family (SQL injection, command injection, SSRF, path
  traversal, unsafe deserialization, permissive CORS/debug).
- Per-citation authority classification, an auditable suppression ledger and a
  `clearmap suppressions` command, `--history` secret scanning, and corrected
  `--diff` across both engines (gitleaks migrated to `dir`/`git`).
- CI hardening: least-privilege permissions, concurrency, checksum-verified
  engine install, rule validation, and a wheel build + install smoke job.

### Changed
- The reported score distinguishes a complete assessment, an automated-layer-only
  assessment, and an unavailable score (required-engine failure). Display label
  is "ClearMap HIPAA Technical Risk Score".
- Reasoning findings are validated against the registry and redacted more
  strictly (including titles and file paths), and require provider provenance and
  a completion manifest before an assessment counts as complete.
- README is plugin-first; standalone scanner usage moves to `docs/standalone-cli.md`.
  SECURITY.md documents the pluggable, local-by-default provider model.

## [0.1.0]

- Initial public release.
