# Contributing to ClearMap

Thanks for helping make healthcare software safer. A few ground rules keep
ClearMap trustworthy.

## Dev setup

```bash
# engines (the versions ClearMap is calibrated against)
pip install semgrep==1.164.0
brew install gitleaks        # or the 8.30.x release binary

# optional: editable install for the `clearmap` CLI + dev tools
pip install -e ".[dev]"

# run everything
python3 -m unittest discover -s tests -v
pipx run ruff check scripts tests
```

Core code is **Python 3.10+ standard library only**. No runtime pip
dependencies; local-first is a product guarantee, not a preference. Optional
integrations (Presidio) live behind extras and degrade gracefully when absent.

## Non-negotiables

1. **Determinism.** `scan.py` output is byte-stable for the same input and
   engine versions. Nothing time-, locale-, or order-dependent may enter
   `findings.json`.
2. **Redaction.** No raw PHI-like value or secret may reach findings or
   reports. If you touch snippet handling, extend `tests/test_phi_leak_e2e.py`
   canaries too.
3. **No compliance claims.** Report copy must pass the banned-phrase guard
   (`report.check_banned`). ClearMap never says anything "is HIPAA compliant".
4. **No em or en dashes** in any user-facing output copy.
5. **Never hand-edit `expected-findings.json`.** Both fixture manifests are
   generated: change `examples/build_manifest.py` and re-run it. CI fails if
   the committed manifests drift from the generator.

## Changing report content

`report.build_model()` makes every content decision once; `render_md()` and
`report_html.render_html()` are mechanical emitters. Put content changes in
the model, not the emitters.

The golden fixtures pin the rendered output byte-for-byte. When you change
content intentionally:

```bash
python3 scripts/report.py tests/fixtures/golden/findings.json \
    --repo golden-fixture --date 2026-01-01 --format both \
    --out tests/fixtures/golden/report.md
```

Regenerate in a **separate, code-free commit** and review that diff line by
line; the diff is the design review. The byte-independent invariant tests in
`tests/test_report.py` (no rule slugs as headings, citations joined, no
jargon, guard passes) must stay green without edits.

## Adding rules

- Deterministic rules live in `rules/*.yaml` (Semgrep) and
  `rules/gitleaks.toml`. Every rule needs `clearmap_title`, category,
  severity, and a `hipaa_ref` that resolves in
  `references/regulatory-baseline.json`.
- Seed exactly one instance in `examples/vulnerable-health-app`, add the
  entry to `build_manifest.py`, and add a must-not-flag counterpart to
  `examples/safe-health-app` if the rule has a plausible false-positive class.
- Calibration gates in CI: deterministic recall and precision on the fixtures
  must not regress (see `.github/workflows/ci.yml`).

## Reasoning checks

The AI-assisted checks live in `references/clinical-checks.md` and
`references/audit-checks.md`. Each check needs hit criteria, negative
criteria, a reviewer question, and remediation. Checks must be evaluable from
code alone.
