# Security Policy

## Reporting a vulnerability

Email **smorhaim@vantageio.com** with a description and reproduction steps.
Please do not open a public issue for security reports. You will get an
acknowledgment within 3 business days.

## What ClearMap does with your code and data

- **Local-first, no telemetry.** The deterministic scanner, scoring, and report
  rendering run entirely on your machine and make no network calls; ClearMap
  sends no telemetry ever. The HTML report fetches no external resources; the
  only links in it are plain anchors to official regulatory sources (ecfr.gov,
  hhs.gov, federalregister.gov, law.cornell.edu) and they are inert until clicked.
- **AI-assisted review is pluggable, local by default.** By default the review
  runs in your coding agent (host-agent): ClearMap makes no extra network call.
  You may optionally configure an OpenAI-compatible provider. Under the default
  `local-only` privacy mode only a loopback endpoint (a local model such as
  Ollama or LM Studio) is allowed, and a non-loopback endpoint is refused before
  any request. A remote provider (OpenRouter and similar) requires the explicit
  `provider-managed` mode; when configured, the files under review are sent to
  the endpoint you set, and only to it. ClearMap never sends its own fixtures,
  and never stores your API key (only the name of the env var that holds it).
- **Read-only on the target.** The scanner never writes into the scanned
  repository except the `.clearmap/` output directory you ask for. Engine
  temp files go to the system temp dir and are removed.
- **No shell interpolation.** External engines (Semgrep, Gitleaks) are
  invoked with argument lists, never through a shell.

## Redaction guarantees and limits

Every code snippet is passed through `scripts/redact.py` before it can reach
`findings.json` or any report, and again as a safety net at merge time.

Covered by the default (stdlib, zero-dependency) redactor: API keys and
secret-looking assignments, credentials in connection strings, SSNs, MRNs,
email addresses, US phone numbers, street addresses, US and ISO dates, and
values assigned to name/DOB/address-keyed fields.

**Limits, stated plainly:** the default redactor is pattern-based. It cannot
recognize a bare person name in free text (for example a name inside a
comment with no field label). For that class of detection, run the opt-in
Presidio pass (`scan.py --presidio`, requires `pip install
"clearmap[presidio]"`). An end-to-end canary test
(`tests/test_phi_leak_e2e.py`) asserts that no seeded PHI-like literal
survives into findings or any report format.

## Scope reminder

ClearMap is a technical risk signal for the HIPAA Security Rule technical
safeguards (45 CFR 164.312) plus AI/LLM/RAG clinical risk. It is not a
compliance certification and does not replace a security review, a
penetration test, or counsel.
