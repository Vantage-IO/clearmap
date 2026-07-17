# ClearMap categories

Each maps to a HIPAA Security Rule technical safeguard or a documented extension. Apply only those relevant to the task.

| Code | What it covers | Primary authority |
|---|---|---|
| `ACCESS` | Authorization, role checks, session termination, credential management | 45 CFR 164.312(a) |
| `AUTH` | Verifying who a caller is: authentication on PHI access | 164.312(d) |
| `AUDIT` | Recording activity on systems that hold or use ePHI (actor, action, resource, time) | 164.312(b) |
| `INTEGRITY` | Protecting ePHI from improper alteration; AI output kept unverified until reviewed | 164.312(c) |
| `TRANSIT` | Guarding ePHI in transit on every network path; encryption | 164.312(e) |
| `SESSION` | Client-side exposure: PHI in browser storage, cookies, or a client SDK | 164.312(a)(2)(iv) (extension) |
| `TRACKING` | Analytics/tracking on patient-facing surfaces carrying health context | HHS OCR online-tracking guidance (extension) |
| `AI-RAG` | Clinical AI/LLM/RAG reliability: redaction before prompts, abstain paths, citations, model-call audit, prompt-injection defense, bounded synthesis | ONC HTI-1 45 CFR 170.315(b)(11) (extension) |
| `SECRETS` | Credential/secret material in source | 164.312(a)(1) (extension) |
| `APPSEC` | Application-security weaknesses that can undermine a safeguard: SQL injection, command injection, SSRF, path traversal, unsafe deserialization, permissive CORS/debug | OWASP / CWE (security best practice) |

Authority types: a finding is grounded in a HIPAA requirement, a HIPAA addressable specification, OCR guidance, an ONC certification criterion, a security best practice, or a clinical safety practice. ClearMap uses these as an engineering target; counsel confirms any regulatory claim.
