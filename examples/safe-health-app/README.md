# safe-health-app (ClearMap test fixture)

The clean counterpart to `vulnerable-health-app`. Same application: a clinical-
notes RAG assistant: implementing **every feature correctly**. This is the
**must-not-flag** set: a healthy run of ClearMap should report **zero findings**
here. `expected-findings.json` has `must_catch: []`.

It also carries a `near_misses` list: clean code that an over-broad rule could
wrongly flag. Those define the **false-positive budget**: ClearMap must stay
silent on them. (Regenerate the manifest with `../build_manifest.py`.)

## What each category looks like done right

| Code | Vulnerable pattern (other fixture) | Safe pattern here |
|------|-----|-----|
| `ACCESS` | Hardcoded creds, over-permissive delete, non-expiring tokens | `config.py` reads secrets from env; `_require_role` gates writes/deletes; `auth.py` issues short-lived, revocable tokens |
| `AUTH` | Unauthenticated PHI endpoints | every route carries `Depends(current_user)` |
| `AUDIT` | PHI access with no audit | `audit.record_event` on every read/create/update/delete, document read, and model call |
| `INTEGRITY` | Unauthenticated mutation, AI-as-fact, context overwrite | Authorized mutations; AI notes stored as `unverified` drafts; context appended/versioned, never overwritten |
| `TRANSIT` | `http://` + `ws://` for PHI, patient pushed to CRM | TLS everywhere (`https`/`wss`); CRM sync sends only an opaque `patient_ref` |
| `SESSION` | PHI in localStorage/sessionStorage/cookies/SDK | PHI stays in transient in-memory state; storage holds only non-PHI prefs + opaque tokens |
| `TRACKING` | Analytics + health fields on patient screens | Only non-PHI interaction signals; opaque ids; no health fields |
| `AI-RAG` | Raw PHI in prompts, no abstain, no citations, unbounded synthesis, injection | `redact.py` before prompts; abstain on weak retrieval; cited + confidence-scored answers; "answer only from sources"; external docs quoted as data; full model-call audit |
| `SECRETS` | Hardcoded EHR/model/signing keys | All secrets from the environment |

## Near-misses (must NOT be flagged)

Intentional traps for naive rules: see `expected-findings.json` `near_misses`
for exact lines. Each is tagged with the `relates_to` finding it could be
mistaken for:

- **`SESSION-01/02/03`**: `localStorage`/`sessionStorage`/`cookie` used for
  **non-PHI** values (theme, CSRF token, opaque session ref), including a
  `patientToken` parameter name that actually holds a CSRF token.
- **`SESSION-04` / `TRACKING-02`**: `analytics.identify` / `analytics.track`
  with **non-PHI** properties only.
- **`TRANSIT-01`**: a plain `http://localhost` **readiness probe** carrying no PHI.
- **`ACCESS-01` / `SECRETS-03`**: `DATABASE_URL = os.environ[...]` /
  `SECRET_KEY = os.environ[...]`: credential- and secret-shaped names that load
  from the environment, not literals.
