# vulnerable-health-app (ClearMap test fixture)

A deliberately insecure synthetic application: a small **clinical-notes RAG
assistant** for a specialty practice. It is *not* runnable production code: it
is the **must-catch corpus** for ClearMap. Each canonical finding ID from the
rule/check catalog is seeded **exactly once**, on a known line, so the
deterministic and reasoning layers can be measured for precision and recall.

> ⚠️ Every credential, key, and endpoint here is fake and intentionally unsafe.
> Do not copy any pattern in this directory into real code.

## How this fixture is used

- `expected-findings.json` is the machine-readable **MUST-CATCH** manifest: the
  contract the rules and reasoning checks must satisfy. It is generated and
  integrity-checked by `../build_manifest.py` (every ID resolves to exactly one
  unique line; regenerate after any edit).
- Finding IDs use **descriptive category codes**; the regulatory citation lives in
  a separate `hipaa_ref` field (so IDs stay stable as the regulation evolves).
  Full mapping in [`../../references/regulatory-map.md`](../../references/regulatory-map.md).
- `source` says which layer must catch it: `deterministic` =
  Semgrep/Gitleaks rules; `reasoning` = host-agent checks.
- The companion `safe-health-app/` is the **must-not-flag** set (same features,
  done right) used to measure the false-positive budget.

## Categories

| Code | Name | Regulatory anchor |
|------|------|-------------------|
| `ACCESS` | Access Control | 45 CFR 164.312(a) |
| `AUTH` | Person/Entity Authentication | 45 CFR 164.312(d) |
| `AUDIT` | Audit Controls | 45 CFR 164.312(b) |
| `INTEGRITY` | Integrity | 45 CFR 164.312(c) |
| `TRANSIT` | Transmission Security | 45 CFR 164.312(e) |
| `SESSION` | Frontend / Session Exposure | 164.312(a)(2)(iv) *(extension)* |
| `TRACKING` | Tracking / Analytics | HHS OCR online-tracking guidance *(extension)* |
| `AI-RAG` | AI / LLM / RAG Risk | ONC HTI-1 170.315(b)(11) *(extension)* |
| `SECRETS` | Secrets / Config | 164.312(a)(1) *(extension)* |

## Seeded findings (one per canonical id)

| ID | Severity | Source | HIPAA ref | Where | What |
|----|----------|--------|-----------|-------|------|
| `ACCESS-01` | critical | deterministic | 164.312(a)(2)(i) | `backend/config.py` | Hardcoded DB credentials |
| `ACCESS-02` | high | deterministic | 164.312(a)(1) | `backend/api/patients.py` | Delete endpoint with no role check |
| `ACCESS-03` | medium | deterministic | 164.312(a)(2)(iii) | `backend/auth.py` | Non-expiring token / no automatic logoff |
| `AUTH-01` | critical | deterministic | 164.312(d) | `backend/api/patients.py` | Unguarded PHI GET endpoint (no authentication) |
| `AUDIT-01` | high | reasoning | 164.312(b) | `backend/api/patients.py` | Patient create with no audit event |
| `AUDIT-02` | medium | reasoning | 164.312(b) | `backend/llm_client.py` | LLM call with no logging |
| `AUDIT-03` | medium | reasoning | 164.312(b) | `backend/storage.py` | PHI document read with no audit |
| `AUDIT-04` | medium | reasoning | 164.312(b) | `backend/records.py` | AI summary stored without source provenance |
| `INTEGRITY-01` | critical | reasoning | 164.312(c)(1) | `backend/api/patients.py` | Unauthenticated patient mutation (PATCH) |
| `INTEGRITY-02` | high | reasoning | 164.312(c)(2) | `backend/records.py` | AI output stored without review state |
| `INTEGRITY-03` | medium | reasoning | 164.312(c)(2) | `backend/records.py` | Source-context overwrite destroys evidence |
| `TRANSIT-01` | critical | deterministic | 164.312(e)(1) | `backend/integrations.py` | PHI over cleartext `http://` |
| `TRANSIT-02` | high | deterministic | 164.312(e)(1) | `frontend/src/vitals.ts` | PHI streamed over insecure `ws://` |
| `TRANSIT-03` | critical | deterministic | 164.312(e)(1) | `backend/integrations.py` | Full patient object pushed to third-party CRM |
| `TRANSIT-04` | low | deterministic | 164.312(e)(1) | `backend/integrations.py` | Internal cleartext PHI (advisory, not hard) |
| `SESSION-01` | high | deterministic | 164.312(a)(2)(iv) | `frontend/src/storage.ts` | PHI in localStorage |
| `SESSION-02` | high | deterministic | 164.312(a)(2)(iv) | `frontend/src/storage.ts` | PHI in sessionStorage |
| `SESSION-03` | medium | deterministic | 164.312(a)(2)(iv) | `frontend/src/storage.ts` | MRN in JS-readable cookie |
| `SESSION-04` | critical | deterministic | 164.312(a)(2)(iv) | `frontend/src/analytics.ts` | Patient state passed to third-party SDK |
| `TRACKING-01` | high | deterministic | OCR guidance | `frontend/src/PatientView.tsx` | Analytics pageview in authed patient view |
| `TRACKING-02` | high | deterministic | OCR guidance | `frontend/src/analytics.ts` | Diagnosis sent as analytics event property |
| `TRACKING-03` | medium | deterministic | OCR guidance | `frontend/src/PatientView.tsx` | Health context in URL query param |
| `AI-RAG-01` | critical | reasoning | HTI-1 | `backend/rag/assistant.py` | Unredacted PHI in LLM prompt |
| `AI-RAG-02` | high | reasoning | HTI-1 | `backend/rag/assistant.py` | No abstain/fallback on weak retrieval |
| `AI-RAG-03` | high | reasoning | HTI-1 | `backend/api/assistant.py` | No source traceability in response |
| `AI-RAG-04` | high | reasoning | HTI-1 | `backend/rag/assistant.py` | No model-call audit |
| `AI-RAG-05` | high | reasoning | HTI-1 | `backend/records.py` | AI output written to record as fact |
| `AI-RAG-06` | critical | reasoning | HTI-1 | `backend/rag/assistant.py` | Prompt injection of untrusted clinical text |
| `AI-RAG-07` | medium | reasoning | HTI-1 | `backend/rag/retriever.py` | Weak retrieval evidence handling |
| `AI-RAG-08` | medium | reasoning | HTI-1 | `backend/rag/assistant.py` | No bounded synthesis |
| `SECRETS-01` | critical | deterministic | 164.312(a)(1) | `backend/config.py` | Hardcoded EHR/FHIR API key |
| `SECRETS-02` | critical | deterministic | 164.312(a)(1) | `backend/config.py` | Hardcoded model-provider API key |
| `SECRETS-03` | high | deterministic | 164.312(a)(1) | `backend/config.py` | Hardcoded signing secret |

**33 findings** across 9 categories. Exact line numbers + structural snippets +
`hipaa_ref` live in `expected-findings.json` (regenerated from source, never
hand-edited).

## Transmission: external vs internal (the `TRANSIT` rule must severity-split)

§164.312(e)(1) (Required) covers ePHI on **any** network path. But "Addressable"
encryption (§164.306(d)(3)) gives flexibility *inside a trusted boundary*, so a
blanket "any `http://` = critical" rule would false-positive on normal backends.
The corpus therefore seeds **all three** cases to prove the rule
classifies the host and splits severity correctly:

| Case | Example | Expected |
|------|---------|----------|
| **External / open network** + PHI | `TRANSIT-01` http → lab partner; `TRANSIT-03` → CRM; `TRANSIT-02` `ws://` | **hard** (critical/high) |
| **Internal** (trusted boundary) + PHI | `TRANSIT-04` http → `*.svc.cluster.local` | **low / advisory** |
| **Internal** + no PHI | safe fixture near-miss: `http://localhost` readiness probe | **silent** |

Host is classified internal via `localhost`, RFC-1918 (`10./172.16-31./192.168.`),
`*.internal`, `*.svc.cluster.local`. Internal cleartext PHI is acceptable where
documented + backed by compensating controls (segmentation, access control);
zero-trust best practice is to encrypt internal hops too. Encryption is currently
*Addressable* but the Dec-2024 NPRM would make it **Required**: ClearMap already
treats encryption-in-transit as required for external paths.

## Notes on overlapping pairs

A few IDs are intentionally close: distinct *lenses* on related risk, which is
why the catalog lists them separately. The fixture keeps them on separate lines
so each can be scored independently:

- **AUDIT-02 vs AI-RAG-04**: AUDIT-02 is "the model call has no logging hook
  anywhere" (`llm_client.py`); AI-RAG-04 is "the RAG orchestrator never feeds the
  audit trail with inputs/outputs/sources/user" (`rag/assistant.py`).
- **AUDIT-04 vs AI-RAG-03**: AUDIT-04 is "no *stored* provenance linking a saved
  answer to its sources" (audit/forensics, `records.py`); AI-RAG-03 is "no
  citations in the *API response* returned to the clinician" (`api/assistant.py`).
- **INTEGRITY-02 vs AI-RAG-05**: INTEGRITY-02 is the integrity lens (record
  stored with no review/confidence state); AI-RAG-05 is the AI-risk lens
  (generated text persisted and treated as fact).
- **AUTH-01 vs INTEGRITY-01**: AUTH-01 is a *read* with no authentication (who
  are you); INTEGRITY-01 is a *write* with no authentication (improper alteration
  of ePHI). Different safeguards: 164.312(d) vs 164.312(c)(1).
