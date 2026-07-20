# ClearMap HIPAA Risk Report: golden-fixture

**Generated:** 2026-01-01 · **ClearMap:** v0.4.0 · **Regulatory baseline:** 2026.1 (as of 2026-06-01)

> **Technical risk signal, not a certification.** This report is not a HIPAA compliance certification and does not mean the product is or is not HIPAA compliant.

## 1. Executive summary

**ClearMap HIPAA Technical Risk Score: 51/100.** Elevated technical risk: multiple significant gaps.

*Technical code-risk signal only. Not a compliance score, certification, formal HIPAA risk analysis, or legal determination.*

| Critical | High | Medium | Low |
|----------|------|--------|-----|
| 3 | 2 | 1 | 1 |

7 findings across 8 of 10 applicable safeguard categories: 4 confirmed by automated rules and 3 identified by AI-assisted review (pending engineer verification). 3 likely false positives were suppressed automatically.

**Top findings**

1. **Database connection string with embedded credentials** (Critical) · `backend/config.py:9`
2. **Unredacted PHI interpolated into LLM prompt** (Critical) · `backend/rag/assistant.py:24`
3. **Unguarded PHI read endpoint (no authentication)** (Critical) · `backend/api/patients.py:13`

**Suggested next steps**

- Remediate the 3 critical findings first. The worst finding caps the overall score.
- Have an engineer verify the 3 findings identified by AI-assisted review.
- Re-run ClearMap after remediation to confirm the score improves.

## 2. Scope and method

**Scanned:** golden-fixture. 8 of 10 safeguard categories apply to this codebase; categories with no matching surface are excluded from scoring rather than scored 100.

**Automated pattern analysis:** curated ClearMap rules executed by Semgrep 1.164.0 and Gitleaks 8.30.1. These findings are reproducible from run to run and appear below as Confirmed.

**AI-assisted code review:** an AI agent reviewed the code against ClearMap's clinical and audit checklists, covering risks that pattern matching cannot judge. Any issues it raised appear below as Needs verification and should be confirmed by an engineer.

**Suppressed:** 3 findings filtered as known false-positive classes (vendored paths, publishable tokens, i18n keys, templated placeholders) or by explicit allow rules.

The automated scan ran locally. An AI-assisted review was included; the reviewed code was processed by whichever agent or model provider ran it.

**Assessment coverage:** automated scan complete; AI-assisted review complete. Regulatory baseline 2026.1. Authority basis cited: hipaa-required, onc-certification-criterion.

## 3. HIPAA Risk Score

**51/100.** Elevated technical risk: multiple significant gaps.

*The score is capped at 51/100 (3 critical findings). The worst finding sets the cap, and critical findings compound with diminishing returns. ClearMap checks technical safeguards only and never reports a perfect score. Appendix A explains how the score is built.*

## 4. Category scorecard

| Category | Score | Findings | Weight | Applies? |
|----------|-------|----------|--------|----------|
| AI-RAG: AI / LLM / RAG | 67 | 2 to verify | 0.27 | yes |
| AUDIT: Audit Controls | 85 | 1 to verify | 0.21 | yes |
| ACCESS: Access Control | 75 | 1 confirmed | 0.11 | yes |
| TRANSIT: Transmission Security | 85 | 1 confirmed | 0.11 | yes |
| APPSEC: Application Security | 100 | 0 | 0.11 | yes |
| INTEGRITY: Integrity | 100 | 0 | 0.09 | yes |
| AUTH: Authentication | 75 | 1 confirmed | 0.05 | yes |
| SECRETS: Secrets / Config | 97 | 1 confirmed | 0.05 | yes |
| TRACKING: Tracking / Analytics | N/A | | | not detected |
| SESSION: Frontend / Session | N/A | | | not detected |

*N/A means that category's surface (for example frontend or AI/LLM) was not detected in this codebase; it is excluded from the score, not scored 100. Weights are renormalized across the categories that apply.*

## 5. Findings

| Severity | Finding | Location | Citation | Status |
|----------|---------|----------|----------|--------|
| Critical | Database connection string with embedded credentials | `backend/config.py:9` | 164.312(a)(2)(i) | Confirmed |
| Critical | Unredacted PHI interpolated into LLM prompt | `backend/rag/assistant.py:24` | HTI-1 (b)(11) | Needs verification |
| Critical | Unguarded PHI read endpoint (no authentication) | `backend/api/patients.py:13` | 164.312(d) | Confirmed |
| High | PHI create without audit event | `backend/api/patients.py:30` | 164.312(b) | Needs verification |
| High | PHI transmitted over cleartext to an external host | `backend/integrations.py:15` | 164.312(e)(1) | Confirmed |
| Medium | No abstain path on weak retrieval | `backend/rag/assistant.py:41` |  | Needs verification |
| Low | JWT (test-fixture path: verify it is not a real credential) | `tests/test_auth.py:9` | 164.312(a)(1) | Confirmed |

## 6. Priority findings: critical and high

*AI/LLM/RAG findings are detailed separately in section 7.*

#### Database connection string with embedded credentials (Critical)
- **Location:** `backend/config.py:9`
- **Regulation:** 45 CFR 164.312(a)(2)(i): Unique user identification (HIPAA Security Rule requirement)
- **Evidence (redacted):** `DATABASE_URL = "postgresql://admin:[REDACTED]@db.internal:5432/patients"`
- **Why it matters:** DB credentials are committed in source.
- **Reviewer question:** Are PHI actions restricted to permitted roles, and sessions revocable?
- **Remediation:** Load credentials from a secret manager; rotate the password.
- **Verification:** Confirmed by automated rule
- **Reference:** clearmap-db-uri-credentials (gitleaks rule)

#### Unguarded PHI read endpoint (no authentication) (Critical)
- **Location:** `backend/api/patients.py:13`
- **Regulation:** 45 CFR 164.312(d): Person or entity authentication (HIPAA Security Rule requirement)
- **Evidence (redacted):** `@router.get("/patients/{patient_id}")`
- **Why it matters:** No authentication dependency on a PHI route.
- **Reviewer question:** Is every PHI access authenticated?
- **Remediation:** Require an authenticated principal on every PHI route.
- **Verification:** Confirmed by automated rule
- **Reference:** access-fastapi-unauthenticated-phi-read (semgrep rule)

#### PHI create without audit event (High)
- **Location:** `backend/api/patients.py:30`
- **Regulation:** 45 CFR 164.312(b): Audit controls (HIPAA Security Rule requirement)
- **Evidence (redacted):** `_PATIENTS[patient["id"]] = patient`
- **Why it matters:** A new patient record is written with no audit event.
- **Reviewer question:** Is every PHI write recorded with actor + action + resource?
- **Remediation:** Emit an audit event on every PHI create/read/update/delete.
- **Verification:** Identified by AI-assisted review, requires human verification (high confidence)
- **Reference:** AUDIT-01

#### PHI transmitted over cleartext to an external host (High)
- **Location:** `backend/integrations.py:15`
- **Regulation:** 45 CFR 164.312(e)(1): Transmission security (HIPAA Security Rule requirement)
- **Evidence (redacted):** `resp = requests.get(f"http://labs.partner-network.example/...")`
- **Why it matters:** PHI travels over plain http to an external host.
- **Reviewer question:** Is all PHI encrypted in transit on every external path?
- **Remediation:** Use https/TLS for every PHI transmission.
- **Verification:** Confirmed by automated rule
- **Reference:** transit-external-cleartext-url (semgrep rule)

## 7. AI / LLM / RAG findings

#### Unredacted PHI interpolated into LLM prompt (Critical)
- **Location:** `backend/rag/assistant.py:24`
- **Regulation:** 45 CFR 170.315(b)(11) (ONC HTI-1): Decision support intervention transparency (ONC certification criterion)
- **Evidence (redacted):** `prompt = f"Patient {name} ({mrn}): {note}"`
- **Why it matters:** Raw identifiers flow into the model prompt without redaction.
- **Reviewer question:** Is PHI redacted before prompts, output cited + bounded to sources, and model calls audited?
- **Remediation:** Redact/tokenize PHI before prompt construction.
- **Verification:** Identified by AI-assisted review, requires human verification (high confidence)
- **Reference:** AI-RAG-01

#### No abstain path on weak retrieval (Medium)
- **Location:** `backend/rag/assistant.py:41`
- **Evidence (redacted):** `answer = llm_client.complete(prompt)`
- **Why it matters:** The assistant answers even when retrieval is empty.
- **Reviewer question:** Is PHI redacted before prompts, output cited + bounded to sources, and model calls audited?
- **Remediation:** Abstain or surface low confidence on weak retrieval.
- **Verification:** Identified by AI-assisted review, requires human verification (medium confidence)
- **Reference:** AI-RAG-02

## 8. What an enterprise reviewer will ask

- **ACCESS:** Are PHI actions restricted to permitted roles, and sessions revocable?
- **AI-RAG:** Is PHI redacted before prompts, output cited + bounded to sources, and model calls audited?
- **AUDIT:** Is every PHI access and model call recorded to an audit trail?
- **AUTH:** Is every PHI access authenticated?
- **SECRETS:** Are all credentials loaded from a secret manager rather than source?
- **TRANSIT:** Is all PHI encrypted in transit on every external path?

## 9. Regulatory citations referenced

Findings in this report map to the following requirements (regulatory baseline 2026.1).

| Citation | Requirement | Status | Source |
|----------|-------------|--------|--------|
| 45 CFR 164.312(a)(2)(i) | Unique user identification | HIPAA Security Rule requirement | https://www.ecfr.gov/current/title-45/section-164.312 |
| 45 CFR 170.315(b)(11) (ONC HTI-1) | Decision support intervention transparency | ONC certification criterion | https://www.federalregister.gov/documents/2024/01/09/2023-28857/health-data-technology-and-interoperability-certification-program-updates-algorithm-transparency-and |
| 45 CFR 164.312(d) | Person or entity authentication | HIPAA Security Rule requirement | https://www.ecfr.gov/current/title-45/section-164.312 |
| 45 CFR 164.312(b) | Audit controls | HIPAA Security Rule requirement | https://www.ecfr.gov/current/title-45/section-164.312 |
| 45 CFR 164.312(e)(1) | Transmission security | HIPAA Security Rule requirement | https://www.ecfr.gov/current/title-45/section-164.312 |
| 45 CFR 164.312(a)(1) | Access control | HIPAA Security Rule requirement | https://www.ecfr.gov/current/title-45/section-164.312 |

- Although encryption is an Addressable spec ((e)(2)(ii) in transit, (a)(2)(iv) at rest), the parent standard 164.312(e)(1) Transmission Security is Required. For ePHI over open/public networks there is no reasonable equivalent to encryption, and OCR treats unencrypted transmission over open networks as a violation. ClearMap therefore treats encryption-in-transit as REQUIRED and anchors TRANSIT findings to the Required standard 164.312(e)(1).
- A certification criterion for developers of ONC-certified health IT (Decision Support Interventions), not a universal HIPAA requirement for every healthcare application. ClearMap uses it as the engineering authority for clinical AI/LLM reliability and transparency; whether it legally applies to a given product depends on whether that product is, or integrates, certified health IT. Counsel confirms.

## Appendix A: How the score is built

- **Findings mix:** 4 confirmed by automated rules + 3 identified by AI-assisted review (marked Needs verification).
- **Rule-confirmed composite:** 94/100, computed from automated-rule findings only (reproducible: same input, same number).
- **With AI-assisted findings included:** 82/100 before the severity cap.
- **Severity cap:** 51/100 (3 critical findings). The reported score is the lower of the two.
- **Method:** each category starts at 100 and loses points per finding by severity. The overall score is a weighted composite across the categories that apply (categories that do not apply are excluded, not scored 100), then capped by the worst severity present: one critical finding caps the score at 75, and additional criticals lower the cap further with diminishing returns toward a floor of 40. ClearMap never reports a perfect score because it checks technical safeguards only.

## Appendix B: About this report

ClearMap is a **technical risk signal, not a legal HIPAA compliance certification.**
A ClearMap score does not mean a product is or is not HIPAA compliant. ClearMap
does not cover administrative safeguards (45 CFR 164.308), physical safeguards
(164.310), BAAs, organizational policy, or a full risk analysis, and does not
replace a security review, a penetration test, or counsel. Regulatory citations
are an engineering target; counsel must confirm them.

---

*Prepared with ClearMap, an open-source HIPAA technical-risk scanner by Vantage IO. This is a partial, automated technical review, not a full audit. A complete reliability assessment goes further: deeper and broader detection coverage, expert verification of every finding, and review of the safeguards no automated tool can see. For that deeper look, visit vantageio.com.*

