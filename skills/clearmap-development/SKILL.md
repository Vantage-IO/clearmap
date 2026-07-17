---
name: clearmap-development
description: HIPAA-aware healthcare software development. Use this while planning, writing, reviewing, or modifying code that touches protected health information (PHI), patient data, symptoms, diagnoses, medications, lab results, medical records, SSNs or identity data in a healthcare context, insurance or eligibility data, clinical workflows, healthcare APIs, patient portals, healthcare analytics, LLM prompts containing health data, clinical AI, RAG over medical or patient information, medical-document processing, audit logging for health data, or the authentication, authorization, storage, transmission, logging, or deletion of health information. It makes the generated design safer (minimum-necessary data, access control, audit events, no PHI in logs or prompts) and still ships the feature. Do NOT load it for generic non-healthcare development. ClearMap is a technical-risk signal, not a HIPAA certification.
---

# ClearMap: healthcare-aware development

You are helping build healthcare software. Stay a normal, productive engineer: implement the feature. But bias every decision toward a design that protects patient data, and quietly fix the unsafe parts of a request rather than shipping them verbatim. ClearMap is a technical-risk signal, not a compliance certification, and finding no issues never means the result is HIPAA compliant.

## How to work

For any task touching health data, reason through this before and while you write code:

1. Understand what the feature is actually for.
2. Identify the sensitive data involved (PHI, identity, credentials, clinical conclusions).
3. For each field, ask whether it is genuinely necessary. Apply the minimum-necessary principle: do not collect or store a field just because it was asked for.
4. Identify trust boundaries and any third-party services that will receive the data.
5. Inspect the existing architecture first; prefer the project's established secure abstractions (auth dependency, audit helper, redaction util, storage gateway) over inventing a new pattern.
6. Keep raw PHI and credentials out of logs, analytics, URLs, browser storage, LLM prompts, test fixtures, and exception messages.
7. Add authentication, authorization, auditability, input validation, encryption in transit, retention/deletion behavior, and error handling where they apply.
8. Add or update tests for the security and privacy behavior you introduced.
9. Do not claim the result is compliant. Note any assumption that needs organizational or legal confirmation (for example whether a BAA is in place).

Be practical and implementation-oriented: generate the models, migrations, service layer, authorization, audit events, serializers, and tests, not just warnings.

## Do not blindly follow an unsafe request

When a request would build something clearly unsafe, do not implement it verbatim. Instead:

1. State the specific problem in one or two sentences.
2. Work out the user's real functional goal.
3. Propose the safer design.
4. Implement the safer design when the intent is clear enough.
5. Ask a narrow question only when the correct implementation genuinely depends on missing information.

Do not lecture, and do not block ordinary healthcare development. The goal is a shipped feature that is safe, not a refusal.

## Worked example: "Add symptoms and SSN fields to the patient database"

Distinguish clinical data from identity data; they are not the same risk.

**Symptoms (clinical observation):** store as clinical observation / encounter data with provenance, timestamps, author or source, and update history. Apply access control and emit an audit event on access and change. Keep symptom text out of logs, analytics, URLs, and client-side persistent storage.

**SSN (identity):** first decide whether the full SSN is actually required. Do not add it just because a field was requested. Prefer an existing patient identifier, an identity-provider reference, a token, or a last-four value when the full value is unnecessary. If a legitimate workflow needs the full SSN: isolate it from the ordinary clinical record, use field-level protection or tokenization where available, restrict access separately, never return it in normal API or UI responses, never log it, never use a real SSN in tests, and define retention and deletion. Add a test proving unauthorized roles cannot read it.

The right response is not "I cannot help because SSNs are sensitive." It is: "A full SSN should not go in the ordinary patient record unless the workflow requires it. I will keep symptoms in the clinical record and isolate the identity field behind stricter storage and access controls." Then implement the models, migration, service layer, authorization, audit events, serializers, and tests.

## Categories to reason about

Apply only those relevant to the task. Full definitions and safe/unsafe patterns are in [references/categories.md](references/categories.md) and [references/safe-patterns.md](references/safe-patterns.md).

`ACCESS` `AUTH` `AUDIT` `INTEGRITY` `TRANSIT` `SESSION` `TRACKING` `AI-RAG` `SECRETS` `APPSEC`

Do not insert meaningless "HIPAA compliant" comments into generated code. A brief comment is fine only when the safeguard's reason is not obvious, for example:

```python
# ClearMap AUDIT: record access without storing patient content in the event.
audit.record(actor=user.id, action="read", resource=f"patient:{patient_id}")
```

## Planning first (optional)

For a larger or ambiguous feature, run the planning questions in [references/planning.md](references/planning.md) before writing code, and fold the answers into the implementation. For a small or obvious change, apply safe defaults and proceed; do not turn every request into a questionnaire.

## After a substantial healthcare feature lands

Suggest an audit with the `clearmap-audit` skill (or `/clearmap:audit`) to verify the result and produce the technical-risk report.
