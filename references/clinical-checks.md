# Category AI-RAG: Clinical AI reasoning checks (the IP)

The differentiator. These are **reasoning-led**: the host agent reads the code
and judges them; regex cannot. Authority: ONC HTI-1 §170.315(b)(11) (decision-
support transparency) + general clinical-AI reliability practice.

Every emitted finding requires: `id` (family `AI-RAG`), `category: AI-RAG`,
`title` (a short human sentence, no rule slugs),
`severity`, `source: reasoning`, **`confidence`** (high/medium/low),
`file`, `line`, `structural_snippet` (redacted: no raw PHI), `why`,
`reviewer_question`, `remediation`. Mark all as "agent-identified, verify."

## How to run this pass (procedure)

1. **Locate the AI surface.** Find model-call sites (OpenAI/Anthropic/Bedrock/
   LangChain/LlamaIndex/`requests` to an LLM endpoint, `.chat`, `.complete`,
   `.invoke`, `.generate`). If there is **no LLM/RAG usage, emit nothing** for
   this category: do not invent findings.
2. For each model surface, trace: **inputs → prompt construction → retrieval →
   response shape → persistence → audit.**
3. Evaluate each check below. Apply the **negative criteria** before emitting -
   if the safe pattern is present, do **not** flag (this is where precision is
   won or lost; cf. the deterministic layer's false positives on real repos).
4. Emit one finding per distinct gap, with a redacted structural snippet and a
   calibrated `confidence`.

> **Confidence calibration.** `high` = the gap is visible in the code with no
> plausible mitigation elsewhere. `medium` = likely a gap but a mitigation may
> exist out of view. `low` = a smell worth a reviewer's eye. When unsure between
> two levels, pick the lower one.

---

## AI-RAG-01: Unredacted PHI in prompt: severity: critical
**Hit when:** patient identifiers or clinical free-text (name, MRN, DOB, SSN,
note body, lab values) are interpolated into a model prompt with no redaction or
tokenization step in between.
**Structural patterns:** f-strings / template strings / `+` concatenation that
embed a patient/record field directly into prompt text; `messages=[{...patient...}]`.
**NOT a hit (negative criteria):** PHI passed through a redaction/de-identify
step first (e.g. `redact(...)`, Presidio, a tokenizer) before reaching the
prompt; only opaque ids / non-PHI references in the prompt; the "PHI" is actually
synthetic/test fixtures or schema field *names* (not values).
**Reviewer question:** "Is any patient identifier or note text sent to the model without redaction?"
**Remediation:** redact/tokenize PHI before prompt construction; pass references, not raw identifiers.

## AI-RAG-02: No abstain / fallback path: severity: high
**Hit when:** the assistant returns a confident answer even when retrieval is
empty or low-relevance: no branch that abstains, returns "insufficient
evidence", or surfaces low confidence.
**Structural patterns:** retrieval result used unconditionally; no `if not
evidence:` / threshold check before generation.
**NOT a hit:** an explicit abstain/low-confidence branch exists; a relevance
threshold gates generation; the feature is not a question-answering/RAG surface.
**Reviewer question:** "What does the system return when retrieval finds nothing relevant?"
**Remediation:** abstain or flag low-confidence when evidence is empty/weak; require an evidence threshold.

## AI-RAG-03: No source traceability in response: severity: high
**Hit when:** the response returned to the caller (API/UI) contains the generated
text but **no citations / source ids / provenance** the clinician can verify.
**Structural patterns:** `return {"answer": text}` with no `citations`/`sources`
field; response model lacks a sources array.
**NOT a hit:** the response schema includes source ids/spans/links; citations are
attached even if rendered elsewhere.
**Reviewer question:** "Can a clinician see which sources produced this answer?"
**Remediation:** return structured citations (source ids + spans) with every answer.

## AI-RAG-04: No model-call audit: severity: high
**Hit when:** a model interaction is not recorded to an audit trail: no log of
actor, inputs (redacted), output, sources, timestamp.
**Structural patterns:** model call with no surrounding audit/log of the
interaction; orchestrator returns without writing an audit event.
**NOT a hit:** an audit/log call records the interaction (even if PHI is redacted
in the log); a middleware/decorator audits all model calls.
**Reviewer question:** "Is every model call auditable (who, what, which sources, when)?"
**Remediation:** audit each model call: actor, prompt (redacted), response, source refs, timestamp.

## AI-RAG-05: AI output written to clinical record as fact: severity: high
**Hit when:** generated content is persisted to a clinical/patient record with no
review state, confidence, or "AI-generated/unverified" marker: indistinguishable
downstream from a clinician-authored, verified note.
**Structural patterns:** `save(... ai_text ...)` into a notes/records store with
no `review_status`/`reviewed_by`/`confidence` field.
**NOT a hit:** stored as a draft/unverified with a review state + confidence;
requires human sign-off before clinical use; rendered with an "AI-generated" badge.
**Reviewer question:** "Is AI-generated content distinguishable from verified clinical content?"
**Remediation:** persist AI output as unverified draft + confidence + review state until clinician sign-off.

## AI-RAG-06: Prompt injection of untrusted clinical text: severity: critical
**Hit when:** untrusted external content (faxed referral, patient upload, scraped
portal text, retrieved web doc) is concatenated into the prompt without being
delimited/sanitized as **data**, so embedded instructions can execute.
**Structural patterns:** external doc strings joined directly into prompt text;
no fencing/escaping/"treat as data" framing.
**NOT a hit:** external text is clearly delimited and labeled as untrusted data
(fenced block, system instruction to ignore embedded instructions); input is
sanitized/escaped first.
**Reviewer question:** "Could text inside a retrieved/external document change the model's instructions?"
**Remediation:** treat retrieved/external text as quoted data; delimit + sanitize; never let it carry instructions.

## AI-RAG-07: Weak retrieval evidence handling: severity: medium
**Hit when:** retrieval returns chunks with no similarity score, no ranking, and
no separation of authoritative sources (guidelines/formulary) from low-quality
ones (old notes/emails); nothing thresholds by relevance.
**Structural patterns:** retriever returns bare strings; no score kept; no sort;
no source-quality tier.
**NOT a hit:** scored + ranked + thresholded retrieval; authoritative sources
preferred; provenance retained on each chunk.
**Reviewer question:** "How does the system tell strong evidence from weak?"
**Remediation:** score + rank retrievals, threshold by relevance, prefer authoritative sources.

## AI-RAG-08: No bounded synthesis: severity: medium
**Hit when:** the prompt invites the model to answer beyond the retrieved context
("use your own medical knowledge", "answer fully") rather than constraining it to
the provided sources.
**Structural patterns:** prompt text encouraging outside knowledge; no "answer
only from sources / say if insufficient" instruction.
**NOT a hit:** prompt explicitly constrains to provided sources and instructs the
model to abstain when context is insufficient.
**Reviewer question:** "Is the model constrained to answer only from retrieved sources?"
**Remediation:** constrain to provided sources; instruct the model to say when context is insufficient.

---

Reference must-catch examples (validate recall against these):
`examples/vulnerable-health-app/backend/rag/assistant.py`,
`backend/rag/retriever.py`, `backend/records.py`, `backend/api/assistant.py`.
The safe counterpart (`examples/safe-health-app/`) must produce **zero** AI-RAG
findings: use it to check the negative criteria.
