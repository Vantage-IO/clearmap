# ClearMap: Plan mode (`/clearmap plan`)

Invoked explicitly before code is written. No auto-detection
dependency. The agent asks the HIPAA-aware questions below that are relevant to
the stack in play, and folds the answers into the implementation plan.

> ClearMap is a technical risk signal, not a compliance certification.

## Trigger
User runs `/clearmap plan` (optionally with a feature description).

## Stack-aware planning questions

Ask only those that apply to what's being built; group by category code.

- **PHI scope**: Will this feature touch PHI (names, MRNs, DOB, diagnoses,
  notes, labs, images)? Which fields, and where do they flow?
- **ACCESS / AUTH (164.312(a)/(d))**: Who may call this? How are callers
  authenticated and authorized (role checks)? Session expiry / logout?
- **AUDIT (164.312(b))**: What audit events will record PHI create/read/update/
  delete, document access, and model calls (actor, action, resource, time)?
- **INTEGRITY (164.312(c))**: Are mutations authenticated? If AI generates
  content, is it stored as an unverified draft with a review state?
- **TRANSIT (164.312(e))**: Is every PHI hop over TLS (https/wss)? Any external
  partner / third-party call? (Internal hops inside a trusted boundary may use
  cleartext if documented: see regulatory-map.md.)
- **SESSION**: Will any PHI land in localStorage/sessionStorage/cookies or a
  client SDK? (Default: no: keep PHI server-side.)
- **TRACKING**: Any analytics on patient-facing screens? Health fields in
  events or URLs? (Default: strip them.)
- **AI-RAG**: If this calls an LLM/RAG: PHI redacted before the prompt? Abstain
  path on weak retrieval? Citations + confidence in the response? Model-call
  audit? External docs treated as data (injection)? Output bounded to sources?
- **SECRETS**: Where do credentials/keys live? (Default: secret manager, never
  source.)

## Output
A short "HIPAA technical-risk plan" section appended to the implementation plan:
per applicable category, the decision + the safeguard that will be implemented.
