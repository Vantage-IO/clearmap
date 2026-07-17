# Planning questions (ask only what changes the design)

Before a larger or ambiguous healthcare feature, ask only the questions whose answers materially change the architecture or risk profile, then fold the answers into the implementation as a short "HIPAA technical-risk plan" (per applicable category: the decision + the safeguard). For a small or obvious change, apply safe defaults and proceed.

- **Data in:** what data enters the feature? Does it contain PHI, identity data, credentials, or clinical conclusions?
- **Necessity:** is each sensitive field genuinely required (minimum necessary)?
- **Access (ACCESS/AUTH, 164.312(a)/(d)):** who may call this? How are callers authenticated and authorized? Which operations need distinct permissions? Session expiry / logout?
- **Storage:** where is the data stored, and how long is it retained? What is the deletion behavior?
- **Third parties:** which external services receive it? Is a BAA or equivalent expected?
- **AI (AI-RAG):** will the data enter an LLM or embedding system? Is PHI redacted before the prompt? Is there an abstain path on weak retrieval? Are citations and confidence returned? Are model calls audited? Is retrieved/external text treated as data, not instructions? Is output bounded to sources?
- **Leakage (SESSION/TRACKING/AUDIT):** can data appear in logs, traces, URLs, analytics, or browser storage? What audit events are required (actor, action, resource, time), and do they avoid storing patient content?
- **Integrity (INTEGRITY):** are mutations authenticated? If AI generates content, is it stored as an unverified draft with a review state until a human signs off?
- **Transit (TRANSIT, 164.312(e)):** is every PHI hop over TLS (https/wss)? Any external partner call? (Internal hops in a documented trusted boundary may use cleartext; prefer mTLS.)
- **Failure:** what happens when authorization fails, or when retrieval / AI confidence is weak?
- **Testing:** how will each safeguard be tested (including a test proving unauthorized roles cannot read the sensitive field)?

Do not turn every request into a large questionnaire.
