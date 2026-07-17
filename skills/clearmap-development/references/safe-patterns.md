# Safe patterns: prefer the safe form when generating healthcare code

For each risky pattern, generate the safe alternative, not just a warning. Note the category code briefly when the reason is not obvious.

| Risk (avoid) | Safe alternative (generate this) |
|---|---|
| Hardcoded creds/keys (`SECRETS`, `ACCESS`) | Read from env / a secret manager |
| PHI endpoint with no auth (`AUTH`) | Require an authenticated principal on every PHI route |
| Mutation/delete with no role check (`ACCESS`) | Enforce role/permission before the action |
| Non-expiring/non-revocable tokens (`ACCESS`) | Short TTL + server-side revocation; invalidate on logout |
| PHI create/read/update/delete with no audit (`AUDIT`) | Emit an audit event (actor, action, resource, time) with no patient content in the event |
| PHI over `http://` / `ws://` to an external host (`TRANSIT`) | Use `https`/`wss`; for internal hops document the boundary, prefer mTLS |
| PHI in localStorage/sessionStorage/cookie/SDK (`SESSION`) | Keep PHI server-side; opaque ids client-side |
| Health fields in analytics / URLs (`TRACKING`) | Track non-PHI signals; reference by opaque id |
| Raw PHI in an LLM prompt (`AI-RAG`) | Redact/tokenize before prompt construction |
| No abstain on weak retrieval (`AI-RAG`) | Abstain / low-confidence when evidence is weak |
| AI output stored as fact (`AI-RAG`/`INTEGRITY`) | Persist as an unverified draft + confidence + review state |
| External docs concatenated into a prompt (`AI-RAG`) | Treat retrieved/external text as quoted data, never instructions |
| Answer beyond sources (`AI-RAG`) | Constrain to provided sources; cite source ids |
| User input built into SQL / shell / paths / URLs / deserializers (`APPSEC`) | Parameterized queries, argument-list process calls, normalized+bounded paths, allowlisted URLs, safe deserializers |

## PHI must never reach

Logs, traces, analytics events, URLs and query strings, browser storage or cookies, LLM prompts, test fixtures, exception messages, or error responses. When one of these needs a reference to a patient, use an opaque id, not the content.
