# Categories AUDIT + INTEGRITY (+ absence checks): reasoning checks

Reasoning-led (`source: reasoning`, `confidence` required). High consulting
signal. Authority: AUDIT → 45 CFR 164.312(b); INTEGRITY → 164.312(c). This file
also owns the **absence/semantic checks** the deterministic layer cannot judge
with high precision (AUTH-01, ACCESS-02, ACCESS-03) and the internal-transit
advisory (TRANSIT-04).

Emit: `id`, `category`, `title` (a short human sentence, no rule slugs),
`severity`, `source: reasoning`, **`confidence`**,
`file`, `line`, `structural_snippet` (redacted), `why`, `reviewer_question`,
`remediation`. Apply **negative criteria** before emitting (precision).

## Procedure
1. Map PHI access paths: endpoints/handlers that create/read/update/delete
   patient data, document reads, and model calls.
2. For each, check whether the required safeguard is present **anywhere on the
   path** (decorator, middleware, dependency, helper) before concluding it's
   absent: middleware/decorators are the most common reason a naive "missing X"
   is a false positive.
3. Emit one finding per path with a calibrated confidence.

---

## AUDIT-01: PHI CRUD without audit event: high
**Hit:** a create/read/update/delete of PHI with no audit event (actor, action,
resource) on that path. **Not a hit:** an audit call on the path, or a
middleware/decorator/ORM hook that audits all PHI mutations centrally.
**Reviewer Q:** "Is every PHI create/read/update/delete recorded to the audit trail?"
**Fix:** emit an audit event on every PHI access path.

## AUDIT-02: LLM call not logged: medium
**Hit:** a model invocation with no logging/audit hook anywhere around it.
**Not a hit:** a logging wrapper/decorator covers model calls. (See also AI-RAG-04,
the RAG-specific lens.)
**Reviewer Q:** "Is there any record that a model call happened?"  **Fix:** wrap model calls with structured logging.

## AUDIT-03: PHI document/file access without audit: medium
**Hit:** reading a stored patient document/file with no audit record of who
accessed what. **Not a hit:** the read path emits an audit event, or goes through
an audited storage gateway.
**Reviewer Q:** "Are PHI document reads audited?"  **Fix:** audit every document read (actor + patient + file).

## AUDIT-04: No source-to-output traceability: medium
**Hit:** a stored AI artifact keeps no provenance linking it to the sources that
produced it (sources accepted but dropped). **Not a hit:** source ids/refs are
persisted with the artifact.
**Reviewer Q:** "Can a stored AI answer be traced back to its sources?"  **Fix:** persist source refs with the artifact.

## INTEGRITY-01: Unauthenticated mutation of patient data: critical
**Hit:** a PHI-mutating endpoint/handler with no authentication/authorization on
the path. **Not a hit:** auth dependency/middleware/guard protects the route, or
it's an internal-only function called behind an authenticated boundary.
**Reviewer Q:** "Can an unauthenticated caller alter patient data here?"  **Fix:** require auth + authz on all mutating PHI endpoints.

## INTEGRITY-02: AI output stored without review state: high
**Hit:** generated content saved with no review/confidence/status field. **Not a
hit:** stored with review_status/confidence/reviewed_by. (Integrity lens; cf.
AI-RAG-05.)
**Reviewer Q:** "Is stored AI output marked unverified until reviewed?"  **Fix:** add review_status + confidence; require sign-off.

## INTEGRITY-03: Source-context overwrite: medium
**Hit:** supporting context/evidence overwritten wholesale instead of
versioned/appended, destroying the prior evidence trail. **Not a hit:** context
is appended/versioned.
**Reviewer Q:** "Is the evidence trail preserved across regenerations?"  **Fix:** append/version context, never overwrite.

---

## Absence / semantic checks (precision)

A regex can't reliably tell "missing auth/role/expiry" from correct code; doing
it deterministically false-positives on safe code. The agent confirms intent +
context (decorators, middleware, dependencies) before emitting.

### AUTH-01: Unguarded PHI endpoint (no authentication): critical
**Hit:** a PHI read endpoint with no authentication on the path. **Not a hit:**
an auth dependency/middleware protects it (check decorators, router-level deps,
gateway auth).  **HIPAA:** 164.312(d).
**Reviewer Q:** "Can an unauthenticated caller read PHI here?"  **Fix:** require an authenticated principal on all PHI routes.

### ACCESS-02: Missing role check on a privileged action: high
**Hit:** an authenticated but **unauthorized** privileged action (e.g. delete)
with no role/permission check. **Not a hit:** a role/permission guard exists on
the path.  **HIPAA:** 164.312(a)(1).
**Reviewer Q:** "Is this destructive action restricted to permitted roles?"  **Fix:** enforce role/permission before the action.

### ACCESS-03: Weak session termination: medium
**Hit:** session tokens with no expiry and no server-side revocation; logout
can't actually invalidate. **Not a hit:** short TTL + revocation/denylist;
automatic logoff.  **HIPAA:** 164.312(a)(2)(iii).
**Reviewer Q:** "Can a leaked/old session token still be used, and can logout revoke it?"  **Fix:** short expiry + server-side revocation; invalidate on logout.

### TRANSIT-04: Internal cleartext PHI (advisory): low
**Hit:** PHI sent over cleartext (`http://`/`ws://`) to an **internal** host
(localhost, RFC-1918, `*.internal`, `*.svc.cluster.local`) where PHI genuinely
flows. Emit a **low advisory**, not a hard finding. **Not a hit:** the internal
hop carries no PHI (e.g. a health probe: cf. the safe fixture's
`http://localhost`), or the boundary uses mTLS.  **HIPAA:** 164.312(e)(1) +
164.306(d)(3) (addressable inside a documented trusted boundary).
**Reviewer Q:** "Does PHI cross this internal hop in cleartext, and is the boundary documented + controlled?"
**Fix:** acceptable within a documented trusted boundary; zero-trust = TLS/mTLS internally too.

---

Reference must-catch examples: `examples/vulnerable-health-app/backend/api/patients.py`,
`backend/records.py`, `backend/storage.py`, `backend/llm_client.py`, `backend/auth.py`,
`backend/integrations.py`. The safe fixture must produce **zero** of these.
