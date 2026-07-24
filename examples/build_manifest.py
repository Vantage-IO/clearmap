#!/usr/bin/env python3
"""Generate and verify the expected-findings.json manifest for the corpus.

This is the single source of truth for ClearMap's canonical finding-ID
taxonomy. Each entry's `anchor` is a substring that uniquely
identifies the seeded line inside the vulnerable fixture; this script resolves
it to a real file:line and emits the manifest, asserting that:

  * every taxonomy ID resolves to exactly one line (no missing, no duplicates),
  * the resolved line/snippet is written back into the manifest.

Finding IDs use descriptive category codes (not bare letters). The HIPAA /
regulatory citation lives in a separate `hipaa_ref` field so IDs stay stable
even as the regulation evolves (e.g. the Dec-2024 NPRM that would promote
encryption to a required standalone standard). See references/regulatory-map.md.

The rules and reasoning checks must produce exactly these finding IDs.
Run from the repo root:  python3 examples/build_manifest.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VULN = HERE / "vulnerable-health-app"
SAFE = HERE / "safe-health-app"
BASELINE = HERE.parent / "references" / "regulatory-baseline.json"
TAXONOMY = HERE.parent / "references" / "taxonomy.json"

# code -> (full name, regulatory anchor, kind)
CATEGORIES = {
    "ACCESS":    ("Access Control",            "45 CFR 164.312(a)", "HIPAA technical safeguard"),
    "AUTH":      ("Person/Entity Authentication", "45 CFR 164.312(d)", "HIPAA technical safeguard"),
    "AUDIT":     ("Audit Controls",            "45 CFR 164.312(b)", "HIPAA technical safeguard"),
    "INTEGRITY": ("Integrity",                 "45 CFR 164.312(c)", "HIPAA technical safeguard"),
    "TRANSIT":   ("Transmission Security",     "45 CFR 164.312(e)", "HIPAA technical safeguard"),
    "SESSION":   ("Frontend / Session Exposure", "45 CFR 164.312(a)(2)(iv)", "extension"),
    "TRACKING":  ("Tracking / Analytics",      "HHS OCR online-tracking guidance", "extension"),
    "AI-RAG":    ("AI / LLM / RAG Risk",       "ONC HTI-1 45 CFR 170.315(b)(11)", "extension"),
    "SECRETS":   ("Secrets / Config",          "45 CFR 164.312(a)(1)", "extension"),
    "APPSEC":    ("Application Security",       "OWASP / CWE application-security", "extension"),
}
# APPSEC-07 uses CWE-532 (sensitive data in logs); the anchor lives in appsec.py.

# id, category code, title, severity, source, file (rel to fixture), anchor,
# hipaa_ref (specific paragraph), why, remediation
SPEC = [
    # --- ACCESS — 164.312(a) ---
    ("ACCESS-01", "ACCESS", "Hardcoded database credentials", "critical", "deterministic",
     "backend/config.py", 'postgresql://admin:', "164.312(a)(2)(i)",
     "DB username and password are committed in source; anyone with repo access gets prod data.",
     "Load credentials from a secret manager / env vars; rotate the exposed password."),
    ("ACCESS-02", "ACCESS", "Missing role check on destructive action", "high", "reasoning",
     "backend/api/patients.py", '_PATIENTS.pop(patient_id, None)', "164.312(a)(1)",
     "Delete is authenticated but never checks role, so any logged-in user can delete patients.",
     "Enforce role/permission (e.g. require an admin/clinician role) before mutation."),
    ("ACCESS-03", "ACCESS", "Weak session termination (no automatic logoff)", "medium", "reasoning",
     "backend/auth.py", 'payload = {"sub": user_id, "role": role}', "164.312(a)(2)(iii)",
     "JWT carries no exp/iat claim and logout cannot revoke it, so a leaked token is valid forever.",
     "Add short expiry + server-side revocation/denylist; invalidate on logout."),

    # --- AUTH — 164.312(d) ---
    ("AUTH-01", "AUTH", "Unguarded PHI endpoint (no authentication)", "critical", "reasoning",
     "backend/api/patients.py", 'return _PATIENTS[patient_id]', "164.312(d)",
     "GET /patients/{id} has no auth dependency, so any unauthenticated caller can read any chart.",
     "Require an authenticated principal (Depends(current_user)) on all PHI routes."),

    # --- AUDIT — 164.312(b) ---
    ("AUDIT-01", "AUDIT", "PHI create without audit event", "high", "reasoning",
     "backend/api/patients.py", '_PATIENTS[patient["id"]] = patient', "164.312(b)",
     "A new patient (PHI) is written with no audit.record_event call; creation is untraceable.",
     "Emit an audit event (actor, action, resource) on every PHI create/read/update/delete."),
    ("AUDIT-02", "AUDIT", "LLM call not logged", "medium", "reasoning",
     "backend/llm_client.py", 'resp = requests.post(', "164.312(b)",
     "The model invocation has no logging hook at all — no record the call happened.",
     "Wrap model calls with structured logging of request/response metadata."),
    ("AUDIT-03", "AUDIT", "PHI document read without audit", "medium", "reasoning",
     "backend/storage.py", 'with open(path, "rb") as fh:', "164.312(b)",
     "Reading a patient's stored document produces no audit record of who accessed what.",
     "Record an audit event on every document read keyed by actor + patient + file."),
    ("AUDIT-04", "AUDIT", "No source-to-output traceability", "medium", "reasoning",
     "backend/records.py", 'sources argument is dropped on the floor', "164.312(b)",
     "AI summaries are stored without their source provenance, so output cannot be traced to inputs.",
     "Persist the source ids/refs alongside the generated artifact."),

    # --- INTEGRITY — 164.312(c) ---
    ("INTEGRITY-01", "INTEGRITY", "Unauthenticated mutation of patient data", "critical", "reasoning",
     "backend/api/patients.py", '_PATIENTS[patient_id].update(changes)', "164.312(c)(1)",
     "PATCH /patients/{id} has no auth dependency; any caller can alter clinical fields (also implicates 164.312(d)).",
     "Require authentication + authorization on all mutating PHI endpoints."),
    ("INTEGRITY-02", "INTEGRITY", "AI output stored without review state", "high", "reasoning",
     "backend/records.py", '_NOTES[note_id] = {', "164.312(c)(2)",
     "AI summary is saved with no reviewed/confidence/status field; indistinguishable from a verified note.",
     "Store a review_status + reviewer + confidence; require human sign-off before clinical use."),
    ("INTEGRITY-03", "INTEGRITY", "Source-context overwrite destroys evidence trail", "medium", "reasoning",
     "backend/records.py", '_NOTES[note_id]["context"] = retrieved_context', "164.312(c)(2)",
     "Re-attaching context replaces it wholesale, silently destroying the prior evidence trail.",
     "Append/version source context instead of overwriting."),

    # --- TRANSIT — 164.312(e). General principle: ALL PHI in transit on ANY
    #     network path (internal, partner, third-party, realtime/streaming)
    #     must be encrypted. The seeds below are representative instances. ---
    ("TRANSIT-01", "TRANSIT", "PHI transmitted over cleartext HTTP", "critical", "deterministic",
     "backend/integrations.py", 'resp = requests.get(f"http://labs.partner-network', "164.312(e)(1)",
     "PHI travels over plain http. 164.312(e)(1) requires guarding ePHI on ANY network path — this "
     "rule is system-wide (internal services, partners, third parties), not specific to this lab call.",
     "Use https/TLS for every PHI transmission, everywhere; reject non-TLS endpoints by policy."),
    ("TRANSIT-02", "TRANSIT", "PHI streamed over insecure WebSocket", "high", "deterministic",
     "frontend/src/vitals.ts", 'new WebSocket(`ws://vitals', "164.312(e)(1)",
     "Live vitals (PHI) stream over unencrypted ws://. All streaming/realtime transport carrying PHI "
     "must be encrypted, not just request/response APIs.",
     "Use wss:// (TLS) for any channel carrying PHI; forbid ws:// on PHI paths."),
    ("TRANSIT-03", "TRANSIT", "Full patient object sent to third party", "critical", "deterministic",
     "backend/integrations.py", '"diagnosis": patient["diagnosis"],', "164.312(e)(1)",
     "Name, DOB, email and diagnosis are pushed to a third-party CRM with no BAA, over http.",
     "Do not send PHI to marketing tools; if integration is required, minimize fields + use a BAA + TLS."),
    # TRANSIT-05/06: the deterministic layer catches the cleartext URL LITERALS
    # in config (it cannot see through the variable indirection at the
    # TRANSIT-01/03 usage sites in integrations.py).
    ("TRANSIT-05", "TRANSIT", "Cleartext external lab endpoint configured", "critical", "deterministic",
     "backend/config.py", 'LAB_PARTNER_URL = "http://', "164.312(e)(1)",
     "The lab-partner base URL is configured as plain http://, so every PHI call through it is unencrypted.",
     "Configure https:// for all external partner endpoints; reject non-TLS URLs at startup."),
    ("TRANSIT-06", "TRANSIT", "Cleartext third-party webhook configured", "critical", "deterministic",
     "backend/config.py", 'CRM_WEBHOOK_URL = "http://', "164.312(e)(1)",
     "The CRM webhook used for patient sync is plain http://, so PHI pushed to it travels unencrypted.",
     "Use https:// and verify the receiving party is BAA-covered before sending PHI."),
    ("TRANSIT-07", "TRANSIT", "TLS certificate verification disabled", "high", "deterministic",
     "backend/integrations.py", 'https://rx.partner-network.example/mrn/', "164.312(e)(1)",
     "A PHI call disables TLS certificate verification (verify=False), leaving the connection "
     "encrypted but unauthenticated and open to a machine-in-the-middle.",
     "Never disable certificate verification; install the correct CA/trust chain and keep verify on."),
    ("TRANSIT-04", "TRANSIT", "Internal cleartext PHI (low/advisory)", "low", "reasoning",
     "backend/integrations.py", 'http://records.internal.svc.cluster.local', "164.312(e)(1)",
     "Internal service-to-service PHI over http to a host inside a trusted boundary (private cluster "
     "service name). REASONING, not deterministic: a regex can classify the host as internal but cannot tell "
     "whether PHI flows over it (cf. the safe fixture's http://localhost probe, which must stay silent). The "
     "agent confirms PHI + trusted boundary and emits a LOW advisory; external cleartext (TRANSIT-01) stays "
     "deterministic + critical. Defensible per 164.306(d)(3) with compensating controls.",
     "Acceptable within a documented trusted boundary; zero-trust best practice is to use TLS/mTLS internally too."),

    # --- SESSION — client-side PHI exposure (extension; relates 164.312(a)(2)(iv)) ---
    ("SESSION-01", "SESSION", "PHI persisted to localStorage", "high", "deterministic",
     "frontend/src/storage.ts", 'localStorage.setItem(`patient:', "164.312(a)(2)(iv)",
     "Full patient object is stored in localStorage; survives logout, readable by any origin script.",
     "Keep PHI server-side; if caching is needed use in-memory state cleared on logout."),
    ("SESSION-02", "SESSION", "PHI persisted to sessionStorage", "high", "deterministic",
     "frontend/src/storage.ts", 'sessionStorage.setItem("activePatient"', "164.312(a)(2)(iv)",
     "Active patient chart written to sessionStorage, exposed to any XSS for the session.",
     "Avoid persisting PHI in web storage; hold transient state in memory only."),
    ("SESSION-03", "SESSION", "PHI written to a JS-readable cookie", "medium", "deterministic",
     "frontend/src/storage.ts", 'document.cookie = `recentMrn=', "164.312(a)(2)(iv)",
     "MRN stored in a non-HttpOnly cookie, readable by JS and sent on every request.",
     "Do not store PHI client-side; if cookies are required, use HttpOnly + Secure server-set cookies without PHI."),
    ("SESSION-04", "SESSION", "Patient state passed to third-party SDK", "critical", "deterministic",
     "frontend/src/analytics.ts", 'analytics.identify(patient.id, {', "164.312(a)(2)(iv)",
     "Patient identity + diagnosis handed to the analytics vendor via identify().",
     "Never pass PHI to client analytics SDKs; identify by opaque non-PHI id only."),
    ("SESSION-05", "SESSION", "PHI passed to a third-party user-identification method", "high", "deterministic",
     "frontend/src/observability.ts", 'analytics.setUser({ name: patient.name', "164.312(a)(2)(iv)",
     "Patient name, MRN, and DOB passed to a third-party setUser call.",
     "Use an opaque non-PHI id; never pass name/MRN/DOB/SSN/diagnosis to a client SDK."),
    ("SESSION-06", "SESSION", "PHI serialized to web storage under a benign key", "high", "deterministic",
     "frontend/src/storage.ts", 'localStorage.setItem("appState", JSON.stringify(patientChart))', "164.312(a)(2)(iv)",
     "The storage key looks harmless but the value serializes a PHI-named object into localStorage.",
     "Keep PHI server-side; hold transient state in memory cleared on logout."),

    # --- TRACKING — OCR online-tracking guidance (extension) ---
    ("TRACKING-01", "TRACKING", "Analytics firing inside authenticated patient view", "high", "deterministic",
     "frontend/src/PatientView.tsx", 'analytics.page("PatientChart"', "OCR online-tracking guidance",
     "A third-party pageview is sent from a screen rendering PHI, tying tracking to a patient chart.",
     "Disable third-party analytics on authenticated PHI screens, or use a self-hosted, BAA-covered path."),
    ("TRACKING-02", "TRACKING", "Health field sent as analytics event property", "high", "deterministic",
     "frontend/src/analytics.ts", 'analytics.track("diagnosis_viewed"', "OCR online-tracking guidance",
     "The diagnosis (a health field) is shipped as an analytics event property.",
     "Strip health fields from analytics; track only non-PHI interaction signals."),
    ("TRACKING-03", "TRACKING", "Health context in URL query parameter", "medium", "deterministic",
     "frontend/src/PatientView.tsx", 'const shareLink =', "OCR online-tracking guidance",
     "Condition + MRN placed in a URL query string, leaking into history, logs, and Referer headers.",
     "Reference records by opaque id; never put health context in URLs."),
    ("TRACKING-04", "TRACKING", "Session-replay SDK initialized in a PHI application", "high", "deterministic",
     "frontend/src/observability.ts", 'datadogRum.init({', "OCR online-tracking guidance",
     "A session-replay SDK records the full patient screen and ships it to a third-party vendor.",
     "Disable session replay on PHI surfaces or mask all PHI; require a BAA and privacy review."),

    # --- AI-RAG — ONC HTI-1 170.315(b)(11) (extension) — the differentiator ---
    ("AI-RAG-01", "AI-RAG", "Unredacted PHI interpolated into LLM prompt", "critical", "reasoning",
     "backend/rag/assistant.py", 'f"You are a clinical assistant. Patient ', "ONC HTI-1 170.315(b)(11)",
     "Patient name, MRN, DOB and raw note are interpolated directly into the prompt with no redaction.",
     "Redact/tokenize PHI before prompt construction; pass references, not raw identifiers."),
    ("AI-RAG-02", "AI-RAG", "No abstain or fallback path on weak retrieval", "high", "reasoning",
     "backend/rag/assistant.py", 'answer = llm_client.complete(prompt)', "ONC HTI-1 170.315(b)(11)",
     "The assistant always answers, even when retrieval returned nothing, instead of abstaining.",
     "Abstain or surface low-confidence when retrieval is empty/weak; require an evidence threshold."),
    ("AI-RAG-03", "AI-RAG", "No source traceability in response", "high", "reasoning",
     "backend/api/assistant.py", 'return {"answer": answer}', "ONC HTI-1 170.315(b)(11)",
     "API returns a bare answer string with no citations/sources field to verify grounding.",
     "Return structured citations (source ids + spans) with every answer."),
    ("AI-RAG-04", "AI-RAG", "No model-call audit", "high", "reasoning",
     "backend/rag/assistant.py", 'return answer', "ONC HTI-1 170.315(b)(11)",
     "The orchestrator never records the interaction (user, inputs, outputs, sources) to the audit trail.",
     "Audit each model call: actor, prompt, response, source refs, timestamp."),
    ("AI-RAG-05", "AI-RAG", "AI output written to clinical record as fact", "high", "reasoning",
     "backend/records.py", '"text": ai_text,', "ONC HTI-1 170.315(b)(11)",
     "Generated text is persisted into the clinical record and treated as authoritative downstream.",
     "Persist AI output as draft/unverified with a confidence + review state until clinician sign-off."),
    ("AI-RAG-06", "AI-RAG", "Prompt injection of untrusted clinical text", "critical", "reasoning",
     "backend/rag/assistant.py", 'injected_context = "\\n".join(', "ONC HTI-1 170.315(b)(11)",
     "External documents are concatenated into the prompt unsanitized, so embedded instructions execute.",
     "Treat retrieved/external text as data: delimit, sanitize, and never let it carry instructions."),
    ("AI-RAG-07", "AI-RAG", "Weak retrieval evidence handling", "medium", "reasoning",
     "backend/rag/retriever.py", 'hits.append(doc["text"])', "ONC HTI-1 170.315(b)(11)",
     "Chunks returned with no score, no ranking, and no separation of authoritative vs low-quality sources.",
     "Score + rank retrievals, threshold by relevance, and prefer authoritative sources."),
    ("AI-RAG-08", "AI-RAG", "No bounded synthesis", "medium", "reasoning",
     "backend/rag/assistant.py", 'Answer fully using your own medical knowledge', "ONC HTI-1 170.315(b)(11)",
     "The prompt invites the model to go beyond retrieved context using its own knowledge.",
     "Constrain the model to answer only from provided sources; instruct it to say when context is insufficient."),

    # --- SECRETS — credential/secret material in source (extension) ---
    ("SECRETS-01", "SECRETS", "Hardcoded EHR/FHIR API key", "critical", "deterministic",
     "backend/config.py", 'EHR_API_KEY =', "164.312(a)(1)",
     "Live EHR integration key committed in source.",
     "Move to a secret manager; rotate the key."),
    ("SECRETS-02", "SECRETS", "Hardcoded model-provider API key", "critical", "deterministic",
     "backend/config.py", 'OPENAI_API_KEY =', "164.312(a)(1)",
     "Live model-provider key committed in source.",
     "Move to a secret manager; rotate the key."),
    ("SECRETS-03", "SECRETS", "Hardcoded signing secret", "high", "deterministic",
     "backend/config.py", 'SECRET_KEY =', "164.312(a)(1)",
     "Session signing key is a hardcoded literal, so anyone with the repo can forge sessions.",
     "Generate per-environment secrets from a secret manager; rotate."),

    # --- APPSEC — OWASP / CWE application-security weaknesses (extension) ---
    ("APPSEC-01", "APPSEC", "SQL injection via string-built query", "critical", "deterministic",
     "backend/appsec.py", 'cur.execute(f"SELECT * FROM patients', "CWE-89",
     "A request value is interpolated into a raw SQL statement, so input can change the query.",
     "Use parameterized queries; never interpolate values into SQL."),
    ("APPSEC-02", "APPSEC", "OS command injection via shell", "critical", "deterministic",
     "backend/appsec.py", 'os.system(f"tar czf', "CWE-78",
     "A shell command is built from input, allowing command injection and remote code execution.",
     "Use subprocess with an argument list and shell=False; never build shell strings from input."),
    ("APPSEC-03", "APPSEC", "Server-side request forgery (user-controlled URL)", "high", "deterministic",
     "backend/appsec.py", 'requests.get(request.query_params["url"])', "CWE-918",
     "An outbound request uses a URL taken directly from request input with no allowlist (SSRF).",
     "Validate the URL host against an allowlist before fetching; reject internal targets."),
    ("APPSEC-04", "APPSEC", "Path traversal from unsanitized input", "high", "deterministic",
     "backend/appsec.py", 'open(os.path.join(DOCS_ROOT, request.query_params["file"])', "CWE-22",
     "A file path is joined from request input with no normalization, allowing traversal to any file.",
     "Use os.path.basename or resolve + verify the path stays within the document root."),
    ("APPSEC-05", "APPSEC", "Unsafe deserialization of untrusted data", "critical", "deterministic",
     "backend/appsec.py", 'pickle.loads(blob)', "CWE-502",
     "Untrusted bytes are unpickled, which can execute arbitrary code.",
     "Deserialize with json or yaml.safe_load; never unpickle untrusted input."),
    ("APPSEC-06", "APPSEC", "Permissive CORS with credentials", "high", "deterministic",
     "backend/appsec.py", 'allow_origins=["*"], allow_credentials=True', "CWE-16",
     "Wildcard CORS combined with credentials lets any origin read authenticated responses.",
     "List explicit trusted origins; never combine wildcard origin with credentials."),
    ("APPSEC-07", "APPSEC", "Sensitive request data written to logs", "high", "deterministic",
     "backend/appsec.py", 'logger.info("incoming request headers=%s', "CWE-532",
     "Full request headers (Authorization) and the raw body are written to the logs, spilling credentials and PHI.",
     "Log only non-sensitive metadata; redact/omit Authorization, Cookie, and request/response bodies."),
]


# Findings whose primary source is `reasoning` but that rules/access.yaml can
# ALSO catch deterministically. The det layer anchors on a different
# line for route checks (the decorator, not the body) — det_anchor resolves to
# det_line in the manifest; calibrate.py uses it when scoring the det layer,
# and merge_reasoning.py dedupes the overlap so scores never double-count.
# id -> det_anchor (same file as the finding), or None when det matches the
# primary anchor line already.
ALSO_DETECTABLE = {
    "AUTH-01": '@router.get("/patients/{patient_id}")',
    "INTEGRITY-01": '@router.patch("/patients/{patient_id}")',
    "ACCESS-03": None,
}

# Clean code in the safe fixture that a naive/over-broad rule might wrongly
# flag. These define the FALSE-POSITIVE budget: ClearMap must NOT report them.
# (relates_to id, file, anchor, why it is clean)
NEAR_MISSES = [
    ("ACCESS-01", "backend/config.py", 'DATABASE_URL = os.environ',
     "Looks like a credential assignment but loads from the environment, not a literal."),
    ("SECRETS-03", "backend/config.py", 'SECRET_KEY = os.environ',
     "Secret-shaped name but sourced from the environment / secret manager."),
    ("TRANSIT-01", "backend/config.py", 'HEALTHCHECK_URL = "http://localhost',
     "Plain http:// but a localhost readiness probe carrying no PHI."),
    ("TRANSIT-07", "backend/integrations.py", 'resp = requests.get(f"{LAB_PARTNER_URL}/results/',
     "TLS verification is left at its secure default (not disabled); must not fire."),
    ("SESSION-01", "frontend/src/storage.ts", 'localStorage.setItem("ui.theme"',
     "localStorage used only for a non-PHI UI preference."),
    ("SESSION-02", "frontend/src/storage.ts", 'sessionStorage.setItem("csrf"',
     "sessionStorage holds an opaque CSRF token; the param name 'patientToken' is a decoy."),
    ("SESSION-03", "frontend/src/storage.ts", 'document.cookie = `sessionRef=',
     "Cookie holds an opaque, Secure session ref — no PHI."),
    ("SESSION-04", "frontend/src/analytics.ts", 'analytics.identify(patient.id, { plan',
     "identify() passes only an opaque id + non-PHI plan tier."),
    ("SESSION-06", "frontend/src/storage.ts", 'localStorage.setItem("appState", JSON.stringify(prefs))',
     "Benign key + JSON.stringify of a NON-PHI object (UI prefs); must not fire."),
    ("TRACKING-02", "frontend/src/analytics.ts", 'analytics.track("chart_opened"',
     "Analytics event carries only a non-PHI interaction signal."),
    # Real-world false-positive classes: must stay silent forever.
    ("TRANSIT-01", "frontend/src/PatientView.tsx", 'xmlns="http://www.w3.org/2000/svg"',
     "SVG xmlns is a constant XML namespace identifier, not a network endpoint."),
    ("SECRETS-01", "backend/config.py", 'SMTP_PASSWORD = "${SMTP_PASSWORD}"',
     "Templated placeholder substituted at deploy time — not a real credential."),
    ("ACCESS-01", "backend/config.py", 'SAMPLE_DB_URL = "postgresql://app:',
     "DB connection string whose password is a ${...} template, not a real credential."),
    ("SECRETS-02", "frontend/src/observability.ts", 'clientToken: "pub',
     "Datadog RUM client token is publishable by design (ships in the browser bundle)."),
    ("TRACKING-04", "frontend/src/observability.ts", 'datadogRum.init({',
     "RUM init for error monitoring with no session replay / interaction capture; must not fire."),
    ("SECRETS-02", "frontend/src/observability.ts", 'snippet.js?key=',
     "Support-widget embed URL with a public key= UUID served to every visitor."),
    ("SECRETS-03", "frontend/src/observability.ts", 'labelKey: "q1_option_a"',
     "i18n label key — a translation-catalog path, not secret material."),
    # APPSEC safe counterparts (must-not-flag).
    ("APPSEC-01", "backend/appsec.py", 'execute("SELECT * FROM patients WHERE name = ?"',
     "Parameterized query; the value is bound, not interpolated."),
    ("APPSEC-01", "backend/appsec.py", 'cur.execute(f"SELECT count(*) FROM patients")',
     "Constant f-string with no interpolation builds no dynamic SQL; must not fire."),
    ("APPSEC-02", "backend/appsec.py", 'os.system(f"find /backups',
     "Constant f-string command with no interpolation is not injectable."),
    ("APPSEC-02", "backend/appsec.py", 'subprocess.run(["tar"',
     "Argument list with shell=False; no shell to inject into."),
    ("APPSEC-03", "backend/appsec.py", 'return requests.get(url)',
     "URL host is validated against an allowlist before the fetch."),
    ("APPSEC-04", "backend/appsec.py", 'open(os.path.join(DOCS_ROOT, name))',
     "basename strips traversal before the path is joined."),
    ("APPSEC-05", "backend/appsec.py", 'return json.loads(blob)',
     "json, not pickle; no code execution on load."),
    ("APPSEC-06", "backend/appsec.py", 'allow_origins=["https://portal.example.org"]',
     "Explicit trusted origin, not a wildcard."),
    ("APPSEC-07", "backend/appsec.py", 'logger.info("incoming %s %s", request.method',
     "Logs only non-sensitive metadata (method + path), never the headers or body."),
]


def resolve(fixture: Path, rel: str, anchor: str) -> tuple[int, str]:
    path = fixture / rel
    if not path.exists():
        raise SystemExit(f"  MISSING FILE: {rel}")
    lines = path.read_text().splitlines()
    matches = [(i + 1, ln) for i, ln in enumerate(lines) if anchor in ln]
    if len(matches) == 0:
        raise SystemExit(f"  ANCHOR NOT FOUND in {rel}: {anchor!r}")
    if len(matches) > 1:
        raise SystemExit(f"  ANCHOR NOT UNIQUE in {rel} ({len(matches)}x): {anchor!r}")
    line_no, text = matches[0]
    return line_no, text.strip()


def main() -> int:
    baseline = json.loads(BASELINE.read_text())
    known_refs = set(baseline["regulations"])
    baseline_stamp = {"version": baseline["baseline_version"], "as_of": baseline["as_of"]}
    registry = json.loads(TAXONOMY.read_text())["findings"]

    seen_ids: set[str] = set()
    findings = []
    for fid, code, title, sev, source, rel, anchor, hipaa_ref, why, remediation in SPEC:
        if fid in seen_ids:
            raise SystemExit(f"DUPLICATE ID in spec: {fid}")
        if code not in CATEGORIES:
            raise SystemExit(f"UNKNOWN category code {code} on {fid}")
        if hipaa_ref not in known_refs:
            raise SystemExit(f"UNKNOWN hipaa_ref {hipaa_ref!r} on {fid} "
                             f"(not in regulatory-baseline {baseline_stamp['version']})")
        reg = registry.get(fid)
        if reg is None:
            raise SystemExit(f"{fid} is not in the canonical taxonomy registry "
                             f"(references/taxonomy.json)")
        drift = [f"{k} {reg[k]!r} != {v!r}" for k, v in
                 (("category", code), ("severity", sev), ("layer", source), ("hipaa_ref", hipaa_ref))
                 if reg[k] != v]
        if drift:
            raise SystemExit(f"{fid} disagrees with the taxonomy registry: " + "; ".join(drift))
        seen_ids.add(fid)
        line_no, snippet = resolve(VULN, rel, anchor)
        entry = {
            "id": fid,
            "category": code,
            "category_name": CATEGORIES[code][0],
            "title": title,
            "severity": sev,
            "source": source,
            "hipaa_ref": hipaa_ref,
            "file": rel,
            "line": line_no,
            "structural_snippet": snippet,
            "why": why,
            "remediation": remediation,
        }
        if fid in ALSO_DETECTABLE:
            if source != "reasoning":
                raise SystemExit(f"ALSO_DETECTABLE only applies to reasoning findings: {fid}")
            entry["also_detectable_by"] = ["deterministic"]
            det_anchor = ALSO_DETECTABLE[fid]
            entry["det_line"] = (resolve(VULN, rel, det_anchor)[0]
                                 if det_anchor else line_no)
        findings.append(entry)

    orphan_ids = set(registry) - seen_ids
    if orphan_ids:
        raise SystemExit(f"taxonomy registry ids with no fixture seed in SPEC: "
                         f"{sorted(orphan_ids)}")

    manifest = {
        "fixture": "vulnerable-health-app",
        "description": "Synthetic HIPAA-risk corpus. Exactly one seeded issue per canonical "
                       "finding id. This is the MUST-CATCH set for ClearMap precision/recall.",
        "taxonomy_version": "0.2",
        "regulatory_baseline": baseline_stamp,
        "categories": {code: {"name": n, "regulatory_anchor": r, "kind": k}
                       for code, (n, r, k) in CATEGORIES.items()},
        "must_catch": findings,
    }
    out = VULN / "expected-findings.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n")

    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    print(f"OK: regulatory baseline {baseline_stamp['version']} (as of {baseline_stamp['as_of']})")
    print(f"OK: resolved {len(findings)} findings across {len(by_cat)} categories")
    for code in CATEGORIES:
        if code in by_cat:
            print(f"  {code:10s} {by_cat[code]}  ({CATEGORIES[code][1]})")
    print(f"wrote {out.relative_to(HERE.parent)}")

    # --- safe fixture: zero must-catch, documented near-misses ---
    near = []
    for rel_id, rel, anchor, why in NEAR_MISSES:
        line_no, snippet = resolve(SAFE, rel, anchor)
        near.append({
            "relates_to": rel_id,
            "file": rel,
            "line": line_no,
            "structural_snippet": snippet,
            "why_clean": why,
        })
    safe_manifest = {
        "fixture": "safe-health-app",
        "description": "Clean counterpart of vulnerable-health-app. MUST-NOT-FLAG set: every "
                       "feature implemented correctly. near_misses are clean patterns that "
                       "over-broad rules might wrongly flag — they define the false-positive budget.",
        "taxonomy_version": "0.2",
        "regulatory_baseline": baseline_stamp,
        "must_catch": [],
        "near_misses": near,
    }
    safe_out = SAFE / "expected-findings.json"
    safe_out.write_text(json.dumps(safe_manifest, indent=2) + "\n")
    print(f"OK: safe fixture clean, {len(near)} near-misses documented")
    print(f"wrote {safe_out.relative_to(HERE.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
