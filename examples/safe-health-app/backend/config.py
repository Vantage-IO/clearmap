"""Application configuration — secrets loaded from the environment.

Clean counterpart to vulnerable-health-app/backend/config.py. Nothing
sensitive is hardcoded; every credential comes from the environment / secret
manager at runtime.
"""

import os

DATABASE_URL = os.environ["DATABASE_URL"]
EHR_API_KEY = os.environ["EHR_API_KEY"]
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
SECRET_KEY = os.environ["SECRET_KEY"]

DOCUMENT_ROOT = os.environ.get("DOCUMENT_ROOT", "/var/lib/clinic/documents")

# PHI partners are reached over TLS only.
LAB_PARTNER_URL = "https://labs.partner-network.example/api/v2"

# NEAR-MISS: a non-PHI internal readiness probe over plain http. A naive
# "http:// in source" rule would flag this; it carries no PHI and is localhost.
HEALTHCHECK_URL = "http://localhost:8080/healthz"

# NEAR-MISS: a templated placeholder, not a real credential — the deploy
# tooling substitutes the value. A naive secret rule keys on the assignment.
SMTP_PASSWORD = "${SMTP_PASSWORD}"

# NEAR-MISS: a sample DB connection string whose password is a ${...} template,
# substituted at deploy time. A scheme-agnostic db-uri rule would flag it; the
# placeholder-guarded rule must not (the password is not a real credential).
SAMPLE_DB_URL = "postgresql://app:${DB_PASSWORD}@db.internal:5432/app"
