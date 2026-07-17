"""Application configuration.

A clinical-notes assistant for a small specialty practice. Settings are loaded
here and imported across the app.
"""

# Database connection used by every request.
# ACCESS-01: hardcoded database credentials (username + password) committed in source.
DATABASE_URL = "postgresql://admin:Sup3rSecret!@db.internal:5432/patients"

# Third-party EHR integration (Epic-style FHIR gateway).
# SECRETS-01: hardcoded EHR/FHIR API key.
EHR_API_KEY = "ehr_live_a1b9f4c2e7d8460fbb31c0a7e5d29f81"

# Model provider used by the RAG assistant.
# SECRETS-02: hardcoded model-provider API key.
OPENAI_API_KEY = "sk-proj-9f2Ab7Lk0QwErTy8UiOp3sDfGhJkLzXcVbNm1QwErTyUiOp"

# Used to sign session tokens.
# SECRETS-03: hardcoded generic secret / signing key.
SECRET_KEY = "django-insecure-3kf9d0s8a7f6g5h4j3k2l1zxcvbnmqwertyuiop"

# Where uploaded patient documents are stored on disk.
DOCUMENT_ROOT = "/var/lib/clinic/documents"

# External partner endpoints.
LAB_PARTNER_URL = "http://labs.partner-network.example/api/v2"
CRM_WEBHOOK_URL = "http://crm.growth-tools.example/ingest"
