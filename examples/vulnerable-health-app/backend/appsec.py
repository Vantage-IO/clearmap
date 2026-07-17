# APPSEC demo: general application-security weaknesses in a PHI service.
# NOT runnable production code. Each function seeds exactly one canonical
# APPSEC finding for the corpus.
import os
import pickle

import requests
from fastapi.middleware.cors import CORSMiddleware

DOCS_ROOT = "/srv/patient-docs"


def find_patient(cur, name):
    # APPSEC-01: request value built straight into a raw SQL statement.
    cur.execute(f"SELECT * FROM patients WHERE name = '{name}'")
    return cur.fetchall()


def export_records(patient_id):
    # APPSEC-02: shell command string built from input.
    os.system(f"tar czf /backups/{patient_id}.tgz /data/{patient_id}")


def fetch_avatar(request):
    # APPSEC-03: SSRF, outbound URL taken directly from request input.
    return requests.get(request.query_params["url"])


def read_document(request):
    # APPSEC-04: document path joined from request input with no normalization.
    with open(os.path.join(DOCS_ROOT, request.query_params["file"])) as fh:
        return fh.read()


def load_session(blob):
    # APPSEC-05: untrusted bytes deserialized with pickle.
    return pickle.loads(blob)


def make_app(app):
    # APPSEC-06: wildcard CORS combined with credentials.
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
    return app
