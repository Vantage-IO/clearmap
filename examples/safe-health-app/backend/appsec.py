# APPSEC safe counterparts: the same features implemented correctly. Every
# function here is the must-not-flag twin of a vulnerable seed. NOT runnable.
import json
import os
import subprocess
from urllib.parse import urlparse

import requests
from fastapi.middleware.cors import CORSMiddleware

DOCS_ROOT = "/srv/patient-docs"
ALLOWED_HOSTS = {"cdn.example.org"}


def find_patient(cur, name):
    # Parameterized query: the value can never change the statement.
    cur.execute("SELECT * FROM patients WHERE name = ?", (name,))
    return cur.fetchall()


def export_records(patient_id):
    # Argument list, no shell interpretation.
    subprocess.run(["tar", "czf", f"/backups/{patient_id}.tgz", f"/data/{patient_id}"],
                   shell=False, check=True)


def fetch_avatar(request):
    # URL host validated against an allowlist before fetching.
    url = request.query_params["url"]
    if urlparse(url).hostname in ALLOWED_HOSTS:
        return requests.get(url)
    raise ValueError("host not allowed")


def read_document(request):
    # basename strips any traversal before joining to the document root.
    name = os.path.basename(request.query_params["file"])
    with open(os.path.join(DOCS_ROOT, name)) as fh:
        return fh.read()


def load_session(blob):
    # json, not pickle.
    return json.loads(blob)


def make_app(app):
    # Explicit trusted origin, not a wildcard.
    app.add_middleware(CORSMiddleware, allow_origins=["https://portal.example.org"],
                       allow_credentials=True)
    return app
