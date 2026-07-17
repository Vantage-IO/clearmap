"""Flask must-NOT-catch near-misses for rules/access.yaml."""
import os

from flask import Flask, jsonify
from flask_login import login_required

app = Flask(__name__)

_PATIENTS: dict[str, dict] = {}


# NEAR-MISS: same PHI route shape, guarded by an auth decorator.
@app.route("/patients/<patient_id>")
@login_required
def get_patient(patient_id: str):
    return jsonify(_PATIENTS[patient_id])


# NEAR-MISS: non-PHI route needs no auth decorator to stay silent.
@app.route("/healthz")
def healthz():
    return "ok"


# NEAR-MISS: auth toggle sourced from the environment, not hardcoded.
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "false") == "true"
