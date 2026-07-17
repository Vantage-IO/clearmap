"""Flask must-catch cases for rules/access.yaml.

Each block documents the rule that must fire. Companion safe_app.py holds the
must-not-catch near-misses. Verified by tests/test_access_rules.py.
"""
from flask import Flask, jsonify

app = Flask(__name__)

_PATIENTS: dict[str, dict] = {}


# MUST-CATCH access-flask-unauthenticated-phi-route: PHI route, only @app.route,
# no auth decorator.
@app.route("/patients/<patient_id>")
def get_patient(patient_id: str):
    return jsonify(_PATIENTS[patient_id])


# MUST-CATCH access-auth-disabled-flag: hardcoded auth kill-switch.
AUTH_DISABLED = True
