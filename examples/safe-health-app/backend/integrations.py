"""Outbound integrations with external partners — TLS + data minimization."""

import requests

from config import LAB_PARTNER_URL


def fetch_lab_results(patient_mrn: str) -> dict:
    """Pull lab results over TLS from the lab partner (BAA in place)."""
    resp = requests.get(f"{LAB_PARTNER_URL}/results/{patient_mrn}", timeout=10)
    return resp.json()


def sync_patient_to_crm(patient: dict) -> None:
    """Notify the (BAA-covered) follow-up system using a non-PHI opaque id only.

    No name, DOB, email, or diagnosis leaves the boundary — just an internal id
    the CRM cannot resolve to a person on its own.
    """
    requests.post(
        "https://crm.internal.example/ingest",
        json={"patient_ref": patient["id"]},
        timeout=10,
    )
