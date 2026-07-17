"""Outbound integrations with external partners."""

import requests

from config import CRM_WEBHOOK_URL


def fetch_lab_results(patient_mrn: str) -> dict:
    """Pull lab results for a patient from the lab partner.

    TRANSIT-01: PHI transmitted over a non-TLS endpoint. The lab partner is called over
    plain `http://` (see config.LAB_PARTNER_URL), so the patient MRN and the
    returned results travel unencrypted.
    """
    resp = requests.get(f"http://labs.partner-network.example/api/v2/results/{patient_mrn}")
    return resp.json()


def sync_patient_to_crm(patient: dict) -> None:
    """Push a patient to the growth/CRM tool for follow-up campaigns.

    TRANSIT-03: a full patient object containing PHI (name, dob, diagnosis) is sent to
    a third-party marketing system, and over plain http at that.
    """
    requests.post(
        CRM_WEBHOOK_URL,
        json={
            "name": patient["name"],
            "dob": patient["dob"],
            "email": patient["email"],
            "diagnosis": patient["diagnosis"],
        },
    )


def fetch_internal_record(patient_mrn: str) -> dict:
    """Fetch a chart from the internal records microservice (same VPC / cluster).

    TRANSIT-04: internal service-to-service PHI over cleartext http. The host is
    inside a trusted boundary (a private cluster service name), so this is a
    LOW-severity ADVISORY, not a hard finding: cleartext here is defensible where
    documented and backed by compensating controls (network segmentation, access
    control) per 164.306(d)(3) — though zero-trust best practice is to encrypt
    in transit on internal hops too. Contrast TRANSIT-01 (external = hard).
    """
    resp = requests.get(f"http://records.internal.svc.cluster.local:8080/records/{patient_mrn}")
    return resp.json()
