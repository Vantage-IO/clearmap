"""Patient CRUD endpoints (FastAPI-style)."""

from fastapi import APIRouter, Depends

from auth import current_user

router = APIRouter()

# Pretend ORM.
_PATIENTS: dict[str, dict] = {}


@router.get("/patients/{patient_id}")
def get_patient(patient_id: str):
    """Return a patient's full chart.

    AUTH-01: unguarded PHI endpoint. There is no authentication dependency on this
    route, so anyone who can reach the API can read any patient's chart by id.
    """
    return _PATIENTS[patient_id]


@router.post("/patients")
def create_patient(patient: dict, user=Depends(current_user)):
    """Create a new patient record.

    AUDIT-01: PHI create with no audit event. A new patient (PHI) is written and
    `audit.record_event` is never called, so the creation is untraceable.
    """
    _PATIENTS[patient["id"]] = patient
    return {"ok": True}


@router.patch("/patients/{patient_id}")
def update_patient(patient_id: str, changes: dict):
    """Update fields on a patient record.

    INTEGRITY-01: unauthenticated mutation of patient data. This mutating endpoint has no
    auth dependency at all — any caller can alter clinical fields (allergies,
    medications) on any patient.
    """
    _PATIENTS[patient_id].update(changes)
    return {"ok": True}


@router.delete("/patients/{patient_id}")
def delete_patient(patient_id: str, user=Depends(current_user)):
    """Delete a patient record.

    ACCESS-02: missing role check. The caller is authenticated, but there is no check
    that `user["role"]` is permitted to delete — any logged-in user, including
    a read-only front-desk account, can delete any patient.
    """
    _PATIENTS.pop(patient_id, None)
    return {"ok": True}
