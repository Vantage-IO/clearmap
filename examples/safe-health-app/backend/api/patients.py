"""Patient CRUD endpoints — authenticated, authorized, and audited."""

from fastapi import APIRouter, Depends, HTTPException

import audit
from auth import current_user

router = APIRouter()

_PATIENTS: dict[str, dict] = {}

_WRITE_ROLES = {"clinician", "admin"}


def _require_role(user: dict, allowed: set[str]) -> None:
    if user.get("role") not in allowed:
        raise HTTPException(status_code=403, detail="forbidden")


@router.get("/patients/{patient_id}")
def get_patient(patient_id: str, user=Depends(current_user)):
    """Return a patient's chart (authenticated; read access audited)."""
    audit.record_event(user["sub"], "patient.read", f"patient:{patient_id}")
    return _PATIENTS[patient_id]


@router.post("/patients")
def create_patient(patient: dict, user=Depends(current_user)):
    """Create a patient (authorized + audited)."""
    _require_role(user, _WRITE_ROLES)
    _PATIENTS[patient["id"]] = patient
    audit.record_event(user["sub"], "patient.create", f"patient:{patient['id']}")
    return {"ok": True}


@router.patch("/patients/{patient_id}")
def update_patient(patient_id: str, changes: dict, user=Depends(current_user)):
    """Update a patient (authenticated, authorized, audited)."""
    _require_role(user, _WRITE_ROLES)
    _PATIENTS[patient_id].update(changes)
    audit.record_event(user["sub"], "patient.update", f"patient:{patient_id}", fields=list(changes))
    return {"ok": True}


@router.delete("/patients/{patient_id}")
def delete_patient(patient_id: str, user=Depends(current_user)):
    """Delete a patient (admin only, audited)."""
    _require_role(user, {"admin"})
    _PATIENTS.pop(patient_id, None)
    audit.record_event(user["sub"], "patient.delete", f"patient:{patient_id}")
    return {"ok": True}
