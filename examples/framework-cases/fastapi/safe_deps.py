"""FastAPI must-NOT-catch near-misses for the Depends-aware access rules (R1/R2).

Each PHI route here IS authenticated, so none may fire. The auth guard appears
in every supported form: a per-route auth dependency alongside a DB dependency,
a plain auth dependency, and a route-level dependencies=[...] list.
"""
from fastapi import APIRouter, Depends

from auth import require_user, get_current_user, verify_token
from db import get_db

router = APIRouter()


# NEAR-MISS: auth dependency present (require_user); the DB dependency is incidental.
@router.get("/patients/{patient_id}")
def get_patient(patient_id: str, user=Depends(require_user), db=Depends(get_db)):
    return db.get(patient_id)


# NEAR-MISS: authenticated by current_user.
@router.get("/patients/{patient_id}/chart")
def get_chart(patient_id: str, principal=Depends(get_current_user)):
    return {"patient_id": patient_id}


# NEAR-MISS: route-level dependencies=[...] applies the auth guard.
@router.patch("/patients/{patient_id}", dependencies=[Depends(verify_token)])
def update_patient(patient_id: str, changes: dict, db=Depends(get_db)):
    db.update(patient_id, changes)
    return {"ok": True}
