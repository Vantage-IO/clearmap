"""FastAPI must-catch cases for the Depends-aware access rules (R1).

A PHI route whose ONLY dependency is a non-auth provider (a DB/session/settings/
pagination helper) is still unauthenticated. Companion safe_deps.py holds the
must-not-catch near-misses. Verified by tests/test_access_rules.py.
"""
from fastapi import APIRouter, Depends

from db import get_db, get_session
from settings import get_settings
from pagination import paginate

router = APIRouter()


# MUST-CATCH access-fastapi-unauthenticated-phi-read: only a DB session provider.
@router.get("/patients/{patient_id}")
def get_patient(patient_id: str, db=Depends(get_db)):
    return db.get(patient_id)


# MUST-CATCH access-fastapi-unauthenticated-phi-read: DB + settings + pagination,
# none of which authenticate the caller.
@router.get("/patients/{patient_id}/labs")
def list_labs(patient_id: str, db=Depends(get_session),
              cfg=Depends(get_settings), page=Depends(paginate)):
    return db.labs(patient_id, page)


# MUST-CATCH access-fastapi-unauthenticated-phi-mutation: mutation guarded only
# by a DB dependency.
@router.patch("/patients/{patient_id}")
def update_patient(patient_id: str, changes: dict, db=Depends(get_db)):
    db.update(patient_id, changes)
    return {"ok": True}
