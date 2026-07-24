"""Strawberry GraphQL must-NOT-catch near-misses for the object-level-auth rule.

Every resolver here enforces access: it reads the authenticated principal from
info.context and/or calls an ownership/authorization helper before returning an
object. None may fire.
"""
import strawberry

import db
from authz import require_ownership, ensure_can_edit


@strawberry.type
class Query:
    # NEAR-MISS: authorizes via info.context + an ownership check.
    @strawberry.field
    def patient(self, info: strawberry.Info, patient_id: str) -> dict:
        require_ownership(info.context.user, patient_id)
        return db.get_patient(patient_id)

    # NEAR-MISS: derives the id from the authenticated context (no external id).
    @strawberry.field
    def my_chart(self, info: strawberry.Info) -> dict:
        return db.get_patient(info.context.user.id)

    # NEAR-MISS: no id parameter at all, so there is nothing to authorize per-object.
    @strawberry.field
    def clinics(self) -> list:
        return db.list_clinics()

    # NEAR-MISS: parenthesized decorator, but authorized via info.context.
    @strawberry.field(description="Fetch a lab result")
    def lab_result(self, info: strawberry.Info, result_id: str) -> dict:
        require_ownership(info.context.user, result_id)
        return db.get_lab(result_id)


@strawberry.type
class Mutation:
    # NEAR-MISS: ownership helper guards the mutation.
    @strawberry.mutation
    def update_chart(self, chart_id: str, note: str) -> bool:
        ensure_can_edit(chart_id)
        return db.update_chart(chart_id, note)
