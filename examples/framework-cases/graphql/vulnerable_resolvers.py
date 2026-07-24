"""Strawberry GraphQL must-catch cases for the object-level-authorization rule (R9).

Each resolver takes an object id but never touches info.context (the authenticated
request) and never calls an ownership/authorization helper, so any caller can read
or mutate another patient's record by id (IDOR). Companion safe_resolvers.py holds
the must-not-catch near-misses. Verified by tests/test_access_rules.py.
"""
import strawberry
import strawberry_django

import db


@strawberry.type
class Query:
    # MUST-CATCH: reads a patient by id with no context / ownership check.
    @strawberry.field
    def patient(self, patient_id: str) -> dict:
        return db.get_patient(patient_id)

    # MUST-CATCH: async resolver, same gap.
    @strawberry.field
    async def record(self, record_id: str) -> dict:
        return await db.get_record(record_id)

    # MUST-CATCH: parenthesized decorator form, still no authorization.
    @strawberry.field(description="Fetch a lab result")
    def lab_result(self, result_id: str) -> dict:
        return db.get_lab(result_id)

    # MUST-CATCH: strawberry-django resolver keyed by id, no ownership check.
    @strawberry_django.field
    def encounter(self, encounter_id: str) -> dict:
        return db.get_encounter(encounter_id)


@strawberry.type
class Mutation:
    # MUST-CATCH: mutation keyed by id with no authorization.
    @strawberry.mutation
    def update_chart(self, chart_id: str, note: str) -> bool:
        return db.update_chart(chart_id, note)
