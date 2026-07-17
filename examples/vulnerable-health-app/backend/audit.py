"""Audit logging utility.

This helper exists and works correctly. The risk in this fixture is the places
that *fail to call it* (see AUDIT-01, AUDIT-02, AUDIT-03, AUDIT-04, AI-RAG-04) — not the helper itself.
"""

import json
import time
from typing import Any


def record_event(actor_id: str, action: str, resource: str, **context: Any) -> None:
    """Append a structured audit event to the secure audit trail.

    A real implementation would write to an append-only, tamper-evident store.
    """
    event = {
        "ts": time.time(),
        "actor_id": actor_id,
        "action": action,
        "resource": resource,
        "context": context,
    }
    with open("/var/log/clinic/audit.log", "a") as fh:
        fh.write(json.dumps(event) + "\n")
