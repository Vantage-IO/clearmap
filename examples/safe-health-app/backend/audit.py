"""Audit logging utility (identical to the vulnerable fixture's helper).

The difference between the two fixtures is not this helper — it is that the
safe app actually *calls* it on every PHI access path.
"""

import json
import time
from typing import Any


def record_event(actor_id: str, action: str, resource: str, **context: Any) -> None:
    event = {
        "ts": time.time(),
        "actor_id": actor_id,
        "action": action,
        "resource": resource,
        "context": context,
    }
    with open("/var/log/clinic/audit.log", "a") as fh:
        fh.write(json.dumps(event) + "\n")
