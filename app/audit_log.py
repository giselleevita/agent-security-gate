from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from audit.events import append_hash_chained_event
from app.config import audit_log_path


def append_audit_event(audit_id: str, event: dict[str, Any]) -> None:
    append_hash_chained_event(
        audit_log_path(),
        {
            "audit_id": audit_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        },
    )
