from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from audit.events import append_hash_chained_event
from app.config import audit_log_path
from app.tracing import correlation_fields


class AuditWriteError(RuntimeError):
    """The audit event could not be persisted, so the decision must not be allowed."""


def append_audit_event(audit_id: str, event: dict[str, Any]) -> None:
    try:
        append_hash_chained_event(
            audit_log_path(),
            {
                "audit_id": audit_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **correlation_fields(),
                **event,
            },
        )
    except OSError as exc:
        raise AuditWriteError(f"audit event {audit_id} could not be written") from exc
