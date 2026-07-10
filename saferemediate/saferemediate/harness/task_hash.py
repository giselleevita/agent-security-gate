"""Deterministic task binding hash."""

from __future__ import annotations

import hashlib


def task_hash(task: str, session_id: str, tenant_id: str = "acme") -> str:
    payload = f"{tenant_id}:{session_id}:{task}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]
