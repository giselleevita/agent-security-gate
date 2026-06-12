from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import HTTPException

from app.config import opa_url, policy_data_path
from app.schemas import DecideRequest


def load_policy_config() -> dict[str, Any]:
    raw = json.loads(policy_data_path().read_text(encoding="utf-8"))
    return {
        "allowed_tools": list(raw.get("allowed_tools", [])),
        "denied_doc_prefixes": list(raw.get("denied_doc_prefixes", [])),
        "denied_doc_ids": list(raw.get("denied_doc_ids", [])),
        "output_max_chars": int(raw.get("output_max_chars", 2000)),
        "approval_required_tools": list(raw.get("approval_required_tools", [])),
        "http_allowlist": list(raw.get("http_allowlist", [])),
        "max_actions": int(raw.get("max_actions", 50)),
    }


def build_opa_input(body: DecideRequest, policy_config: dict[str, Any], *, action_count: int) -> dict[str, Any]:
    ctx = dict(body.context)
    if "output_length" not in ctx:
        ctx["output_length"] = 0
    return {
        "tenant_id": body.tenant_id,
        "session_id": body.session_id,
        "action": body.action,
        "tool": body.tool,
        "mode": body.mode,
        "context": ctx,
        "session": {"action_count": action_count},
        "config": policy_config,
    }


def opa_post(client: httpx.Client, path: str, opa_input: dict[str, Any]) -> Any:
    r = client.post(
        f"{opa_url()}{path}",
        json={"input": opa_input},
        headers={"Content-Type": "application/json"},
        timeout=10.0,
    )
    r.raise_for_status()
    data = r.json()
    if "result" not in data:
        raise HTTPException(status_code=502, detail="OPA response missing result")
    return data["result"]
