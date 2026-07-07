from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
from fastapi import HTTPException

from app.config import opa_url, policy_data_path, tenant_policy_strict
from app.schemas import DecideRequest

# Tenant identifiers used to build a filesystem path must be strictly bounded so a
# hostile `tenant_id` cannot traverse directories or escape the tenants root.
_SAFE_TENANT_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _normalize_policy(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "allowed_tools": list(raw.get("allowed_tools", [])),
        "denied_doc_prefixes": list(raw.get("denied_doc_prefixes", [])),
        "denied_doc_ids": list(raw.get("denied_doc_ids", [])),
        "output_max_chars": int(raw.get("output_max_chars", 2000)),
        "approval_required_tools": list(raw.get("approval_required_tools", [])),
        "dual_approval_tools": list(raw.get("dual_approval_tools", [])),
        "allowed_http_domains": list(raw.get("allowed_http_domains", [])),
        "max_actions": int(raw.get("max_actions", 50)),
    }


def tenant_policy_path(tenant_id: str) -> Path | None:
    """
    Path to a tenant's dedicated policy file (`.../tenants/{tenant_id}/policy_data.json`),
    or None if `tenant_id` is not a safe, single path segment.
    """
    if not _SAFE_TENANT_ID.match(tenant_id or ""):
        return None
    # Reject dot-only segments ('.', '..') which pass the charset check but resolve to
    # the current/parent directory.
    if set(tenant_id) == {"."}:
        return None
    return policy_data_path().parent / "tenants" / tenant_id / "policy_data.json"


def tenant_known(tenant_id: str | None) -> bool:
    """
    Whether the tenant may be served. In strict mode a tenant is known only if it has a
    dedicated policy file; otherwise all tenants are known (they fall back to default).
    """
    if not tenant_policy_strict():
        return True
    path = tenant_policy_path(tenant_id or "")
    return path is not None and path.is_file()


def load_policy_config(tenant_id: str | None = None) -> dict[str, Any]:
    """
    Resolve the effective policy config for a tenant.

    A per-tenant file at `.../tenants/{tenant_id}/policy_data.json` fully overrides the
    default policy so tenants never share allow/deny rules. When no per-tenant file
    exists the default file is used (in strict mode the caller should first reject the
    request via `tenant_known`, so the default is never silently applied to an unknown
    tenant).
    """
    if tenant_id:
        path = tenant_policy_path(tenant_id)
        if path is not None and path.is_file():
            return _normalize_policy(json.loads(path.read_text(encoding="utf-8")))
    return _normalize_policy(json.loads(policy_data_path().read_text(encoding="utf-8")))


def build_opa_input(
    body: DecideRequest,
    policy_config: dict[str, Any],
    *,
    action_count: int,
    active_exceptions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ctx = dict(body.context)
    # Derive output_length from the output ASG can actually see rather than trusting a
    # caller-supplied value, so the OPA output cap cannot be bypassed by understating it.
    tool_output = ctx.get("tool_output")
    if isinstance(tool_output, str):
        ctx["output_length"] = len(tool_output)
    elif "output_length" not in ctx:
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
        "active_exceptions": active_exceptions or [],
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
