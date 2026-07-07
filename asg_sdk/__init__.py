"""
Agent Security Gate connector SDK.

Enforcement contract (see docs/connector-sdk.md):

1. Call ``/v1/gateway/decide`` **before** performing a side effect.
2. Pass the returned ``audit_id`` to the tool/adapter call.
3. Adapters refuse to run without a matching prior allow (in ``ASG_ENFORCE_MODE=strict``).

This client wires those three steps together so an agent physically cannot execute a gated
tool without first obtaining an allow decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import httpx

__all__ = ["AsgClient", "AsgError", "AsgDenied", "Decision", "GatedTool"]


class AsgError(Exception):
    """Base error for SDK failures."""


class AsgDenied(AsgError):
    """Raised when the gateway denies (or requires approval for) an operation."""

    def __init__(self, reason: str, approval_url: str | None = None) -> None:
        super().__init__(f"operation denied by policy: {reason}")
        self.reason = reason
        self.approval_url = approval_url


@dataclass
class Decision:
    allowed: bool
    reason: str
    audit_id: str
    approval_url: str | None = None


class AsgClient:
    """Thin client that couples a policy decision to the subsequent tool execution."""

    def __init__(
        self,
        base_url: str,
        token: str,
        tenant_id: str,
        *,
        session_id: str = "default-session",
        requester_id: str | None = None,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._tenant_id = tenant_id
        self._session_id = session_id
        self._headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
        if requester_id:
            self._headers["X-Requester-Id"] = requester_id
        self._client = client or httpx.Client(base_url=self._base_url, timeout=timeout)

    # -- core -----------------------------------------------------------------------------

    def decide(self, tool: str, context: dict[str, Any], *, action: str = "tool_call") -> Decision:
        """Ask the gateway whether ``tool`` may run with ``context``. No side effect."""
        resp = self._client.post(
            "/v1/gateway/decide",
            json={
                "tenant_id": self._tenant_id,
                "session_id": self._session_id,
                "action": action,
                "tool": tool,
                "context": context,
            },
            headers=self._headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return Decision(
            allowed=bool(data["allowed"]),
            reason=str(data["reason"]),
            audit_id=str(data["audit_id"]),
            approval_url=data.get("approval_url"),
        )

    def guard(self, tool: str, context: dict[str, Any], *, action: str = "tool_call") -> str:
        """Return the ``audit_id`` for an allowed operation, else raise ``AsgDenied``.

        Use this to gate a custom side effect the SDK does not wrap directly::

            audit_id = client.guard("db.write", {"query": q})
            do_write(q)  # only reached if allowed
        """
        decision = self.decide(tool, context, action=action)
        if not decision.allowed:
            raise AsgDenied(decision.reason, decision.approval_url)
        return decision.audit_id

    def _execute(self, path: str, payload: dict[str, Any], audit_id: str) -> dict[str, Any]:
        resp = self._client.post(
            path,
            json=payload,
            headers={**self._headers, "X-ASG-Audit-Id": audit_id},
        )
        resp.raise_for_status()
        return resp.json()

    # -- built-in gated tools -------------------------------------------------------------

    def http_get(self, url: str, *, method: str = "GET") -> dict[str, Any]:
        decision = self.decide("http.get", {"url": url, "method": method})
        if not decision.allowed:
            raise AsgDenied(decision.reason, decision.approval_url)
        return self._execute("/v1/http/proxy", {"url": url, "method": method}, decision.audit_id)

    def docs_read(self, path: str, *, doc_id: str | None = None) -> dict[str, Any]:
        context: dict[str, Any] = {"path": path}
        if doc_id is not None:
            context["doc_id"] = doc_id
        decision = self.decide("docs.read", context)
        if not decision.allowed:
            raise AsgDenied(decision.reason, decision.approval_url)
        return self._execute("/v1/docs/read", {"path": path, "doc_id": doc_id}, decision.audit_id)

    # -- lifecycle ------------------------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AsgClient":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class GatedTool:
    """
    Wrap a side-effecting callable so it can only run after an allow decision.

    The wrapped function is invoked with the same context kwargs plus an ``audit_id`` so the
    underlying adapter can present it for strict-mode enforcement::

        write = GatedTool(client, "db.write", lambda audit_id, query: db.execute(query))
        write(query="update ...")  # raises AsgDenied unless policy allows it
    """

    def __init__(self, client: AsgClient, tool: str, fn: Callable[..., Any]) -> None:
        self._client = client
        self._tool = tool
        self._fn = fn

    def __call__(self, **context: Any) -> Any:
        audit_id = self._client.guard(self._tool, context)
        return self._fn(audit_id=audit_id, **context)
