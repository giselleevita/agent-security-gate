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

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

__all__ = [
    "AsgClient",
    "AsgError",
    "AsgDenied",
    "AsgRecoveryError",
    "Decision",
    "GatedTool",
    "RecoveryController",
    "RemediationAction",
    "RemediationAdvice",
]


class AsgError(Exception):
    """Base error for SDK failures."""


class AsgRecoveryError(AsgError):
    """Raised when a proposed recovery violates the gateway's remediation contract."""


@dataclass(frozen=True)
class RemediationAction:
    type: str
    tool: str | None = None
    requires_user_input: bool = False

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RemediationAction":
        return cls(
            type=str(value["type"]),
            tool=str(value["tool"]) if value.get("tool") is not None else None,
            requires_user_input=bool(value.get("requires_user_input", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "tool": self.tool,
            "requires_user_input": self.requires_user_input,
        }


@dataclass(frozen=True)
class RemediationAdvice(Mapping[str, Any]):
    """Typed remediation that remains usable as a read-only dictionary."""

    version: str
    category_code: str
    message: str
    retry_mode: str
    next_actions: tuple[RemediationAction, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any] | None) -> "RemediationAdvice | None":
        if value is None:
            return None
        return cls(
            version=str(value.get("version", "1")),
            category_code=str(value["category_code"]),
            message=str(value.get("message", "")),
            retry_mode=str(value.get("retry_mode", "never")),
            next_actions=tuple(
                RemediationAction.from_dict(action)
                for action in value.get("next_actions", [])
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "category_code": self.category_code,
            "message": self.message,
            "retry_mode": self.retry_mode,
            "next_actions": [action.to_dict() for action in self.next_actions],
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return 5


class AsgDenied(AsgError):
    """Raised when the gateway denies (or requires approval for) an operation."""

    def __init__(
        self,
        reason: str,
        approval_url: str | None = None,
        remediation: RemediationAdvice | Mapping[str, Any] | None = None,
        denied_tool: str | None = None,
        denied_context: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(f"operation denied by policy: {reason}")
        self.reason = reason
        self.approval_url = approval_url
        self.remediation = (
            remediation
            if isinstance(remediation, RemediationAdvice)
            else RemediationAdvice.from_dict(remediation)
        )
        self.remediation_raw = self.remediation.to_dict() if self.remediation else None
        self.denied_tool = denied_tool
        self.denied_context = dict(denied_context or {})


@dataclass
class Decision:
    allowed: bool
    reason: str
    audit_id: str
    approval_url: str | None = None
    remediation: RemediationAdvice | None = None


def _operation_fingerprint(tool: str, context: Mapping[str, Any]) -> str:
    return json.dumps(
        {"tool": tool, "context": dict(context)},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


class RecoveryController:
    """Opt-in guardrail for choosing one advertised post-denial action."""

    def __init__(self, client: "AsgClient", denial: AsgDenied) -> None:
        if denial.remediation is None:
            raise AsgRecoveryError("the denial did not include remediation advice")
        self._client = client
        self._denial = denial

    def validate(self, action_type: str, tool: str, context: Mapping[str, Any]) -> None:
        matches = [
            action
            for action in self._denial.remediation.next_actions
            if action.type == action_type
        ]
        if not matches:
            raise AsgRecoveryError(f"recovery action is not permitted: {action_type}")
        if not any(action.tool is None or action.tool == tool for action in matches):
            raise AsgRecoveryError(
                f"recovery action {action_type} does not permit tool {tool}"
            )
        if self._denial.denied_tool and _operation_fingerprint(
            self._denial.denied_tool, self._denial.denied_context
        ) == _operation_fingerprint(tool, context):
            raise AsgRecoveryError("recovery must not repeat the identical denied operation")

    def guard(
        self,
        action_type: str,
        tool: str,
        context: dict[str, Any],
        *,
        action: str = "tool_call",
    ) -> str:
        """Validate the recovery choice and obtain a fresh gateway decision."""
        self.validate(action_type, tool, context)
        return self._client.guard(tool, context, action=action)


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
            remediation=RemediationAdvice.from_dict(data.get("remediation")),
        )

    def guard(self, tool: str, context: dict[str, Any], *, action: str = "tool_call") -> str:
        """Return the ``audit_id`` for an allowed operation, else raise ``AsgDenied``.

        Use this to gate a custom side effect the SDK does not wrap directly::

            audit_id = client.guard("db.write", {"query": q})
            do_write(q)  # only reached if allowed
        """
        decision = self.decide(tool, context, action=action)
        if not decision.allowed:
            raise AsgDenied(
                decision.reason,
                decision.approval_url,
                decision.remediation,
                denied_tool=tool,
                denied_context=context,
            )
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
            raise AsgDenied(
                decision.reason,
                decision.approval_url,
                decision.remediation,
                denied_tool="http.get",
                denied_context={"url": url, "method": method},
            )
        return self._execute("/v1/http/proxy", {"url": url, "method": method}, decision.audit_id)

    def docs_read(self, path: str, *, doc_id: str | None = None) -> dict[str, Any]:
        context: dict[str, Any] = {"path": path}
        if doc_id is not None:
            context["doc_id"] = doc_id
        decision = self.decide("docs.read", context)
        if not decision.allowed:
            raise AsgDenied(
                decision.reason,
                decision.approval_url,
                decision.remediation,
                denied_tool="docs.read",
                denied_context=context,
            )
        return self._execute("/v1/docs/read", {"path": path, "doc_id": doc_id}, decision.audit_id)

    def recovery(self, denial: AsgDenied) -> RecoveryController:
        return RecoveryController(self, denial)

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
