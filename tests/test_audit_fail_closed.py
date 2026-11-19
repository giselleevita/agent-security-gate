"""An allow decision must not stand if its audit event cannot be persisted."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.audit_log as audit_log
import app.decision as decision
from app.audit_log import AuditWriteError, append_audit_event


def _failing_append(*_args, **_kwargs):
    raise OSError("disk full")


def test_unwritable_audit_log_raises_audit_write_error(monkeypatch, tmp_path):
    monkeypatch.setattr(audit_log, "append_hash_chained_event", _failing_append)
    monkeypatch.setattr(audit_log, "audit_log_path", lambda: tmp_path / "audit.jsonl")

    with pytest.raises(AuditWriteError):
        append_audit_event("evt_test", {"response": {"allowed": True}})


def test_decision_is_denied_when_audit_cannot_be_written(monkeypatch, tmp_path):
    monkeypatch.setattr(audit_log, "append_hash_chained_event", _failing_append)
    monkeypatch.setattr(audit_log, "audit_log_path", lambda: tmp_path / "audit.jsonl")

    def impl_that_would_allow(**_kwargs):
        # Stands in for the real decision path: it allows, then tries to record the allow.
        append_audit_event("evt_allow", {"response": {"allowed": True}})
        raise AssertionError("unreachable: the audit write above must fail")

    monkeypatch.setattr(decision, "decide_tool_call_impl", impl_that_would_allow)
    body = SimpleNamespace(tenant_id="tenant-a", tool="docs.read", action="tool_call")

    response = decision.decide_tool_call(body=body, resume_token=None, x_requester_id=None)

    assert response.allowed is False
    assert response.reason == "audit_unavailable"
