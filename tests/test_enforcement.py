from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.main as main


class _FakeRedis:
    def __init__(self) -> None:
        self.kv: dict[str, str] = {}

    def set(self, name, value, ex=None):  # noqa: ARG002
        self.kv[name] = value
        return True

    def get(self, name):
        return self.kv.get(name)

    def getdel(self, name):
        return self.kv.pop(name, None)


@pytest.fixture
def fake_redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr(main, "_redis", lambda: r)
    return r


OP = '{"action":"tool_call","context":{"path":"/a"},"tool":"docs.read"}'


def test_off_mode_is_noop(fake_redis, monkeypatch):
    monkeypatch.delenv("ASG_ENFORCE_MODE", raising=False)
    # Neither a missing nor a present token triggers anything in off mode.
    main._enforce_tool_execution(audit_id=None, operation_key=OP)
    main._enforce_tool_execution(audit_id="evt_1", operation_key=OP)
    # Grants are not recorded when disabled.
    main._record_enforcement_grant("evt_1", OP)
    assert fake_redis.kv == {}


def test_strict_requires_audit_id(fake_redis, monkeypatch):
    monkeypatch.setenv("ASG_ENFORCE_MODE", "strict")
    with pytest.raises(HTTPException) as ei:
        main._enforce_tool_execution(audit_id=None, operation_key=OP)
    assert ei.value.status_code == 403


def test_strict_valid_grant_is_single_use(fake_redis, monkeypatch):
    monkeypatch.setenv("ASG_ENFORCE_MODE", "strict")
    main._record_enforcement_grant("evt_1", OP)
    assert fake_redis.kv[main._enforce_key("evt_1")] == OP

    # First use succeeds and consumes the grant.
    main._enforce_tool_execution(audit_id="evt_1", operation_key=OP)
    assert main._enforce_key("evt_1") not in fake_redis.kv

    # Replay is rejected.
    with pytest.raises(HTTPException) as ei:
        main._enforce_tool_execution(audit_id="evt_1", operation_key=OP)
    assert ei.value.status_code == 403


def test_strict_operation_mismatch_is_rejected(fake_redis, monkeypatch):
    monkeypatch.setenv("ASG_ENFORCE_MODE", "strict")
    main._record_enforcement_grant("evt_1", OP)
    with pytest.raises(HTTPException) as ei:
        main._enforce_tool_execution(audit_id="evt_1", operation_key="different-op")
    assert ei.value.status_code == 403


def test_permissive_allows_missing_but_verifies_present(fake_redis, monkeypatch):
    monkeypatch.setenv("ASG_ENFORCE_MODE", "permissive")
    # Missing token: allowed (migration mode).
    main._enforce_tool_execution(audit_id=None, operation_key=OP)
    # Present but unknown token: rejected (fail closed on explicit mismatch).
    with pytest.raises(HTTPException) as ei:
        main._enforce_tool_execution(audit_id="evt_x", operation_key=OP)
    assert ei.value.status_code == 403
    # Present and valid: consumed.
    main._record_enforcement_grant("evt_1", OP)
    main._enforce_tool_execution(audit_id="evt_1", operation_key=OP)
    assert main._enforce_key("evt_1") not in fake_redis.kv
