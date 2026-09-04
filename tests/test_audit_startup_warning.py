from __future__ import annotations

import logging

from app.main import _warn_if_audit_unsigned


def test_warns_when_enforcing_without_hmac_key(monkeypatch, caplog) -> None:
    monkeypatch.setenv("ASG_ENFORCE_MODE", "strict")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="asg.audit"):
        _warn_if_audit_unsigned()
    assert any("AUDIT_HMAC_KEY is not set" in r.message for r in caplog.records)


def test_silent_when_key_present(monkeypatch, caplog) -> None:
    monkeypatch.setenv("ASG_ENFORCE_MODE", "strict")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "a-key")
    with caplog.at_level(logging.WARNING, logger="asg.audit"):
        _warn_if_audit_unsigned()
    assert caplog.records == []


def test_silent_when_enforcement_off(monkeypatch, caplog) -> None:
    monkeypatch.setenv("ASG_ENFORCE_MODE", "off")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="asg.audit"):
        _warn_if_audit_unsigned()
    assert caplog.records == []
