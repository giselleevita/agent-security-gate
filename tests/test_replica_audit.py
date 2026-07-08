from __future__ import annotations

from pathlib import Path

from app import config


def test_replica_id_none_when_unset(monkeypatch):
    monkeypatch.delenv(config.REPLICA_ID_ENV, raising=False)
    assert config.replica_id() is None


def test_replica_id_blank_is_none(monkeypatch):
    monkeypatch.setenv(config.REPLICA_ID_ENV, "   ")
    assert config.replica_id() is None


def test_replica_id_sanitised(monkeypatch):
    monkeypatch.setenv(config.REPLICA_ID_ENV, "gateway/../evil id!")
    # Path separators, dots-as-traversal chars, spaces and punctuation collapse to '-'.
    rid = config.replica_id()
    assert rid is not None
    assert "/" not in rid and " " not in rid and "!" not in rid


def test_audit_log_path_unchanged_without_replica(monkeypatch):
    monkeypatch.delenv(config.REPLICA_ID_ENV, raising=False)
    monkeypatch.setenv(config.AUDIT_LOG_PATH_ENV, "/data/audit/events.jsonl")
    assert config.audit_log_path() == Path("/data/audit/events.jsonl")


def test_audit_log_path_suffixed_per_replica(monkeypatch):
    monkeypatch.setenv(config.AUDIT_LOG_PATH_ENV, "/data/audit/events.jsonl")
    monkeypatch.setenv(config.REPLICA_ID_ENV, "gw-abc123")
    assert config.audit_log_path() == Path("/data/audit/events-gw-abc123.jsonl")


def test_audit_log_path_distinct_per_replica(monkeypatch):
    monkeypatch.setenv(config.AUDIT_LOG_PATH_ENV, "audit/events.jsonl")
    monkeypatch.setenv(config.REPLICA_ID_ENV, "one")
    first = config.audit_log_path()
    monkeypatch.setenv(config.REPLICA_ID_ENV, "two")
    second = config.audit_log_path()
    assert first != second
    assert first.name == "events-one.jsonl"
    assert second.name == "events-two.jsonl"
