from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from audit import events as audit_events
from audit import sinks
from audit.events import append_hash_chained_event
from scripts.verify_audit import verify


@pytest.fixture(autouse=True)
def _reset_sink():
    sinks.reset_external_sink()
    yield
    sinks.reset_external_sink()


# --- HMAC signing / verification --------------------------------------------------------


def test_hmac_signed_chain_verifies_and_detects_tamper(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "super-secret-key")
    path = tmp_path / "events.jsonl"
    append_hash_chained_event(path, {"a": 1})
    append_hash_chained_event(path, {"b": 2})

    # Every entry carries a signature.
    for line in path.read_text(encoding="utf-8").splitlines():
        assert "signature" in json.loads(line)

    assert verify(path, hmac_key="super-secret-key") is True
    # Chain-only verification (no key) still passes; signature is additive.
    assert verify(path) is True
    # Wrong key fails.
    assert verify(path, hmac_key="wrong-key") is False


def test_signature_forgery_requires_key(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "k1")
    path = tmp_path / "events.jsonl"
    append_hash_chained_event(path, {"a": 1})

    # Attacker rewrites the event and recomputes the hash chain but cannot forge the sig.
    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    import hashlib

    tampered_event = {"a": 999}
    canonical = json.dumps(tampered_event, sort_keys=True, separators=(",", ":"))
    obj["event"] = tampered_event
    obj["hash"] = hashlib.sha256((obj["previous_hash"] + canonical).encode()).hexdigest()
    path.write_text(json.dumps(obj) + "\n", encoding="utf-8")

    # Recomputed chain passes chain-only check but fails signature check.
    assert verify(path) is True
    assert verify(path, hmac_key="k1") is False


# --- Local file sink --------------------------------------------------------------------


def test_local_file_sink_appends_json_lines(tmp_path: Path):
    path = tmp_path / "sink.jsonl"
    sink = sinks.LocalFileSink(path)
    sink.emit({"hash": "h1", "event": {"x": 1}})
    sink.emit({"hash": "h2", "event": {"x": 2}})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(x)["hash"] for x in lines] == ["h1", "h2"]


# --- S3 Object Lock sink ----------------------------------------------------------------


class _FakeS3Client:
    def __init__(self):
        self.objects: dict[str, dict] = {}
        self.calls: list[dict] = []

    def put_object(self, **params):
        self.calls.append(params)
        self.objects[params["Key"]] = params


def test_s3_sink_writes_content_addressed_objects_with_object_lock():
    fake = _FakeS3Client()
    sink = sinks.S3ObjectLockSink(
        bucket="audit-bucket",
        prefix="asg/",
        retention_days=7,
        object_lock_mode="COMPLIANCE",
        client=fake,
    )
    wrapper = {"previous_hash": "0" * 64, "hash": "abc123", "event": {"k": "v"}}
    sink.emit(wrapper)

    assert "asg/abc123.json" in fake.objects
    call = fake.calls[0]
    assert call["Bucket"] == "audit-bucket"
    assert call["ContentType"] == "application/json"
    assert call["ObjectLockMode"] == "COMPLIANCE"
    assert isinstance(call["ObjectLockRetainUntilDate"], datetime)
    assert json.loads(call["Body"].decode("utf-8"))["hash"] == "abc123"


def test_s3_sink_without_retention_omits_object_lock():
    fake = _FakeS3Client()
    sink = sinks.S3ObjectLockSink(bucket="b", client=fake)
    sink.emit({"hash": "h", "event": {}})
    assert "ObjectLockMode" not in fake.calls[0]


# --- Async worker + fan-out from events.py ---------------------------------------------


def test_async_worker_drains_to_wrapped_sink(tmp_path: Path):
    captured: list[dict] = []

    class _Capture(sinks.AuditSink):
        def emit(self, wrapper):
            captured.append(wrapper)

    worker = sinks.AsyncSinkWorker(_Capture())
    try:
        for i in range(5):
            worker.emit({"hash": f"h{i}", "event": {"i": i}})
        worker.flush()
    finally:
        worker.close()
    assert [w["hash"] for w in captured] == [f"h{i}" for i in range(5)]


def test_events_fan_out_to_external_sink_and_bundle_verifies(tmp_path: Path, monkeypatch):
    captured: list[dict] = []

    class _Capture(sinks.AuditSink):
        def emit(self, wrapper):
            captured.append(wrapper)

    # Force get_external_sink() to return our capture worker regardless of S3 config.
    # events.py imported the name directly, so patch it on the events module.
    _capture_worker = sinks.AsyncSinkWorker(_Capture())
    monkeypatch.setattr(audit_events, "get_external_sink", lambda: _capture_worker)

    path = tmp_path / "events.jsonl"
    try:
        append_hash_chained_event(path, {"a": 1})
        append_hash_chained_event(path, {"b": 2})
        append_hash_chained_event(path, {"c": 3})
        _capture_worker.flush()
    finally:
        _capture_worker.close()

    # External sink saw the same signed wrappers as the local file.
    local_lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert [w["hash"] for w in captured] == [w["hash"] for w in local_lines]

    # Reassemble a downloaded S3-style bundle (unordered files) and verify by chain-follow.
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for w in reversed(captured):  # intentionally out of order
        (bundle / f"{w['hash']}.json").write_text(json.dumps(w), encoding="utf-8")
    assert verify(bundle) is True
