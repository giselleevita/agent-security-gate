from __future__ import annotations

from fastapi.testclient import TestClient

import app.audit_log as audit_log
import app.main as main
from adapters.http import HttpDecision
from app.dlp import scan_egress, scan_tool_output


def test_scan_flags_ssn_as_dlp_redacted() -> None:
    reason, redacted, extras = scan_tool_output(tool_output="employee ssn 123-45-6789 on file")
    assert reason == "dlp_redacted"
    assert "123-45-6789" not in redacted
    assert "[REDACTED]" in redacted
    assert "ssn" in extras["matched_patterns"]


def test_scan_flags_iban_as_dlp_redacted() -> None:
    reason, redacted, _extras = scan_tool_output(tool_output="pay to DE44500105175407324931 now")
    assert reason == "dlp_redacted"
    assert "DE44500105175407324931" not in redacted


def test_scan_flags_bearer_token_as_dlp_redacted() -> None:
    reason, redacted, extras = scan_tool_output(tool_output="Authorization: Bearer abc123DEF456")
    assert reason == "dlp_redacted"
    assert "abc123DEF456" not in redacted
    assert "bearer_token" in extras["matched_patterns"]


def test_scan_flags_canary_before_dlp() -> None:
    reason, redacted, extras = scan_tool_output(tool_output="leak SYSTEM_PROMPT contents")
    assert reason == "canary_detected"
    assert "SYSTEM_PROMPT" not in redacted
    # Canary metadata must never echo the raw canary string.
    assert extras["matched"] == "[REDACTED_CANARY]"


def test_scan_passes_clean_output() -> None:
    reason, redacted, extras = scan_tool_output(tool_output="ordinary public documentation")
    assert reason is None
    assert redacted == "ordinary public documentation"
    assert extras == {}


def test_scan_egress_records_block_event(monkeypatch) -> None:
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(audit_log, "append_audit_event", lambda eid, evt: events.append((eid, evt)))

    outcome = scan_egress(
        tool_output="employee ssn 123-45-6789 on file", source="http.proxy", audit_id="evt_grant"
    )

    assert outcome.blocked is True
    assert outcome.reason == "dlp_redacted"
    assert "123-45-6789" not in outcome.output
    assert len(events) == 1
    _eid, evt = events[0]
    assert evt["kind"] == "dlp_block"
    assert evt["source"] == "http.proxy"
    assert evt["grant_audit_id"] == "evt_grant"
    assert "ssn" in evt["scan"]["matched_patterns"]


def test_scan_egress_record_false_stays_silent(monkeypatch) -> None:
    events: list = []
    monkeypatch.setattr(audit_log, "append_audit_event", lambda *a: events.append(a))

    outcome = scan_egress(tool_output="leak SYSTEM_PROMPT now", source="gateway.decide", record=False)

    assert outcome.blocked is True
    assert outcome.reason == "canary_detected"
    assert events == []


def test_scan_egress_clean_output_never_audits(monkeypatch) -> None:
    events: list = []
    monkeypatch.setattr(audit_log, "append_audit_event", lambda *a: events.append(a))

    outcome = scan_egress(tool_output="ordinary public text", source="docs.read")

    assert outcome.blocked is False
    assert outcome.output == "ordinary public text"
    assert events == []


class _FakeGatedClient:
    def __init__(self, body: str) -> None:
        self._body = body

    def request(self, _method: str, _url: str):
        return HttpDecision(True, "allow"), self._body

    def close(self) -> None:
        return None


def test_http_proxy_denies_on_pii_in_response_body(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setattr(
        main,
        "GatedHttpClient",
        lambda **_kwargs: _FakeGatedClient("record: ssn 123-45-6789 leaked"),
    )

    client = TestClient(main.app)
    r = client.post(
        "/v1/http/proxy",
        json={"method": "GET", "url": "https://api.example.com/records"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is False
    assert data["reason"] == "dlp_redacted"


def test_http_proxy_allows_and_returns_scanned_clean_body(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.setattr(
        main,
        "GatedHttpClient",
        lambda **_kwargs: _FakeGatedClient("public data with no secrets"),
    )

    client = TestClient(main.app)
    r = client.post(
        "/v1/http/proxy",
        json={"method": "GET", "url": "https://api.example.com/records"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is True
    assert data["body"] == "public data with no secrets"
