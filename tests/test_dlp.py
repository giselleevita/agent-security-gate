from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main
from adapters.http import HttpDecision
from app.dlp import scan_tool_output


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
