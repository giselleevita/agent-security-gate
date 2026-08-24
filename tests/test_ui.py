"""UI routes for approver console."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_ui_redirects_to_approvals(client: TestClient):
    r = client.get("/ui", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/ui/approvals"


def test_approvals_console_html(client: TestClient):
    r = client.get("/ui/approvals")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "Approval Console" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert "'unsafe-inline'" not in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "innerHTML" not in r.text
    assert "<script>" not in r.text
    static = Path(__file__).resolve().parents[1] / "app" / "static" / "approvals.html"
    assert static.is_file()


def test_approvals_assets_are_same_origin_and_xss_safe(client: TestClient):
    script = client.get("/ui/assets/approvals.js")
    assert script.status_code == 200
    assert "text/javascript" in script.headers["content-type"]
    assert "innerHTML" not in script.text
    assert "textContent" in script.text
    assert "replaceChildren" in script.text
    assert script.headers["x-content-type-options"] == "nosniff"

    styles = client.get("/ui/assets/approvals.css")
    assert styles.status_code == 200
    assert "text/css" in styles.headers["content-type"]
