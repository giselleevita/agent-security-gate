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
    static = Path(__file__).resolve().parents[1] / "app" / "static" / "approvals.html"
    assert static.is_file()
