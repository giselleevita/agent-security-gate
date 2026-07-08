from __future__ import annotations

import app.main as main


def test_all_expected_routes_are_registered() -> None:
    paths = {r.path for r in main.app.routes}
    expected = {
        "/health",
        "/health/ready",
        "/metrics",
        "/audit",
        "/v1/gateway/decide",
        "/agent",
        "/v1/http/proxy",
        "/v1/docs/read",
        "/v1/approvals/request",
        "/v1/approvals/{request_id}/approve",
        "/v1/approvals/{request_id}/deny",
        "/v1/approvals/{tenant_id}",
        "/v1/policy/exceptions",
        "/v1/policy/exceptions/{tenant_id}",
        "/v1/audit/export",
        "/v1/stats",
    }
    assert expected <= paths


def test_routers_share_main_patch_points() -> None:
    # Router handlers must reach shared logic through the app.main module so tests can
    # monkeypatch a single override point. Guard the key symbols exist on main.
    for name in ("_decide_tool_call", "_append_audit_event", "_db_connect", "GatedHttpClient"):
        assert hasattr(main, name), name
