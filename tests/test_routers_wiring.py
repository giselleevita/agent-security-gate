from __future__ import annotations

import app.main as main


def test_all_expected_routes_are_registered() -> None:
    # Read the surface from the OpenAPI schema rather than walking `app.routes`. Starlette
    # 1.6 / FastAPI 0.141 stopped flattening `include_router` into the top-level route list
    # and inserted opaque `_IncludedRouter` wrappers that carry no `.path`, so the old
    # traversal broke on a routine dependency bump while routing itself was fine.
    # `app.openapi()` is public API and reports the same paths under both layouts.
    paths = set(main.app.openapi()["paths"])
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
