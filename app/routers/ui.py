from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, RedirectResponse

router = APIRouter(tags=["ui"])

_STATIC = Path(__file__).resolve().parents[1] / "static"
_UI_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


@router.get("/ui/approvals", include_in_schema=False)
def approvals_console() -> FileResponse:
    """Minimal approver console for pending approval requests."""
    return FileResponse(_STATIC / "approvals.html", media_type="text/html", headers=_UI_HEADERS)


@router.get("/ui/assets/approvals.css", include_in_schema=False)
def approvals_styles() -> FileResponse:
    return FileResponse(_STATIC / "approvals.css", media_type="text/css", headers=_UI_HEADERS)


@router.get("/ui/assets/approvals.js", include_in_schema=False)
def approvals_script() -> FileResponse:
    return FileResponse(_STATIC / "approvals.js", media_type="text/javascript", headers=_UI_HEADERS)


@router.get("/ui", include_in_schema=False)
def ui_root() -> RedirectResponse:
    return RedirectResponse(url="/ui/approvals", status_code=302)
