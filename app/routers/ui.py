from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, RedirectResponse

router = APIRouter(tags=["ui"])

_STATIC = Path(__file__).resolve().parents[1] / "static"


@router.get("/ui/approvals", include_in_schema=False)
def approvals_console() -> FileResponse:
    """Minimal approver console for pending approval requests."""
    return FileResponse(_STATIC / "approvals.html", media_type="text/html")


@router.get("/ui", include_in_schema=False)
def ui_root() -> RedirectResponse:
    return RedirectResponse(url="/ui/approvals", status_code=302)
