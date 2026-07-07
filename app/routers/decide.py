from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse

from app import main as m
from app.auth import require_bearer_token
from app.config import (
    decide_rate_limit_max as _decide_rate_limit_max,
    decide_rate_limit_window_s as _decide_rate_limit_window_s,
)
from app.schemas import DecideRequest, DecideResponse

router = APIRouter()


@router.post("/v1/gateway/decide", response_model=DecideResponse)
def gateway_decide(
    body: DecideRequest,
    bearer_token: str = Depends(require_bearer_token),
    resume_token: str | None = Header(default=None, alias="Resume-Token"),
    x_requester_id: str | None = Header(default=None, alias="X-Requester-Id"),
):
    try:
        m._rate_limit_or_raise(
            bearer_token=bearer_token,
            bucket="decide",
            max_requests=_decide_rate_limit_max(),
            window_s=_decide_rate_limit_window_s(),
        )
    except HTTPException as exc:
        if exc.status_code == 429 and isinstance(exc.detail, dict):
            audit_id = f"evt_{uuid.uuid4().hex}"
            m._append_audit_event(audit_id, {"request": body.model_dump(), "response": exc.detail})
            return JSONResponse(status_code=429, content=exc.detail, headers=exc.headers or {})
        raise
    return m._decide_tool_call(body=body, resume_token=resume_token, x_requester_id=x_requester_id)
