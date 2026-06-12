from __future__ import annotations

import time

import jwt
import pytest
from fastapi import HTTPException

from app.auth import RESUME_TOKEN_AUDIENCE, RESUME_TOKEN_ISSUER, sign_resume_token, verify_resume_token
from app.config import DEMO_JWT_SECRET


def test_resume_token_is_bound_to_expected_issuer_and_audience(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")

    token = sign_resume_token(
        request_id="request-1",
        tenant_id="tenant-1",
        session_id="session-1",
        requester_id="requester-1",
    )

    claims = verify_resume_token(token)
    assert claims["iss"] == RESUME_TOKEN_ISSUER
    assert claims["aud"] == RESUME_TOKEN_AUDIENCE


@pytest.mark.parametrize(
    ("issuer", "audience"),
    [
        ("another-service", RESUME_TOKEN_AUDIENCE),
        (RESUME_TOKEN_ISSUER, "another-audience"),
    ],
)
def test_resume_token_rejects_wrong_scope(monkeypatch, issuer: str, audience: str) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "typ": "asg_resume",
            "request_id": "request-1",
            "tenant_id": "tenant-1",
            "session_id": "session-1",
            "requester_id": "requester-1",
            "iat": now,
            "exp": now + 600,
        },
        DEMO_JWT_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(HTTPException, match="invalid resume token") as exc_info:
        verify_resume_token(token)

    assert exc_info.value.status_code == 401
