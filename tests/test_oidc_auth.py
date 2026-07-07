from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app import auth


ISSUER = "https://issuer.example.com"
AUDIENCE = "asg-api"


@pytest.fixture
def rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


class _FakeSigningKey:
    def __init__(self, public_key):
        self.key = public_key


class _FakeJWKSClient:
    def __init__(self, public_key):
        self._public_key = public_key

    def get_signing_key_from_jwt(self, _token):
        return _FakeSigningKey(self._public_key)


def _enable_oidc(monkeypatch, public_key):
    monkeypatch.setenv("ASG_DEMO_MODE", "false")
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("OIDC_JWKS_URL", f"{ISSUER}/jwks")
    # No static tokens configured -> only OIDC accepted.
    monkeypatch.delenv("AUTH_TOKEN", raising=False)
    monkeypatch.delenv("APPROVER_TOKEN", raising=False)
    monkeypatch.setattr(auth, "_jwks_clients", {})
    monkeypatch.setattr(auth, "_jwks_client", lambda _url: _FakeJWKSClient(public_key))


def _make_token(private_key, *, roles, sub="user-1", exp_delta=600, aud=AUDIENCE, iss=ISSUER):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "roles": roles,
            "iat": now,
            "exp": now + exp_delta,
        },
        private_key,
        algorithm="RS256",
    )


def test_oidc_agent_token_accepted(monkeypatch, rsa_keypair) -> None:
    private_key, public_key = rsa_keypair
    _enable_oidc(monkeypatch, public_key)
    token = _make_token(private_key, roles=[auth.ROLE_AGENT])
    principal = auth.require_bearer_token(authorization=f"Bearer {token}")
    assert principal == "oidc:user-1"


def test_oidc_agent_token_missing_role_rejected(monkeypatch, rsa_keypair) -> None:
    private_key, public_key = rsa_keypair
    _enable_oidc(monkeypatch, public_key)
    token = _make_token(private_key, roles=["some:other"])
    with pytest.raises(HTTPException) as exc:
        auth.require_bearer_token(authorization=f"Bearer {token}")
    assert exc.value.status_code == 403


def test_oidc_approver_role_enforced(monkeypatch, rsa_keypair) -> None:
    private_key, public_key = rsa_keypair
    _enable_oidc(monkeypatch, public_key)
    agent_token = _make_token(private_key, roles=[auth.ROLE_AGENT])
    with pytest.raises(HTTPException) as exc:
        auth.verify_approver(authorization=f"Bearer {agent_token}")
    assert exc.value.status_code == 403

    approver_token = _make_token(private_key, roles=[auth.ROLE_APPROVER], sub="human-9")
    # Should not raise.
    auth.verify_approver(authorization=f"Bearer {approver_token}")


def test_oidc_expired_token_rejected(monkeypatch, rsa_keypair) -> None:
    private_key, public_key = rsa_keypair
    _enable_oidc(monkeypatch, public_key)
    token = _make_token(private_key, roles=[auth.ROLE_AGENT], exp_delta=-10)
    with pytest.raises(HTTPException) as exc:
        auth.require_bearer_token(authorization=f"Bearer {token}")
    assert exc.value.status_code == 401


def test_oidc_wrong_audience_rejected(monkeypatch, rsa_keypair) -> None:
    private_key, public_key = rsa_keypair
    _enable_oidc(monkeypatch, public_key)
    token = _make_token(private_key, roles=[auth.ROLE_AGENT], aud="other-api")
    with pytest.raises(HTTPException) as exc:
        auth.require_bearer_token(authorization=f"Bearer {token}")
    assert exc.value.status_code == 401


def test_realm_access_roles_supported(monkeypatch, rsa_keypair) -> None:
    private_key, public_key = rsa_keypair
    _enable_oidc(monkeypatch, public_key)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "kc-user",
            "realm_access": {"roles": [auth.ROLE_APPROVER]},
            "iat": now,
            "exp": now + 600,
        },
        private_key,
        algorithm="RS256",
    )
    auth.verify_approver(authorization=f"Bearer {token}")


def test_static_token_still_works_in_demo_mode(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    monkeypatch.delenv("AUTH_TOKEN", raising=False)
    principal = auth.require_bearer_token(authorization="Bearer test-token")
    assert principal == "test-token"
