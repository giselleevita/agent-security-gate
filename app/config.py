from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException

AUTH_TOKEN_ENV = "AUTH_TOKEN"
APPROVER_TOKEN_ENV = "APPROVER_TOKEN"
JWT_SECRET_ENV = "JWT_SECRET"
OPA_URL_ENV = "OPA_URL"
POLICY_DATA_PATH_ENV = "POLICY_DATA_PATH"
AUDIT_LOG_PATH_ENV = "AUDIT_LOG_PATH"
DATABASE_URL_ENV = "DATABASE_URL"
REDIS_URL_ENV = "REDIS_URL"
AGENT_RATE_LIMIT_MAX_ENV = "AGENT_RATE_LIMIT_MAX"
AGENT_RATE_LIMIT_WINDOW_S_ENV = "AGENT_RATE_LIMIT_WINDOW_S"
DECIDE_RATE_LIMIT_MAX_ENV = "DECIDE_RATE_LIMIT_MAX"
DECIDE_RATE_LIMIT_WINDOW_S_ENV = "DECIDE_RATE_LIMIT_WINDOW_S"
APPROVAL_RATE_LIMIT_MAX_ENV = "APPROVAL_RATE_LIMIT_MAX"
APPROVAL_RATE_LIMIT_WINDOW_S_ENV = "APPROVAL_RATE_LIMIT_WINDOW_S"
APPROVAL_TTL_S_ENV = "APPROVAL_TTL_S"
LEGACY_RATE_LIMIT_MAX_ENV = "RATE_LIMIT_MAX"
LEGACY_RATE_LIMIT_WINDOW_ENV = "RATE_LIMIT_WINDOW"
DLP_PATTERNS_PATH_ENV = "DLP_PATTERNS_PATH"
CANARIES_PATH_ENV = "CANARIES_PATH"
DEMO_MODE_ENV = "ASG_DEMO_MODE"
OIDC_ISSUER_ENV = "OIDC_ISSUER"
OIDC_AUDIENCE_ENV = "OIDC_AUDIENCE"
OIDC_JWKS_URL_ENV = "OIDC_JWKS_URL"
TENANT_POLICY_STRICT_ENV = "ASG_TENANT_POLICY_STRICT"
AUDIT_HMAC_KEY_ENV = "AUDIT_HMAC_KEY"
AUDIT_S3_BUCKET_ENV = "AUDIT_S3_BUCKET"
AUDIT_S3_PREFIX_ENV = "AUDIT_S3_PREFIX"
AUDIT_S3_REGION_ENV = "AUDIT_S3_REGION"
AUDIT_S3_ENDPOINT_URL_ENV = "AUDIT_S3_ENDPOINT_URL"
AUDIT_S3_RETENTION_DAYS_ENV = "AUDIT_S3_RETENTION_DAYS"
AUDIT_S3_OBJECT_LOCK_MODE_ENV = "AUDIT_S3_OBJECT_LOCK_MODE"
ENFORCE_MODE_ENV = "ASG_ENFORCE_MODE"
ENFORCE_TTL_S_ENV = "ASG_ENFORCE_TTL_S"

DEMO_AUTH_TOKEN = "test-token"
DEMO_APPROVER_TOKEN = "approver-token"
DEMO_JWT_SECRET = "asg-demo-jwt-secret-minimum-32-bytes"


def dlp_patterns_path() -> Path:
    return Path(os.environ.get(DLP_PATTERNS_PATH_ENV, "policies/data/dlp_patterns.yaml"))


def canaries_path() -> Path:
    return Path(os.environ.get(CANARIES_PATH_ENV, "policies/data/canaries.yaml"))


def policy_data_path() -> Path:
    return Path(os.environ.get(POLICY_DATA_PATH_ENV, "policies/data/policy_data.json"))


def tenant_policy_strict() -> bool:
    """
    When enabled, a request whose `tenant_id` has no dedicated per-tenant policy file is
    denied (`unknown_tenant`) instead of falling back to the default policy. Recommended
    for multi-tenant production so a new/unknown tenant never inherits another tenant's
    (or a permissive default) policy.
    """
    return os.environ.get(TENANT_POLICY_STRICT_ENV, "false").lower() in {"1", "true", "yes", "on"}


def audit_log_path() -> Path:
    return Path(os.environ.get(AUDIT_LOG_PATH_ENV, "audit/events.jsonl"))


def audit_hmac_key() -> str | None:
    """
    Optional HMAC key used to sign each audit chain entry. Loaded from `AUDIT_HMAC_KEY`
    or `AUDIT_HMAC_KEY_FILE`. When set, tampering that recomputes the hash chain still
    fails verification because the attacker cannot forge the signature.
    """
    return _read_env_or_file(AUDIT_HMAC_KEY_ENV)


def audit_s3_bucket() -> str | None:
    value = os.environ.get(AUDIT_S3_BUCKET_ENV)
    return value.strip() if value and value.strip() else None


def audit_s3_prefix() -> str:
    prefix = os.environ.get(AUDIT_S3_PREFIX_ENV, "audit/")
    return prefix if prefix.endswith("/") or prefix == "" else prefix + "/"


def audit_s3_region() -> str | None:
    value = os.environ.get(AUDIT_S3_REGION_ENV)
    return value.strip() if value and value.strip() else None


def audit_s3_endpoint_url() -> str | None:
    value = os.environ.get(AUDIT_S3_ENDPOINT_URL_ENV)
    return value.strip() if value and value.strip() else None


def audit_s3_retention_days() -> int:
    try:
        return max(0, int(os.environ.get(AUDIT_S3_RETENTION_DAYS_ENV, "0")))
    except ValueError:
        return 0


def audit_s3_object_lock_mode() -> str:
    mode = os.environ.get(AUDIT_S3_OBJECT_LOCK_MODE_ENV, "GOVERNANCE").upper()
    return mode if mode in {"GOVERNANCE", "COMPLIANCE"} else "GOVERNANCE"


def _read_env_or_file(env_name: str) -> str | None:
    """
    Resolve a secret/config value from `{env_name}` or, if unset, from a file path in
    `{env_name}_FILE`.

    The `_FILE` convention lets secrets be mounted by Vault/Kubernetes/Docker secrets
    without ever appearing in the process environment or logs. A direct env value wins;
    an unreadable `_FILE` path is a hard error so misconfiguration fails loudly.
    """
    direct = os.environ.get(env_name)
    if direct is not None and direct.strip():
        return direct
    file_path = os.environ.get(f"{env_name}_FILE")
    if file_path:
        try:
            content = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"{env_name}_FILE could not be read: {exc}") from exc
        if content:
            return content
    return None


def database_url() -> str:
    return _read_env_or_file(DATABASE_URL_ENV) or "postgresql://asg:asg@localhost:5432/asg"


def redis_url() -> str:
    return _read_env_or_file(REDIS_URL_ENV) or "redis://localhost:6379/0"


def opa_url() -> str:
    return os.environ.get(OPA_URL_ENV, "http://localhost:8181").rstrip("/")


def demo_mode_enabled() -> bool:
    return os.environ.get(DEMO_MODE_ENV, "false").lower() in {"1", "true", "yes", "on"}


def oidc_issuer() -> str | None:
    value = os.environ.get(OIDC_ISSUER_ENV)
    return value.strip() if value and value.strip() else None


def oidc_audience() -> str | None:
    value = os.environ.get(OIDC_AUDIENCE_ENV)
    return value.strip() if value and value.strip() else None


def oidc_jwks_url() -> str | None:
    explicit = os.environ.get(OIDC_JWKS_URL_ENV)
    if explicit and explicit.strip():
        return explicit.strip()
    issuer = oidc_issuer()
    if issuer:
        # Standard OIDC discovery location for the signing key set.
        return f"{issuer.rstrip('/')}/.well-known/jwks.json"
    return None


def oidc_enabled() -> bool:
    return oidc_issuer() is not None and oidc_audience() is not None


def required_secret(env_name: str, *, demo_value: str) -> str:
    value = _read_env_or_file(env_name)
    if demo_mode_enabled():
        return value or demo_value
    if value is None or not value.strip():
        raise HTTPException(status_code=500, detail=f"{env_name} is not configured")
    if value == demo_value:
        raise HTTPException(status_code=500, detail=f"{env_name} is using the demo value")
    return value


def validate_startup_secrets() -> None:
    """
    Fail loudly at startup if required secrets are missing or still the demo values
    while running outside demo mode. Raises RuntimeError so the process aborts before
    serving traffic instead of returning 500s per request.

    JWT_SECRET (resume-token signing) is always required. The static agent/approver
    tokens are required only when OIDC is not configured; with OIDC enabled they become
    optional service credentials.
    """
    if demo_mode_enabled():
        return
    required = [(JWT_SECRET_ENV, DEMO_JWT_SECRET)]
    if not oidc_enabled():
        required.append((AUTH_TOKEN_ENV, DEMO_AUTH_TOKEN))
        required.append((APPROVER_TOKEN_ENV, DEMO_APPROVER_TOKEN))
    missing: list[str] = []
    for env_name, demo_value in required:
        value = _read_env_or_file(env_name)
        if value is None or not value.strip() or value == demo_value:
            missing.append(env_name)
    if missing:
        raise RuntimeError(
            "missing or demo-valued required secrets (set them, or a *_FILE path, or "
            f"enable ASG_DEMO_MODE for local demos): {', '.join(sorted(missing))}"
        )


def enforce_mode() -> str:
    """
    Tool-execution enforcement mode:

    - ``off`` (default): tool endpoints run without checking for a prior decide grant
      (backwards compatible; zero overhead).
    - ``permissive``: decide records a single-use grant keyed by ``audit_id``; tool
      endpoints consume it when an ``X-ASG-Audit-Id`` is supplied but still run without
      one (useful while migrating agents onto the SDK).
    - ``strict``: tool endpoints refuse (403) unless a valid, matching, unused grant is
      presented, guaranteeing no side effect executes without a prior allow decision.
    """
    mode = os.environ.get(ENFORCE_MODE_ENV, "off").lower()
    return mode if mode in {"off", "permissive", "strict"} else "off"


def enforce_recording_enabled() -> bool:
    return enforce_mode() in {"permissive", "strict"}


def enforce_strict() -> bool:
    return enforce_mode() == "strict"


def enforce_ttl_s() -> int:
    """How long an unused decide grant remains valid for a follow-up tool call."""
    try:
        return max(1, int(os.environ.get(ENFORCE_TTL_S_ENV, "300")))
    except ValueError:
        return 300


def agent_rate_limit_max() -> int:
    try:
        return int(os.environ.get(AGENT_RATE_LIMIT_MAX_ENV, os.environ.get(LEGACY_RATE_LIMIT_MAX_ENV, "5")))
    except ValueError:
        return 5


def agent_rate_limit_window_s() -> int:
    try:
        return int(os.environ.get(AGENT_RATE_LIMIT_WINDOW_S_ENV, os.environ.get(LEGACY_RATE_LIMIT_WINDOW_ENV, "60")))
    except ValueError:
        return 60


def decide_rate_limit_max() -> int:
    # The gateway decision endpoint is the primary API path, so it gets its own, much
    # higher budget than the /agent demo façade.
    try:
        return int(os.environ.get(DECIDE_RATE_LIMIT_MAX_ENV, "120"))
    except ValueError:
        return 120


def decide_rate_limit_window_s() -> int:
    try:
        return int(os.environ.get(DECIDE_RATE_LIMIT_WINDOW_S_ENV, "60"))
    except ValueError:
        return 60


def approval_rate_limit_max() -> int:
    # Bounds how many approval requests a single caller can create per window,
    # preventing approver-queue flooding / spam.
    try:
        return int(os.environ.get(APPROVAL_RATE_LIMIT_MAX_ENV, "20"))
    except ValueError:
        return 20


def approval_rate_limit_window_s() -> int:
    try:
        return int(os.environ.get(APPROVAL_RATE_LIMIT_WINDOW_S_ENV, "60"))
    except ValueError:
        return 60


def approval_ttl_s() -> int:
    # Pending approvals older than this are swept to 'expired' and can no longer
    # be approved or consumed. Zero or negative disables expiry (approvals never
    # time out).
    try:
        return int(os.environ.get(APPROVAL_TTL_S_ENV, "3600"))
    except ValueError:
        return 3600
