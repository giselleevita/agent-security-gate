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
LEGACY_RATE_LIMIT_MAX_ENV = "RATE_LIMIT_MAX"
LEGACY_RATE_LIMIT_WINDOW_ENV = "RATE_LIMIT_WINDOW"
DLP_PATTERNS_PATH_ENV = "DLP_PATTERNS_PATH"
CANARIES_PATH_ENV = "CANARIES_PATH"
DEMO_MODE_ENV = "ASG_DEMO_MODE"

DEMO_AUTH_TOKEN = "test-token"
DEMO_APPROVER_TOKEN = "approver-token"
DEMO_JWT_SECRET = "asg-demo-jwt-secret-minimum-32-bytes"


def dlp_patterns_path() -> Path:
    return Path(os.environ.get(DLP_PATTERNS_PATH_ENV, "policies/data/dlp_patterns.yaml"))


def canaries_path() -> Path:
    return Path(os.environ.get(CANARIES_PATH_ENV, "policies/data/canaries.yaml"))


def policy_data_path() -> Path:
    return Path(os.environ.get(POLICY_DATA_PATH_ENV, "policies/data/policy_data.json"))


def audit_log_path() -> Path:
    return Path(os.environ.get(AUDIT_LOG_PATH_ENV, "audit/events.jsonl"))


def database_url() -> str:
    return os.environ.get(DATABASE_URL_ENV, "postgresql://asg:asg@localhost:5432/asg")


def redis_url() -> str:
    return os.environ.get(REDIS_URL_ENV, "redis://localhost:6379/0")


def opa_url() -> str:
    return os.environ.get(OPA_URL_ENV, "http://localhost:8181").rstrip("/")


def demo_mode_enabled() -> bool:
    return os.environ.get(DEMO_MODE_ENV, "false").lower() in {"1", "true", "yes", "on"}


def required_secret(env_name: str, *, demo_value: str) -> str:
    value = os.environ.get(env_name)
    if demo_mode_enabled():
        return value or demo_value
    if value is None or not value.strip():
        raise HTTPException(status_code=500, detail=f"{env_name} is not configured")
    if value == demo_value:
        raise HTTPException(status_code=500, detail=f"{env_name} is using the demo value")
    return value


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
