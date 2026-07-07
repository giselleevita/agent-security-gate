from __future__ import annotations

from pathlib import Path

import pytest

from app import config


def test_read_env_or_file_prefers_direct_env(monkeypatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "token"
    secret_file.write_text("from-file", encoding="utf-8")
    monkeypatch.setenv("AUTH_TOKEN", "from-env")
    monkeypatch.setenv("AUTH_TOKEN_FILE", str(secret_file))
    assert config._read_env_or_file("AUTH_TOKEN") == "from-env"


def test_read_env_or_file_falls_back_to_file(monkeypatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "token"
    secret_file.write_text("  from-file\n", encoding="utf-8")
    monkeypatch.delenv("AUTH_TOKEN", raising=False)
    monkeypatch.setenv("AUTH_TOKEN_FILE", str(secret_file))
    assert config._read_env_or_file("AUTH_TOKEN") == "from-file"


def test_read_env_or_file_missing_file_raises(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AUTH_TOKEN", raising=False)
    monkeypatch.setenv("AUTH_TOKEN_FILE", str(tmp_path / "does-not-exist"))
    with pytest.raises(RuntimeError, match="AUTH_TOKEN_FILE could not be read"):
        config._read_env_or_file("AUTH_TOKEN")


def test_required_secret_loads_from_file(monkeypatch, tmp_path: Path) -> None:
    secret_file = tmp_path / "jwt"
    secret_file.write_text("a-real-production-secret-value-32bytes", encoding="utf-8")
    monkeypatch.setenv("ASG_DEMO_MODE", "false")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret_file))
    assert config.required_secret("JWT_SECRET", demo_value=config.DEMO_JWT_SECRET) == (
        "a-real-production-secret-value-32bytes"
    )


def test_validate_startup_secrets_ok_in_demo_mode(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "true")
    # Should not raise even though only demo values are present.
    config.validate_startup_secrets()


def test_validate_startup_secrets_fails_when_missing(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "false")
    for name in ("AUTH_TOKEN", "APPROVER_TOKEN", "JWT_SECRET"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    with pytest.raises(RuntimeError, match="required secrets"):
        config.validate_startup_secrets()


def test_validate_startup_secrets_rejects_demo_values(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "false")
    monkeypatch.setenv("AUTH_TOKEN", config.DEMO_AUTH_TOKEN)
    monkeypatch.setenv("APPROVER_TOKEN", "a-strong-approver-secret")
    monkeypatch.setenv("JWT_SECRET", "a-strong-jwt-secret-value-32-bytes!!")
    with pytest.raises(RuntimeError, match="AUTH_TOKEN"):
        config.validate_startup_secrets()


def test_validate_startup_secrets_passes_with_real_values(monkeypatch) -> None:
    monkeypatch.setenv("ASG_DEMO_MODE", "false")
    monkeypatch.setenv("AUTH_TOKEN", "a-strong-agent-secret-value")
    monkeypatch.setenv("APPROVER_TOKEN", "a-strong-approver-secret-value")
    monkeypatch.setenv("JWT_SECRET", "a-strong-jwt-secret-value-32-bytes!!")
    config.validate_startup_secrets()
