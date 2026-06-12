from __future__ import annotations

import hashlib
import time
from pathlib import Path

import psycopg

from app.config import database_url


def migration_paths() -> list[Path]:
    root = Path(__file__).resolve().parents[1] / "db" / "migrations"
    return sorted(root.glob("*.sql"))


def migration_checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply_pending_migrations(connection: psycopg.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version TEXT PRIMARY KEY,
          checksum TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    for path in migration_paths():
        checksum = migration_checksum(path)
        row = connection.execute(
            "SELECT checksum FROM schema_migrations WHERE version = %s",
            (path.name,),
        ).fetchone()
        if row is not None:
            if str(row[0]) != checksum:
                raise RuntimeError(f"applied migration changed: {path.name}")
            continue
        connection.execute(path.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES (%s, %s)",
            (path.name, checksum),
        )


def migrate(*, attempts: int = 30, delay_seconds: float = 1.0) -> None:
    last_error: psycopg.Error | None = None
    for _ in range(attempts):
        try:
            with psycopg.connect(database_url()) as connection:
                apply_pending_migrations(connection)
            return
        except psycopg.Error as exc:
            last_error = exc
            time.sleep(delay_seconds)
    raise RuntimeError(f"database migration failed after {attempts} attempts: {last_error}")


if __name__ == "__main__":
    migrate()
