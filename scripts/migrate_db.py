from __future__ import annotations

import time
from pathlib import Path

import psycopg

from app.config import database_url


def migration_paths() -> list[Path]:
    root = Path(__file__).resolve().parents[1] / "db" / "migrations"
    return sorted(root.glob("*.sql"))


def migrate(*, attempts: int = 30, delay_seconds: float = 1.0) -> None:
    last_error: psycopg.Error | None = None
    for _ in range(attempts):
        try:
            with psycopg.connect(database_url()) as connection:
                for path in migration_paths():
                    connection.execute(path.read_text(encoding="utf-8"))
            return
        except psycopg.Error as exc:
            last_error = exc
            time.sleep(delay_seconds)
    raise RuntimeError(f"database migration failed after {attempts} attempts: {last_error}")


if __name__ == "__main__":
    migrate()
