from __future__ import annotations

from pathlib import Path

import pytest

from scripts import migrate_db


class FakeResult:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self) -> None:
        self.applied: dict[str, str] = {}
        self.migration_sql: list[str] = []

    def execute(self, query: str, params=None) -> FakeResult:
        normalized = " ".join(query.split())
        if "pg_advisory_lock" in normalized or "pg_advisory_unlock" in normalized:
            return FakeResult()
        if normalized.startswith("SELECT checksum"):
            version = params[0]
            checksum = self.applied.get(version)
            return FakeResult((checksum,) if checksum is not None else None)
        if normalized.startswith("INSERT INTO schema_migrations"):
            version, checksum = params
            self.applied[version] = checksum
            return FakeResult()
        if not normalized.startswith("CREATE TABLE IF NOT EXISTS schema_migrations"):
            self.migration_sql.append(query)
        return FakeResult()


def test_pending_migrations_are_applied_once(monkeypatch, tmp_path: Path) -> None:
    migration = tmp_path / "001_example.sql"
    migration.write_text("SELECT 1;\n", encoding="utf-8")
    connection = FakeConnection()
    monkeypatch.setattr(migrate_db, "migration_paths", lambda: [migration])

    migrate_db.apply_pending_migrations(connection)
    migrate_db.apply_pending_migrations(connection)

    assert connection.migration_sql == ["SELECT 1;\n"]
    assert connection.applied["001_example.sql"] == migrate_db.migration_checksum(migration)


def test_changed_applied_migration_is_rejected(monkeypatch, tmp_path: Path) -> None:
    migration = tmp_path / "001_example.sql"
    migration.write_text("SELECT 1;\n", encoding="utf-8")
    connection = FakeConnection()
    monkeypatch.setattr(migrate_db, "migration_paths", lambda: [migration])
    migrate_db.apply_pending_migrations(connection)
    migration.write_text("SELECT 2;\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="applied migration changed"):
        migrate_db.apply_pending_migrations(connection)
