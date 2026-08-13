"""Тесты миграций: применение, идемпотентность, версия схемы."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

from cigilbot.storage.migrations import MIGRATIONS, current_version, migrate


async def _tables(conn: aiosqlite.Connection) -> set[str]:
    cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    rows = await cursor.fetchall()
    return {row[0] for row in rows}


async def _columns(conn: aiosqlite.Connection, table: str) -> set[str]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    rows = await cursor.fetchall()
    return {row[1] for row in rows}


class TestMigrate:
    async def test_fresh_db_reaches_latest_version(self, tmp_path: Path) -> None:
        conn = await aiosqlite.connect(tmp_path / "test.db")
        try:
            version = await migrate(conn)
            assert version == MIGRATIONS[-1][0]
            assert await current_version(conn) == version
        finally:
            await conn.close()

    async def test_creates_expected_tables(self, tmp_path: Path) -> None:
        conn = await aiosqlite.connect(tmp_path / "test.db")
        try:
            await migrate(conn)
            tables = await _tables(conn)
            for expected in (
                "mod_users", "mod_messages", "mod_clusters",
                "mod_cluster_members", "mod_verdicts", "mod_signals",
                "mod_action_queue", "mod_actions", "mod_panel_users", "mod_trusted",
                "mod_patterns",
            ):
                assert expected in tables
        finally:
            await conn.close()

    async def test_pattern_id_column_added_to_clusters_and_verdicts(
        self, tmp_path: Path
    ) -> None:
        conn = await aiosqlite.connect(tmp_path / "test.db")
        try:
            await migrate(conn)
            assert "pattern_id" in await _columns(conn, "mod_clusters")
            assert "pattern_id" in await _columns(conn, "mod_verdicts")
        finally:
            await conn.close()

    async def test_idempotent_on_already_migrated_db(self, tmp_path: Path) -> None:
        conn = await aiosqlite.connect(tmp_path / "test.db")
        try:
            first = await migrate(conn)
            second = await migrate(conn)
            assert first == second
        finally:
            await conn.close()

    async def test_survives_reconnect(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        conn1 = await aiosqlite.connect(db_path)
        await migrate(conn1)
        await conn1.close()

        conn2 = await aiosqlite.connect(db_path)
        try:
            version = await current_version(conn2)
            assert version == MIGRATIONS[-1][0]
            # повторный migrate() на уже применённой схеме не должен падать
            await migrate(conn2)
        finally:
            await conn2.close()

    async def test_empty_db_starts_at_version_zero(self, tmp_path: Path) -> None:
        conn = await aiosqlite.connect(tmp_path / "test.db")
        try:
            assert await current_version(conn) == 0
        finally:
            await conn.close()
