"""Тест Database.purge_old_messages — bug-аудит 2026-08-15, HIGH #16:
recent_messages в bot.db росла без ретеншена. Не полное покрытие bot/
database.py (у модуля вообще нет тестового файла, это отдельная,
более широкая находка), только регрессия на этот конкретный фикс.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from bot.database import Database


@pytest.fixture
async def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "test_bot.db"))
    await database.connect()
    return database


class TestPurgeOldMessages:
    async def test_deletes_messages_older_than_cutoff(self, db: Database) -> None:
        now = time.time()
        await db._conn.execute(
            "INSERT INTO recent_messages (username, content, created_at) VALUES (?, ?, ?)",
            ("old_user", "старое сообщение", now - 40 * 86400),
        )
        await db._conn.execute(
            "INSERT INTO recent_messages (username, content, created_at) VALUES (?, ?, ?)",
            ("recent_user", "недавнее сообщение", now - 1 * 86400),
        )
        await db._conn.commit()

        deleted = await db.purge_old_messages(older_than_days=30.0)
        assert deleted == 1

        cursor = await db._conn.execute("SELECT username FROM recent_messages")
        rows = await cursor.fetchall()
        assert [row[0] for row in rows] == ["recent_user"]

    async def test_nothing_to_delete_returns_zero(self, db: Database) -> None:
        assert await db.purge_old_messages(older_than_days=30.0) == 0
