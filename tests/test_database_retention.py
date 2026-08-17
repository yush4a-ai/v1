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


class TestConnectionLifecycle:
    """bug-аудит 2026-08-15, HIGH #12: close() закрывал соединение, но не
    обнулял _conn — идемпотентный connect() (докстринг: "срабатывает у
    twitchio на КАЖДЫЙ реконнект IRC") после close() видел _conn "не None"
    и молча возвращался, ничего не открыв заново."""

    async def test_close_before_connect_is_a_noop(self, tmp_path: Path) -> None:
        database = Database(str(tmp_path / "unconnected.db"))
        await database.close()

    async def test_reconnect_after_close_works(self, tmp_path: Path) -> None:
        database = Database(str(tmp_path / "reconnect.db"))
        await database.connect()
        await database.touch_viewer("viewer1")
        await database.close()

        await database.connect()
        cursor = await database._conn.execute("SELECT username FROM viewers")
        rows = await cursor.fetchall()
        assert [row[0] for row in rows] == ["viewer1"]
        await database.close()
