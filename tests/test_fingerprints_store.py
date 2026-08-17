"""Тесты FingerprintStore: запись/чтение известных забаненных across каналов."""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.storage.fingerprints_store import FingerprintStore


@pytest.fixture
async def store(tmp_path: Path) -> FingerprintStore:
    s = FingerprintStore(str(tmp_path / "fingerprints.db"))
    await s.connect()
    return s


class TestRecordBan:
    async def test_empty_by_default(self, store: FingerprintStore) -> None:
        assert await store.list_all() == []
        assert await store.get("1") is None

    async def test_records_and_reads_back(self, store: FingerprintStore) -> None:
        await store.record_ban(
            user_id="1",
            login="bot1",
            banned_on_broadcaster_id="A",
            banned_on_login="dobriy_yura",
            reason="known bot pattern",
        )

        actor = await store.get("1")

        assert actor is not None
        assert actor.login == "bot1"
        assert actor.banned_on_broadcaster_id == "A"
        assert actor.banned_on_login == "dobriy_yura"
        assert actor.reason == "known bot pattern"

    async def test_second_ban_on_different_channel_updates_record(
        self, store: FingerprintStore
    ) -> None:
        await store.record_ban(
            user_id="1", login="bot1", banned_on_broadcaster_id="A", banned_on_login="channel_a"
        )
        await store.record_ban(
            user_id="1", login="bot1", banned_on_broadcaster_id="B", banned_on_login="channel_b"
        )

        actor = await store.get("1")

        assert actor is not None
        assert actor.banned_on_broadcaster_id == "B"
        assert len(await store.list_all()) == 1

    async def test_list_all_returns_every_actor(self, store: FingerprintStore) -> None:
        await store.record_ban(
            user_id="1", login="bot1", banned_on_broadcaster_id="A", banned_on_login="channel_a"
        )
        await store.record_ban(
            user_id="2", login="bot2", banned_on_broadcaster_id="A", banned_on_login="channel_a"
        )

        actors = await store.list_all()

        assert {a.user_id for a in actors} == {"1", "2"}


class TestConnectionLifecycle:
    async def test_using_store_before_connect_raises(self, tmp_path: Path) -> None:
        store = FingerprintStore(str(tmp_path / "unconnected.db"))
        with pytest.raises(RuntimeError, match="connect"):
            await store.list_all()

    async def test_close_before_connect_is_a_noop(self, tmp_path: Path) -> None:
        store = FingerprintStore(str(tmp_path / "unconnected.db"))
        await store.close()

    async def test_reconnect_after_close_works(self, tmp_path: Path) -> None:
        db = tmp_path / "reconnect.db"
        store = FingerprintStore(str(db))
        await store.connect()
        await store.record_ban(
            user_id="1", login="bot1", banned_on_broadcaster_id="A", banned_on_login="channel_a"
        )
        await store.close()

        await store.connect()
        actor = await store.get("1")
        assert actor is not None
        assert actor.login == "bot1"
        await store.close()

    async def test_use_after_close_raises_connect_error_not_stale_connection(
        self, tmp_path: Path
    ) -> None:
        """bug-аудит 2026-08-15, HIGH #12: close() закрывал aiosqlite-
        соединение, но не обнулял _conn — свойство _db (единственный
        guard "не вызван ли connect()") видело _conn "не None" и отдавало
        УЖЕ ЗАКРЫТОЕ соединение вместо RuntimeError. Вызывающий код получал
        невнятный aiosqlite.ValueError("no active connection") вместо
        понятной ошибки жизненного цикла."""
        store = FingerprintStore(str(tmp_path / "reconnect.db"))
        await store.connect()
        await store.close()

        with pytest.raises(RuntimeError, match="connect"):
            await store.list_all()
