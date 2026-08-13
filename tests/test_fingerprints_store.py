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
