"""Тесты cigilbot/store.py::get_moderator_activity_stats.

Пользователь 2026-08-13: "можем сводку отправлять в дискорд по работе
модераторов на канале?" — источник mod_actions (тот же, что Audit-экран
панели), считает отдельно от DigestStats.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "test.db"))
    await s.connect()
    return s


async def record(
    store: ModerationStore, *, actor: str, action: str, succeeded: int = 1, failed: int = 0,
    age_seconds: float = 0.0,
) -> None:
    audit_id = await store.record_action_audit(
        actor=actor, actor_role="MODERATOR", action=action, scope="user",
        reason="test", confirmation="MANUAL", succeeded=succeeded, failed=failed, details={},
    )
    if age_seconds:
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_actions SET created_at = ? WHERE id = ?",
            (time.time() - age_seconds, audit_id),
        )
        await store._db.commit()  # noqa: SLF001


class TestGetModeratorActivityStats:
    async def test_counts_timeouts_bans_deletes_separately(self, store: ModerationStore) -> None:
        await record(store, actor="mod1", action="TIMEOUT")
        await record(store, actor="mod1", action="BAN")
        await record(store, actor="mod1", action="DELETE_MESSAGES")

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        assert stats.total_timeouts == 1
        assert stats.total_bans == 1
        assert stats.total_deletes == 1

    async def test_only_counts_succeeded(self, store: ModerationStore) -> None:
        await record(store, actor="mod1", action="TIMEOUT", succeeded=0, failed=1)

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        assert stats.total_timeouts == 0

    async def test_ignores_actions_outside_period(self, store: ModerationStore) -> None:
        await record(store, actor="mod1", action="TIMEOUT", age_seconds=100_000)
        await record(store, actor="mod1", action="TIMEOUT", age_seconds=10)

        stats = await store.get_moderator_activity_stats(since=time.time() - 1000)

        assert stats.total_timeouts == 1

    async def test_no_activity_returns_zeros(self, store: ModerationStore) -> None:
        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        assert stats.total_timeouts == 0
        assert stats.total_bans == 0
        assert stats.total_deletes == 0
        assert stats.by_moderator == ()
        assert stats.recent == ()

    async def test_by_moderator_breaks_down_per_actor(self, store: ModerationStore) -> None:
        await record(store, actor="mod1", action="TIMEOUT")
        await record(store, actor="mod1", action="TIMEOUT")
        await record(store, actor="mod2", action="BAN")

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        by_actor = {m.actor: m for m in stats.by_moderator}
        assert by_actor["mod1"].timeouts == 2
        assert by_actor["mod2"].bans == 1

    async def test_by_moderator_ordered_by_total_desc(self, store: ModerationStore) -> None:
        await record(store, actor="mod_quiet", action="TIMEOUT")
        await record(store, actor="mod_busy", action="TIMEOUT")
        await record(store, actor="mod_busy", action="BAN")
        await record(store, actor="mod_busy", action="DELETE_MESSAGES")

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        assert stats.by_moderator[0].actor == "mod_busy"

    async def test_recent_actions_newest_first(self, store: ModerationStore) -> None:
        await record(store, actor="mod1", action="TIMEOUT", age_seconds=10)
        await record(store, actor="mod2", action="BAN", age_seconds=1)

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        assert stats.recent[0].actor == "mod2"
        assert stats.recent[1].actor == "mod1"

    async def test_recent_respects_limit(self, store: ModerationStore) -> None:
        for i in range(5):
            await record(store, actor=f"mod{i}", action="TIMEOUT")

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600, recent_limit=2)

        assert len(stats.recent) == 2

    async def test_moderator_action_total_property(self, store: ModerationStore) -> None:
        await record(store, actor="mod1", action="TIMEOUT")
        await record(store, actor="mod1", action="BAN")

        stats = await store.get_moderator_activity_stats(since=time.time() - 3600)

        assert stats.by_moderator[0].total == 2
