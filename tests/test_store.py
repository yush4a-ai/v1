"""Тесты ModerationStore: сохранение пользователей, сообщений, вердиктов, кластеров."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.types import (
    Action,
    ClusterInfo,
    Mode,
    Signal,
    SignalFamily,
    TrustLevel,
    Verdict,
)
from cigilbot.storage.store import ModerationStore, PatternInput
from tests.conftest import EventFactory


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "test.db"))
    await s.connect()
    return s


def make_signal(name: str = "new_account", value: float = 1.0) -> Signal:
    return Signal(
        name=name, family=SignalFamily.IDENTITY, weight=10.0, value=value, evidence="test"
    )


class TestUpsertUser:
    async def test_creates_new_user(self, store: ModerationStore, event_factory: EventFactory) -> None:
        event = event_factory(user_id="1", login="viewer1")
        await store.upsert_user(event)

        state = await store.get_user_state("1")
        assert state is not None
        assert state.login == "viewer1"
        assert state.message_count == 1

    async def test_increments_message_count_on_repeat(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        event = event_factory(user_id="1", login="viewer1")
        await store.upsert_user(event)
        await store.upsert_user(event)
        await store.upsert_user(event)

        state = await store.get_user_state("1")
        assert state is not None
        assert state.message_count == 3

    async def test_updates_login_on_rename(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="old_name"))
        await store.upsert_user(event_factory(user_id="1", login="new_name"))

        state = await store.get_user_state("1")
        assert state is not None
        assert state.login == "new_name"

    async def test_unknown_user_returns_none(self, store: ModerationStore) -> None:
        assert await store.get_user_state("nobody") is None

    async def test_defaults_are_sane(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))
        state = await store.get_user_state("1")
        assert state is not None
        assert state.trust_level == TrustLevel.UNKNOWN
        assert state.account_created_at is None
        assert state.marked_safe is False
        assert state.prior_timeouts == 0


class TestIncrementPriorTimeouts:
    async def test_increments_from_zero(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))

        new_value = await store.increment_prior_timeouts("1")

        assert new_value == 1
        state = await store.get_user_state("1")
        assert state is not None
        assert state.prior_timeouts == 1

    async def test_accumulates_across_calls(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))

        await store.increment_prior_timeouts("1")
        await store.increment_prior_timeouts("1")
        third = await store.increment_prior_timeouts("1")

        assert third == 3


class TestListUsers:
    async def test_empty_by_default(self, store: ModerationStore) -> None:
        assert await store.list_users() == []

    async def test_returns_created_user(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="viewer1"))

        rows = await store.list_users()

        assert len(rows) == 1
        assert rows[0]["login"] == "viewer1"
        assert rows[0]["trust_level"] == "UNKNOWN"
        assert rows[0]["marked_safe"] is False

    async def test_sorted_by_message_count_descending(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="quiet"))
        for _ in range(5):
            await store.upsert_user(event_factory(user_id="2", login="chatty"))

        rows = await store.list_users()

        assert [r["login"] for r in rows] == ["chatty", "quiet"]

    async def test_search_filters_by_login_substring(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="alice"))
        await store.upsert_user(event_factory(user_id="2", login="bob"))

        rows = await store.list_users(search="ali")

        assert len(rows) == 1
        assert rows[0]["login"] == "alice"

    async def test_search_case_insensitive(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="alice"))

        rows = await store.list_users(search="ALICE")

        assert len(rows) == 1

    async def test_limit_and_offset(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        for i in range(5):
            await store.upsert_user(event_factory(user_id=str(i), login=f"user{i}"))

        rows = await store.list_users(limit=2, offset=2)

        assert len(rows) == 2

    async def test_reflects_marked_safe_state(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="trusted1"))
        await store.mark_trusted("1", added_by="mod1", reason="regular viewer")

        rows = await store.list_users()

        assert rows[0]["marked_safe"] is True
        assert rows[0]["marked_safe_by"] == "mod1"


class TestAccountCreatedAt:
    async def test_set_and_read_back(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))
        created = time.time() - 86400 * 3
        await store.set_account_created_at("1", created)

        state = await store.get_user_state("1")
        assert state is not None
        assert state.account_created_at == pytest.approx(created)
        assert state.account_age_days is not None
        assert 2.9 < state.account_age_days < 3.1


class TestSaveMessage:
    async def test_returns_incrementing_ids(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        e1 = event_factory(text="привет")
        e2 = event_factory(text="ещё сообщение")
        id1 = await store.save_message(e1, fingerprint(e1.text))
        id2 = await store.save_message(e2, fingerprint(e2.text))
        assert id2 > id1


class TestSaveVerdict:
    async def test_round_trips_verdict_and_signals(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        event = event_factory(user_id="1", login="suspicious1")
        msg_id = await store.save_message(event, fingerprint(event.text))

        signals = (make_signal("new_account"), make_signal("first_message"))
        verdict = Verdict(
            user_id="1", login="suspicious1", risk_score=42, confidence=0.55,
            signals=signals, recommended_action=Action.OBSERVE, reason="test reason",
            timestamp=time.time(), families_triggered=1, mode=Mode.SHADOW,
            engine_version="v1", config_version="1",
        )

        verdict_id = await store.save_verdict(verdict, message_id=msg_id)
        assert verdict_id > 0

        # проверяем, что реально записалось — читаем напрямую через internal conn
        cursor = await store._db.execute(
            "SELECT risk_score, confidence, recommended_action FROM mod_verdicts WHERE id = ?",
            (verdict_id,),
        )
        row = await cursor.fetchone()
        assert row == (42, 0.55, "OBSERVE")

        cursor = await store._db.execute(
            "SELECT COUNT(*) FROM mod_signals WHERE verdict_id = ?", (verdict_id,)
        )
        count_row = await cursor.fetchone()
        assert count_row is not None
        assert count_row[0] == 2

    async def test_verdict_without_signals(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        verdict = Verdict(
            user_id="1", login="ok_user", risk_score=0, confidence=0.0, signals=(),
            recommended_action=Action.NOTHING, reason="clean", timestamp=time.time(),
        )
        verdict_id = await store.save_verdict(verdict)
        assert verdict_id > 0

    async def test_pattern_id_persisted(self, store: ModerationStore) -> None:
        pattern_id = await store.create_pattern(make_pattern_input())
        verdict = Verdict(
            user_id="1", login="bot1", risk_score=80, confidence=0.9, signals=(),
            recommended_action=Action.BAN, reason="matched pattern", timestamp=time.time(),
            pattern_id=pattern_id,
        )

        verdict_id = await store.save_verdict(verdict)

        cursor = await store._db.execute(
            "SELECT pattern_id FROM mod_verdicts WHERE id = ?", (verdict_id,)
        )
        row = await cursor.fetchone()
        assert row == (pattern_id,)


class TestGetRecentVerdicts:
    async def test_includes_signal_names(self, store: ModerationStore) -> None:
        signals = (make_signal("new_account"), make_signal("first_message"))
        verdict = Verdict(
            user_id="1", login="suspicious1", risk_score=42, confidence=0.55,
            signals=signals, recommended_action=Action.OBSERVE, reason="test reason",
            timestamp=time.time(), families_triggered=1, mode=Mode.SHADOW,
        )
        await store.save_verdict(verdict)

        rows = await store.get_recent_verdicts(min_risk_level=30)
        assert len(rows) == 1
        assert sorted(rows[0]["signal_names"]) == ["first_message", "new_account"]

    async def test_empty_signals_gives_empty_list(self, store: ModerationStore) -> None:
        verdict = Verdict(
            user_id="1", login="ok_user", risk_score=30, confidence=0.0, signals=(),
            recommended_action=Action.OBSERVE, reason="clean", timestamp=time.time(),
        )
        await store.save_verdict(verdict)

        rows = await store.get_recent_verdicts(min_risk_level=30)
        assert rows[0]["signal_names"] == []

    async def test_no_rows_returns_empty_list(self, store: ModerationStore) -> None:
        assert await store.get_recent_verdicts(min_risk_level=30) == []

    async def test_signals_not_mixed_between_verdicts(self, store: ModerationStore) -> None:
        v1 = Verdict(
            user_id="1", login="user1", risk_score=50, confidence=0.5,
            signals=(make_signal("exact_duplicate"),), recommended_action=Action.OBSERVE,
            reason="r1", timestamp=time.time(),
        )
        v2 = Verdict(
            user_id="2", login="user2", risk_score=60, confidence=0.6,
            signals=(make_signal("user_message_burst"),), recommended_action=Action.OBSERVE,
            reason="r2", timestamp=time.time(),
        )
        await store.save_verdict(v1)
        await store.save_verdict(v2)

        rows = await store.get_recent_verdicts(min_risk_level=30)
        by_login = {r["login"]: r["signal_names"] for r in rows}
        assert by_login["user1"] == ["exact_duplicate"]
        assert by_login["user2"] == ["user_message_burst"]


class TestSaveCluster:
    async def test_round_trips_cluster_and_members(self, store: ModerationStore) -> None:
        cluster = ClusterInfo(
            cluster_id=1,
            user_ids=("1", "2", "3"),
            logins=("bot1", "bot2", "bot3"),
            similarity_score=0.9,
            arrival_window_sec=5.0,
            first_message_ratio=1.0,
            new_account_ratio=1.0,
            shared_domains=("bit.ly",),
            signals=(make_signal("cluster_membership"),),
            risk_score=55,
            confidence=0.6,
            created_at=time.time(),
        )
        db_cluster_id = await store.save_cluster(cluster)
        assert db_cluster_id > 0

        cursor = await store._db.execute(
            "SELECT COUNT(*) FROM mod_cluster_members WHERE cluster_id = ?", (db_cluster_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 3

    async def test_duplicate_member_insert_does_not_fail(self, store: ModerationStore) -> None:
        # INSERT OR IGNORE защищает от повторной записи того же участника
        cluster = ClusterInfo(
            cluster_id=1, user_ids=("1", "1"), logins=("a", "a"), similarity_score=0.9,
            arrival_window_sec=1.0, first_message_ratio=1.0, new_account_ratio=1.0,
            shared_domains=(), signals=(), risk_score=10, confidence=0.2,
            created_at=time.time(),
        )
        db_cluster_id = await store.save_cluster(cluster)
        assert db_cluster_id > 0


def make_cluster(**overrides: object) -> ClusterInfo:
    defaults: dict[str, object] = {
        "cluster_id": 1,
        "user_ids": ("1", "2", "3"),
        "logins": ("bot1", "bot2", "bot3"),
        "similarity_score": 0.9,
        "arrival_window_sec": 5.0,
        "first_message_ratio": 1.0,
        "new_account_ratio": 1.0,
        "shared_domains": (),
        "signals": (),
        "risk_score": 55,
        "confidence": 0.6,
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return ClusterInfo(**defaults)  # type: ignore[arg-type]


class TestUpsertClusterByMembers:
    async def test_first_call_creates_new_cluster(self, store: ModerationStore) -> None:
        cluster = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        cluster_id = await store.upsert_cluster_by_members(cluster)
        assert cluster_id > 0

        cursor = await store._db.execute("SELECT COUNT(*) FROM mod_clusters")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1

    async def test_overlapping_members_update_same_row_not_insert_new(
        self, store: ModerationStore
    ) -> None:
        # Симулирует BUG-002: растущий рой ботов — второй вызов пересекается
        # по user_id "2" с первым, значит это ТОТ ЖЕ инцидент, выросший с
        # 3 до 5 участников, а не второй параллельный кластер.
        first = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        first_id = await store.upsert_cluster_by_members(first)

        second = make_cluster(
            user_ids=("2", "3", "4", "5", "6"),
            logins=("b", "c", "d", "e", "f"),
            risk_score=80,
        )
        second_id = await store.upsert_cluster_by_members(second)

        assert second_id == first_id
        cursor = await store._db.execute("SELECT COUNT(*) FROM mod_clusters")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1

    async def test_update_reflects_latest_metrics(self, store: ModerationStore) -> None:
        first = make_cluster(user_ids=("1", "2"), logins=("a", "b"), risk_score=40)
        cluster_id = await store.upsert_cluster_by_members(first)

        second = make_cluster(user_ids=("2", "3"), logins=("b", "c"), risk_score=90)
        await store.upsert_cluster_by_members(second)

        cursor = await store._db.execute(
            "SELECT risk_score FROM mod_clusters WHERE id = ?", (cluster_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 90

    async def test_all_members_accumulate_across_calls(self, store: ModerationStore) -> None:
        first = make_cluster(user_ids=("1", "2"), logins=("a", "b"))
        cluster_id = await store.upsert_cluster_by_members(first)

        second = make_cluster(user_ids=("2", "3", "4"), logins=("b", "c", "d"))
        await store.upsert_cluster_by_members(second)

        cursor = await store._db.execute(
            "SELECT COUNT(*) FROM mod_cluster_members WHERE cluster_id = ?", (cluster_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 4  # 1, 2, 3, 4 — без дублей

    async def test_no_overlap_creates_separate_cluster(self, store: ModerationStore) -> None:
        first = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        first_id = await store.upsert_cluster_by_members(first)

        unrelated = make_cluster(user_ids=("10", "11", "12"), logins=("x", "y", "z"))
        second_id = await store.upsert_cluster_by_members(unrelated)

        assert second_id != first_id
        cursor = await store._db.execute("SELECT COUNT(*) FROM mod_clusters")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 2

    async def test_ignores_non_active_clusters_when_matching(
        self, store: ModerationStore
    ) -> None:
        # Кластер, помеченный ignored/actioned/marked_safe — закрытый
        # инцидент; новое появление тех же user_id должно завести НОВЫЙ
        # активный кластер, а не тихо оживить закрытый.
        first = make_cluster(user_ids=("1", "2"), logins=("a", "b"))
        first_id = await store.upsert_cluster_by_members(first)
        await store.set_cluster_status(first_id, "ignored")

        second = make_cluster(user_ids=("1", "2"), logins=("a", "b"))
        second_id = await store.upsert_cluster_by_members(second)

        assert second_id != first_id


class TestUpsertClusterByMembersEx:
    """upsert_cluster_by_members_ex() — та же логика, что
    upsert_cluster_by_members(), плюс is_new: используется движком, чтобы
    решить, отправлять ли Discord-алерт (только на новый кластер, не на
    каждое обновление уже известного роя — направление 01 master-plan.html)."""

    async def test_first_call_reports_new(self, store: ModerationStore) -> None:
        cluster = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        cluster_id, is_new = await store.upsert_cluster_by_members_ex(cluster)
        assert is_new is True
        assert cluster_id > 0

    async def test_overlapping_second_call_reports_not_new(self, store: ModerationStore) -> None:
        first = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        first_id, _ = await store.upsert_cluster_by_members_ex(first)

        second = make_cluster(user_ids=("2", "3", "4"), logins=("b", "c", "d"))
        second_id, is_new = await store.upsert_cluster_by_members_ex(second)

        assert second_id == first_id
        assert is_new is False

    async def test_unrelated_cluster_reports_new(self, store: ModerationStore) -> None:
        first = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        await store.upsert_cluster_by_members_ex(first)

        unrelated = make_cluster(user_ids=("10", "11"), logins=("x", "y"))
        _, is_new = await store.upsert_cluster_by_members_ex(unrelated)

        assert is_new is True

    async def test_plain_upsert_still_returns_bare_id(self, store: ModerationStore) -> None:
        # upsert_cluster_by_members() (без _ex) — контракт для вызывающих
        # мест, не переписанных под кортеж (тесты выше в этом файле,
        # engine.py::observe() до направления 01): должен остаться int.
        cluster = make_cluster(user_ids=("1", "2"), logins=("a", "b"))
        result = await store.upsert_cluster_by_members(cluster)
        assert isinstance(result, int)


class TestDiscordWebhook:
    async def test_unconfigured_channel_returns_none(self, store: ModerationStore) -> None:
        assert await store.get_discord_webhook() is None

    async def test_set_then_get_roundtrips(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="dobriy_yura"
        )

        config = await store.get_discord_webhook()

        assert config is not None
        assert config.url == "https://discord.com/api/webhooks/1/abc"
        assert config.enabled is True
        assert config.updated_by == "dobriy_yura"

    async def test_second_set_overwrites_not_duplicates(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(url="https://discord.com/a", enabled=True, updated_by="a")
        await store.set_discord_webhook(url="https://discord.com/b", enabled=False, updated_by="b")

        config = await store.get_discord_webhook()

        assert config is not None
        assert config.url == "https://discord.com/b"
        assert config.enabled is False
        cursor = await store._db.execute("SELECT COUNT(*) FROM mod_discord_webhook")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1

    async def test_disabling_keeps_url(self, store: ModerationStore) -> None:
        # Модератор должен уметь временно выключить алерты, не вводя адрес
        # заново — enabled и url обновляются независимо на панели.
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=False, updated_by="a"
        )

        config = await store.get_discord_webhook()

        assert config is not None
        assert config.enabled is False
        assert config.url == "https://discord.com/api/webhooks/1/abc"


class TestGetDigestStats:
    """Ежедневный digest (направление 01 master-plan.html) считается
    напрямую по mod_messages/mod_verdicts/mod_clusters, не по
    mod_stats_daily (см. докстринг DigestStats)."""

    async def test_counts_messages_since_period_start(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        now = time.time()
        old = event_factory(user_id="1", login="a", timestamp=now - 100_000)
        recent = event_factory(user_id="2", login="b", timestamp=now - 10)
        await store.save_message(old, fingerprint(old.text))
        await store.save_message(recent, fingerprint(recent.text))

        stats = await store.get_digest_stats(since=now - 1000)

        assert stats.total_messages == 1

    async def test_counts_timeout_and_ban_verdicts_separately(
        self, store: ModerationStore
    ) -> None:
        now = time.time()
        timeout_verdict = Verdict(
            user_id="1", login="a", risk_score=60, confidence=0.6, signals=(),
            recommended_action=Action.TIMEOUT, reason="test", timestamp=now,
        )
        ban_verdict = Verdict(
            user_id="2", login="b", risk_score=90, confidence=0.9, signals=(),
            recommended_action=Action.BAN, reason="test", timestamp=now,
        )
        await store.save_verdict(timeout_verdict)
        await store.save_verdict(ban_verdict)
        await store.save_verdict(ban_verdict)

        stats = await store.get_digest_stats(since=now - 1000)

        assert stats.would_timeout == 1
        assert stats.would_ban == 2
        assert stats.suspicious_verdicts == 3

    async def test_observe_and_nothing_excluded_from_suspicious(
        self, store: ModerationStore
    ) -> None:
        # OBSERVE срабатывает часто на безобидные сообщения — считать его
        # "подозрительным" в сводке раздул бы цифру до бессмысленной.
        now = time.time()
        for action in (Action.OBSERVE, Action.NOTHING):
            verdict = Verdict(
                user_id="1", login="a", risk_score=10, confidence=0.1, signals=(),
                recommended_action=action, reason="test", timestamp=now,
            )
            await store.save_verdict(verdict)

        stats = await store.get_digest_stats(since=now - 1000)

        assert stats.suspicious_verdicts == 0
        assert stats.would_timeout == 0
        assert stats.would_ban == 0

    async def test_counts_new_clusters_in_period(self, store: ModerationStore) -> None:
        now = time.time()
        cluster = make_cluster(created_at=now)
        await store.save_cluster(cluster)

        stats = await store.get_digest_stats(since=now - 1000)

        assert stats.new_clusters == 1

    async def test_empty_period_returns_zeros(self, store: ModerationStore) -> None:
        stats = await store.get_digest_stats(since=time.time())

        assert stats.total_messages == 0
        assert stats.suspicious_verdicts == 0
        assert stats.would_timeout == 0
        assert stats.would_ban == 0
        assert stats.new_clusters == 0


class TestMarkDigestSent:
    async def test_sets_last_digest_sent_at(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        await store.mark_digest_sent(sent_at=12345.0)

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.last_digest_sent_at == 12345.0

    async def test_default_before_any_digest_is_none(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        config = await store.get_discord_webhook()

        assert config is not None
        assert config.last_digest_sent_at is None

    async def test_does_not_touch_url_or_enabled(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        await store.mark_digest_sent(sent_at=999.0)

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.url == "https://discord.com/api/webhooks/1/abc"
        assert config.enabled is True


class TestCountRecentNewClusters:
    """Эскалация при повторных атаках (направление 01 master-plan.html)
    считает НОВЫЕ кластеры — created_at пишется только save_cluster(), рост
    уже существующего кластера новыми участниками (upsert по общим
    user_id) сюда не попадает."""

    async def test_counts_clusters_created_since(self, store: ModerationStore) -> None:
        now = time.time()
        old = make_cluster(created_at=now - 100_000)
        recent1 = make_cluster(user_ids=("10", "11"), logins=("x", "y"), created_at=now - 10)
        recent2 = make_cluster(user_ids=("20", "21"), logins=("p", "q"), created_at=now - 5)
        await store.save_cluster(old)
        await store.save_cluster(recent1)
        await store.save_cluster(recent2)

        count = await store.count_recent_new_clusters(since=now - 1000)

        assert count == 2

    async def test_growth_of_existing_cluster_not_double_counted(
        self, store: ModerationStore
    ) -> None:
        now = time.time()
        first = make_cluster(user_ids=("1", "2"), logins=("a", "b"), created_at=now)
        await store.upsert_cluster_by_members_ex(first)
        grown = make_cluster(user_ids=("2", "3"), logins=("b", "c"), created_at=now)
        await store.upsert_cluster_by_members_ex(grown)

        count = await store.count_recent_new_clusters(since=now - 1000)

        assert count == 1

    async def test_no_clusters_returns_zero(self, store: ModerationStore) -> None:
        assert await store.count_recent_new_clusters(since=time.time() - 1000) == 0


class TestMarkEscalationSent:
    async def test_sets_last_escalation_sent_at(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        await store.mark_escalation_sent(sent_at=54321.0)

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.last_escalation_sent_at == 54321.0

    async def test_default_before_any_escalation_is_none(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        config = await store.get_discord_webhook()

        assert config is not None
        assert config.last_escalation_sent_at is None

    async def test_independent_from_digest_timestamp(self, store: ModerationStore) -> None:
        # Два разных cooldown на одной строке — не должны затирать друг
        # друга при независимых обновлениях.
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )
        await store.mark_digest_sent(sent_at=111.0)
        await store.mark_escalation_sent(sent_at=222.0)

        config = await store.get_discord_webhook()

        assert config is not None
        assert config.last_digest_sent_at == 111.0
        assert config.last_escalation_sent_at == 222.0


class TestSetAlertConfidenceThreshold:
    """Порог confidence для Discord-алерта (направление 01 master-plan.html)
    настраивается per-channel, не жёсткая константа в engine.py."""

    async def test_default_is_point_nine(self, store: ModerationStore) -> None:
        config = await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )
        assert config.alert_confidence_threshold == 0.9

    async def test_updates_threshold(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        await store.set_alert_confidence_threshold(threshold=0.7)

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.alert_confidence_threshold == 0.7

    async def test_does_not_touch_url_or_enabled(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        await store.set_alert_confidence_threshold(threshold=0.5)

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.url == "https://discord.com/api/webhooks/1/abc"
        assert config.enabled is True

    async def test_rejects_out_of_range_threshold(self, store: ModerationStore) -> None:
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )

        with pytest.raises(ValueError, match=r"\[0, 1\]"):
            await store.set_alert_confidence_threshold(threshold=1.5)

    async def test_raises_when_webhook_not_configured(self, store: ModerationStore) -> None:
        with pytest.raises(ValueError, match="ещё не настроен"):
            await store.set_alert_confidence_threshold(threshold=0.7)

    async def test_survives_url_change(self, store: ModerationStore) -> None:
        # set_discord_webhook (url/enabled) не должен затирать порог,
        # выставленный отдельным вызовом — независимые настройки.
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="a"
        )
        await store.set_alert_confidence_threshold(threshold=0.6)

        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/2/xyz", enabled=True, updated_by="a"
        )

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.alert_confidence_threshold == 0.6


class TestGetClusterMemberIds:
    async def test_returns_current_members(self, store: ModerationStore) -> None:
        cluster = make_cluster(user_ids=("1", "2", "3"), logins=("a", "b", "c"))
        cluster_id = await store.save_cluster(cluster)

        member_ids = await store.get_cluster_member_ids(cluster_id)

        assert sorted(member_ids) == ["1", "2", "3"]

    async def test_unknown_cluster_returns_empty(self, store: ModerationStore) -> None:
        assert await store.get_cluster_member_ids(999) == []

    async def test_reflects_growth_after_upsert(self, store: ModerationStore) -> None:
        first = make_cluster(user_ids=("1", "2"), logins=("a", "b"))
        cluster_id = await store.upsert_cluster_by_members(first)
        second = make_cluster(user_ids=("2", "3"), logins=("b", "c"))
        await store.upsert_cluster_by_members(second)

        member_ids = await store.get_cluster_member_ids(cluster_id)

        assert sorted(member_ids) == ["1", "2", "3"]


class TestPersistence:
    async def test_reconnect_preserves_data(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        path = str(tmp_path / "persist.db")

        store1 = ModerationStore(path)
        await store1.connect()
        await store1.upsert_user(event_factory(user_id="1", login="viewer1"))
        await store1.close()

        store2 = ModerationStore(path)
        await store2.connect()
        state = await store2.get_user_state("1")
        assert state is not None
        assert state.login == "viewer1"
        await store2.close()


class TestNotConnected:
    async def test_raises_clear_error_before_connect(self) -> None:
        store = ModerationStore("/nonexistent/path.db")
        with pytest.raises(RuntimeError, match="connect"):
            _ = store._db


class TestActionQueue:
    async def test_enqueue_returns_id(self, store: ModerationStore) -> None:
        qid = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        assert qid > 0

    async def test_pending_action_roundtrips_payload(self, store: ModerationStore) -> None:
        payload = {"action": "BAN", "target_user_ids": ["1", "2"], "reason": "spam", "cluster_id": 5}
        await store.enqueue_action(requested_by="mod1", requested_role="MODERATOR", payload=payload)

        items = await store.get_pending_actions()
        assert len(items) == 1
        assert items[0].requested_by == "mod1"
        assert items[0].requested_role == "MODERATOR"
        assert items[0].payload == payload

    async def test_pending_excludes_started_items(self, store: ModerationStore) -> None:
        qid = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        await store.mark_action_started(qid)

        items = await store.get_pending_actions()
        assert items == []

    async def test_respects_limit(self, store: ModerationStore) -> None:
        for _ in range(5):
            await store.enqueue_action(
                requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
            )
        items = await store.get_pending_actions(limit=2)
        assert len(items) == 2

    async def test_returns_in_fifo_order(self, store: ModerationStore) -> None:
        first = await store.enqueue_action(
            requested_by="a", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        second = await store.enqueue_action(
            requested_by="b", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        items = await store.get_pending_actions()
        assert [i.id for i in items] == [first, second]

    async def test_update_progress(self, store: ModerationStore) -> None:
        qid = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        await store.update_action_progress(qid, 3, 10)

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT progress_done, progress_total FROM mod_action_queue WHERE id = ?", (qid,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert tuple(row) == (3, 10)

    async def test_complete_action_sets_status_and_result(self, store: ModerationStore) -> None:
        qid = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        await store.complete_action(qid, status="completed", result={"succeeded": ["1"], "failed": []})

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, result_json FROM mod_action_queue WHERE id = ?", (qid,)
        )
        row = await cursor.fetchone()
        assert row is not None
        status, result_json = row
        assert status == "completed"
        assert json.loads(result_json) == {"succeeded": ["1"], "failed": []}


class TestReclaimStuckActions:
    """BUG-003 аудита: задание, застрявшее в 'running' (бот упал/перезапустился
    посреди исполнения), должно возвращаться в 'pending', чтобы process_pending()
    подобрал его снова, а не оставлял висеть в аудите навсегда."""

    async def _make_stuck(self, store: ModerationStore, *, age_seconds: float) -> int:
        qid = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
        )
        await store.mark_action_started(qid)
        # mark_action_started() всегда ставит time.time() — "состариваем"
        # запись напрямую, публичного API для этого нет и не должно быть.
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - age_seconds, qid),
        )
        await store._db.commit()  # noqa: SLF001
        return qid

    async def test_recent_running_action_not_reclaimed(self, store: ModerationStore) -> None:
        await self._make_stuck(store, age_seconds=1.0)

        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)

        assert reclaimed == 0

    async def test_old_running_action_reclaimed_to_pending(self, store: ModerationStore) -> None:
        qid = await self._make_stuck(store, age_seconds=300.0)

        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)

        assert reclaimed == 1
        items = await store.get_pending_actions()
        assert [i.id for i in items] == [qid]

    async def test_pending_actions_not_touched(self, store: ModerationStore) -> None:
        qid = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "BAN"}
        )

        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)

        assert reclaimed == 0
        items = await store.get_pending_actions()
        assert [i.id for i in items] == [qid]

    async def test_completed_actions_not_touched(self, store: ModerationStore) -> None:
        qid = await self._make_stuck(store, age_seconds=300.0)
        await store.complete_action(qid, status="completed", result={})

        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)

        assert reclaimed == 0

    async def test_reclaimed_action_clears_started_at(self, store: ModerationStore) -> None:
        qid = await self._make_stuck(store, age_seconds=300.0)

        await store.reclaim_stuck_actions(timeout_seconds=120.0)

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT started_at FROM mod_action_queue WHERE id = ?", (qid,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is None


class TestActionAudit:
    async def test_record_and_read_back(self, store: ModerationStore) -> None:
        audit_id = await store.record_action_audit(
            actor="mod1", actor_role="MODERATOR", action="BAN", scope="cluster",
            cluster_id=42, reason="known bot pattern", confirmation="MANUAL",
            succeeded=17, failed=0, details={"succeeded": list(map(str, range(17)))},
        )
        assert audit_id > 0

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT actor, action, scope, cluster_id, succeeded, failed FROM mod_actions WHERE id = ?",
            (audit_id,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert tuple(row) == ("mod1", "BAN", "cluster", 42, 17, 0)

    async def test_user_scope_without_cluster_id(self, store: ModerationStore) -> None:
        audit_id = await store.record_action_audit(
            actor="mod1", actor_role="MODERATOR", action="TIMEOUT", scope="user",
            reason="spam", confirmation="MANUAL", succeeded=1, failed=0, details={},
        )
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT cluster_id FROM mod_actions WHERE id = ?", (audit_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is None


class TestTrustedUsers:
    async def test_not_trusted_by_default(self, store: ModerationStore) -> None:
        assert await store.is_trusted("1") is False

    async def test_mark_trusted_updates_mod_users_marked_safe(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        event = event_factory(user_id="1", login="viewer1")
        await store.upsert_user(event)

        await store.mark_trusted("1", added_by="mod1", reason="known regular")

        assert await store.is_trusted("1") is True
        state = await store.get_user_state("1")
        assert state is not None
        assert state.marked_safe is True

    async def test_mark_trusted_without_prior_user_row_raises(
        self, store: ModerationStore
    ) -> None:
        # SEC-005 аудита: user_id, которого движок ещё не видел в чате этого
        # канала, нельзя пометить доверенным — раньше UPDATE молча не находил
        # строк, но mod_trusted всё равно получал запись (тихий баг).
        with pytest.raises(ValueError, match="ghost"):
            await store.mark_trusted("ghost", added_by="mod1", reason="preemptive")
        assert await store.is_trusted("ghost") is False

    async def test_unmark_trusted_reverts_marked_safe(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        event = event_factory(user_id="1", login="viewer1")
        await store.upsert_user(event)
        await store.mark_trusted("1", added_by="mod1")

        await store.unmark_trusted("1")

        assert await store.is_trusted("1") is False
        state = await store.get_user_state("1")
        assert state is not None
        assert state.marked_safe is False

    async def test_list_trusted_ordered_newest_first(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="viewer1"))
        await store.upsert_user(event_factory(user_id="2", login="viewer2"))
        await store.mark_trusted("1", added_by="mod1", reason="first")
        await store.mark_trusted("2", added_by="mod1", reason="second")

        rows = await store.list_trusted()

        assert [r["user_id"] for r in rows] == ["2", "1"]

    async def test_mark_trusted_is_idempotent_upsert(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="viewer1"))
        await store.mark_trusted("1", added_by="mod1", reason="first reason")
        await store.mark_trusted("1", added_by="mod2", reason="updated reason")

        rows = await store.list_trusted()
        assert len(rows) == 1
        assert rows[0]["added_by"] == "mod2"
        assert rows[0]["reason"] == "updated reason"

    async def test_list_trusted_includes_login_and_message_count(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        event = event_factory(user_id="1", login="viewer1")
        await store.upsert_user(event)
        await store.upsert_user(event)  # message_count = 2
        await store.mark_trusted("1", added_by="mod1", reason="regular")

        rows = await store.list_trusted()

        assert rows[0]["login"] == "viewer1"
        assert rows[0]["message_count"] == 2


def make_pattern_input(**overrides: object) -> PatternInput:
    defaults: dict[str, object] = {
        "name": "mass registration attack",
        "description": "10+ новых аккаунтов пришли за секунды с общей ссылкой",
        "required_signal_names": ("shared_link_multi_user", "synchronized_arrival"),
        "min_families": 2,
        "min_risk_score": 60,
        "min_confidence": 0.7,
        "min_cluster_size": 10,
        "enabled": True,
        "auto_enabled": False,
        "weight": 5.0,
        "created_by": "mod1",
    }
    defaults.update(overrides)
    return PatternInput(**defaults)  # type: ignore[arg-type]


class TestPatterns:
    async def test_create_and_list(self, store: ModerationStore) -> None:
        pattern_id = await store.create_pattern(make_pattern_input())

        patterns = await store.list_patterns()

        assert len(patterns) == 1
        assert patterns[0].id == pattern_id
        assert patterns[0].name == "mass registration attack"
        assert patterns[0].required_signal_names == ("shared_link_multi_user", "synchronized_arrival")
        assert patterns[0].min_cluster_size == 10
        assert patterns[0].created_by == "mod1"

    async def test_list_enabled_only_filters_disabled(self, store: ModerationStore) -> None:
        await store.create_pattern(make_pattern_input(name="enabled one", enabled=True))
        await store.create_pattern(make_pattern_input(name="disabled one", enabled=False))

        all_patterns = await store.list_patterns(enabled_only=False)
        enabled_patterns = await store.list_patterns(enabled_only=True)

        assert len(all_patterns) == 2
        assert len(enabled_patterns) == 1
        assert enabled_patterns[0].name == "enabled one"

    async def test_list_ordered_by_weight_descending(self, store: ModerationStore) -> None:
        await store.create_pattern(make_pattern_input(name="weak", weight=1.0))
        await store.create_pattern(make_pattern_input(name="strong", weight=9.0))

        patterns = await store.list_patterns()

        assert [p.name for p in patterns] == ["strong", "weak"]

    async def test_set_pattern_enabled(self, store: ModerationStore) -> None:
        pattern_id = await store.create_pattern(make_pattern_input(enabled=True))

        await store.set_pattern_enabled(pattern_id, False)

        patterns = await store.list_patterns()
        assert patterns[0].enabled is False

    async def test_delete_pattern(self, store: ModerationStore) -> None:
        pattern_id = await store.create_pattern(make_pattern_input())

        await store.delete_pattern(pattern_id)

        assert await store.list_patterns() == []

    async def test_empty_required_signal_names_roundtrip(self, store: ModerationStore) -> None:
        await store.create_pattern(make_pattern_input(required_signal_names=()))

        patterns = await store.list_patterns()

        assert patterns[0].required_signal_names == ()


class TestAttackMode:
    async def test_inactive_by_default(self, store: ModerationStore) -> None:
        assert await store.get_active_attack_mode() is None

    async def test_activate_returns_status(self, store: ModerationStore) -> None:
        status = await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)

        assert status.activated_by == "admin1"
        assert status.expires_at > status.activated_at

    async def test_get_active_after_activation(self, store: ModerationStore) -> None:
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)

        status = await store.get_active_attack_mode()

        assert status is not None
        assert status.activated_by == "admin1"

    async def test_deactivate_clears_status(self, store: ModerationStore) -> None:
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)

        await store.deactivate_attack_mode()

        assert await store.get_active_attack_mode() is None

    async def test_expired_attack_mode_reads_as_inactive(self, store: ModerationStore) -> None:
        # duration_seconds отрицательный -> expires_at в прошлом сразу же.
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=-1)

        assert await store.get_active_attack_mode() is None

    async def test_reactivation_overwrites_previous(self, store: ModerationStore) -> None:
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)
        await store.activate_attack_mode(activated_by="admin2", duration_seconds=600)

        status = await store.get_active_attack_mode()

        assert status is not None
        assert status.activated_by == "admin2"

    async def test_to_dict_includes_seconds_remaining(self, store: ModerationStore) -> None:
        status = await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)

        d = status.to_dict()

        assert d["activated_by"] == "admin1"
        seconds_remaining = d["seconds_remaining"]
        assert isinstance(seconds_remaining, float)
        assert 0 < seconds_remaining <= 1800


class TestGiveawayMode:
    async def test_inactive_by_default(self, store: ModerationStore) -> None:
        assert await store.get_active_giveaway_mode() is None

    async def test_activate_returns_status(self, store: ModerationStore) -> None:
        status = await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=900)

        assert status.activated_by == "admin1"
        assert status.expires_at > status.activated_at

    async def test_get_active_after_activation(self, store: ModerationStore) -> None:
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=900)

        status = await store.get_active_giveaway_mode()

        assert status is not None
        assert status.activated_by == "admin1"

    async def test_deactivate_clears_status(self, store: ModerationStore) -> None:
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=900)

        await store.deactivate_giveaway_mode()

        assert await store.get_active_giveaway_mode() is None

    async def test_expired_giveaway_mode_reads_as_inactive(self, store: ModerationStore) -> None:
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=-1)

        assert await store.get_active_giveaway_mode() is None

    async def test_reactivation_overwrites_previous(self, store: ModerationStore) -> None:
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=900)
        await store.activate_giveaway_mode(activated_by="admin2", duration_seconds=300)

        status = await store.get_active_giveaway_mode()

        assert status is not None
        assert status.activated_by == "admin2"

    async def test_independent_from_attack_mode(self, store: ModerationStore) -> None:
        # Обе таблицы singleton (id=1), но РАЗНЫЕ — активация одной не
        # должна задевать другую.
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)
        await store.activate_giveaway_mode(activated_by="admin2", duration_seconds=900)

        attack = await store.get_active_attack_mode()
        giveaway = await store.get_active_giveaway_mode()

        assert attack is not None and attack.activated_by == "admin1"
        assert giveaway is not None and giveaway.activated_by == "admin2"


class TestFeedback:
    async def test_record_and_list(self, store: ModerationStore) -> None:
        feedback_id = await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="FALSE_POSITIVE",
            user_id="1",
        )

        rows = await store.list_feedback()

        assert len(rows) == 1
        assert rows[0]["id"] == feedback_id
        assert rows[0]["signal_name"] == "unexpected_language"
        assert rows[0]["decision"] == "FALSE_POSITIVE"
        assert rows[0]["moderator"] == "mod1"

    async def test_fp_penalty_zero_without_feedback(self, store: ModerationStore) -> None:
        assert await store.get_signal_fp_penalty("exact_duplicate") == 0.0

    async def test_fp_penalty_computed_from_ratio(self, store: ModerationStore) -> None:
        await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="FALSE_POSITIVE"
        )
        await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="FALSE_POSITIVE"
        )
        await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="CONFIRMED_BOT"
        )

        penalty = await store.get_signal_fp_penalty("unexpected_language")

        assert penalty == 2 / 3

    async def test_fp_penalty_only_considers_matching_signal(self, store: ModerationStore) -> None:
        await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="FALSE_POSITIVE"
        )
        await store.record_feedback(
            signal_name="exact_duplicate", moderator="mod1", decision="FALSE_POSITIVE"
        )

        assert await store.get_signal_fp_penalty("unexpected_language") == 1.0
        assert await store.get_signal_fp_penalty("exact_duplicate") == 1.0

    async def test_fp_penalty_respects_sample_size(self, store: ModerationStore) -> None:
        # 1 false positive, потом 5 confirmed_bot -> penalty должен
        # учитывать только последние sample_size записей.
        await store.record_feedback(
            signal_name="s1", moderator="mod1", decision="FALSE_POSITIVE"
        )
        for _ in range(5):
            await store.record_feedback(
                signal_name="s1", moderator="mod1", decision="CONFIRMED_BOT"
            )

        penalty = await store.get_signal_fp_penalty("s1", sample_size=2)

        # последние 2 записи (по created_at DESC) — обе CONFIRMED_BOT
        assert penalty == 0.0


class TestDailyStats:
    async def test_increment_creates_row(self, store: ModerationStore) -> None:
        await store.increment_daily_stats(date="2026-08-08", total_messages=10, suspicious=3)

        rows = await store.get_daily_stats()

        assert len(rows) == 1
        assert rows[0]["date"] == "2026-08-08"
        assert rows[0]["total_messages"] == 10
        assert rows[0]["suspicious"] == 3
        assert rows[0]["would_ban"] == 0

    async def test_increment_accumulates(self, store: ModerationStore) -> None:
        await store.increment_daily_stats(date="2026-08-08", total_messages=10)
        await store.increment_daily_stats(date="2026-08-08", total_messages=5)

        rows = await store.get_daily_stats()

        assert rows[0]["total_messages"] == 15

    async def test_separate_dates_separate_rows(self, store: ModerationStore) -> None:
        await store.increment_daily_stats(date="2026-08-07", total_messages=10)
        await store.increment_daily_stats(date="2026-08-08", total_messages=5)

        rows = await store.get_daily_stats()

        assert len(rows) == 2

    async def test_unknown_counter_rejected(self, store: ModerationStore) -> None:
        with pytest.raises(ValueError, match="typo_counter"):
            await store.increment_daily_stats(date="2026-08-08", typo_counter=1)

    async def test_no_counters_is_noop(self, store: ModerationStore) -> None:
        await store.increment_daily_stats(date="2026-08-08")
        assert await store.get_daily_stats() == []

    async def test_days_limit_respected(self, store: ModerationStore) -> None:
        for day in range(1, 6):
            await store.increment_daily_stats(date=f"2026-08-{day:02d}", total_messages=1)

        rows = await store.get_daily_stats(days=2)

        assert len(rows) == 2
        # ORDER BY date DESC -> самые свежие даты первыми
        assert rows[0]["date"] == "2026-08-05"
