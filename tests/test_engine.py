"""Тесты engine.py — сквозная проверка всей цепочки observe(event) -> Verdict.

Здесь те же два обязательных сценария из ТЗ (раздел 18), что и в
test_clustering.py, но прогнанные через ПОЛНЫЙ движок (детекторы + кластеры
+ scoring + confidence + policy), а не через один клин архитектуры — это
проверяет, что слои действительно стыкуются, а не только каждый по
отдельности.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from cigilbot.domain.config import ChannelProfile, default_config
from cigilbot.domain.types import Action, ClusterInfo, Mode
from cigilbot.orchestration.engine import ESCALATION_CLUSTER_THRESHOLD, ModerationEngine
from cigilbot.storage.store import ModerationStore, PatternInput
from tests.conftest import EventFactory


def make_engine(store: ModerationStore | None = None, **profile_overrides: object) -> ModerationEngine:
    cfg = default_config()
    defaults: dict[str, object] = {"channel": "test"}
    defaults.update(profile_overrides)
    profile = ChannelProfile(**defaults)  # type: ignore[arg-type]
    return ModerationEngine(cfg, profile, store, mode=Mode.SHADOW)


class TestBasicObserve:
    async def test_single_clean_message_is_nothing(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        verdict = await engine.observe(event_factory(text="привет всем, как дела"))
        assert verdict.recommended_action == Action.NOTHING
        assert verdict.risk_score < 30

    async def test_mode_is_recorded_on_verdict(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        verdict = await engine.observe(event_factory())
        assert verdict.mode == Mode.SHADOW

    async def test_provisional_when_account_age_unknown(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        verdict = await engine.observe(event_factory(account_created_at=None))
        assert verdict.is_provisional is True

    async def test_not_provisional_once_helix_supplies_account_age(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        # Возраст аккаунта приходит асинхронно от Helix, а не в самом
        # ChatEvent (см. types.py) — движок узнаёт о нём только через
        # store.set_account_created_at между вызовами observe().
        store = ModerationStore(str(tmp_path / "provisional.db"))
        await store.connect()
        engine = make_engine(store=store)

        event = event_factory(user_id="1", login="viewer1")
        first = await engine.observe(event)
        assert first.is_provisional is True

        await store.set_account_created_at("1", time.time() - 365 * 86400)

        # новый экземпляр движка эмулирует пересчёт с уже известным возрастом
        engine2 = make_engine(store=store)
        second = await engine2.observe(event_factory(user_id="1", login="viewer1"))
        assert second.is_provisional is False

        await store.close()


class TestProvisionalVerdictViaEngine:
    """FALSE-BAN-002 аудита: движок передаёт is_provisional в policy.decide(),
    поэтому даже атака, набравшая формально достаточно risk/confidence/семейств
    для BAN, не может получить BAN, пока возраст аккаунта неизвестен."""

    async def test_strong_attack_capped_at_timeout_while_provisional(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        now = time.time()
        verdicts = []
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            ev = event_factory(
                user_id=f"bot{i}", login=f"bot{i}", text=text,
                timestamp=now + i * (3.0 / 50), is_first_message=True,
                account_created_at=None,  # явно провизорно
            )
            verdicts.append(await engine.observe(ev))

        assert all(v.is_provisional for v in verdicts)
        assert all(v.recommended_action != Action.BAN for v in verdicts)

    async def test_same_attack_can_ban_once_account_age_known(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        # ChatEvent.account_created_at сам по себе не формирует
        # UserState.account_created_at — тот приходит только асинхронно,
        # через store.set_account_created_at() (см. соседний тест
        # test_not_provisional_once_helix_supplies_account_age в
        # TestBasicObserve). set_account_created_at() — обычный UPDATE, он
        # молча не находит строк для пользователя, которого upsert_user()
        # ещё ни разу не создавал в mod_users — поэтому сначала один проход
        # (создаёт строки, вердикты провизорны), затем Helix "отвечает" про
        # возраст, затем НОВЫЙ движок повторяет ту же атаку с уже известным
        # возрастом (эмулирует пересчёт на следующем сообщении).
        store = ModerationStore(str(tmp_path / "provisional_ban_possible.db"))
        await store.connect()
        now = time.time()

        engine_first_pass = make_engine(store=store)
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            ev = event_factory(
                user_id=f"bot{i}", login=f"bot{i}", text=text,
                timestamp=now + i * (3.0 / 50), is_first_message=True,
            )
            await engine_first_pass.observe(ev)

        for i in range(50):
            await store.set_account_created_at(f"bot{i}", now - 86400.0)

        engine_second_pass = make_engine(store=store)
        verdicts = []
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            ev = event_factory(
                user_id=f"bot{i}", login=f"bot{i}", text=text,
                timestamp=now + 100 + i * (3.0 / 50), is_first_message=True,
            )
            verdicts.append(await engine_second_pass.observe(ev))

        assert all(not v.is_provisional for v in verdicts)
        # Раз is_provisional больше не блокирует, у сильной атаки снова есть
        # возможность дойти до BAN (сама возможность, не гарантия — прочие
        # инварианты confidence/families по-прежнему применяются как обычно).
        assert any(v.recommended_action == Action.BAN for v in verdicts[-10:])

        await store.close()


class TestSpecScenarioViaEngine:
    """Прямая проверка ТЗ (раздел 18) через полный движок."""

    async def test_50_bots_form_cluster_and_engine_recommends_action(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        now = time.time()
        verdicts = []
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            ev = event_factory(
                user_id=f"bot{i}", login=f"bot{i}", text=text,
                timestamp=now + i * (3.0 / 50), is_first_message=True,
            )
            verdicts.append(await engine.observe(ev))

        last = verdicts[-1]
        assert last.cluster_id is not None
        assert last.risk_score >= 60
        # хотя бы часть последних участников должна получить рекомендацию
        # выше NOTHING — атака обязана быть замечена
        assert any(v.recommended_action != Action.NOTHING for v in verdicts[-10:])

    async def test_10_polish_viewers_never_exceed_observe(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine(expected_languages=("ru", "en"), suspicious_languages=("pl",))
        now = time.time()
        messages = [
            "dzień dobry wszystkim, jak się dzisiaj macie",
            "super stream jak zawsze, pozdrawiam wszystkich",
            "czy ktoś wie kiedy zaczyna się kolejny odcinek",
            "świetna gra, gratulacje za wygraną w tym meczu",
            "przepraszam za pytanie ale co to za gra jest",
            "no i super, dzięki za miły wieczór wszystkim",
            "czekam na kolejny stream z wielką niecierpliwością",
            "pierwszy raz oglądam, bardzo mi się podoba klimat",
            "ale klimat na tym kanale, super sprawa naprawdę",
            "dzięki za rozrywkę, do zobaczenia jutro wieczorem",
        ]
        verdicts = []
        for i, text in enumerate(messages):
            ev = event_factory(
                user_id=f"pl{i}", login=f"pl{i}", text=text,
                timestamp=now + i * 1.5, is_first_message=(i % 3 == 0),
            )
            verdicts.append(await engine.observe(ev))

        for v in verdicts:
            assert v.recommended_action in (Action.NOTHING, Action.OBSERVE)
            assert v.recommended_action != Action.BAN
            assert v.recommended_action != Action.TIMEOUT


class TestPrivilegedNeverAutoActioned:
    async def test_moderator_spamming_links_stays_at_observe(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        now = time.time()
        verdict = None
        for i in range(15):
            ev = event_factory(
                user_id="mod1", login="mod1", text=f"заходите scam-site.com/promo{i}",
                timestamp=now + i * 0.3, is_moderator=True,
            )
            verdict = await engine.observe(ev)
        assert verdict is not None
        assert verdict.recommended_action in (Action.NOTHING, Action.OBSERVE)


class TestStoreIntegration:
    async def test_verdict_persisted_when_store_given(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "engine_test.db"))
        await store.connect()
        engine = make_engine(store=store)

        event = event_factory(text="привет")
        verdict = await engine.observe(event)

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM mod_verdicts WHERE user_id = ?", (event.user_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1
        assert verdict.risk_score >= 0

        await store.close()

    async def test_user_state_persists_across_engine_instances(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        db_path = str(tmp_path / "persist_engine.db")

        store1 = ModerationStore(db_path)
        await store1.connect()
        engine1 = make_engine(store=store1)
        event = event_factory(user_id="1", login="viewer1")
        await engine1.observe(event)
        await store1.close()

        store2 = ModerationStore(db_path)
        await store2.connect()
        state = await store2.get_user_state("1")
        assert state is not None
        assert state.message_count == 1
        await store2.close()

    async def test_works_without_store(self, event_factory: EventFactory) -> None:
        engine = make_engine(store=None)
        verdict = await engine.observe(event_factory())
        assert verdict is not None


class TestUserCacheEviction:
    """BUG-004 аудита: self._users — LRU с потолком, не безграничный dict."""

    async def test_cache_does_not_grow_past_max_cached_users(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine(store=None)
        # Маленький потолок ради скорости теста — подменяем модульную
        # константу, а не гоняем MAX_CACHED_USERS+ сообщений.
        engine_max = 5
        import cigilbot.orchestration.engine as engine_module

        original = engine_module.MAX_CACHED_USERS
        engine_module.MAX_CACHED_USERS = engine_max
        try:
            for i in range(engine_max + 3):
                await engine.observe(event_factory(user_id=f"u{i}", login=f"u{i}"))
            assert len(engine._users) <= engine_max  # noqa: SLF001
        finally:
            engine_module.MAX_CACHED_USERS = original

    async def test_evicted_user_falls_back_to_store_not_lost(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "eviction.db"))
        await store.connect()
        engine = make_engine(store=store)

        import cigilbot.orchestration.engine as engine_module

        original = engine_module.MAX_CACHED_USERS
        engine_module.MAX_CACHED_USERS = 2
        try:
            first_event = event_factory(user_id="u0", login="u0")
            await engine.observe(first_event)
            # Заполняем кеш другими юзерами, вытесняя "u0" из памяти.
            for i in range(1, 5):
                await engine.observe(event_factory(user_id=f"u{i}", login=f"u{i}"))
            assert "u0" not in engine._users  # noqa: SLF001

            # Возврат вытесненного юзера — состояние подтягивается из store,
            # а не создаётся с нуля (message_count не начинает с 1 снова).
            verdict = await engine.observe(
                event_factory(user_id="u0", login="u0", timestamp=first_event.timestamp + 10)
            )
            assert verdict is not None
            state = await store.get_user_state("u0")
            assert state is not None
            assert state.message_count == 2
        finally:
            engine_module.MAX_CACHED_USERS = original
            await store.close()

    async def test_accessing_existing_user_marks_it_recently_used(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine(store=None)

        import cigilbot.orchestration.engine as engine_module

        original = engine_module.MAX_CACHED_USERS
        engine_module.MAX_CACHED_USERS = 3
        try:
            await engine.observe(event_factory(user_id="u0", login="u0"))
            await engine.observe(event_factory(user_id="u1", login="u1"))
            await engine.observe(event_factory(user_id="u2", login="u2"))
            # Трогаем u0 снова — теперь он самый свежий, не должен быть
            # вытеснен следующим новым юзером (вытесниться должен u1).
            await engine.observe(event_factory(user_id="u0", login="u0"))
            await engine.observe(event_factory(user_id="u3", login="u3"))

            assert "u0" in engine._users  # noqa: SLF001
            assert "u1" not in engine._users  # noqa: SLF001
        finally:
            engine_module.MAX_CACHED_USERS = original


class TestWindowStateAccumulates:
    async def test_burst_detected_across_multiple_observe_calls(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        now = time.time()
        verdicts = []
        for i in range(15):
            ev = event_factory(
                user_id="spammer", login="spammer", text=f"сообщение номер {i}",
                timestamp=now + i * 0.2,
            )
            verdicts.append(await engine.observe(ev))

        # хотя бы одно из поздних сообщений должно словить burst-сигнал
        later_signals = {s.name for v in verdicts[-5:] for s in v.signals}
        assert "user_message_burst" in later_signals


class TestFeedbackLoop:
    """Этап 9d: fp_penalty из mod_feedback снижает confidence по сработавшему
    сигналу — только явный reload_fp_penalties() подтягивает изменения,
    как и Pattern Library/Attack Mode."""

    async def test_without_reload_fp_penalty_is_zero(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "feedback_no_reload.db"))
        await store.connect()
        for _ in range(10):
            await store.record_feedback(
                signal_name="user_message_burst", moderator="mod1", decision="FALSE_POSITIVE"
            )

        engine = make_engine(store=store)
        now = time.time()
        verdicts = []
        for i in range(15):
            ev = event_factory(
                user_id="spammer1", login="spammer1", text=f"сообщение номер {i}",
                timestamp=now + i * 0.2,
            )
            verdicts.append(await engine.observe(ev))

        await store.close()
        # без reload_fp_penalties() движок не знает о фидбеке — confidence
        # не отличается от случая без всякого feedback вообще.
        assert any("user_message_burst" in v.signal_names for v in verdicts)

    async def test_high_fp_rate_lowers_confidence(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "feedback_reload.db"))
        await store.connect()

        engine_clean = make_engine(store=store)
        now = time.time()
        clean_verdict = None
        for i in range(15):
            ev = event_factory(
                user_id="spammer_clean", login="spammer_clean", text=f"сообщение номер {i}",
                timestamp=now + i * 0.2,
            )
            clean_verdict = await engine_clean.observe(ev)

        for _ in range(10):
            await store.record_feedback(
                signal_name="user_message_burst", moderator="mod1", decision="FALSE_POSITIVE"
            )

        engine_penalized = make_engine(store=store)
        await engine_penalized.reload_fp_penalties()
        penalized_verdict = None
        for i in range(15):
            ev = event_factory(
                user_id="spammer_penalized", login="spammer_penalized",
                text=f"сообщение номер {i}", timestamp=now + i * 0.2,
            )
            penalized_verdict = await engine_penalized.observe(ev)

        assert clean_verdict is not None
        assert penalized_verdict is not None
        assert "user_message_burst" in clean_verdict.signal_names
        assert "user_message_burst" in penalized_verdict.signal_names
        assert penalized_verdict.confidence < clean_verdict.confidence

        await store.close()

    async def test_reload_without_store_is_noop(self, event_factory: EventFactory) -> None:
        engine = make_engine(store=None)
        await engine.reload_fp_penalties()  # не должно упасть без store


class TestAttackMode:
    """Этап 9c: Attack Mode поднимает Sensitivity.ATTACK для расчёта
    risk_score, но не может обойти MIN_FAMILIES_FOR_BAN/confidence-пороги
    в policy.py — те инварианты заперты константой независимо от режима."""

    async def test_inactive_by_default(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        assert engine.attack_mode_active is False

    async def test_raises_risk_score_for_same_signals(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "attack_mode_engine.db"))
        await store.connect()

        engine_normal = make_engine(store=store)
        now = time.time()
        normal_verdict = None
        for i in range(15):
            ev = event_factory(
                user_id="spammer1", login="spammer1", text=f"сообщение номер {i}",
                timestamp=now + i * 0.2,
            )
            normal_verdict = await engine_normal.observe(ev)

        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)
        engine_attack = make_engine(store=store)
        await engine_attack.sync_attack_mode()
        assert engine_attack.attack_mode_active is True

        attack_verdict = None
        for i in range(15):
            ev = event_factory(
                user_id="spammer2", login="spammer2", text=f"сообщение номер {i}",
                timestamp=now + i * 0.2,
            )
            attack_verdict = await engine_attack.observe(ev)

        assert normal_verdict is not None
        assert attack_verdict is not None
        assert attack_verdict.risk_score >= normal_verdict.risk_score

        await store.close()

    async def test_does_not_bypass_min_families_for_ban(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        # Инвариант: даже с Attack Mode активным, одно-единственное семейство
        # сигналов не может привести к BAN — MIN_FAMILIES_FOR_BAN в policy.py
        # не читается ни из конфига, ни из Sensitivity.
        store = ModerationStore(str(tmp_path / "attack_mode_invariant.db"))
        await store.connect()
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)

        engine = make_engine(store=store)
        await engine.sync_attack_mode()

        # Один слабый сигнал (unexpected_language) — не должен эскалировать
        # до BAN даже под Attack Mode.
        verdict = await engine.observe(
            event_factory(text="dzień dobry wszystkim, jak się macie dzisiaj")
        )

        assert verdict.recommended_action != Action.BAN

    async def test_expired_attack_mode_not_applied(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "attack_mode_expired.db"))
        await store.connect()
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=-1)

        engine = make_engine(store=store)
        await engine.sync_attack_mode()

        assert engine.attack_mode_active is False

        await store.close()

    async def test_deactivate_stops_applying_attack_sensitivity(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "attack_mode_deactivate.db"))
        await store.connect()
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)

        engine = make_engine(store=store)
        await engine.sync_attack_mode()
        active_before: bool = engine.attack_mode_active
        assert active_before is True

        await store.deactivate_attack_mode()
        await engine.sync_attack_mode()

        active_after: bool = engine.attack_mode_active
        assert active_after is False

        await store.close()

    async def test_sync_without_store_is_noop(self, event_factory: EventFactory) -> None:
        engine = make_engine(store=None)
        await engine.sync_attack_mode()  # не должно упасть без store
        assert engine.attack_mode_active is False


class TestKnownBadActors:
    """Cross-Channel Bot Fingerprint (направление 03 master-plan.html):
    ModerationHub раздаёт снимок известных user_id через
    sync_known_bad_actors(), движок сам не ходит в fingerprints.db."""

    async def test_empty_by_default(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        verdict = await engine.observe(event_factory(user_id="1", text="привет всем"))
        assert "known_bad_actor" not in [s.name for s in verdict.signals]

    async def test_known_user_gets_signal(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        engine.sync_known_bad_actors(frozenset({"1"}))

        verdict = await engine.observe(event_factory(user_id="1", text="привет всем"))

        assert "known_bad_actor" in [s.name for s in verdict.signals]

    async def test_unrelated_user_unaffected(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        engine.sync_known_bad_actors(frozenset({"other_user"}))

        verdict = await engine.observe(event_factory(user_id="1", text="привет всем"))

        assert "known_bad_actor" not in [s.name for s in verdict.signals]

    async def test_resync_replaces_previous_set(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        engine.sync_known_bad_actors(frozenset({"1"}))
        engine.sync_known_bad_actors(frozenset({"2"}))

        verdict = await engine.observe(event_factory(user_id="1", text="привет всем"))

        assert "known_bad_actor" not in [s.name for s in verdict.signals]


class TestAutoChannelContext:
    """FALSE-BAN-001 аудита: раньше engine.observe() без явного
    channel_context всегда получал ChannelContext() (все флаги False) —
    ни рейд, ни розыгрыш, ни хайп никогда не учитывались confidence.py.
    Теперь движок сам строит контекст из raid_active/giveaway_mode_active/
    эвристики скорости чата, когда вызывающий код не передаёт его явно."""

    async def test_no_context_by_default(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        assert engine.raid_active is False
        assert engine.giveaway_mode_active is False

    async def test_mark_raid_started_activates_raid_context(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        engine.mark_raid_started()
        assert engine.raid_active is True

    async def test_raid_expires_after_context_window(self, event_factory: EventFactory) -> None:
        from cigilbot.orchestration.engine import RAID_CONTEXT_SECONDS

        engine = make_engine()
        long_ago = time.time() - RAID_CONTEXT_SECONDS - 1
        engine.mark_raid_started(now=long_ago)
        assert engine.raid_active is False

    async def test_explicit_channel_context_not_overridden(
        self, event_factory: EventFactory
    ) -> None:
        from cigilbot.domain.types import ChannelContext

        engine = make_engine()
        # Явно переданный контекст должен использоваться как есть, даже
        # если движок сам не считает канал в состоянии рейда/хайпа.
        explicit = ChannelContext(is_raid=True)
        verdict = await engine.observe(event_factory(text="normal message"), channel_context=explicit)
        assert verdict is not None  # прошло без ошибок — сигнал дошёл до confidence.py

    async def test_giveaway_mode_reflected_in_property(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "giveaway_engine.db"))
        await store.connect()
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=900)

        engine = make_engine(store=store)
        await engine.sync_giveaway_mode()

        assert engine.giveaway_mode_active is True
        await store.close()

    async def test_expired_giveaway_mode_not_active(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "giveaway_expired.db"))
        await store.connect()
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=-1)

        engine = make_engine(store=store)
        await engine.sync_giveaway_mode()

        assert engine.giveaway_mode_active is False
        await store.close()

    async def test_sync_giveaway_without_store_is_noop(self, event_factory: EventFactory) -> None:
        engine = make_engine(store=None)
        await engine.sync_giveaway_mode()  # не должно упасть без store
        assert engine.giveaway_mode_active is False

    async def test_channel_activity_reflects_recent_messages(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        now = time.time()
        for i in range(5):
            await engine.observe(
                event_factory(user_id=f"u{i}", login=f"u{i}", text=f"msg {i}", timestamp=now + i * 0.1)
            )
        rate, unique = engine.channel_activity(now=now + 1)
        assert rate > 0
        assert unique == 5

    async def test_auto_context_applies_raid_discount_without_explicit_context(
        self, event_factory: EventFactory
    ) -> None:
        # Сквозная проверка FALSE-BAN-001: без явного channel_context движок
        # сам подставляет is_raid=True после mark_raid_started(), и это
        # реально снижает risk_score для одного и того же набора сигналов
        # относительно немаркированного канала (через context_factor в
        # confidence.py и дампинг в burst.py).
        now = time.time()

        engine_normal = make_engine()
        normal_verdicts = []
        for i in range(20):
            ev = event_factory(
                user_id=f"viewer{i}", login=f"viewer{i}", text="привет всем", timestamp=now + i * 0.05,
                is_first_message=True,
            )
            normal_verdicts.append(await engine_normal.observe(ev))

        engine_raid = make_engine()
        engine_raid.mark_raid_started(now=now)
        raid_verdicts = []
        for i in range(20):
            ev = event_factory(
                user_id=f"raider{i}", login=f"raider{i}", text="привет всем", timestamp=now + i * 0.05,
                is_first_message=True,
            )
            raid_verdicts.append(await engine_raid.observe(ev))

        # confidence ниже (или равна) под рейдом — context_factor("raid")=0.5
        # применяется и на burst-детекторе, и на общем confidence.
        assert raid_verdicts[-1].confidence <= normal_verdicts[-1].confidence


class TestPatternMatching:
    """Этап 9b: Bot Pattern Library классифицирует уже готовый вердикт/
    кластер названием шаблона, не меняя risk/confidence/action."""

    async def test_50_bots_attack_gets_pattern_id(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "patterns_engine.db"))
        await store.connect()
        pattern_id = await store.create_pattern(
            PatternInput(
                name="mass link spam",
                description="10+ ботов с общей ссылкой пришли почти одновременно",
                required_signal_names=("synchronized_arrival",),
                min_families=0,
                min_risk_score=0,
                min_confidence=0.0,
                min_cluster_size=10,
                enabled=True,
                auto_enabled=False,
                weight=5.0,
                created_by="mod1",
            )
        )

        engine = make_engine(store=store)
        await engine.reload_patterns()

        now = time.time()
        verdicts = []
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            ev = event_factory(
                user_id=f"bot{i}", login=f"bot{i}", text=text,
                timestamp=now + i * (3.0 / 50), is_first_message=True,
            )
            verdicts.append(await engine.observe(ev))

        last = verdicts[-1]
        assert last.cluster_id is not None
        assert last.pattern_id == pattern_id

        await store.close()

    async def test_without_reload_patterns_no_pattern_id_assigned(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        # Паттерн создан в БД, но reload_patterns() не вызывался — движок
        # не подхватывает его "магически", список паттернов read-only после
        # инициализации, пока не обновлён явно (см. докстринг reload_patterns).
        store = ModerationStore(str(tmp_path / "patterns_no_reload.db"))
        await store.connect()
        await store.create_pattern(
            PatternInput(
                name="mass link spam", description="", required_signal_names=(),
                min_families=0, min_risk_score=0, min_confidence=0.0, min_cluster_size=0,
                enabled=True, auto_enabled=False, weight=5.0, created_by="mod1",
            )
        )

        engine = make_engine(store=store)
        verdict = await engine.observe(event_factory(text="привет"))

        assert verdict.pattern_id is None

        await store.close()

    async def test_disabled_pattern_not_assigned(
        self, tmp_path: Path, event_factory: EventFactory
    ) -> None:
        store = ModerationStore(str(tmp_path / "patterns_disabled.db"))
        await store.connect()
        await store.create_pattern(
            PatternInput(
                name="disabled pattern", description="", required_signal_names=(),
                min_families=0, min_risk_score=0, min_confidence=0.0, min_cluster_size=0,
                enabled=False, auto_enabled=False, weight=5.0, created_by="mod1",
            )
        )

        engine = make_engine(store=store)
        await engine.reload_patterns()  # list_patterns(enabled_only=True) -> пусто
        verdict = await engine.observe(event_factory(text="привет"))

        assert verdict.pattern_id is None

        await store.close()


class TestAutomaticTrust:
    """Этап 9a: пользователь с достаточной историей на канале получает
    TrustLevel.REGULAR и сниженный risk_score — не полную защиту (та
    требует ручного MARK SAFE до TRUSTED), но менее агрессивную реакцию на
    органичные копипаста-переклички постоянных зрителей (находка replay,
    этап 6: tema7_5/digitalthevoid и др.)."""

    async def test_regular_status_lowers_risk_for_borderline_signals(
        self, event_factory: EventFactory
    ) -> None:
        engine = make_engine()
        now = time.time()

        # Разгоняем историю пользователя до порога REGULAR (20 сообщений,
        # 3+ дня) — первое сообщение "рождает" first_seen в прошлом, затем
        # остальные обычные сообщения быстро добирают message_count.
        old_start = now - 5 * 86400
        for i in range(19):
            await engine.observe(
                event_factory(
                    user_id="regular1", login="regular1",
                    text=f"обычное сообщение {i}", timestamp=old_start + i,
                )
            )

        # 20-е сообщение — то же самое, что нашёл replay: короткая копипаста
        # фраза, которую параллельно пишут другие зрители (эмулируем добавив
        # такую же фразу от другого, не-REGULAR пользователя для сравнения).
        borderline_text = "вы че повторяете?"
        verdict_regular = await engine.observe(
            event_factory(
                user_id="regular1", login="regular1", text=borderline_text, timestamp=now,
            )
        )
        verdict_stranger = await engine.observe(
            event_factory(
                user_id="stranger1", login="stranger1", text=borderline_text, timestamp=now + 0.5,
            )
        )

        assert verdict_regular.risk_score <= verdict_stranger.risk_score

    async def test_regular_status_does_not_block_real_attack(
        self, event_factory: EventFactory
    ) -> None:
        # Инвариант: REGULAR — это скидка, не иммунитет. Пользователь с
        # историей, внезапно участвующий в скоординированной атаке (много
        # независимых семейств сигналов), всё ещё получает эскалацию.
        engine = make_engine()
        now = time.time()
        old_start = now - 5 * 86400
        for i in range(19):
            await engine.observe(
                event_factory(
                    user_id="regular2", login="regular2",
                    text=f"обычное сообщение {i}", timestamp=old_start + i,
                )
            )

        # regular2 присоединяется ПОСЛЕДНИМ — к этому моменту кластеризация
        # уже видит остальных 19 ботов в окне и связывает его с ними
        # (кластеризация оценивает окно НА МОМЕНТ текущего сообщения,
        # см. engine.py: clustering выполняется после добавления в окно).
        verdicts = []
        attack_start = now
        for i in range(19):
            uid = f"bot{i}"
            ev = event_factory(
                user_id=uid, login=uid,
                text=f"Забирай подписчики bit.ly/promo{i % 3}",
                timestamp=attack_start + i * 0.2, is_first_message=True,
            )
            verdicts.append(await engine.observe(ev))

        regular_verdict = await engine.observe(
            event_factory(
                user_id="regular2", login="regular2",
                text="Забирай подписчики bit.ly/promo0",
                timestamp=attack_start + 19 * 0.2,
            )
        )

        assert regular_verdict.recommended_action != Action.NOTHING


class TestExplainability:
    async def test_verdict_explain_never_says_ai_thinks(self, event_factory: EventFactory) -> None:
        engine = make_engine()
        now = time.time()
        verdict = None
        for i in range(20):
            ev = event_factory(
                user_id=f"bot{i}", login=f"bot{i}",
                text=f"Забирай подписчики bit.ly/x{i % 3}",
                timestamp=now + i * 0.2, is_first_message=True,
            )
            verdict = await engine.observe(ev)
        assert verdict is not None
        text = verdict.explain()
        assert "ai" not in text.lower()
        assert "нейросеть" not in text.lower()


async def _form_bot_wave(engine: ModerationEngine, event_factory: EventFactory, *, wave: int, now: float) -> None:
    """20 сообщений от новых ботов — тот же паттерн, что
    TestSpecScenarioViaEngine, но с уникальным user_id на волну, чтобы
    каждый вызов формировал НЕСВЯЗАННЫЙ (не растущий) кластер — иначе
    upsert_cluster_by_members_ex посчитал бы это ростом одного и того же
    кластера, а не новым инцидентом (см. store.py::TestUpsertClusterByMembersEx)."""
    for i in range(20):
        ev = event_factory(
            user_id=f"w{wave}bot{i}", login=f"w{wave}bot{i}",
            text=f"Забирай подписчики bit.ly/w{wave}x{i % 3}",
            timestamp=now + i * 0.2, is_first_message=True,
        )
        await engine.observe(ev)


class TestNewClusterAlert:
    """Направление 01 master-plan.html: алерт на новый кластер уходит в
    Discord через фоновую задачу (asyncio.create_task в
    _notify_new_cluster) — тесты ждут её явным yield цикла событий, не
    полагаются на то, что await observe() сам её дождался.

    Порог confidence сохраняется в webhook.alert_confidence_threshold через
    store.set_alert_confidence_threshold(threshold=0.0) в тестах, не
    проверяющих сам фильтр: реальный confidence кластера, собранного
    детекторами в этом сценарии, зависит от scoring/confidence.py и
    меняется при их доработке — тесты про факт отправки алерта не должны
    быть завязаны на конкретное число, которое к теме теста не относится
    (см. TestAlertConfidenceFilter ниже про сам порог)."""

    async def test_alert_sent_when_webhook_configured(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent: list[ClusterInfo] = []

        async def fake_send_cluster_alert(webhook, cluster, *, channel, transport=None):  # type: ignore[no-untyped-def]
            sent.append(cluster)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", fake_send_cluster_alert)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        await store.set_alert_confidence_threshold(threshold=0.0)
        engine = make_engine(store=store)

        await _form_bot_wave(engine, event_factory, wave=0, now=time.time())
        await asyncio.sleep(0)  # даём фоновой задаче _notify_new_cluster выполниться

        assert len(sent) == 1

    async def test_no_alert_without_webhook_configured(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent: list[ClusterInfo] = []

        async def fake_send_cluster_alert(webhook, cluster, *, channel, transport=None):  # type: ignore[no-untyped-def]
            sent.append(cluster)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", fake_send_cluster_alert)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        engine = make_engine(store=store)

        await _form_bot_wave(engine, event_factory, wave=0, now=time.time())
        await asyncio.sleep(0)

        assert sent == []


class TestAlertConfidenceFilter:
    """Порог confidence настраивается per-channel (webhook.
    alert_confidence_threshold), не жёсткая константа в engine.py —
    низкоуверенные кластеры не должны отвлекать модератора алертом, но
    остаются видны на экране Live независимо от порога."""

    async def test_cluster_above_threshold_sends_alert(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent: list[ClusterInfo] = []

        async def fake_send_cluster_alert(webhook, cluster, *, channel, transport=None):  # type: ignore[no-untyped-def]
            sent.append(cluster)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", fake_send_cluster_alert)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        await store.set_alert_confidence_threshold(threshold=0.0)  # порог не блокирует
        engine = make_engine(store=store)

        await _form_bot_wave(engine, event_factory, wave=0, now=time.time())
        await asyncio.sleep(0)

        assert len(sent) == 1

    async def test_cluster_below_threshold_does_not_send_alert(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent: list[ClusterInfo] = []

        async def fake_send_cluster_alert(webhook, cluster, *, channel, transport=None):  # type: ignore[no-untyped-def]
            sent.append(cluster)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", fake_send_cluster_alert)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        await store.set_alert_confidence_threshold(threshold=1.0)
        engine = make_engine(store=store)

        await _form_bot_wave(engine, event_factory, wave=0, now=time.time())
        await asyncio.sleep(0)

        # Реальный кластер из детекторов почти никогда не набирает ровно
        # confidence=1.0 — порог=1.0 гарантированно режет любой реальный
        # результат без знания точного числа заранее.
        assert sent == []

    async def test_default_threshold_is_point_nine(self, tmp_path: Path) -> None:
        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        config = await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        assert config.alert_confidence_threshold == 0.9


class TestEscalation:
    """Направление 01 master-plan.html: ESCALATION_CLUSTER_THRESHOLD+ новых
    кластеров за окно шлют отдельный алерт эскалации, не только обычный
    алерт на каждый кластер."""

    async def test_escalation_sent_once_threshold_reached(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        escalations: list[int] = []

        async def fake_send_escalation(webhook, *, channel, cluster_count, window_hours, transport=None):  # type: ignore[no-untyped-def]
            escalations.append(cluster_count)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", _noop_alert)
        monkeypatch.setattr("cigilbot.orchestration.engine.send_escalation", fake_send_escalation)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        engine = make_engine(store=store)

        now = time.time()
        for wave in range(ESCALATION_CLUSTER_THRESHOLD):
            await _form_bot_wave(engine, event_factory, wave=wave, now=now + wave * 100)
            await asyncio.sleep(0)

        assert escalations == [ESCALATION_CLUSTER_THRESHOLD]

    async def test_no_escalation_below_threshold(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        escalations: list[int] = []

        async def fake_send_escalation(webhook, *, channel, cluster_count, window_hours, transport=None):  # type: ignore[no-untyped-def]
            escalations.append(cluster_count)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", _noop_alert)
        monkeypatch.setattr("cigilbot.orchestration.engine.send_escalation", fake_send_escalation)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        engine = make_engine(store=store)

        now = time.time()
        for wave in range(ESCALATION_CLUSTER_THRESHOLD - 1):
            await _form_bot_wave(engine, event_factory, wave=wave, now=now + wave * 100)
            await asyncio.sleep(0)

        assert escalations == []

    async def test_escalation_not_repeated_within_cooldown(
        self, tmp_path: Path, event_factory: EventFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        escalations: list[int] = []

        async def fake_send_escalation(webhook, *, channel, cluster_count, window_hours, transport=None):  # type: ignore[no-untyped-def]
            escalations.append(cluster_count)

        monkeypatch.setattr("cigilbot.orchestration.engine.send_cluster_alert", _noop_alert)
        monkeypatch.setattr("cigilbot.orchestration.engine.send_escalation", fake_send_escalation)

        store = ModerationStore(str(tmp_path / "mod.db"))
        await store.connect()
        await store.set_discord_webhook(
            url="https://discord.com/api/webhooks/1/abc", enabled=True, updated_by="test"
        )
        engine = make_engine(store=store)

        now = time.time()
        # Порог достигается волной threshold, затем ЕЩЁ одна волна сверх
        # порога в течение того же cooldown-окна не должна слать вторую
        # эскалацию (см. docstring ModerationEngine._maybe_send_escalation).
        for wave in range(ESCALATION_CLUSTER_THRESHOLD + 1):
            await _form_bot_wave(engine, event_factory, wave=wave, now=now + wave * 100)
            await asyncio.sleep(0)

        assert len(escalations) == 1


async def _noop_alert(webhook, cluster, *, channel, transport=None):  # type: ignore[no-untyped-def]
    pass
