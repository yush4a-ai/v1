"""Тесты интеграции Rule Engine (cigilbot/content/) в ModerationEngine.observe().

Главный инвариант этого файла — то, о чём явно предупредил пользователь
(2026-08-12): словарный детектор новый и не должен банить/таймаутить никого
автоматически, пока это явно не включено. Проверяем на всех уровнях:
1. mod_action_queue остаётся пустой независимо от content_moderation_enabled
   (executor.py вообще не читает content-решения — engine.py их туда не
   кладёт, см. ModerationEngine._check_content).
2. content_moderation_enabled=False (дефолт) форсирует OBSERVE даже когда
   совпадение есть и лестница эскалации дошла бы до BAN.
3. Verdict (спам-путь) не меняется от совпадения словаря — пути независимы.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.domain.config import ChannelProfile, default_config
from cigilbot.domain.types import Action, ContentCategory, Mode
from cigilbot.orchestration.engine import ModerationEngine
from cigilbot.storage.store import ModerationStore
from tests.conftest import EventFactory


def make_engine(store: ModerationStore, **profile_overrides: object) -> ModerationEngine:
    cfg = default_config()
    defaults: dict[str, object] = {"channel": "test"}
    defaults.update(profile_overrides)
    profile = ChannelProfile(**defaults)  # type: ignore[arg-type]
    return ModerationEngine(cfg, profile, store, mode=Mode.SHADOW)


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "content_engine.db"))
    await s.connect()
    return s


class TestObserverModeIsDefault:
    """Без единого вызова reload_content_rules()/sync_content_settings()
    (как если бы main.py ещё не подхватил новую фичу) движок не должен
    падать и не должен ничего находить — self._content_rules пуст по
    умолчанию (см. ModerationEngine.__init__)."""

    async def test_no_content_events_without_reload(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        engine = make_engine(store)
        # Намеренно НЕ вызываем reload_content_rules().

        await engine.observe(event_factory(text="тут есть плохое слово"))

        events = await store.list_content_events()
        assert events == []


class TestQueueNeverReceivesContentActions:
    """Главная гарантия для пользователя: даже включив content-модерацию
    и с явным нарушением, ни одно задание не появляется в mod_action_queue —
    engine.py не создаёт их вообще для content-пути (см. _check_content)."""

    async def test_queue_empty_when_disabled(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        engine = make_engine(store)
        await engine.reload_content_rules()
        # content_moderation_enabled остаётся False (дефолт).

        await engine.observe(event_factory(text="тут есть плохое слово"))

        pending = await store.get_pending_actions()
        assert pending == []

    async def test_queue_empty_when_enabled(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        await store.set_content_moderation_enabled(True, updated_by="admin")
        engine = make_engine(store)
        await engine.reload_content_rules()
        await engine.sync_content_settings()

        await engine.observe(event_factory(text="тут есть плохое слово"))

        pending = await store.get_pending_actions()
        assert pending == []


class TestDisabledByDefaultForcesObserve:
    async def test_match_recorded_but_not_enforced(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        engine = make_engine(store)
        await engine.reload_content_rules()
        # sync_content_settings() не вызван -> enabled=False по умолчанию.

        await engine.observe(event_factory(text="тут есть плохое слово"))

        events = await store.list_content_events()
        assert len(events) == 1
        assert events[0]["action"] == Action.OBSERVE.value
        assert events[0]["blocked_by"] == "content_moderation_disabled"
        assert events[0]["enforced"] is False

    async def test_repeated_violation_still_observe_while_disabled(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        engine = make_engine(store)
        await engine.reload_content_rules()

        for _ in range(3):
            await engine.observe(event_factory(user_id="1", text="плохое слово тут"))

        events = await store.list_content_events()
        assert all(e["action"] == Action.OBSERVE.value for e in events)


class TestEnabledEnforcesEscalation:
    async def test_first_violation_is_timeout(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        await store.set_content_moderation_enabled(True, updated_by="admin")
        engine = make_engine(store)
        await engine.reload_content_rules()
        await engine.sync_content_settings()

        await engine.observe(event_factory(user_id="1", text="плохое слово тут"))

        events = await store.list_content_events()
        assert events[0]["action"] == Action.TIMEOUT.value

    async def test_violation_counter_persists_across_observe_calls(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        await store.set_content_moderation_enabled(True, updated_by="admin")
        engine = make_engine(store)
        await engine.reload_content_rules()
        await engine.sync_content_settings()

        await engine.observe(event_factory(user_id="1", text="плохое слово раз"))
        await engine.observe(event_factory(user_id="1", text="плохое слово два"))

        count = await store.get_content_violation_count("1", ContentCategory.RACISM)
        assert count == 2

    async def test_privileged_user_not_actioned_even_when_enabled(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        await store.set_content_moderation_enabled(True, updated_by="admin")
        engine = make_engine(store)
        await engine.reload_content_rules()
        await engine.sync_content_settings()

        await engine.observe(
            event_factory(user_id="1", text="плохое слово тут", is_moderator=True)
        )

        events = await store.list_content_events()
        assert events[0]["action"] == Action.OBSERVE.value
        assert events[0]["blocked_by"] == "privileged_user"


class TestContentPathIndependentFromSpamVerdict:
    async def test_verdict_unaffected_by_content_match(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        await store.set_content_moderation_enabled(True, updated_by="admin")
        engine = make_engine(store)
        await engine.reload_content_rules()
        await engine.sync_content_settings()

        # Обычное безобидное с точки зрения спам-детекторов сообщение,
        # содержащее словарное нарушение — Verdict.recommended_action не
        # должен подскочить до TIMEOUT/BAN только из-за content-совпадения.
        verdict = await engine.observe(event_factory(text="плохое слово, но иначе безобидно"))

        assert verdict.recommended_action == Action.NOTHING

    async def test_no_match_no_content_event(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        engine = make_engine(store)
        await engine.reload_content_rules()

        await engine.observe(event_factory(text="совершенно обычное сообщение"))

        assert await store.list_content_events() == []
