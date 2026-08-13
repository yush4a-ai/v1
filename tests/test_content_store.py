"""Тесты store-методов Rule Engine: mod_content_rules/settings/violations."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.types import ChatEvent, ContentCategory
from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "test.db"))
    await s.connect()
    return s


class TestContentRules:
    async def test_add_and_list(self, store: ModerationStore) -> None:
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="плохое слово", created_by="admin"
        )
        rules = await store.list_content_rules()
        assert len(rules) == 1
        assert rules[0].category == ContentCategory.RACISM
        assert rules[0].phrase == "плохое слово"
        assert rules[0].enabled is True

    async def test_empty_phrase_rejected(self, store: ModerationStore) -> None:
        with pytest.raises(ValueError):
            await store.add_content_rule(
                category=ContentCategory.RACISM, phrase="   ", created_by="admin"
            )

    async def test_list_enabled_only_excludes_disabled(self, store: ModerationStore) -> None:
        rule = await store.add_content_rule(
            category=ContentCategory.ADVERTISING, phrase="реклама", created_by="admin"
        )
        await store.set_content_rule_enabled(rule.id, False)

        all_rules = await store.list_content_rules()
        enabled_rules = await store.list_content_rules(enabled_only=True)
        assert len(all_rules) == 1
        assert len(enabled_rules) == 0

    async def test_delete_removes_rule(self, store: ModerationStore) -> None:
        rule = await store.add_content_rule(
            category=ContentCategory.THREATS, phrase="угроза", created_by="admin"
        )
        await store.delete_content_rule(rule.id)
        assert await store.list_content_rules() == ()

    async def test_stricter_categories_ordered_first(self, store: ModerationStore) -> None:
        await store.add_content_rule(
            category=ContentCategory.ADVERTISING, phrase="реклама", created_by="admin"
        )
        await store.add_content_rule(
            category=ContentCategory.RACISM, phrase="оскорбление", created_by="admin"
        )
        rules = await store.list_content_rules()
        assert rules[0].category == ContentCategory.RACISM
        assert rules[1].category == ContentCategory.ADVERTISING


class TestContentSettings:
    async def test_default_is_disabled(self, store: ModerationStore) -> None:
        settings = await store.get_content_settings()
        assert settings.enabled is False

    async def test_enable_persists(self, store: ModerationStore) -> None:
        await store.set_content_moderation_enabled(True, updated_by="admin")
        settings = await store.get_content_settings()
        assert settings.enabled is True
        assert settings.updated_by == "admin"

    async def test_can_disable_again(self, store: ModerationStore) -> None:
        await store.set_content_moderation_enabled(True, updated_by="admin")
        await store.set_content_moderation_enabled(False, updated_by="admin")
        settings = await store.get_content_settings()
        assert settings.enabled is False


class TestContentViolations:
    async def test_default_count_is_zero(self, store: ModerationStore) -> None:
        count = await store.get_content_violation_count("user1", ContentCategory.RACISM)
        assert count == 0

    async def test_record_increments_count(self, store: ModerationStore) -> None:
        first = await store.record_content_violation("user1", ContentCategory.RACISM)
        second = await store.record_content_violation("user1", ContentCategory.RACISM)
        assert first == 1
        assert second == 2

    async def test_categories_counted_independently(self, store: ModerationStore) -> None:
        await store.record_content_violation("user1", ContentCategory.RACISM)
        await store.record_content_violation("user1", ContentCategory.ADVERTISING)
        racism_count = await store.get_content_violation_count("user1", ContentCategory.RACISM)
        ads_count = await store.get_content_violation_count("user1", ContentCategory.ADVERTISING)
        assert racism_count == 1
        assert ads_count == 1

    async def test_users_counted_independently(self, store: ModerationStore) -> None:
        await store.record_content_violation("user1", ContentCategory.RACISM)
        count = await store.get_content_violation_count("user2", ContentCategory.RACISM)
        assert count == 0


class TestContentEvents:
    async def test_record_and_list(self, store: ModerationStore) -> None:
        await store.record_content_event(
            user_id="1", login="viewer", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )
        events = await store.list_content_events()
        assert len(events) == 1
        assert events[0]["category"] == "racism"
        assert events[0]["enforced"] is False

    async def test_newest_first(self, store: ModerationStore) -> None:
        await store.record_content_event(
            user_id="1", login="a", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="x", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )
        await store.record_content_event(
            user_id="2", login="b", message_id=None, category=ContentCategory.THREATS,
            matched_phrase="y", action="BAN", prior_violations=1, blocked_by="",
            enforced=False,
        )
        events = await store.list_content_events()
        assert events[0]["login"] == "b"
        assert events[1]["login"] == "a"

    async def test_limit_applied(self, store: ModerationStore) -> None:
        for i in range(5):
            await store.record_content_event(
                user_id=str(i), login=f"user{i}", message_id=None,
                category=ContentCategory.ADVERTISING, matched_phrase="x", action="TIMEOUT",
                prior_violations=0, blocked_by="", enforced=False,
            )
        events = await store.list_content_events(limit=2)
        assert len(events) == 2

    async def test_no_message_id_gives_null_twitch_message_id(self, store: ModerationStore) -> None:
        await store.record_content_event(
            user_id="1", login="viewer", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="OBSERVE", prior_violations=0, blocked_by="",
            enforced=False,
        )
        events = await store.list_content_events()
        assert events[0]["twitch_message_id"] is None

    async def test_joins_twitch_message_id_from_saved_message(self, store: ModerationStore) -> None:
        # Ручное модерирование из ленты Content (кнопка "Удалить сообщение")
        # нуждается в НАСТОЯЩЕМ Twitch message_id, не во внутреннем
        # mod_messages.id — миграция 015 добавила колонку, save_message её
        # заполняет из ChatEvent.message_id.
        event = ChatEvent(
            user_id="1", login="viewer", text="плохое слово", timestamp=time.time(),
            message_id="twitch-msg-abc123",
        )
        message_id = await store.save_message(event, fingerprint(event.text))
        await store.record_content_event(
            user_id="1", login="viewer", message_id=message_id, category=ContentCategory.RACISM,
            matched_phrase="слово", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )
        events = await store.list_content_events()
        assert events[0]["twitch_message_id"] == "twitch-msg-abc123"

    async def test_manual_action_null_by_default(self, store: ModerationStore) -> None:
        await store.record_content_event(
            user_id="1", login="viewer", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )
        events = await store.list_content_events()
        assert events[0]["manual_action"] is None
        assert events[0]["manual_action_by"] is None
        assert events[0]["manual_action_at"] is None


class TestMarkContentEventManualAction:
    """Пользователь 2026-08-13: "можем как-то помечать сообщения... может
    цвет более тусклым делать" — пометка переживает обновление страницы
    (в отличие от прежнего состояния, где панель ничего не помнила)."""

    async def test_mark_sets_all_fields(self, store: ModerationStore) -> None:
        event_id = await store.record_content_event(
            user_id="1", login="viewer", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )
        await store.mark_content_event_manual_action(event_id, action="TIMEOUT", actor="mod1")

        events = await store.list_content_events()
        assert events[0]["manual_action"] == "TIMEOUT"
        assert events[0]["manual_action_by"] == "mod1"
        assert events[0]["manual_action_at"] is not None

    async def test_mark_does_not_affect_other_events(self, store: ModerationStore) -> None:
        first_id = await store.record_content_event(
            user_id="1", login="a", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="x", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )
        await store.record_content_event(
            user_id="2", login="b", message_id=None, category=ContentCategory.THREATS,
            matched_phrase="y", action="BAN", prior_violations=0, blocked_by="",
            enforced=False,
        )
        await store.mark_content_event_manual_action(first_id, action="TIMEOUT", actor="mod1")

        events = await store.list_content_events()
        marked = next(e for e in events if e["login"] == "a")
        unmarked = next(e for e in events if e["login"] == "b")
        assert marked["manual_action"] == "TIMEOUT"
        assert unmarked["manual_action"] is None
