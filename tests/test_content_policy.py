"""Тесты cigilbot/content/policy.py: эскалация и режим наблюдателя."""

from __future__ import annotations

import time

from cigilbot.content.policy import decide_content
from cigilbot.domain.types import (
    Action,
    ChatEvent,
    ContentCategory,
    ContentMatch,
    TrustLevel,
    UserState,
)


def make_event(**overrides: object) -> ChatEvent:
    defaults: dict[str, object] = {
        "user_id": "1", "login": "viewer", "text": "x", "timestamp": time.time(),
    }
    defaults.update(overrides)
    return ChatEvent(**defaults)  # type: ignore[arg-type]


def make_user(**overrides: object) -> UserState:
    defaults: dict[str, object] = {
        "user_id": "1", "login": "viewer", "first_seen": 0.0, "last_seen": 0.0,
        "message_count": 0,
    }
    defaults.update(overrides)
    return UserState(**defaults)  # type: ignore[arg-type]


def make_match(category: ContentCategory = ContentCategory.RACISM) -> ContentMatch:
    return ContentMatch(category=category, matched_phrase="слово", normalized_text="слово")


class TestObserverMode:
    """Пользователь опасается случайных действий бота — это самый важный
    набор тестов файла: content_moderation_enabled=False должно ГАРАНТИРОВАННО
    понижать любое действие до OBSERVE, независимо от категории/эскалации."""

    def test_disabled_forces_observe_on_first_violation(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=False,
        )
        assert decision.action == Action.OBSERVE
        assert decision.blocked_by == "content_moderation_disabled"

    def test_disabled_forces_observe_even_at_ban_step(self) -> None:
        # Даже когда лестница эскалации дошла бы до BAN, выключенный
        # переключатель должен победить.
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=5, content_moderation_enabled=False,
        )
        assert decision.action == Action.OBSERVE
        assert decision.blocked_by == "content_moderation_disabled"

    def test_disabled_forces_observe_for_threats(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.THREATS), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=False,
        )
        assert decision.action == Action.OBSERVE

    def test_disabled_forces_observe_for_advertising(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=False,
        )
        assert decision.action == Action.OBSERVE

    def test_enabled_allows_real_action(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.action == Action.TIMEOUT
        assert decision.blocked_by == ""


class TestPrivilegedAndTrustedGuard:
    """Та же защита, что в cigilbot/policy.py: мод/VIP/стример и доверенные
    пользователи не получают автодействие даже при включённой модерации."""

    def test_privileged_user_never_actioned(self) -> None:
        event = make_event(is_moderator=True)
        decision = decide_content(
            make_match(), user=make_user(), event=event,
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.action == Action.OBSERVE
        assert decision.blocked_by == "privileged_user"

    def test_broadcaster_never_actioned(self) -> None:
        event = make_event(is_broadcaster=True)
        decision = decide_content(
            make_match(), user=make_user(), event=event,
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.blocked_by == "privileged_user"

    def test_trusted_user_never_actioned(self) -> None:
        user = make_user(trust_level=TrustLevel.TRUSTED)
        decision = decide_content(
            make_match(), user=user, event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.action == Action.OBSERVE
        assert decision.blocked_by == "trusted_or_marked_safe"

    def test_marked_safe_user_never_actioned(self) -> None:
        user = make_user(marked_safe=True)
        decision = decide_content(
            make_match(), user=user, event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.blocked_by == "trusted_or_marked_safe"


class TestEscalationLadder:
    def test_racism_first_violation_is_timeout(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.action == Action.TIMEOUT

    def test_racism_second_violation_is_ban(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=1, content_moderation_enabled=True,
        )
        assert decision.action == Action.BAN

    def test_threats_second_violation_is_ban(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.THREATS), user=make_user(), event=make_event(),
            prior_violations=1, content_moderation_enabled=True,
        )
        assert decision.action == Action.BAN

    def test_advertising_needs_three_violations_for_ban(self) -> None:
        first = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        second = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=1, content_moderation_enabled=True,
        )
        third = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=2, content_moderation_enabled=True,
        )
        assert first.action == Action.TIMEOUT
        assert second.action == Action.TIMEOUT
        assert third.action == Action.BAN

    def test_action_stays_ban_beyond_ladder_end(self) -> None:
        # Пользователь с 100 прошлыми нарушениями не должен внезапно
        # получить менее строгое действие из-за выхода за пределы таблицы.
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=100, content_moderation_enabled=True,
        )
        assert decision.action == Action.BAN

    def test_timeout_duration_grows_with_violations(self) -> None:
        first = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        second = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=1, content_moderation_enabled=True,
        )
        assert first.timeout_duration_seconds is not None
        assert second.timeout_duration_seconds is not None
        assert second.timeout_duration_seconds > first.timeout_duration_seconds

    def test_ban_has_no_timeout_duration(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=1, content_moderation_enabled=True,
        )
        assert decision.timeout_duration_seconds is None


class TestManualReviewFlag:
    def test_racism_requires_manual_review(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.RACISM), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.requires_manual_review is True

    def test_threats_requires_manual_review(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.THREATS), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.requires_manual_review is True

    def test_advertising_does_not_require_manual_review(self) -> None:
        decision = decide_content(
            make_match(ContentCategory.ADVERTISING), user=make_user(), event=make_event(),
            prior_violations=0, content_moderation_enabled=True,
        )
        assert decision.requires_manual_review is False
