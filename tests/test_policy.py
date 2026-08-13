"""Тесты policy.py: инварианты безопасности (раздел 23 ТЗ).

Это самый важный файл тестов в проекте — здесь проверяются жёсткие правила,
которые не должны ослабляться ни при каких настройках конфига.
"""

from __future__ import annotations

import time
from dataclasses import replace

from cigilbot.domain import policy
from cigilbot.domain.config import default_config
from cigilbot.domain.types import (
    Action,
    ChatEvent,
    Sensitivity,
    Signal,
    SignalFamily,
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


class TestRawActionThresholds:
    def test_below_observe_is_nothing(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=cfg.risk.observe - 1, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action == Action.NOTHING
        assert blocked == ""

    def test_observe_band(self) -> None:
        cfg = default_config()
        action, _ = policy.decide(
            risk_score=cfg.risk.observe, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action == Action.OBSERVE


class TestMinimumFamiliesForBan:
    """Инвариант из ТЗ: BAN невозможен при одном слабом признаке."""

    def test_single_family_blocks_ban_even_with_max_confidence(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=1,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action != Action.BAN
        assert blocked == "minimum_families_for_ban"

    def test_two_families_allow_ban_with_sufficient_confidence(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=cfg.confidence.minimum_for_ban, families_triggered=2,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action == Action.BAN
        assert blocked == ""

    def test_invariant_holds_in_aggressive_mode(self) -> None:
        cfg = default_config()
        cfg = replace(cfg, sensitivity=Sensitivity.AGGRESSIVE)
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=1,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action != Action.BAN
        assert blocked == "minimum_families_for_ban"

    def test_invariant_holds_in_attack_mode(self) -> None:
        cfg = default_config()
        cfg = replace(cfg, sensitivity=Sensitivity.ATTACK)
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=1,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action != Action.BAN
        assert blocked == "minimum_families_for_ban"

    def test_invariant_holds_even_in_safe_mode(self) -> None:
        cfg = default_config()
        cfg = replace(cfg, sensitivity=Sensitivity.SAFE)
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=1,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action != Action.BAN


class TestConfidenceGating:
    def test_ban_downgraded_to_timeout_below_ban_confidence(self) -> None:
        cfg = default_config()
        low_conf = cfg.confidence.minimum_for_ban - 0.01
        action, blocked = policy.decide(
            risk_score=100, confidence=low_conf, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action == Action.TIMEOUT
        assert blocked == "insufficient_confidence_for_ban"

    def test_timeout_downgraded_to_observe_below_timeout_confidence(self) -> None:
        cfg = default_config()
        low_conf = cfg.confidence.minimum_for_timeout - 0.01
        action, blocked = policy.decide(
            risk_score=cfg.risk.timeout, confidence=low_conf, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action == Action.OBSERVE
        assert blocked == "insufficient_confidence_for_timeout"

    def test_high_risk_low_confidence_never_bans(self) -> None:
        cfg = default_config()
        action, _ = policy.decide(
            risk_score=100, confidence=0.1, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action not in (Action.BAN, Action.TIMEOUT)


class TestPrivilegedUsers:
    """Мод/VIP/стример — никогда автодействие выше OBSERVE (раздел 23 ТЗ)."""

    def test_moderator_capped_at_observe(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(is_moderator=True),
        )
        assert action == Action.OBSERVE
        assert blocked == "privileged_user"

    def test_vip_capped_at_observe(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(is_vip=True),
        )
        assert action == Action.OBSERVE
        assert blocked == "privileged_user"

    def test_broadcaster_capped_at_observe(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(is_broadcaster=True),
        )
        assert action == Action.OBSERVE
        assert blocked == "privileged_user"

    def test_privileged_but_low_risk_stays_nothing(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=5, confidence=1.0, families_triggered=0,
            config=cfg, user=make_user(), event=make_event(is_moderator=True),
        )
        assert action == Action.NOTHING
        assert blocked == ""


class TestProvisionalVerdict:
    """FALSE-BAN-002 аудита: BAN невозможен для предварительного вердикта
    (возраст аккаунта ещё не получен от Helix) — понижается до TIMEOUT, тот
    же паттерн, что MIN_FAMILIES_FOR_BAN и confidence-пороги выше."""

    def test_provisional_ban_downgraded_to_timeout(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
            is_provisional=True,
        )
        assert action == Action.TIMEOUT
        assert blocked == "provisional_verdict"

    def test_non_provisional_ban_not_affected(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
            is_provisional=False,
        )
        assert action == Action.BAN
        assert blocked == ""

    def test_default_is_not_provisional(self) -> None:
        # is_provisional не передан явно -> False (обратная совместимость
        # с вызывающим кодом/тестами, которые не знают об этом параметре).
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
        )
        assert action == Action.BAN
        assert blocked == ""

    def test_provisional_does_not_affect_timeout_or_observe(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=cfg.risk.timeout, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
            is_provisional=True,
        )
        assert action == Action.TIMEOUT
        assert blocked == ""  # не понижение, действие и так было TIMEOUT

    def test_provisional_combines_with_other_downgrades(self) -> None:
        # Если и провизорность, и confidence одновременно недостаточны для
        # BAN, первая сработавшая защита фиксируется в blocked_by — порядок
        # проверок в decide() ставит provisional_verdict первым.
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=0.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(),
            is_provisional=True,
        )
        assert action == Action.OBSERVE  # понижено дважды: BAN->TIMEOUT->OBSERVE
        assert blocked == "provisional_verdict"

    def test_privileged_user_takes_priority_over_provisional(self) -> None:
        cfg = default_config()
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=make_user(), event=make_event(is_moderator=True),
            is_provisional=True,
        )
        assert action == Action.OBSERVE
        assert blocked == "privileged_user"


class TestTrustedUsers:
    def test_marked_safe_capped_at_observe(self) -> None:
        cfg = default_config()
        user = make_user(marked_safe=True)
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=user, event=make_event(),
        )
        assert action == Action.OBSERVE
        assert blocked == "trusted_or_marked_safe"

    def test_trust_level_trusted_capped_at_observe(self) -> None:
        cfg = default_config()
        user = make_user(trust_level=TrustLevel.TRUSTED)
        action, blocked = policy.decide(
            risk_score=100, confidence=1.0, families_triggered=5,
            config=cfg, user=user, event=make_event(),
        )
        assert action == Action.OBSERVE
        assert blocked == "trusted_or_marked_safe"

    def test_regular_trust_level_not_protected(self) -> None:
        cfg = default_config()
        user = make_user(trust_level=TrustLevel.REGULAR)
        action, blocked = policy.decide(
            risk_score=100, confidence=cfg.confidence.minimum_for_ban, families_triggered=2,
            config=cfg, user=user, event=make_event(),
        )
        assert action == Action.BAN
        assert blocked == ""


class TestBuildReason:
    def test_nothing_has_generic_reason(self) -> None:
        reason = policy.build_reason(Action.NOTHING, (), "")
        assert "не обнаружено" in reason.lower()

    def test_privileged_reason_mentions_role(self) -> None:
        reason = policy.build_reason(Action.OBSERVE, (), "privileged_user")
        assert "модератор" in reason.lower() or "vip" in reason.lower() or "стример" in reason.lower()

    def test_no_ai_thinks_language(self) -> None:
        sig = Signal(
            name="exact_duplicate", family=SignalFamily.CONTENT, weight=25, value=1.0,
            evidence="test",
        )
        reason = policy.build_reason(Action.TIMEOUT, (sig,), "")
        assert "ai" not in reason.lower()
        assert "искусственный интеллект" not in reason.lower()
