"""Тесты базовых типов: границы значений, пороги risk_level, explain()."""

from __future__ import annotations

import time

import pytest

from cigilbot.domain.types import (
    Action,
    RiskLevel,
    Signal,
    SignalFamily,
    TrustLevel,
    UserState,
    Verdict,
)
from tests.conftest import EventFactory


def make_signal(**overrides: object) -> Signal:
    defaults: dict[str, object] = {
        "name": "test_signal",
        "family": SignalFamily.CONTENT,
        "weight": 10.0,
        "value": 1.0,
        "evidence": "тестовое наблюдение",
    }
    defaults.update(overrides)
    return Signal(**defaults)  # type: ignore[arg-type]


class TestSignal:
    def test_score_is_weight_times_value(self) -> None:
        sig = make_signal(weight=20.0, value=0.5)
        assert sig.score == 10.0

    @pytest.mark.parametrize("bad_value", [-0.01, 1.01, -5.0, 100.0])
    def test_rejects_value_outside_unit_range(self, bad_value: float) -> None:
        with pytest.raises(ValueError, match=r"\[0,1\]"):
            make_signal(value=bad_value)

    def test_rejects_empty_evidence(self) -> None:
        with pytest.raises(ValueError, match="evidence"):
            make_signal(evidence="")

    def test_boundary_values_are_accepted(self) -> None:
        assert make_signal(value=0.0).value == 0.0
        assert make_signal(value=1.0).value == 1.0

    def test_signal_is_frozen(self) -> None:
        sig = make_signal()
        with pytest.raises(AttributeError):
            sig.value = 0.9  # type: ignore[misc]


class TestChatEvent:
    def test_privileged_true_for_moderator(self, event_factory: EventFactory) -> None:
        event = event_factory(is_moderator=True)
        assert event.is_privileged

    def test_privileged_true_for_vip(self, event_factory: EventFactory) -> None:
        event = event_factory(is_vip=True)
        assert event.is_privileged

    def test_privileged_true_for_broadcaster(self, event_factory: EventFactory) -> None:
        event = event_factory(is_broadcaster=True)
        assert event.is_privileged

    def test_ordinary_viewer_not_privileged(self, event_factory: EventFactory) -> None:
        event = event_factory()
        assert not event.is_privileged


class TestUserState:
    def test_account_age_none_when_unknown(self) -> None:
        state = UserState(user_id="1", login="x", first_seen=0.0, last_seen=0.0)
        assert state.account_age_days is None

    def test_account_age_computed_from_created_at(self) -> None:
        created = time.time() - 3 * 86400
        state = UserState(
            user_id="1", login="x", first_seen=0.0, last_seen=0.0,
            account_created_at=created,
        )
        assert state.account_age_days is not None
        assert 2.9 < state.account_age_days < 3.1

    def test_protected_when_marked_safe(self) -> None:
        state = UserState(
            user_id="1", login="x", first_seen=0.0, last_seen=0.0, marked_safe=True
        )
        assert state.is_protected

    def test_protected_when_trusted(self) -> None:
        state = UserState(
            user_id="1", login="x", first_seen=0.0, last_seen=0.0,
            trust_level=TrustLevel.TRUSTED,
        )
        assert state.is_protected

    def test_unknown_user_not_protected(self) -> None:
        state = UserState(user_id="1", login="x", first_seen=0.0, last_seen=0.0)
        assert not state.is_protected

    def test_qualifies_for_regular_requires_both_thresholds(self) -> None:
        now = time.time()
        old_enough = now - 5 * 86400
        state = UserState(
            user_id="1", login="x", first_seen=old_enough, last_seen=now, message_count=25,
        )
        assert state.qualifies_for_regular(min_messages=20, min_days=3.0, now=now)

    def test_qualifies_for_regular_fails_on_message_count_alone(self) -> None:
        # Много сообщений, но аккаунт "родился" только что — активный
        # бот-спамер не должен получить доверие просто по объёму.
        now = time.time()
        state = UserState(
            user_id="1", login="x", first_seen=now, last_seen=now, message_count=1000,
        )
        assert not state.qualifies_for_regular(min_messages=20, min_days=3.0, now=now)

    def test_qualifies_for_regular_fails_on_age_alone(self) -> None:
        # Старый first_seen, но почти не писал — не заслуживает доверия
        # просто по возрасту.
        now = time.time()
        old_enough = now - 30 * 86400
        state = UserState(
            user_id="1", login="x", first_seen=old_enough, last_seen=now, message_count=2,
        )
        assert not state.qualifies_for_regular(min_messages=20, min_days=3.0, now=now)


def make_verdict(**overrides: object) -> Verdict:
    defaults: dict[str, object] = {
        "user_id": "1",
        "login": "viewer",
        "risk_score": 0,
        "confidence": 0.0,
        "signals": (),
        "recommended_action": Action.NOTHING,
        "reason": "нет сигналов",
        "timestamp": time.time(),
    }
    defaults.update(overrides)
    return Verdict(**defaults)  # type: ignore[arg-type]


class TestVerdictRiskLevel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, RiskLevel.LOW),
            (29, RiskLevel.LOW),
            (30, RiskLevel.MEDIUM),
            (59, RiskLevel.MEDIUM),
            (60, RiskLevel.HIGH),
            (79, RiskLevel.HIGH),
            (80, RiskLevel.CRITICAL),
            (100, RiskLevel.CRITICAL),
        ],
    )
    def test_thresholds_match_spec(self, score: int, expected: RiskLevel) -> None:
        assert make_verdict(risk_score=score).risk_level == expected


class TestVerdictExplain:
    def test_explain_lists_evidence_not_raw_ai_claim(self) -> None:
        signals = (
            make_signal(name="mass_message_burst", evidence="14 сообщений за 10 сек", weight=15, value=1.0),
            make_signal(name="duplicate_message_cluster", evidence="совпадает с 7 аккаунтами", weight=25, value=1.0),
        )
        verdict = make_verdict(
            risk_score=82, confidence=0.94, signals=signals,
            recommended_action=Action.BAN, reason="Несколько независимых бот-сигналов",
        )
        text = verdict.explain()

        assert "ИИ считает" not in text
        assert "AI thinks" not in text
        assert "14 сообщений за 10 сек" in text
        assert "совпадает с 7 аккаунтами" in text
        assert "BAN" in text

    def test_explain_handles_no_signals(self) -> None:
        text = make_verdict().explain()
        assert "(нет)" in text

    def test_explain_notes_provisional(self) -> None:
        text = make_verdict(is_provisional=True).explain()
        assert "предварительный" in text

    def test_explain_notes_blocked_by(self) -> None:
        text = make_verdict(blocked_by="minimum_families").explain()
        assert "minimum_families" in text


class TestVerdictToDict:
    def test_to_dict_contains_required_api_fields(self) -> None:
        signals = (make_signal(),)
        verdict = make_verdict(
            risk_score=82, confidence=0.94, signals=signals,
            recommended_action=Action.BAN, reason="test", cluster_id=42,
        )
        d = verdict.to_dict()

        for key in (
            "risk_score", "confidence", "detected_signals", "recommended_action",
            "reason", "cluster_id", "evidence",
        ):
            assert key in d

        assert d["risk_score"] == 82
        assert d["recommended_action"] == "BAN"
        assert d["cluster_id"] == 42
        assert d["detected_signals"] == ["test_signal"]

    def test_to_dict_is_json_serializable(self) -> None:
        import json

        verdict = make_verdict(signals=(make_signal(),))
        json.dumps(verdict.to_dict())  # не должно бросить исключение
