"""Тесты patterns.py: сопоставление условий Pattern с Verdict/ClusterInfo."""

from __future__ import annotations

import time

from cigilbot.domain.patterns import Pattern, match_patterns
from cigilbot.domain.types import Action, ClusterInfo, Mode, Signal, SignalFamily, Verdict


def make_pattern(**overrides: object) -> Pattern:
    defaults: dict[str, object] = {
        "id": 1,
        "name": "test pattern",
        "description": "",
        "required_signal_names": (),
        "min_families": 0,
        "min_risk_score": 0,
        "min_confidence": 0.0,
        "min_cluster_size": 0,
        "enabled": True,
        "auto_enabled": False,
        "weight": 1.0,
        "created_by": "mod1",
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return Pattern(**defaults)  # type: ignore[arg-type]


def sig(name: str, family: SignalFamily, value: float = 1.0) -> Signal:
    return Signal(name=name, family=family, weight=10.0, value=value, evidence="test")


def make_verdict(**overrides: object) -> Verdict:
    defaults: dict[str, object] = {
        "user_id": "1",
        "login": "bot1",
        "risk_score": 70,
        "confidence": 0.8,
        "signals": (sig("exact_duplicate", SignalFamily.CONTENT), sig("synchronized_arrival", SignalFamily.TIMING)),
        "recommended_action": Action.TIMEOUT,
        "reason": "test",
        "timestamp": time.time(),
        "families_triggered": 2,
        "mode": Mode.SHADOW,
    }
    defaults.update(overrides)
    return Verdict(**defaults)  # type: ignore[arg-type]


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
        "signals": (sig("synchronized_arrival", SignalFamily.TIMING), sig("cluster_membership", SignalFamily.NETWORK)),
        "risk_score": 70,
        "confidence": 0.85,
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return ClusterInfo(**defaults)  # type: ignore[arg-type]


class TestPatternMatches:
    def test_disabled_pattern_never_matches(self) -> None:
        pattern = make_pattern(enabled=False, min_risk_score=0)
        assert pattern.matches(make_verdict()) is False

    def test_min_risk_score_enforced(self) -> None:
        pattern = make_pattern(min_risk_score=90)
        assert pattern.matches(make_verdict(risk_score=70)) is False
        assert pattern.matches(make_verdict(risk_score=95)) is True

    def test_min_confidence_enforced(self) -> None:
        pattern = make_pattern(min_confidence=0.9)
        assert pattern.matches(make_verdict(confidence=0.5)) is False
        assert pattern.matches(make_verdict(confidence=0.95)) is True

    def test_required_signal_names_any_match(self) -> None:
        pattern = make_pattern(required_signal_names=("known_scam_domain", "exact_duplicate"))
        # verdict имеет exact_duplicate — совпадает по ЛЮБОМУ из списка
        assert pattern.matches(make_verdict()) is True

    def test_required_signal_names_none_present_fails(self) -> None:
        pattern = make_pattern(required_signal_names=("known_scam_domain",))
        assert pattern.matches(make_verdict()) is False

    def test_empty_required_signal_names_skips_check(self) -> None:
        pattern = make_pattern(required_signal_names=())
        assert pattern.matches(make_verdict()) is True

    def test_min_families_enforced(self) -> None:
        pattern = make_pattern(min_families=3)
        # make_verdict имеет ровно 2 независимых семейства сигналов
        assert pattern.matches(make_verdict()) is False

    def test_min_cluster_size_ignored_for_verdict(self) -> None:
        # min_cluster_size не применяется к Verdict — у пользователя нет "размера"
        pattern = make_pattern(min_cluster_size=50)
        assert pattern.matches(make_verdict()) is True

    def test_min_cluster_size_enforced_for_cluster(self) -> None:
        pattern = make_pattern(min_cluster_size=10)
        assert pattern.matches(make_cluster()) is False  # только 3 участника

        big_cluster = make_cluster(user_ids=tuple(str(i) for i in range(15)))
        assert pattern.matches(big_cluster) is True


class TestMatchPatterns:
    def test_no_patterns_returns_none(self) -> None:
        assert match_patterns(make_verdict(), []) is None

    def test_no_matching_pattern_returns_none(self) -> None:
        pattern = make_pattern(min_risk_score=99)
        assert match_patterns(make_verdict(risk_score=10), [pattern]) is None

    def test_single_match_returned(self) -> None:
        pattern = make_pattern(id=42, min_risk_score=0)
        result = match_patterns(make_verdict(), [pattern])
        assert result is not None
        assert result.id == 42

    def test_highest_weight_wins_among_multiple_matches(self) -> None:
        weak = make_pattern(id=1, name="generic", weight=1.0)
        strong = make_pattern(id=2, name="specific mass-bot pattern", weight=10.0)
        result = match_patterns(make_verdict(), [weak, strong])
        assert result is not None
        assert result.id == 2

    def test_disabled_pattern_never_selected(self) -> None:
        disabled = make_pattern(id=1, enabled=False, weight=100.0)
        enabled = make_pattern(id=2, enabled=True, weight=1.0)
        result = match_patterns(make_verdict(), [disabled, enabled])
        assert result is not None
        assert result.id == 2
