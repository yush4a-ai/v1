"""Тесты scoring.py: risk_score и families_triggered."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.domain.config import default_config
from cigilbot.domain.scoring import families_triggered, risk_score
from cigilbot.domain.types import Sensitivity, Signal, SignalFamily


def sig(name: str, family: SignalFamily, weight: float, value: float = 1.0) -> Signal:
    return Signal(name=name, family=family, weight=weight, value=value, evidence="test")


class TestRiskScore:
    def test_no_signals_is_zero(self) -> None:
        cfg = default_config()
        assert risk_score([], cfg) == 0

    def test_sums_weighted_scores(self) -> None:
        cfg = default_config()
        signals = [
            sig("a", SignalFamily.CONTENT, 20, 1.0),
            sig("b", SignalFamily.TIMING, 15, 1.0),
        ]
        assert risk_score(signals, cfg) == 35

    def test_value_scales_contribution(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT, 20, 0.5)]
        assert risk_score(signals, cfg) == 10

    def test_clamped_to_100(self) -> None:
        cfg = default_config()
        signals = [sig(f"s{i}", SignalFamily.CONTENT, 50, 1.0) for i in range(5)]
        assert risk_score(signals, cfg) == 100

    def test_clamped_to_0_minimum(self) -> None:
        cfg = default_config()
        assert risk_score([], cfg) >= 0

    def test_mode_multiplier_applied(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT, 20, 1.0)]
        balanced = risk_score(signals, cfg, sensitivity=Sensitivity.BALANCED)
        aggressive = risk_score(signals, cfg, sensitivity=Sensitivity.AGGRESSIVE)
        safe = risk_score(signals, cfg, sensitivity=Sensitivity.SAFE)
        assert safe < balanced < aggressive

    def test_default_sensitivity_comes_from_config(self) -> None:
        cfg = default_config()
        cfg = replace(cfg, sensitivity=Sensitivity.AGGRESSIVE)
        signals = [sig("a", SignalFamily.CONTENT, 20, 1.0)]
        assert risk_score(signals, cfg) == risk_score(signals, cfg, sensitivity=Sensitivity.AGGRESSIVE)

    def test_regular_user_gets_discount(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT, 20, 1.0)]
        normal = risk_score(signals, cfg, regular_user=False)
        regular = risk_score(signals, cfg, regular_user=True)
        assert regular < normal

    def test_regular_user_discount_matches_configured_multiplier(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT, 20, 1.0)]
        normal = risk_score(signals, cfg, regular_user=False)
        regular = risk_score(signals, cfg, regular_user=True)
        assert regular == round(normal * cfg.trust.regular_risk_multiplier)

    def test_regular_user_discount_disabled_by_config(self) -> None:
        cfg = default_config()
        cfg = replace(cfg, trust=replace(cfg.trust, enabled=False))
        signals = [sig("a", SignalFamily.CONTENT, 20, 1.0)]
        normal = risk_score(signals, cfg, regular_user=False)
        regular = risk_score(signals, cfg, regular_user=True)
        assert regular == normal

    def test_regular_user_never_negates_a_critical_signal_alone(self) -> None:
        # Инвариант: скидка REGULAR не может сама по себе увести CRITICAL-риск
        # в NOTHING/LOW — она модификатор веса уже существующих сигналов, не
        # право вето. Один достаточно сильный сигнал остаётся заметным.
        cfg = default_config()
        signals = [sig("known_scam_domain", SignalFamily.CONTENT, 100, 1.0)]
        regular = risk_score(signals, cfg, regular_user=True)
        assert regular >= cfg.risk.timeout


class TestFamiliesTriggered:
    def test_empty_is_zero(self) -> None:
        assert families_triggered([]) == 0

    def test_same_family_counts_once(self) -> None:
        signals = [
            sig("exact_duplicate", SignalFamily.CONTENT, 25),
            sig("near_duplicate", SignalFamily.CONTENT, 20),
        ]
        assert families_triggered(signals) == 1

    def test_different_families_count_separately(self) -> None:
        signals = [
            sig("exact_duplicate", SignalFamily.CONTENT, 25),
            sig("user_message_burst", SignalFamily.TIMING, 15),
            sig("new_account", SignalFamily.IDENTITY, 10),
        ]
        assert families_triggered(signals) == 3

    def test_all_six_families(self) -> None:
        signals = [sig(f.value, f, 1) for f in SignalFamily]
        assert families_triggered(signals) == 6
