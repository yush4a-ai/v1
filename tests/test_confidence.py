"""Тесты confidence.py.

Самое важное здесь: один сигнал даже с максимальным value никогда не даёт
confidence, достаточную для timeout/ban — это прямое следствие того, что
family_factor_for(1) существенно ниже confidence.minimum_for_timeout.
"""

from __future__ import annotations

from cigilbot.domain.confidence import confidence
from cigilbot.domain.config import default_config
from cigilbot.domain.types import ChannelContext, Signal, SignalFamily


def sig(name: str, family: SignalFamily, weight: float = 20, value: float = 1.0) -> Signal:
    return Signal(name=name, family=family, weight=weight, value=value, evidence="test")


class TestSingleSignalNeverEnoughConfidence:
    def test_single_strong_signal_below_timeout_minimum(self) -> None:
        cfg = default_config()
        signals = [sig("exact_duplicate", SignalFamily.CONTENT, weight=25, value=1.0)]
        result = confidence(signals, cfg, ChannelContext(), sample_size=1)
        assert result < cfg.confidence.minimum_for_timeout

    def test_single_signal_far_below_ban_minimum(self) -> None:
        cfg = default_config()
        signals = [sig("known_scam_domain", SignalFamily.CONTENT, weight=35, value=1.0)]
        result = confidence(signals, cfg, ChannelContext(), sample_size=1)
        assert result < cfg.confidence.minimum_for_ban

    def test_no_signals_zero_confidence(self) -> None:
        cfg = default_config()
        assert confidence([], cfg, ChannelContext()) == 0.0


class TestMultipleFamiliesIncreaseConfidence:
    def test_more_families_means_higher_confidence(self) -> None:
        cfg = default_config()
        ctx = ChannelContext()

        one_family = [sig("a", SignalFamily.CONTENT)]
        three_families = [
            sig("a", SignalFamily.CONTENT),
            sig("b", SignalFamily.TIMING),
            sig("c", SignalFamily.NETWORK),
        ]

        c1 = confidence(one_family, cfg, ctx, sample_size=5)
        c3 = confidence(three_families, cfg, ctx, sample_size=5)
        assert c3 > c1

    def test_five_independent_families_can_reach_ban_confidence(self) -> None:
        # сценарий из ТЗ: несколько независимых сильных сигналов дают
        # высокую уверенность, оправдывающую BAN
        cfg = default_config()
        signals = [
            sig("mass_first_messages", SignalFamily.NETWORK),
            sig("synchronized_arrival", SignalFamily.TIMING),
            sig("exact_duplicate", SignalFamily.CONTENT),
            sig("new_account", SignalFamily.IDENTITY),
            sig("invisible_chars", SignalFamily.ENCODING),
        ]
        result = confidence(signals, cfg, ChannelContext(), sample_size=10)
        assert result >= cfg.confidence.minimum_for_ban


class TestSampleSize:
    def test_larger_sample_increases_confidence(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT), sig("b", SignalFamily.TIMING)]
        small = confidence(signals, cfg, ChannelContext(), sample_size=1)
        large = confidence(signals, cfg, ChannelContext(), sample_size=15)
        assert large > small

    def test_sample_size_saturates(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT), sig("b", SignalFamily.TIMING)]
        at_ten = confidence(signals, cfg, ChannelContext(), sample_size=10)
        at_hundred = confidence(signals, cfg, ChannelContext(), sample_size=100)
        assert at_ten == at_hundred


class TestContextDampensConfidence:
    def test_raid_lowers_confidence(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT), sig("b", SignalFamily.TIMING)]
        normal = confidence(signals, cfg, ChannelContext(), sample_size=5)
        raid = confidence(signals, cfg, ChannelContext(is_raid=True), sample_size=5)
        assert raid < normal

    def test_giveaway_lowers_confidence(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT), sig("b", SignalFamily.TIMING)]
        normal = confidence(signals, cfg, ChannelContext(), sample_size=5)
        giveaway = confidence(signals, cfg, ChannelContext(is_giveaway=True), sample_size=5)
        assert giveaway < normal


class TestFalsePositivePenalty:
    def test_fp_penalty_lowers_confidence(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT), sig("b", SignalFamily.TIMING)]
        no_penalty = confidence(signals, cfg, ChannelContext(), sample_size=5, fp_penalty=0.0)
        penalized = confidence(signals, cfg, ChannelContext(), sample_size=5, fp_penalty=0.5)
        assert penalized < no_penalty

    def test_fp_penalty_clamped_to_valid_range(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT)]
        # penalty > 1.0 не должен уйти в отрицательный confidence
        result = confidence(signals, cfg, ChannelContext(), sample_size=5, fp_penalty=5.0)
        assert result >= 0.0


class TestBounds:
    def test_confidence_never_exceeds_one(self) -> None:
        cfg = default_config()
        signals = [sig(f"s{i}", list(SignalFamily)[i % 6]) for i in range(20)]
        result = confidence(signals, cfg, ChannelContext(), sample_size=1000)
        assert result <= 1.0

    def test_confidence_never_negative(self) -> None:
        cfg = default_config()
        signals = [sig("a", SignalFamily.CONTENT, value=0.0)]
        result = confidence(signals, cfg, ChannelContext(), sample_size=1)
        assert result >= 0.0
