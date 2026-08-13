"""Тесты детектора Cross-Channel Bot Fingerprint (направление 03 master-plan.html)."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import cross_channel
from cigilbot.domain.config import default_config
from cigilbot.domain.types import SignalFamily
from tests.conftest import EventFactory, make_context


class TestKnownBadActor:
    def test_flags_user_in_known_bad_set(self, event_factory: EventFactory) -> None:
        event = event_factory(user_id="1")
        ctx = make_context(event, known_bad_actor_ids=frozenset({"1"}))

        signals = cross_channel.detect(ctx)

        assert len(signals) == 1
        assert signals[0].name == "known_bad_actor"
        assert signals[0].family == SignalFamily.HISTORY

    def test_no_signal_for_unknown_user(self, event_factory: EventFactory) -> None:
        event = event_factory(user_id="1")
        ctx = make_context(event, known_bad_actor_ids=frozenset({"2", "3"}))

        assert cross_channel.detect(ctx) == []

    def test_no_signal_with_empty_known_set(self, event_factory: EventFactory) -> None:
        event = event_factory(user_id="1")
        ctx = make_context(event)

        assert cross_channel.detect(ctx) == []

    def test_disabled_detector_yields_nothing(self, event_factory: EventFactory) -> None:
        event = event_factory(user_id="1")
        cfg = default_config()
        disabled_cfg = replace(
            cfg,
            detectors=replace(
                cfg.detectors, cross_channel=replace(cfg.detectors.cross_channel, enabled=False)
            ),
        )
        ctx = make_context(event, config=disabled_cfg, known_bad_actor_ids=frozenset({"1"}))

        assert cross_channel.detect(ctx) == []
