"""Тесты детектора паттернов сгенерированных никнеймов."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import username
from cigilbot.domain.config import default_config
from tests.conftest import EventFactory, make_context


class TestGeneratedPattern:
    def test_flags_word_with_long_digit_tail(self, event_factory: EventFactory) -> None:
        event = event_factory(login="viewer48291037")
        ctx = make_context(event)
        assert any(s.name == "generated_username_pattern" for s in username.detect(ctx))

    def test_no_signal_for_normal_username(self, event_factory: EventFactory) -> None:
        event = event_factory(login="dragonslayer")
        ctx = make_context(event)
        assert username.detect(ctx) == []

    def test_no_signal_for_short_digit_suffix(self, event_factory: EventFactory) -> None:
        # "viewer23" — обычное явление, короткий хвост не аномалия
        event = event_factory(login="viewer23")
        ctx = make_context(event)
        assert username.detect(ctx) == []

    def test_no_signal_when_digits_are_minority(self, event_factory: EventFactory) -> None:
        # длинное имя с относительно коротким числовым хвостом — доля мала
        event = event_factory(login="theamazingdragonwarrior123456")
        ctx = make_context(event)
        assert username.detect(ctx) == []

    def test_mostly_digits_flagged_strongly(self, event_factory: EventFactory) -> None:
        event = event_factory(login="x999999999")
        ctx = make_context(event)
        signals = username.detect(ctx)
        assert signals
        assert signals[0].value > 0.5


class TestDisabled:
    def test_disabled_detector_returns_nothing(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(
            cfg,
            detectors=replace(
                cfg.detectors, username=replace(cfg.detectors.username, enabled=False)
            ),
        )
        event = event_factory(login="viewer48291037")
        ctx = make_context(event, config=cfg)
        assert username.detect(ctx) == []
