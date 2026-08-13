"""Тесты детектора эмодзи-спама и залго-текста."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import emote
from cigilbot.domain.config import default_config
from tests.conftest import EventFactory, make_context


class TestEmoteSpam:
    def test_flags_many_emoji(self, event_factory: EventFactory) -> None:
        event = event_factory(text="😀" * 10)
        ctx = make_context(event)
        assert any(s.name == "emote_spam" for s in emote.detect(ctx))

    def test_no_signal_for_normal_emoji_use(self, event_factory: EventFactory) -> None:
        event = event_factory(text="красиво сыграно 😀")
        ctx = make_context(event)
        assert emote.detect(ctx) == []


class TestZalgoTextSpam:
    def test_flags_combining_marks(self, event_factory: EventFactory) -> None:
        # залго-текст: множество комбинирующих диакритик на одной букве
        zalgo = "п" + "́" * 10 + "ривет"
        event = event_factory(text=zalgo)
        ctx = make_context(event)
        assert any(s.name == "zalgo_text_spam" for s in emote.detect(ctx))

    def test_normal_text_no_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="обычное сообщение без диакритики")
        ctx = make_context(event)
        assert emote.detect(ctx) == []


class TestDisabled:
    def test_disabled_detector_returns_nothing(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(
            cfg, detectors=replace(cfg.detectors, emote=replace(cfg.detectors.emote, enabled=False))
        )
        event = event_factory(text="😀" * 10)
        ctx = make_context(event, config=cfg)
        assert emote.detect(ctx) == []
