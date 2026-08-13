"""Тесты детектора невидимых символов и смешения алфавитов."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import unicode as unicode_detector
from cigilbot.domain.config import default_config
from tests.conftest import EventFactory, make_context


class TestInvisibleChars:
    def test_flags_zero_width_space(self, event_factory: EventFactory) -> None:
        event = event_factory(text="при​вет")
        ctx = make_context(event)
        signals = unicode_detector.detect(ctx)
        assert any(s.name == "invisible_chars" for s in signals)

    def test_clean_text_no_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="обычное сообщение без подвоха")
        ctx = make_context(event)
        assert unicode_detector.detect(ctx) == []


class TestHomoglyphs:
    def test_flags_confusable_mix(self, event_factory: EventFactory) -> None:
        # латинская "p" вместо кириллической "р"
        event = event_factory(text="п" + "p" + "ивет всем")
        ctx = make_context(event)
        signals = unicode_detector.detect(ctx)
        assert any(s.name == "homoglyph_mix" for s in signals)

    def test_plain_latin_in_russian_chat_is_normal(self, event_factory: EventFactory) -> None:
        # латиница сама по себе — не аномалия для русского канала
        event = event_factory(text="gg wp nice game")
        ctx = make_context(event)
        assert unicode_detector.detect(ctx) == []

    def test_mixed_word_without_homoglyphs_gives_weaker_signal(
        self, event_factory: EventFactory
    ) -> None:
        event = event_factory(text="Wowчик такое видео")
        ctx = make_context(event)
        signals = unicode_detector.detect(ctx)
        names = {s.name for s in signals}
        assert "script_mix_in_word" in names
        assert "homoglyph_mix" not in names


class TestDisabled:
    def test_disabled_detector_returns_nothing(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(
            cfg,
            detectors=replace(
                cfg.detectors, unicode=replace(cfg.detectors.unicode, enabled=False)
            ),
        )

        event = event_factory(text="при​вет")
        ctx = make_context(event, config=cfg)
        assert unicode_detector.detect(ctx) == []
