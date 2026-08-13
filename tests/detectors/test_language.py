"""Тесты детектора языка.

Главное, что здесь проверяется — инвариант из ТЗ: язык сам по себе не
повод для действия. Польскоязычный зритель на русском канале получает
сигнал с весом ниже порога OBSERVE, а не таймаут.
"""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import language
from cigilbot.domain.config import ChannelProfile, default_config
from tests.conftest import EventFactory, make_context


class TestExpectedLanguageSilent:
    def test_russian_on_russian_channel_no_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="привет всем, как дела у стримера сегодня")
        ctx = make_context(event, channel_profile=ChannelProfile(channel="test"))
        assert language.detect(ctx) == []

    def test_english_in_expected_list_no_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="hello everyone how is the stream going today")
        ctx = make_context(
            event,
            channel_profile=ChannelProfile(
                channel="test", expected_languages=("ru", "en"), suspicious_languages=("pl",)
            ),
        )
        assert language.detect(ctx) == []


class TestUnexpectedLanguageIsWeak:
    def test_polish_produces_only_the_weak_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="dzień dobry wszystkim, jak się dzisiaj macie")
        profile = ChannelProfile(
            channel="test", expected_languages=("ru", "en"), suspicious_languages=("pl",)
        )
        ctx = make_context(event, channel_profile=profile)

        signals = language.detect(ctx)
        assert len(signals) <= 1
        if signals:
            assert signals[0].name == "unexpected_language"

    def test_polish_signal_weight_is_below_observe_threshold(
        self, event_factory: EventFactory
    ) -> None:
        cfg = default_config()
        event = event_factory(text="dzień dobry wszystkim, jak się dzisiaj macie")
        profile = ChannelProfile(
            channel="test", expected_languages=("ru", "en"), suspicious_languages=("pl",)
        )
        ctx = make_context(event, config=cfg, channel_profile=profile)

        signals = language.detect(ctx)
        assert signals, "ожидался сигнал unexpected_language"
        assert signals[0].score < cfg.risk.observe


class TestNoFalsePositiveOnSlang:
    def test_short_twitch_slang_does_not_trigger(self, event_factory: EventFactory) -> None:
        # короткий сленг классификируется с низкой уверенностью — не должен
        # пройти порог min_confidence и создать ложный сигнал
        event = event_factory(text="gg wp")
        profile = ChannelProfile(
            channel="test", expected_languages=("ru", "en"), suspicious_languages=("pl",)
        )
        ctx = make_context(event, channel_profile=profile)
        assert language.detect(ctx) == []


class TestConfigGating:
    def test_disabled_detector_returns_nothing(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(
            cfg,
            detectors=replace(
                cfg.detectors, language=replace(cfg.detectors.language, enabled=False)
            ),
        )
        event = event_factory(text="dzień dobry wszystkim")
        ctx = make_context(
            event,
            config=cfg,
            channel_profile=ChannelProfile(
                channel="test", expected_languages=("ru",), suspicious_languages=("pl",)
            ),
        )
        assert language.detect(ctx) == []

    def test_single_expected_language_skips_detection(self, event_factory: EventFactory) -> None:
        # lingua требует минимум 2 языка-кандидата для сравнения; профиль без
        # suspicious_languages и с одним expected не должен падать
        event = event_factory(text="dzień dobry wszystkim jak się macie")
        ctx = make_context(
            event,
            channel_profile=ChannelProfile(
                channel="test", expected_languages=("ru",), suspicious_languages=()
            ),
        )
        assert language.detect(ctx) == []

    def test_empty_message_no_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="!!!")
        ctx = make_context(event)
        assert language.detect(ctx) == []
