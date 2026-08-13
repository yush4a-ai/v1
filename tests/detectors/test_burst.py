"""Тесты детектора скорости сообщений: пользователь и канал в целом."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import burst
from cigilbot.domain.config import default_config
from cigilbot.domain.types import ChannelContext, Signal
from cigilbot.domain.window import SlidingWindow
from tests.conftest import EventFactory, add_message, make_context


class TestUserBurst:
    def test_no_signal_below_threshold(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        for i in range(5):
            add_message(window, event_factory(user_id="spammer", timestamp=float(i)))

        event = event_factory(user_id="spammer", timestamp=4.0)
        ctx = make_context(event, window=window)

        signals = burst.detect(ctx)
        assert not any(s.name == "user_message_burst" for s in signals)

    def test_signal_above_threshold(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        # дефолтный порог: 10 сообщений за 5 сек
        for i in range(12):
            add_message(window, event_factory(user_id="spammer", timestamp=i * 0.4))

        event = event_factory(user_id="spammer", timestamp=4.4)
        ctx = make_context(event, window=window)

        signals = burst.detect(ctx)
        matches = [s for s in signals if s.name == "user_message_burst"]
        assert len(matches) == 1
        assert matches[0].value > 0

    def test_value_scales_with_severity(self, event_factory: EventFactory) -> None:
        def build(count: int, span: float) -> list[Signal]:
            window = SlidingWindow()
            for i in range(count):
                add_message(
                    window, event_factory(user_id="spammer", timestamp=i * (span / count))
                )
            event = event_factory(user_id="spammer", timestamp=span)
            ctx = make_context(event, window=window)
            return burst.detect(ctx)

        mild = build(11, 5.0)
        severe = build(40, 5.0)

        mild_signal = next(s for s in mild if s.name == "user_message_burst")
        severe_signal = next(s for s in severe if s.name == "user_message_burst")
        assert severe_signal.value > mild_signal.value

    def test_disabled_detector_returns_nothing(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(
            cfg,
            detectors=replace(cfg.detectors, burst=replace(cfg.detectors.burst, enabled=False)),
        )

        window = SlidingWindow()
        for i in range(20):
            add_message(window, event_factory(user_id="spammer", timestamp=float(i) * 0.1))
        event = event_factory(user_id="spammer", timestamp=2.0)
        ctx = make_context(event, window=window, config=cfg)

        assert burst.detect(ctx) == []


class TestChannelBurst:
    def test_many_users_trigger_channel_signal(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        # дефолтный порог: 30 сообщений за 10 сек в канале
        for i in range(40):
            add_message(window, event_factory(user_id=f"u{i}", timestamp=i * 0.2))

        event = event_factory(user_id="last", timestamp=8.0)
        ctx = make_context(event, window=window)

        signals = burst.detect(ctx)
        assert any(s.name == "channel_message_burst" for s in signals)

    def test_raid_context_dampens_channel_signal(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        for i in range(60):
            add_message(window, event_factory(user_id=f"u{i}", timestamp=i * 0.1))
        event = event_factory(user_id="last", timestamp=6.0)

        normal_ctx = make_context(event, window=window, channel_context=ChannelContext())
        raid_ctx = make_context(
            event, window=window, channel_context=ChannelContext(is_raid=True)
        )

        normal_signals = burst.detect(normal_ctx)
        raid_signals = burst.detect(raid_ctx)

        normal_value = next(s.value for s in normal_signals if s.name == "channel_message_burst")
        raid_value = next(
            (s.value for s in raid_signals if s.name == "channel_message_burst"), 0.0
        )
        assert raid_value < normal_value
