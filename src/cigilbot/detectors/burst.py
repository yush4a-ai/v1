"""Скорость сообщений: один пользователь и канал в целом.

Порог даёт не бинарный факт, а плавную величину: 6 сообщений за 5 секунд —
это не то же самое, что 20. value растёт линейно от threshold до 3×threshold,
дальше насыщается — дальнейшее ускорение уже не делает признак «ещё более
достоверным», предел информативности достигнут.
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "burst"


def _scaled_value(count: float, threshold: float) -> float:
    if threshold <= 0 or count <= threshold:
        return 0.0
    return min(1.0, (count - threshold) / (2 * threshold))


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.burst
    if not cfg.enabled:
        return []

    signals: list[Signal] = []
    now = ctx.event.timestamp

    user_count = ctx.window.user_message_count(
        ctx.event.user_id, cfg.user_window_seconds, now=now
    )
    user_value = _scaled_value(user_count, cfg.user_messages_threshold)
    if user_value > 0:
        signals.append(
            Signal(
                name="user_message_burst",
                family=SignalFamily.TIMING,
                weight=ctx.config.weight("user_message_burst").weight,
                value=user_value,
                evidence=(
                    f"{user_count} сообщений от {ctx.event.login} "
                    f"за {cfg.user_window_seconds:.0f} сек"
                ),
            )
        )

    channel_rate = ctx.window.channel_rate_per_minute(cfg.channel_window_seconds, now=now)
    # Порог задан в сообщениях за окно — приводим к той же шкале, что и rate.
    channel_threshold_per_minute = cfg.channel_messages_threshold / cfg.channel_window_seconds * 60.0
    channel_value = _scaled_value(channel_rate, channel_threshold_per_minute)
    if channel_value > 0:
        # Хайп и рейд — контекст, при котором высокая скорость канала норма.
        # Здесь не гасим сигнал совсем (детектор не знает про policy), но
        # ослабляем его пропорционально: дальше это учтёт confidence.py
        # через context_factor, а здесь достаточно не удваивать эффект.
        if ctx.channel_context.is_special:
            channel_value *= 0.4
        if channel_value > 0:
            signals.append(
                Signal(
                    name="channel_message_burst",
                    family=SignalFamily.TIMING,
                    weight=ctx.config.weight("channel_message_burst").weight,
                    value=channel_value,
                    evidence=(
                        f"{channel_rate:.0f} сообщений/мин в канале "
                        f"({ctx.channel_context.label})"
                    ),
                )
            )

    return signals
