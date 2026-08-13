"""Возраст аккаунта, первое сообщение, отсутствие истории на канале.

Каждый из этих сигналов по отдельности имеет высокий false-positive
rate — новый зритель, впервые написавший в чат, абсолютно нормальное
явление на любом канале каждый день. Веса в конфиге сознательно низкие
(5-10), чтобы такой зритель в одиночку не получил ничего выше OBSERVE.

account_created_at может быть ещё не известен на момент оценки (Helix ещё
не ответил, см. ChatEvent.account_created_at) — тогда new_account просто
не выдаётся, а не досчитывается "предположительно новый": вердикт в этом
случае помечается is_provisional на уровне engine.py, а не здесь.
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "account"


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.account
    if not cfg.enabled:
        return []

    signals: list[Signal] = []
    user = ctx.user

    age_days = user.account_age_days
    if age_days is not None and age_days < cfg.new_account_days:
        # Чем свежее аккаунт относительно порога, тем выше value: аккаунту
        # возрастом в час это даёт value~1.0, на грани порога — около 0.
        value = min(1.0, max(0.0, 1.0 - age_days / cfg.new_account_days))
        signals.append(
            Signal(
                name="new_account",
                family=SignalFamily.IDENTITY,
                weight=ctx.config.weight("new_account").weight,
                value=value,
                evidence=f"аккаунт создан {age_days:.1f} дн. назад (порог {cfg.new_account_days:.0f})",
            )
        )

    if ctx.event.is_first_message:
        signals.append(
            Signal(
                name="first_message",
                family=SignalFamily.IDENTITY,
                weight=ctx.config.weight("first_message").weight,
                value=1.0,
                evidence="первое сообщение пользователя на канале (тег Twitch first-msg)",
            )
        )

    if user.message_count <= cfg.no_history_message_count:
        signals.append(
            Signal(
                name="no_history",
                family=SignalFamily.IDENTITY,
                weight=ctx.config.weight("no_history").weight,
                value=1.0,
                evidence=f"на канале известно только {user.message_count} сообщений этого пользователя",
            )
        )

    return signals
