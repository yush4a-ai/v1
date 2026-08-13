"""Паттерны сгенерированных никнеймов: слово + длинный случайный хвост цифр.

Слабый сигнал (вес 8) — у Twitch это ещё и обычное поведение при занятом
желаемом нике: сервис сам предлагает "name48291037" живому человеку. Один
этот признак никогда не должен быть решающим, только вкладом в общую сумму.
"""

from __future__ import annotations

import re

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "username"

# Хвост из 6+ цифр в конце ника — типичный паттерн автогенерации
# (массовые фермы аккаунтов, дефолтные предложения Twitch при занятом нике).
_DIGIT_TAIL_RE = re.compile(r"(\d{6,})$")


def detect(ctx: DetectionContext) -> list[Signal]:
    if not ctx.config.detectors.username.enabled:
        return []

    login = ctx.event.login
    match = _DIGIT_TAIL_RE.search(login)
    if not match:
        return []

    digit_tail = match.group(1)
    ratio = len(digit_tail) / len(login)
    if ratio < 0.4:
        return []

    return [
        Signal(
            name="generated_username_pattern",
            family=SignalFamily.IDENTITY,
            weight=ctx.config.weight("generated_username_pattern").weight,
            value=min(1.0, ratio),
            evidence=f"ник {login!r} — слово со случайным числовым хвостом ({digit_tail})",
        )
    ]
