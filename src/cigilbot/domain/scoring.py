"""Signal[] -> risk_score.

risk_score = clamp(0, 100, Σ signal.weight × signal.value × mode_multiplier)

Плавность (signal.value ∈ [0,1]) даёт систему баллов вместо ступенек
if/else: 6 сообщений за 5 секунд весят меньше, чем 20, хотя оба формально
"превышают порог burst". mode_multiplier применяется к сумме один раз, а
не к каждому сигналу отдельно — иначе AGGRESSIVE/ATTACK не просто повышали
бы чувствительность, а нелинейно искажали относительный вклад сигналов
друг к другу.
"""

from __future__ import annotations

from cigilbot.domain.config import ModerationConfig
from cigilbot.domain.types import Sensitivity, Signal


def risk_score(
    signals: list[Signal],
    config: ModerationConfig,
    *,
    sensitivity: Sensitivity | None = None,
    regular_user: bool = False,
) -> int:
    """regular_user=True — известный каналу пользователь (TrustLevel.REGULAR,
    этап 9a): та же логика сигналов, но с понижающим множителем из
    config.trust.regular_risk_multiplier. Не путать с trusted/marked_safe —
    те дают policy.py полную защиту (максимум OBSERVE), это лишь скидка на
    сырой risk_score, применяется наравне с mode_multiplier."""
    raw = sum(signal.score for signal in signals)
    multiplier = config.mode_multiplier(sensitivity)
    if regular_user and config.trust.enabled:
        multiplier *= config.trust.regular_risk_multiplier
    return max(0, min(100, round(raw * multiplier)))


def families_triggered(signals: list[Signal]) -> int:
    """Сколько РАЗНЫХ семейств сигналов сработало.

    Не то же самое, что len(signals): два сигнала из одного семейства
    (например exact_duplicate и near_duplicate — оба CONTENT) считаются
    одним подтверждением, а не двумя независимыми. Используется в
    confidence.py и как источник инварианта "2+ семейства для BAN".
    """
    return len({signal.family for signal in signals})
