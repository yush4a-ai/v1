"""confidence = family_factor × sample_factor × context_factor × (1 − fp_penalty)

Отдельно от risk_score: risk_score отвечает "насколько это выглядит плохо",
confidence — "насколько мы в этом уверены". Пять слабых сигналов одного
семейства могут дать высокий risk_score и низкий confidence одновременно —
и именно confidence, а не risk_score, определяет допустимость действия
в policy.py.
"""

from __future__ import annotations

from cigilbot.domain.config import ConfidenceConfig, ModerationConfig
from cigilbot.domain.scoring import families_triggered
from cigilbot.domain.types import ChannelContext, Signal


def _sample_factor(sample_size: int, cfg: ConfidenceConfig, saturation: int = 10) -> float:
    """Насколько мы уверены в наблюдении по числу подтверждающих случаев.

    1 сообщение / маленький кластер — sample_factor_low. Начиная с
    saturation наблюдений (10 сообщений, крупный кластер) — sample_factor_high.
    Дальнейший рост объёма уже не добавляет уверенности.
    """
    if sample_size <= 1:
        return cfg.sample_factor_low
    progress = min(1.0, (sample_size - 1) / (saturation - 1))
    return cfg.sample_factor_low + progress * (cfg.sample_factor_high - cfg.sample_factor_low)


def _context_factor(channel_context: ChannelContext, cfg: ConfidenceConfig) -> float:
    """Рейд/розыгрыш/хайп — контекст, в котором обычные признаки атаки
    (всплеск сообщений, много новых аккаунтов разом) объясняются иначе."""
    if channel_context.is_raid:
        return cfg.context_factor.get("raid", 1.0)
    if channel_context.is_giveaway:
        return cfg.context_factor.get("giveaway", 1.0)
    if channel_context.is_hype:
        return cfg.context_factor.get("hype", 1.0)
    return cfg.context_factor.get("normal", 1.0)


def confidence(
    signals: list[Signal],
    config: ModerationConfig,
    channel_context: ChannelContext,
    *,
    sample_size: int = 1,
    fp_penalty: float = 0.0,
) -> float:
    """Итоговая уверенность в вердикте, [0, 1].

    fp_penalty — историческая доля ложных срабатываний для сработавших
    правил (0 = данных ещё нет). Подключается на этапе 9 через таблицу
    mod_feedback: чем чаще модераторы нажимают MARK AS SAFE на срабатывания
    конкретного правила, тем меньше система ему доверяет — confidence.py
    уже сейчас принимает этот параметр, чтобы подключение не потребовало
    менять сигнатуру и всех вызывающих.
    """
    if not signals:
        return 0.0

    families = families_triggered(signals)
    cfg = config.confidence

    value = (
        cfg.family_factor_for(families)
        * _sample_factor(sample_size, cfg)
        * _context_factor(channel_context, cfg)
        * (1.0 - min(1.0, max(0.0, fp_penalty)))
    )
    return max(0.0, min(1.0, value))
