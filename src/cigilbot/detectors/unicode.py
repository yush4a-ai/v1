"""Невидимые символы и гомоглифы — технические признаки обхода фильтров.

Эти сигналы сильнее языка именно потому, что у них почти нет легитимного
объяснения: обычный человек не вставляет в сообщение zero-width space и не
печатает кириллическую букву латинской, маскируясь под другой алфавит.
Смешанные слова без гомоглифов (ники вроде "Wowчик") сюда не попадают —
за это отвечает script_profile.has_mixed_words, который сам по себе сигнала
не даёт (см. normalize.py).
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "unicode"


def detect(ctx: DetectionContext) -> list[Signal]:
    if not ctx.config.detectors.unicode.enabled:
        return []

    signals: list[Signal] = []
    fp = ctx.fingerprint

    if fp.invisible_chars:
        signals.append(
            Signal(
                name="invisible_chars",
                family=SignalFamily.ENCODING,
                weight=ctx.config.weight("invisible_chars").weight,
                value=min(1.0, len(fp.invisible_chars) / 3),
                evidence=(
                    f"невидимые управляющие символы в тексте "
                    f"({', '.join(fp.invisible_chars[:5])})"
                ),
            )
        )

    if fp.scripts.has_confusables:
        signals.append(
            Signal(
                name="homoglyph_mix",
                family=SignalFamily.ENCODING,
                weight=ctx.config.weight("homoglyph_mix").weight,
                value=min(1.0, len(fp.scripts.confusable_words) / 2),
                evidence=(
                    "визуально одинаковые буквы из разных алфавитов внутри слова: "
                    f"{', '.join(fp.scripts.confusable_words[:3])}"
                ),
            )
        )
    elif fp.scripts.has_mixed_words:
        signals.append(
            Signal(
                name="script_mix_in_word",
                family=SignalFamily.ENCODING,
                weight=ctx.config.weight("script_mix_in_word").weight,
                value=min(1.0, len(fp.scripts.mixed_words) / 2),
                evidence=(
                    "слово смешивает алфавиты без явной подмены букв: "
                    f"{', '.join(fp.scripts.mixed_words[:3])}"
                ),
            )
        )

    return signals
