"""Спам эмодзи и забивание сообщения повтором символов ("залго"-текст).

Отдельно от normalize.py: там normalize_text() схлопывает повторы для
СРАВНЕНИЯ сообщений, а здесь нас интересует сам факт "сообщение — это
в основном мусор", независимо от того, похоже ли оно на другие.
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "emote"


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.emote
    if not cfg.enabled:
        return []

    signals: list[Signal] = []
    fp = ctx.fingerprint

    if fp.scripts.emoji_count >= cfg.repeat_threshold:
        signals.append(
            Signal(
                name="emote_spam",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("emote_spam").weight,
                value=min(1.0, fp.scripts.emoji_count / (cfg.repeat_threshold * 2)),
                evidence=f"{fp.scripts.emoji_count} эмодзи в одном сообщении",
            )
        )

    if fp.combining_marks >= cfg.repeat_threshold:
        signals.append(
            Signal(
                # BUG-005 аудита: раньше назывался repeated_char_spam, что
                # вводило в заблуждение — сигнал считает исключительно
                # Unicode-комбинирующие символы (залго-текст), а не повтор
                # обычных символов подряд (такого детектора в системе нет).
                name="zalgo_text_spam",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("zalgo_text_spam").weight,
                value=min(1.0, fp.combining_marks / (cfg.repeat_threshold * 2)),
                evidence=f"{fp.combining_marks} комбинирующих символов (залго-текст)",
            )
        )

    return signals
