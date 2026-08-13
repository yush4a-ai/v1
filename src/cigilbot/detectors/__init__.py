"""Реестр детекторов.

Добавление нового детектора — это новый файл в этом пакете с функцией
detect(ctx) -> list[Signal] и строка в ALL_DETECTORS. scoring.py и всё,
что выше него, не меняются: они работают со списком Signal, а не со
списком конкретных проверок.
"""

from __future__ import annotations

from cigilbot.detectors import (
    account,
    burst,
    cross_channel,
    duplicate,
    emote,
    keyword_overlap,
    language,
    links,
    username,
)
from cigilbot.detectors import (
    unicode as unicode_detector,
)
from cigilbot.detectors.base import DetectionContext, Detector
from cigilbot.domain.types import Signal

ALL_DETECTORS: tuple[Detector, ...] = (
    burst,
    duplicate,
    keyword_overlap,
    links,
    unicode_detector,
    language,
    account,
    username,
    emote,
    cross_channel,
)


def run_all(ctx: DetectionContext) -> list[Signal]:
    """Прогнать контекст через все детекторы и собрать сигналы в один список.

    Сбой одного детектора не должен прятать сигналы остальных — но и не
    должен проходить незамеченным, поэтому падение пробрасывается наружу
    после логирования на уровне engine.py, а не глотается здесь молча.
    """
    signals: list[Signal] = []
    for detector in ALL_DETECTORS:
        signals.extend(detector.detect(ctx))
    return signals
