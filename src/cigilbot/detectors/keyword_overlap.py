"""Совпадение по значимым словам — ловит перефразированный спам, который
duplicate.py пропускает.

duplicate.py сравнивает СИМВОЛЬНЫЕ триграммы (minhash) — это ловит опечатки
и вставленные символы в ОДИНАКОВОМ тексте, но не перефразировку: "го стрим
у меня го глянь" и "у меня тоже стрим щас го смотреть" имеют мало общих
триграмм при похожем смысле, поэтому near_duplicate там не срабатывает
(проверено прогоном: 12 ботов с разными формулировками одной self-promo
фразы, растянуто на 90 сек — max risk=17 из 100, ни одного сигнала кроме
first_message/no_history).

Здесь сравнение на уровне СЛОВ, без учёта порядка: два сообщения от разных
пользователей похожи, если у них много общих значимых слов — даже если
структура фразы и порядок слов различаются. Стоп-слова (местоимения,
частицы, предлоги) исключены — иначе почти любые два сообщения на русском
делили бы "и", "у", "не" и получали бы ложное совпадение.
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "keyword_overlap"


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.keyword_overlap
    if not cfg.enabled:
        return []

    words = ctx.fingerprint.significant_words
    if len(words) < cfg.min_significant_words:
        return []

    recent = ctx.window.recent(cfg.window_seconds, now=ctx.event.timestamp)
    others = [e for e in recent if e.event.user_id != ctx.event.user_id]
    if not others:
        return []

    matched_logins: set[str] = set()
    best_overlap = 0.0
    for entry in others:
        other_words = entry.fingerprint.significant_words
        if len(other_words) < cfg.min_significant_words:
            continue
        # Jaccard по множествам слов — не Дайс и не пересечение/минимум:
        # симметрично и не даёт двум длинным сообщениям, случайно делящим
        # общую тему стрима, набрать высокий score только за счёт объёма.
        union = words | other_words
        if not union:
            continue
        overlap = len(words & other_words) / len(union)
        if overlap >= cfg.overlap_threshold:
            matched_logins.add(entry.event.login)
            best_overlap = max(best_overlap, overlap)

    if len(matched_logins) < cfg.min_matches:
        return []

    return [
        Signal(
            name="keyword_overlap",
            family=SignalFamily.CONTENT,
            weight=ctx.config.weight("keyword_overlap").weight,
            value=min(1.0, len(matched_logins) / (cfg.min_matches * 2)),
            evidence=(
                f"общие ключевые слова с {len(matched_logins)} сообщениями "
                f"({', '.join(sorted(matched_logins)[:5])}), макс. пересечение "
                f"{best_overlap:.0%}"
            ),
        )
    ]
