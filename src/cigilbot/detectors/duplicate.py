"""Дубликаты и почти-дубликаты — сравнение с недавними сообщениями в чате.

Сравниваем текущее сообщение с последними N секундами чата ОТ ЛЮБОГО
пользователя, не только от текущего: спам-атака — это разные аккаунты,
пишущие одно и то же, а не один аккаунт, повторяющий себя.

Это per-сообщение сигнал ("совпадает с N другими"), а не построение
кластера — группировкой конкретных пользователей занимается clustering.py
на следующем этапе. Здесь достаточно быстрого ответа "на этот текст уже
похоже реагировали недавно".

min_content_length — та же защита от хайпа, что в clustering.py
(min_content_length_for_edge), но здесь для ПЕР-СООБЩЕНИЯ сигнала: без неё
"ку", "гг", "+1" от разных обычных зрителей чата засчитывались бы как
exact_duplicate (найдено на replay реального чата, см. docs/moderation-plan.md,
этап 6 — эти короткие приветствия оказались самым частым источником
ложных срабатываний exact_duplicate на 8207 реальных сообщениях).
"""

from __future__ import annotations

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.types import Signal, SignalFamily

name = "duplicate"


def detect(ctx: DetectionContext) -> list[Signal]:
    cfg = ctx.config.detectors.duplicate
    if not cfg.enabled or ctx.fingerprint.is_empty:
        return []
    if len(ctx.fingerprint.matching) < cfg.min_content_length:
        return []

    recent = ctx.window.recent(cfg.window_seconds, now=ctx.event.timestamp)
    # Собственные предыдущие сообщения не считаем — иначе активный зритель,
    # трижды написавший "+" за розыгрыш, сам себе создаёт сигнал дубликата.
    others = [e for e in recent if e.event.user_id != ctx.event.user_id]
    if not others:
        return []

    exact_matches = 0
    near_matches = 0
    skeleton_matches = 0
    best_similarity = 0.0
    matched_logins: set[str] = set()

    for entry in others:
        other_fp = entry.fingerprint
        if other_fp.is_empty or len(other_fp.matching) < cfg.min_content_length:
            continue

        if other_fp.matching == ctx.fingerprint.matching:
            exact_matches += 1
            matched_logins.add(entry.event.login)
            continue

        sim = ctx.fingerprint.similarity_to(other_fp)
        best_similarity = max(best_similarity, sim)
        if sim >= cfg.near_duplicate_threshold:
            near_matches += 1
            matched_logins.add(entry.event.login)
        elif (
            len(ctx.fingerprint.skeleton) >= cfg.skeleton_min_length
            and ctx.fingerprint.skeleton == other_fp.skeleton
        ):
            skeleton_matches += 1
            matched_logins.add(entry.event.login)

    signals: list[Signal] = []

    if exact_matches:
        signals.append(
            Signal(
                name="exact_duplicate",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("exact_duplicate").weight,
                value=min(1.0, exact_matches / 3),
                evidence=(
                    f"точное совпадение с {exact_matches} сообщениями "
                    f"({', '.join(sorted(matched_logins)[:5])})"
                ),
            )
        )
    elif near_matches:
        signals.append(
            Signal(
                name="near_duplicate",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("near_duplicate").weight,
                value=min(1.0, near_matches / 3),
                evidence=(
                    f"похоже (>{cfg.near_duplicate_threshold:.0%}) на "
                    f"{near_matches} сообщений, макс. схожесть {best_similarity:.0%}"
                ),
            )
        )
    elif skeleton_matches:
        signals.append(
            Signal(
                name="skeleton_match",
                family=SignalFamily.CONTENT,
                weight=ctx.config.weight("skeleton_match").weight,
                value=min(1.0, skeleton_matches / 3),
                evidence=(
                    f"структурно совпадает с {skeleton_matches} сообщениями "
                    f"(например, меняются только цифры/имена)"
                ),
            )
        )

    return signals
