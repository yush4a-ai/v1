"""Сводка shadow-статистики и FP по правилам (этап 9d).

Читает mod_stats_daily/mod_feedback через ModerationStore — то, что за
дни/недели накопил движок в SHADOW-режиме, агрегированное в текстовый
отчёт для оператора (CLI scripts/report.py) или будущего REST-эндпоинта
экрана Stats панели. Ничего не пересчитывает и не пишет — чистое чтение.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cigilbot.storage.store import ModerationStore


@dataclass(slots=True)
class SignalFpStats:
    signal_name: str
    total_feedback: int
    false_positive_count: int

    @property
    def fp_rate(self) -> float:
        if self.total_feedback == 0:
            return 0.0
        return self.false_positive_count / self.total_feedback


@dataclass(slots=True)
class ModerationReport:
    days_covered: int
    total_messages: int
    total_suspicious: int
    total_would_timeout: int
    total_would_ban: int
    total_actual_timeouts: int
    total_actual_bans: int
    total_clusters: int
    total_false_positives: int
    signal_fp_stats: list[SignalFpStats] = field(default_factory=list)

    def format_summary(self) -> str:
        lines = [
            f"Сводка модерации за последние {self.days_covered} дн.",
            "",
            f"Сообщений проанализировано: {self.total_messages}",
            f"Подозрительных (risk >= observe): {self.total_suspicious}",
            f"Рекомендовано TIMEOUT: {self.total_would_timeout} "
            f"(реально выполнено: {self.total_actual_timeouts})",
            f"Рекомендовано BAN: {self.total_would_ban} "
            f"(реально выполнено: {self.total_actual_bans})",
            f"Кластеров обнаружено: {self.total_clusters}",
            f"False positive отмечено модераторами: {self.total_false_positives}",
        ]

        if self.signal_fp_stats:
            lines += ["", "FP-статистика по сигналам (доля FALSE_POSITIVE от фидбека):"]
            for stat in sorted(self.signal_fp_stats, key=lambda s: s.fp_rate, reverse=True):
                lines.append(
                    f"  {stat.signal_name}: {stat.fp_rate:.0%} "
                    f"({stat.false_positive_count}/{stat.total_feedback})"
                )

        return "\n".join(lines)


async def build_report(store: ModerationStore, *, days: int = 30) -> ModerationReport:
    daily_rows = await store.get_daily_stats(days=days)
    feedback_rows = await store.list_feedback(limit=10_000)

    # false_positives сюда не входит — get_daily_stats() больше не считает
    # его (см. её докстринг), реальный источник ниже, по feedback_rows.
    totals = {
        "total_messages": 0, "suspicious": 0, "would_timeout": 0, "would_ban": 0,
        "actual_timeouts": 0, "actual_bans": 0, "clusters": 0,
    }
    for row in daily_rows:
        for key in totals:
            totals[key] += row.get(key, 0) or 0

    per_signal: dict[str, list[str]] = {}
    for row in feedback_rows:
        per_signal.setdefault(row["signal_name"], []).append(row["decision"])

    signal_stats = [
        SignalFpStats(
            signal_name=name,
            total_feedback=len(decisions),
            false_positive_count=sum(1 for d in decisions if d == "FALSE_POSITIVE"),
        )
        for name, decisions in per_signal.items()
    ]
    # Раньше total_false_positives читался из totals["false_positives"],
    # который всегда был 0 (mod_stats_daily никогда не заполнялась, см.
    # get_daily_stats) — отчёт врал про число FP, хотя сами данные для
    # этого поля уже лежали в feedback_rows, просто не были просуммированы
    # сюда (bug-аудит store.py, 2026-08-17).
    total_false_positives = sum(s.false_positive_count for s in signal_stats)

    return ModerationReport(
        days_covered=days,
        total_messages=totals["total_messages"],
        total_suspicious=totals["suspicious"],
        total_would_timeout=totals["would_timeout"],
        total_would_ban=totals["would_ban"],
        total_actual_timeouts=totals["actual_timeouts"],
        total_actual_bans=totals["actual_bans"],
        total_clusters=totals["clusters"],
        total_false_positives=total_false_positives,
        signal_fp_stats=signal_stats,
    )
