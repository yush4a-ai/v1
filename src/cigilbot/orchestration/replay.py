"""Прогон исторического чата через движок модерации — без записи в БД,
без похода в Twitch. Позволяет проверять и калибровать пороги на реальных
данных ДО того, как в принципе рассматривать включение автодействий.

Источник данных — таблица recent_messages из bot/database.py (та же,
что видит LLM-бот для контекста ответов). У неё нет полей, которые в
реальном времени приходят из Twitch IRC-тегов и Helix, поэтому вход
для движка синтезируется с явными допущениями:

  - user_id       — Twitch не хранит его в recent_messages; используем
                    username как стабильный псевдо-id (для целей повтора
                    достаточно, реальные ники редко переиспользуются).
  - is_first_message — тег first-msg в реальном времени бесплатен и
                    надёжен, но в старых логах не записан. Приближаем
                    первым появлением username в хронологии ЭТОГО лога —
                    это не то же самое, что "первое сообщение на канале
                    когда-либо", если лог начинается не с первого дня.
  - is_subscriber/is_moderator/is_vip/is_broadcaster, badges — не
                    хранились, все False. Значит: если модератор канала
                    писал что-то похожее на спам-паттерн в этом логе,
                    replay оценит его как обычного зрителя — защита
                    privileged_user из policy.py тут не сработает.
  - account_created_at — недоступен, все вердикты replay получаются
                    is_provisional=True. Это не баг, а честное отражение
                    того, что Helix эти данные никогда не запрашивал.

Главная проверка, ради которой это всё написано (docs/moderation-plan.md,
раздел 12): на реальном чате без настоящих бот-атак ожидается ноль
рекомендаций BAN. Любое срабатывание — предмет ручного разбора как
потенциальный false positive, а не сразу повод паниковать.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from cigilbot.domain.config import ChannelProfile, ModerationConfig
from cigilbot.domain.types import Action, ChatEvent, Verdict
from cigilbot.orchestration.engine import ModerationEngine


@dataclass(frozen=True, slots=True)
class ReplayRow:
    username: str
    content: str
    created_at: float


def read_messages(db_path: Path) -> list[ReplayRow]:
    """Прочитать всю историю чата из recent_messages в хронологическом порядке.

    Открывается в режиме "только чтение" — replay не может испортить
    рабочую БД бота, даже если что-то пойдёт не так.
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT username, content, created_at FROM recent_messages ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    return [
        ReplayRow(username=r["username"], content=r["content"], created_at=r["created_at"])
        for r in rows
    ]


def to_events(rows: list[ReplayRow], channel: str) -> list[ChatEvent]:
    """Синтезировать ChatEvent из строк истории — см. допущения в докстринге модуля."""
    seen: set[str] = set()
    events = []
    for row in rows:
        is_first = row.username not in seen
        seen.add(row.username)
        events.append(
            ChatEvent(
                user_id=row.username,
                login=row.username,
                text=row.content,
                timestamp=row.created_at,
                channel=channel,
                display_name=row.username,
                is_first_message=is_first,
            )
        )
    return events


@dataclass(slots=True)
class ReplayReport:
    total_messages: int
    action_counts: dict[str, int]
    in_cluster_count: int
    flagged: list[Verdict] = field(default_factory=list)  # TIMEOUT/BAN — на ручной разбор
    top_risk: list[Verdict] = field(default_factory=list)  # топ по risk_score для калибровки весов

    @property
    def false_positive_candidates(self) -> int:
        """Сколько вердиктов рекомендовали TIMEOUT/BAN на реальном чате
        без настоящих атак — по умолчанию должно быть 0 (см. докстринг)."""
        return len(self.flagged)

    def format_summary(self) -> str:
        lines = [
            f"Сообщений проанализировано: {self.total_messages}",
            "",
            "По рекомендованному действию:",
        ]
        for action in ("NOTHING", "OBSERVE", "TIMEOUT", "BAN"):
            lines.append(f"  {action}: {self.action_counts.get(action, 0)}")
        lines += [
            "",
            f"Сообщений внутри подозрительного кластера в момент оценки: {self.in_cluster_count}",
            f"Потенциальных TIMEOUT/BAN на разбор: {self.false_positive_candidates}",
        ]
        if self.flagged:
            lines.append("")
            lines.append("Список для ручного разбора:")
            for v in self.flagged:
                lines.append(
                    f"  [{v.recommended_action.value}] {v.login}: risk={v.risk_score} "
                    f"conf={v.confidence:.2f} сигналы={', '.join(v.signal_names)}"
                )
        return "\n".join(lines)


async def run_replay(
    events: list[ChatEvent],
    config: ModerationConfig,
    channel_profile: ChannelProfile,
    *,
    top_n: int = 20,
) -> ReplayReport:
    """Прогнать события через движок без store (в памяти, без записи в БД)."""
    engine = ModerationEngine(config, channel_profile, store=None)

    action_counts: dict[str, int] = {a.value: 0 for a in Action}
    in_cluster_count = 0
    flagged: list[Verdict] = []
    all_verdicts: list[Verdict] = []

    for event in events:
        verdict = await engine.observe(event)
        action_counts[verdict.recommended_action.value] += 1
        if verdict.cluster_id is not None:
            in_cluster_count += 1
        if verdict.recommended_action in (Action.TIMEOUT, Action.BAN):
            flagged.append(verdict)
        all_verdicts.append(verdict)

    top_risk = sorted(all_verdicts, key=lambda v: v.risk_score, reverse=True)[:top_n]

    return ReplayReport(
        total_messages=len(events),
        action_counts=action_counts,
        in_cluster_count=in_cluster_count,
        flagged=flagged,
        top_risk=top_risk,
    )
