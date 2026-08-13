#!/usr/bin/env python
"""CLI: прогнать исторический чат через движок модерации.

Использование:
    .venv\\Scripts\\python scripts\\replay.py --db ..\\twitch-bots\\bot.db --channel мойканал
    .venv\\Scripts\\python scripts\\replay.py --db ..\\twitch-bots\\bot.db --channel мойканал --top 10

--db указывает на bot.db из соседнего проекта twitch-bots — та
БД хранит recent_messages (историю чата), а не эта (Cigilbot). Ничего не
пишет и не трогает Twitch — читает recent_messages в режиме "только
чтение" и печатает отчёт. См. cigilbot/replay.py за объяснением допущений,
на которых строится синтез входных данных.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from cigilbot.domain.config import load_channel_profile, load_config
from cigilbot.orchestration.replay import read_messages, run_replay, to_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", type=Path, required=True, help="Путь к bot.<instance>.db в twitch-bots"
    )
    parser.add_argument("--channel", required=True, help="Имя канала (для config/channels/<канал>.yml)")
    parser.add_argument(
        "--top", type=int, default=20, help="Сколько верхних по risk_score вердиктов показать"
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()

    if not args.db.exists():
        print(f"Файл не найден: {args.db}", file=sys.stderr)
        return 1

    rows = read_messages(args.db)
    if not rows:
        print("В recent_messages нет сообщений — нечего анализировать.")
        return 0

    events = to_events(rows, args.channel)
    config = load_config()
    channel_profile = load_channel_profile(args.channel)

    report = await run_replay(events, config, channel_profile, top_n=args.top)

    print(report.format_summary())
    print()
    print(f"Топ-{args.top} по risk_score (включая NOTHING/OBSERVE — для калибровки весов):")
    for v in report.top_risk:
        print(
            f"  risk={v.risk_score:3d} conf={v.confidence:.2f} "
            f"action={v.recommended_action.value:8s} {v.login}: {', '.join(v.signal_names) or '(нет сигналов)'}"
        )

    return 1 if report.false_positive_candidates > 0 else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
