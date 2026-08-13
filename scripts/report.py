#!/usr/bin/env python
"""CLI: сводка shadow-статистики и FP по правилам за последние N дней.

Использование:
    .venv\\Scripts\\python scripts\\report.py --db mod.168599565.db
    .venv\\Scripts\\python scripts\\report.py --db mod.96757582.db --days 7

Читает mod_stats_daily/mod_feedback через ModerationStore — ничего не
пишет и не трогает Twitch. См. cigilbot/report.py.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from cigilbot.orchestration.report import build_report
from cigilbot.storage.store import ModerationStore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="Путь к mod.<broadcaster_id>.db")
    parser.add_argument("--days", type=int, default=30, help="За сколько последних дней")
    return parser.parse_args()


async def main() -> int:
    args = parse_args()

    if not args.db.exists():
        print(f"Файл не найден: {args.db}", file=sys.stderr)
        return 1

    store = ModerationStore(str(args.db))
    await store.connect()
    try:
        report = await build_report(store, days=args.days)
    finally:
        await store.close()

    print(report.format_summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
