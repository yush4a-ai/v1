"""Разовый перенос ADMIN-оверрайдов ролей: bot.db::panel_admins -> mod.db::mod_panel_users.

Нужен один раз, после слияния панелей в один процесс. До него списки админов
были два: panel_admins в bot.db обслуживал панель ботов (порт 8765),
mod_panel_users в mod.db — панель модерации (8766), и выданный в одной ADMIN
не действовал в другой. Панель одна — список должен быть один, и победил
mod_panel_users (обоснование в panel/auth.py и panel/server.py::db_path).

Не миграция cigilbot/migrations.py намеренно: те знают только собственный
файл БД, а здесь данные едут между двумя разными файлами, причём путь к
исходному (bot.db, чужой проект) зависит от INSTANCE и настроек. Завязывать
на это версионированную схему mod.db значило бы сделать её незапускаемой
там, где bot.db просто нет.

Идемпотентен: повторный запуск ничего не портит, upsert перезапишет те же
значения. Конфликт логинов решается в пользу БОЛЕЕ ВЫСОКОЙ роли — если
человек был ADMIN на одной панели и MODERATOR на другой, отобрать права,
которые у него уже были, молчаливым переносом нельзя.

Запуск из корня проекта:
    ..\\..\\.venv\\Scripts\\python scripts\\merge_panel_admins.py
    ..\\..\\.venv\\Scripts\\python scripts\\merge_panel_admins.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sqlite3
from pathlib import Path

from cigilbot.storage.store import ModerationStore
from paths import BOT_VAR, MOD_DB

# Та же иерархия, что panel/moderation_api.py::_ROLE_RANK.
_ROLE_RANK = {"VIEWER": 0, "MODERATOR": 1, "ADMIN": 2, "OWNER": 3}


def _find_bot_dbs() -> list[Path]:
    """bot.db и все bot.<instance>.db — профильная модель twitch-bots
    разводит БД по INSTANCE, и список админов мог осесть в любой из них."""
    return sorted(p for p in BOT_VAR.glob("bot*.db") if p.is_file())


def _read_panel_admins(db: Path) -> dict[str, str]:
    """{login: role} из panel_admins, или пусто, если таблицы нет.

    Таблицы может не быть законно: bot/database.py больше её не создаёт, так
    что в свежей БД её и не будет. Это не ошибка, а нормальный случай.
    """
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT login, role FROM panel_admins").fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()
    return {login.lower(): role for login, role in rows}


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="только показать, что было бы перенесено"
    )
    args = parser.parse_args()

    source: dict[str, str] = {}
    for db in _find_bot_dbs():
        found = _read_panel_admins(db)
        if found:
            print(f"{db.name}: найдено записей — {len(found)}")
        for login, role in found.items():
            if _ROLE_RANK.get(role, -1) > _ROLE_RANK.get(source.get(login, ""), -1):
                source[login] = role

    if not source:
        print("panel_admins пуст или таблицы нет — переносить нечего.")
        return 0

    mod_db = MOD_DB
    store = ModerationStore(str(mod_db))
    await store.connect()
    try:
        existing = {u["login"]: u["role"] for u in await store.list_panel_users()}
        for login, role in sorted(source.items()):
            current = existing.get(login)
            if current is not None and _ROLE_RANK.get(current, -1) >= _ROLE_RANK.get(role, -1):
                print(f"  {login}: уже {current} в mod_panel_users — пропуск")
                continue
            action = "обновит" if current else "добавит"
            print(f"  {login}: {action} до {role}" + (f" (было {current})" if current else ""))
            if not args.dry_run:
                await store.upsert_panel_user(login, role)
    finally:
        await store.close()

    if args.dry_run:
        print("\n--dry-run: ничего не записано.")
    else:
        print(f"\nГотово. Список админов теперь один: {mod_db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
