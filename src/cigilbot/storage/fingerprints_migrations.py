"""Версионированные миграции схемы Cross-Channel Bot Fingerprint (fingerprints.db).

Отдельный файл от mod.<broadcaster_id>.db и registry.db (направление 03
master-plan.html): known_bad_actors — не per-channel данные модерации
(mod.<id>.db) и не список каналов (registry.db), а факты об аккаунтах,
общие для всех каналов оператора. Смешивать с registry.db значило бы
смешивать "какие каналы существуют" с "кто на них забанен" — два разных
владельца данных, которые уже развели по разным файлам однажды при
переходе на Channel Registry.

Тот же паттерн версионирования, что cigilbot/migrations.py и
registry_migrations.py: PRAGMA user_version, миграции только вперёд.
"""

from __future__ import annotations

import aiosqlite

# banned_on_broadcaster_id/banned_on_login — канал, где случился BAN,
# нужен как контекст в evidence сигнала на другом канале ("забанен на
# dobriy_yura"), не только для дедупликации. user_id — PRIMARY KEY: пишем
# только BAN (см. executor.py), повторный BAN того же аккаунта на другом
# канале обновляет запись через ON CONFLICT, не добавляет вторую строку.
_MIGRATION_001_KNOWN_BAD_ACTORS = """
CREATE TABLE IF NOT EXISTS known_bad_actors (
    user_id TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    banned_on_broadcaster_id TEXT NOT NULL,
    banned_on_login TEXT NOT NULL,
    banned_at REAL NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
"""

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, _MIGRATION_001_KNOWN_BAD_ACTORS),
)


async def current_version(conn: aiosqlite.Connection) -> int:
    cursor = await conn.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    return int(row[0]) if row else 0


async def migrate(conn: aiosqlite.Connection) -> int:
    current = await current_version(conn)

    for version, sql in MIGRATIONS:
        if version <= current:
            continue
        await conn.executescript(sql)
        await conn.execute(f"PRAGMA user_version = {version}")
        current = version

    await conn.commit()
    return current
