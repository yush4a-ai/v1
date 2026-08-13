"""Версионированные миграции схемы Channel Registry (registry.db).

Отдельный файл БД от mod.<broadcaster_id>.db (см. cigilbot/migrations.py) — это
control-plane для ВСЕХ каналов сразу ("какие каналы вообще существуют, в
каком они статусе"), а не per-channel данные модерации одного канала.
Cigilbot и twitch-bots ведут каждый свой registry.db независимо (два
проекта, два процесса, никакого общего файла) — см. docs/master-plan.html,
направление 00. twitch-bots — источник правды по составу каналов,
Cigilbot синхронизируется через POST /api/registry/channels
(panel/registry_api.py).

Тот же паттерн версионирования, что cigilbot/migrations.py: PRAGMA
user_version, миграции применяются по порядку и только вперёд.
"""

from __future__ import annotations

import aiosqlite

# channels — какие каналы известны Cigilbot и в каком состоянии находится
# их consumer-процесс. broadcaster_id (не login!) — стабильный Twitch ID,
# не меняется при переименовании канала; login хранится только как кэш для
# отображения в панели. registered_by различает канал, пришедший через
# автосинхронизацию от twitch-bots ('sync'), от созданного вручную в
# Cigilbot до появления Registry ('manual') — полезно на время миграции с
# файловой модели .env.<profile> и для отладки рассинхрона между проектами.
#
# desired_state/process_status разделены по стандартному паттерну process
# supervisor'ов (аналогично systemd WantedBy/ActiveState): desired_state —
# что оператор ХОЧЕТ (жмёт Start/Stop в панели, пишется немедленно),
# process_status — что РЕАЛЬНО происходит (пишет только supervisor.py на
# каждом тике). Без разделения панель не могла бы отличить "ещё не успел
# стартовать" от "упал и не поднимается".
_MIGRATION_001_CHANNELS = """
CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    broadcaster_id TEXT NOT NULL UNIQUE,
    login TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    registered_by TEXT NOT NULL DEFAULT 'sync',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    desired_state TEXT NOT NULL DEFAULT 'stopped',
    process_status TEXT NOT NULL DEFAULT 'stopped',
    pid INTEGER,
    last_heartbeat_at REAL,
    last_exit_code INTEGER,
    restart_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_channels_status ON channels(status);
"""

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, _MIGRATION_001_CHANNELS),
)


async def current_version(conn: aiosqlite.Connection) -> int:
    cursor = await conn.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    return int(row[0]) if row else 0


async def migrate(conn: aiosqlite.Connection) -> int:
    """Применить все миграции новее текущей версии БД.

    Идемпотентно — см. докстринг cigilbot/migrations.py::migrate() для
    полного обоснования, тот же принцип здесь без изменений.
    """
    current = await current_version(conn)

    for version, sql in MIGRATIONS:
        if version <= current:
            continue
        await conn.executescript(sql)
        await conn.execute(f"PRAGMA user_version = {version}")
        current = version

    await conn.commit()
    return current
