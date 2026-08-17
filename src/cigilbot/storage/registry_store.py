"""Доступ к Channel Registry (registry.db) — какие каналы известны Cigilbot.

Отдельный от ModerationStore класс: registry.db — control-plane файл на
ВСЕ каналы сразу, ModerationStore — per-channel данные модерации в
mod.<broadcaster_id>.db. Смешивать их в одном классе означало бы смешивать
два разных времени жизни (Registry живёт пока жив весь Cigilbot-инстанс,
ModerationStore — пока жив один канал).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import aiosqlite

from cigilbot.storage.registry_migrations import migrate


@dataclass(frozen=True, slots=True)
class ChannelRecord:
    id: int
    broadcaster_id: str
    login: str
    display_name: str | None
    status: str
    registered_by: str
    created_at: float
    updated_at: float
    desired_state: str
    process_status: str
    pid: int | None
    last_heartbeat_at: float | None
    last_exit_code: int | None
    restart_count: int


def _row_to_channel(row: aiosqlite.Row) -> ChannelRecord:
    return ChannelRecord(
        id=row["id"],
        broadcaster_id=row["broadcaster_id"],
        login=row["login"],
        display_name=row["display_name"],
        status=row["status"],
        registered_by=row["registered_by"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        desired_state=row["desired_state"],
        process_status=row["process_status"],
        pid=row["pid"],
        last_heartbeat_at=row["last_heartbeat_at"],
        last_exit_code=row["last_exit_code"],
        restart_count=row["restart_count"],
    )


class RegistryStore:
    def __init__(self, path: str):
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        # Без явного busy_timeout конкурентная запись (supervisor.py тик +
        # HTTP-хендлер в том же процессе, либо запись из twitch-bots в свой
        # registry.db одновременно) может сразу упасть с "database is
        # locked" вместо короткого ожидания снятия блокировки.
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await migrate(self._conn)

    async def close(self) -> None:
        # Сбрасываем _conn, а не только закрываем соединение — иначе
        # закрытая, но не обнулённая ссылка проходит мимо guard'а в
        # свойстве _db ("connect() ещё не вызван"), и следующий запрос
        # падает с невнятным исключением про закрытое соединение вместо
        # понятного RuntimeError (bug-аудит 2026-08-15, HIGH #12).
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def _db(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("RegistryStore.connect() ещё не вызван")
        return self._conn

    async def upsert_channel(
        self,
        *,
        broadcaster_id: str,
        login: str,
        display_name: str | None = None,
        registered_by: str = "sync",
    ) -> ChannelRecord:
        """Создать канал или обновить login/display_name существующего.

        Идемпотентно по broadcaster_id — безопасно вызывать повторно (нужно
        для ретраев POST /api/registry/channels, см. panel/registry_api.py).
        Не трогает desired_state/process_status у уже существующей записи —
        синхронизация состава каналов не должна случайно перезапускать/
        останавливать уже управляемый supervisor'ом процесс.
        """
        now = time.time()
        await self._db.execute(
            """
            INSERT INTO channels (broadcaster_id, login, display_name, registered_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(broadcaster_id) DO UPDATE SET
                login = excluded.login,
                display_name = excluded.display_name,
                updated_at = excluded.updated_at
            """,
            (broadcaster_id, login, display_name, registered_by, now, now),
        )
        await self._db.commit()
        return await self.get_channel(broadcaster_id)  # type: ignore[return-value]

    async def get_channel(self, broadcaster_id: str) -> ChannelRecord | None:
        cursor = await self._db.execute(
            "SELECT * FROM channels WHERE broadcaster_id = ?", (broadcaster_id,)
        )
        row = await cursor.fetchone()
        return _row_to_channel(row) if row else None

    async def list_channels(self, *, status: str | None = "active") -> list[ChannelRecord]:
        if status is None:
            cursor = await self._db.execute("SELECT * FROM channels ORDER BY login")
        else:
            cursor = await self._db.execute(
                "SELECT * FROM channels WHERE status = ? ORDER BY login", (status,)
            )
        rows = await cursor.fetchall()
        return [_row_to_channel(row) for row in rows]

    async def set_desired_state(self, broadcaster_id: str, desired_state: str) -> None:
        await self._db.execute(
            "UPDATE channels SET desired_state = ?, updated_at = ? WHERE broadcaster_id = ?",
            (desired_state, time.time(), broadcaster_id),
        )
        await self._db.commit()

    async def update_process_state(
        self,
        broadcaster_id: str,
        *,
        process_status: str,
        pid: int | None = None,
        last_exit_code: int | None = None,
        increment_restart_count: bool = False,
    ) -> None:
        """Пишет ТОЛЬКО supervisor.py — единственный писатель process_status.

        Панель/API никогда не вызывает этот метод напрямую (см. докстринг
        ChannelRecord.desired_state vs process_status в registry_migrations.py).
        """
        if increment_restart_count:
            await self._db.execute(
                """
                UPDATE channels
                SET process_status = ?, pid = ?, last_exit_code = ?,
                    last_heartbeat_at = ?, restart_count = restart_count + 1
                WHERE broadcaster_id = ?
                """,
                (process_status, pid, last_exit_code, time.time(), broadcaster_id),
            )
        else:
            await self._db.execute(
                """
                UPDATE channels
                SET process_status = ?, pid = ?, last_exit_code = ?, last_heartbeat_at = ?
                WHERE broadcaster_id = ?
                """,
                (process_status, pid, last_exit_code, time.time(), broadcaster_id),
            )
        await self._db.commit()

    async def reset_crash(self, broadcaster_id: str) -> None:
        await self._db.execute(
            "UPDATE channels SET restart_count = 0, process_status = 'stopped' WHERE broadcaster_id = ?",
            (broadcaster_id,),
        )
        await self._db.commit()
