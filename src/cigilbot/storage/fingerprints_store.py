"""Доступ к fingerprints.db — известные боты, забаненные хотя бы на одном
канале оператора (направление 03 master-plan.html: Cross-Channel Bot
Fingerprint).

Отдельный от RegistryStore и ModerationStore класс — см. докстринг
fingerprints_migrations.py про то, почему это не таблица в одном из них.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import aiosqlite

from cigilbot.storage.fingerprints_migrations import migrate


@dataclass(frozen=True, slots=True)
class KnownBadActor:
    user_id: str
    login: str
    banned_on_broadcaster_id: str
    banned_on_login: str
    banned_at: float
    reason: str


def _row_to_actor(row: aiosqlite.Row) -> KnownBadActor:
    return KnownBadActor(
        user_id=row["user_id"],
        login=row["login"],
        banned_on_broadcaster_id=row["banned_on_broadcaster_id"],
        banned_on_login=row["banned_on_login"],
        banned_at=row["banned_at"],
        reason=row["reason"],
    )


class FingerprintStore:
    def __init__(self, path: str):
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        # Пишут все каналы оператора параллельно (BAN на канале A и BAN на
        # канале B в одну секунду — не редкость при синхронной атаке ботнета
        # на несколько каналов сразу), читает раз в тик ModerationHub.
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
            raise RuntimeError("FingerprintStore.connect() ещё не вызван")
        return self._conn

    async def record_ban(
        self,
        *,
        user_id: str,
        login: str,
        banned_on_broadcaster_id: str,
        banned_on_login: str,
        reason: str = "",
        banned_at: float | None = None,
    ) -> None:
        """Вызывается executor.py после успешного BAN. Повторный BAN того
        же user_id (на этом же или другом канале) обновляет запись — нам
        важен факт "забанен хоть где-то", не история всех банов подряд
        (та уже есть per-channel в mod_actions)."""
        await self._db.execute(
            """
            INSERT INTO known_bad_actors
                (user_id, login, banned_on_broadcaster_id, banned_on_login, banned_at, reason)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                login = excluded.login,
                banned_on_broadcaster_id = excluded.banned_on_broadcaster_id,
                banned_on_login = excluded.banned_on_login,
                banned_at = excluded.banned_at,
                reason = excluded.reason
            """,
            (
                user_id,
                login,
                banned_on_broadcaster_id,
                banned_on_login,
                banned_at if banned_at is not None else time.time(),
                reason,
            ),
        )
        await self._db.commit()

    async def get(self, user_id: str) -> KnownBadActor | None:
        cursor = await self._db.execute(
            "SELECT * FROM known_bad_actors WHERE user_id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        return _row_to_actor(row) if row else None

    async def list_all(self) -> list[KnownBadActor]:
        """Снимок всей таблицы — ModerationHub перечитывает её целиком
        раз в тик и раздаёт всем движкам (см. pipeline.py), а не запрашивает
        по одному user_id на каждое сообщение чата."""
        cursor = await self._db.execute("SELECT * FROM known_bad_actors")
        rows = await cursor.fetchall()
        return [_row_to_actor(row) for row in rows]
