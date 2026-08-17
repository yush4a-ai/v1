import time

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS viewers (
    username TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    note TEXT
);

CREATE TABLE IF NOT EXISTS recent_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Сообщения, поставленные оператором в панели (POST /api/chat_send,
-- panel/bots_api.py) для отправки от имени бота в конкретный канал.
-- sent_at IS NULL — ещё не обработано; main.py::_poll_panel_outbox
-- вычитывает раз в секунду и шлёт через тот же MessageQueue, которым
-- бот уже пользуется для DeepSeek-ответов.
CREATE TABLE IF NOT EXISTS panel_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_login TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at REAL NOT NULL,
    sent_at REAL
);

-- mod_inbox здесь больше не создаётся. Это была исходящая очередь чата
-- для отдельного процесса модерации: main.py писал сюда каждое сообщение
-- вместо прямого вызова ModerationEngine.observe(), а Cigilbot открывал
-- своё соединение к ЭТОМУ файлу и поллил её в фоне.
--
-- Движок модерации теперь живёт в процессе бота (см. cigilbot/pipeline.py),
-- и очередь стала очередью в памяти — таблица не нужна. В существующих
-- bot.db она остаётся лежать: SQLite её не удаляет, а дропать самим значило
-- бы уничтожить ещё не разобранные сообщения у того, кто обновился с
-- непустой очередью. Прочитать их всё равно больше некому, так что после
-- обновления таблицу можно дропнуть вручную.

-- panel_admins здесь больше не создаётся. ADMIN-оверрайды ролей панели
-- пережили полный круг: сначала общий список mod_panel_users на обе
-- панели, потом (когда панели разнесли по разным процессам) отдельный
-- panel_admins здесь и mod_panel_users в Cigilbot, теперь — снова один
-- список в mod_panel_users, потому что панель снова одна.
--
-- В уже существующих bot.db таблица остаётся лежать как есть: SQLite её
-- не удаляет, а удалять самим значило бы потерять данные у того, кто не
-- прогнал перенос. Разовый scripts/merge_panel_admins.py
-- переносит записи в mod_panel_users; после него таблица не читается
-- никем и её можно дропнуть вручную.
"""

# Сколько последних сообщений чата держим для контекста ответов бота
CONTEXT_WINDOW = 30


class Database:
    def __init__(self, path: str):
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        # Идемпотентно: event_ready (main.py) срабатывает у twitchio на
        # КАЖДЫЙ успешный (пере)коннект IRC, не только при старте процесса
        # — без этой проверки повторный вызов на реконнекте открывал новое
        # соединение, оставляя старое утечкой (bug-аудит 2026-08-15,
        # CRITICAL #3).
        if self._conn is not None:
            return
        self._conn = await aiosqlite.connect(self._path)
        # WAL заводился ради mod_inbox — второй процесс держал своё
        # соединение к этому же файлу. Такого процесса больше нет, но режим
        # оставлен: панель по-прежнему читает bot.db параллельно с ботом
        # (экран Viewers/Chat feed), и это ровно тот же сценарий.
        await self._conn.execute("PRAGMA journal_mode=WAL")
        # Без busy_timeout конкурентный писатель (панель пишет заметку о
        # зрителе/шлёт сообщение в чат, пока бот пишет свою запись) получает
        # немедленный sqlite3.OperationalError: database is locked вместо
        # короткого ожидания — тот же риск, что уже закрыт в
        # registry_store.py/fingerprints_store.py (bug-аудит 2026-08-15,
        # HIGH #6).
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        # Сбрасываем _conn, а не только закрываем соединение — иначе
        # идемпотентность connect() (см. её докстринг) превращается в
        # ловушку: connect() после close() видит _conn "не None" и молча
        # возвращается, ничего не открыв заново, хотя соединение уже
        # закрыто (bug-аудит 2026-08-15, HIGH #12).
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def touch_viewer(self, username: str) -> None:
        now = time.time()
        await self._conn.execute(
            """
            INSERT INTO viewers (username, first_seen, last_seen, message_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(username) DO UPDATE SET
                last_seen = excluded.last_seen,
                message_count = message_count + 1
            """,
            (username, now, now),
        )
        await self._conn.commit()

    async def get_viewer(self, username: str) -> aiosqlite.Row | None:
        self._conn.row_factory = aiosqlite.Row
        cursor = await self._conn.execute(
            "SELECT * FROM viewers WHERE username = ?", (username,)
        )
        return await cursor.fetchone()

    async def set_note(self, username: str, note: str) -> None:
        await self._conn.execute(
            "UPDATE viewers SET note = ? WHERE username = ?", (note, username)
        )
        await self._conn.commit()

    async def log_message(self, username: str, content: str) -> None:
        await self._conn.execute(
            "INSERT INTO recent_messages (username, content, created_at) VALUES (?, ?, ?)",
            (username, content, time.time()),
        )
        await self._conn.commit()

    async def get_recent_context(self, limit: int = CONTEXT_WINDOW) -> list[tuple[str, str]]:
        self._conn.row_factory = aiosqlite.Row
        cursor = await self._conn.execute(
            "SELECT username, content FROM recent_messages ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [(row["username"], row["content"]) for row in reversed(rows)]

    async def purge_old_messages(self, *, older_than_days: float) -> int:
        """Удаляет recent_messages старше older_than_days — bug-аудит
        2026-08-15, HIGH #16: таблица росла без ограничения. Возвращает
        число удалённых строк, для лога вызывающего кода."""
        cutoff = time.time() - older_than_days * 86400
        cursor = await self._conn.execute(
            "DELETE FROM recent_messages WHERE created_at < ?", (cutoff,)
        )
        await self._conn.commit()
        return cursor.rowcount

    async def pop_pending_panel_messages(self) -> list[tuple[int, str, str]]:
        """Сообщения из панели, ещё не отправленные в чат — вычитывается
        циклом main.py::_poll_panel_outbox. Не удаляет строки (в отличие
        от VoiceQueue.pop_all): sent_at остаётся аудитом того, что и когда
        реально ушло от имени бота."""
        self._conn.row_factory = aiosqlite.Row
        cursor = await self._conn.execute(
            "SELECT id, channel_login, text FROM panel_outbox WHERE sent_at IS NULL ORDER BY id"
        )
        rows = await cursor.fetchall()
        return [(row["id"], row["channel_login"], row["text"]) for row in rows]

    async def mark_panel_message_sent(self, message_id: int) -> None:
        await self._conn.execute(
            "UPDATE panel_outbox SET sent_at = ? WHERE id = ?", (time.time(), message_id)
        )
        await self._conn.commit()

    # enqueue_chat_event/prune_mod_inbox убраны вместе с самой очередью:
    # движок модерации переехал в этот же процесс и получает события
    # напрямую (см. cigilbot/pipeline.py::ModerationHub.submit).

    # ADMIN-оверрайды ролей панели читаются и пишутся через
    # ModerationStore (mod_panel_users) — get_panel_role/upsert_panel_admin/
    # list_panel_admins убраны отсюда вместе со слиянием панелей в один
    # процесс. Бот ролями панели не пользовался никогда: эти методы
    # существовали ради panel/server.py, которого больше нет.
