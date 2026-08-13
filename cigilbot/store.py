"""Персистентность движка модерации: пользователи, сообщения, вердикты, кластеры.

ModerationStore живёт в собственном файле БД Cigilbot (mod.<broadcaster_id>.db,
см. panel/moderation_api.py::_db_path), физически отдельном от
bot.<instance>.db в twitch-bots. Единственная точка, где Cigilbot касается
чужого файла БД — cigilbot/inbox.py (входящая очередь чата от main.py),
всё остальное здесь работает только с таблицами mod_* этого файла (см.
cigilbot/migrations.py).

engine.py (этап 5) читает отсюда UserState перед оценкой сообщения и
пишет сюда каждый вердикт — это единственный способ, которым модерация
"помнит" пользователя между перезапусками (SlidingWindow в памяти такой
памяти не даёт, она сбрасывается при рестарте).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import aiosqlite

from cigilbot.content.detector import ContentRule
from cigilbot.migrations import migrate
from cigilbot.normalize import MessageFingerprint, minhash, similarity
from cigilbot.patterns import Pattern
from cigilbot.types import ChatEvent, ClusterInfo, ContentCategory, TrustLevel, UserState, Verdict


@dataclass(frozen=True, slots=True)
class PatternInput:
    """Поля, которые задаёт создатель паттерна (панель/миграция вручную) —
    без id/created_at, которые генерирует store.py."""

    name: str
    description: str
    required_signal_names: tuple[str, ...]
    min_families: int
    min_risk_score: int
    min_confidence: float
    min_cluster_size: int
    enabled: bool
    auto_enabled: bool
    weight: float
    created_by: str


def _row_to_pattern(row: aiosqlite.Row) -> Pattern:
    return Pattern(
        id=row["id"],
        name=row["name"],
        description=row["description"] or "",
        required_signal_names=tuple(json.loads(row["required_signal_names"])),
        min_families=row["min_families"],
        min_risk_score=row["min_risk_score"],
        min_confidence=row["min_confidence"],
        min_cluster_size=row["min_cluster_size"],
        enabled=bool(row["enabled"]),
        auto_enabled=bool(row["auto_enabled"]),
        weight=row["weight"],
        created_by=row["created_by"],
        created_at=row["created_at"],
    )


@dataclass(frozen=True, slots=True)
class AttackModeStatus:
    """Активный Attack Mode на канале (этап 9c) — None означает "не
    активирован или уже истёк", см. store.get_active_attack_mode()."""

    activated_by: str
    activated_at: float
    expires_at: float

    def to_dict(self) -> dict[str, object]:
        return {
            "activated_by": self.activated_by,
            "activated_at": self.activated_at,
            "expires_at": self.expires_at,
            "seconds_remaining": max(0.0, self.expires_at - time.time()),
        }


@dataclass(frozen=True, slots=True)
class GiveawayModeStatus:
    """Активный Giveaway Mode на канале (FALSE-BAN-001 аудита) — тот же
    singleton-паттерн, что AttackModeStatus, но противоположный по смыслу:
    Attack Mode ПОВЫШАЕТ чувствительность, Giveaway Mode её СНИЖАЕТ
    (ChannelContext.is_giveaway -> confidence.py context_factor)."""

    activated_by: str
    activated_at: float
    expires_at: float

    def to_dict(self) -> dict[str, object]:
        return {
            "activated_by": self.activated_by,
            "activated_at": self.activated_at,
            "expires_at": self.expires_at,
            "seconds_remaining": max(0.0, self.expires_at - time.time()),
        }


@dataclass(frozen=True, slots=True)
class ContentSettings:
    """Выключатель словарного детектора (Rule Engine) — singleton-паттерн,
    как AttackModeStatus. enabled=False по умолчанию (см. миграцию 014):
    без явного включения через панель content-детектор работает только в
    режиме наблюдателя — см. content/policy.py::decide_content()."""

    enabled: bool
    updated_by: str
    updated_at: float

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class DiscordWebhookConfig:
    """Discord-webhook канала (направление 01 master-plan.html) — тот же
    singleton-паттерн, что AttackModeStatus: одна строка на БД, одна БД на
    канал. enabled отделён от url, чтобы модератор мог временно выключить
    алерты, не стирая и не вводя заново сам адрес. last_digest_sent_at и
    last_escalation_sent_at — None, пока соответствующий алерт ни разу не
    уходил на этот webhook. alert_confidence_threshold — porog per-channel
    (не жёсткая константа в engine.py): разным каналам подходит разная
    граница "достаточно уверены, чтобы отвлекать модератора"."""

    url: str
    enabled: bool
    updated_by: str
    updated_at: float
    last_digest_sent_at: float | None = None
    last_escalation_sent_at: float | None = None
    alert_confidence_threshold: float = 0.9

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "enabled": self.enabled,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
            "alert_confidence_threshold": self.alert_confidence_threshold,
        }


@dataclass(frozen=True, slots=True)
class DigestStats:
    """Сводка активности канала за период (направление 01 master-plan.html:
    ежедневный digest). Считается напрямую по mod_messages/mod_verdicts/
    mod_clusters за период — НЕ по mod_stats_daily: те счётчики
    (increment_daily_stats) сейчас нигде не вызываются из реального кода
    движка, только из тестов, так что таблица в проде всегда пустая."""

    total_messages: int
    suspicious_verdicts: int
    would_timeout: int
    would_ban: int
    new_clusters: int

    def to_dict(self) -> dict[str, object]:
        return {
            "total_messages": self.total_messages,
            "suspicious_verdicts": self.suspicious_verdicts,
            "would_timeout": self.would_timeout,
            "would_ban": self.would_ban,
            "new_clusters": self.new_clusters,
        }


@dataclass(frozen=True, slots=True)
class ModeratorActionSummary:
    """Одна строка рейтинга модераторов — сколько действий каждого типа
    выполнил конкретный actor за период."""

    actor: str
    timeouts: int
    bans: int
    deletes: int

    @property
    def total(self) -> int:
        return self.timeouts + self.bans + self.deletes


@dataclass(frozen=True, slots=True)
class RecentModeratorAction:
    """Одна строка из "последние действия" в сводке — кто/что/кого."""

    created_at: float
    actor: str
    action: str
    scope: str
    succeeded: int
    failed: int


@dataclass(frozen=True, slots=True)
class ModeratorActivityStats:
    """Сводка по работе модераторов за период (пользователь 2026-08-13:
    "можем сводку отправлять в дискорд по работе модераторов на канале?") —
    отдельно от DigestStats: та описывает, что НАШЁЛ бот, эта — что СДЕЛАЛИ
    люди руками. Источник — mod_actions, единственная таблица, куда
    executor.py и ручные действия из панели пишут аудит (record_action_audit)."""

    total_timeouts: int
    total_bans: int
    total_deletes: int
    by_moderator: tuple[ModeratorActionSummary, ...]
    recent: tuple[RecentModeratorAction, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "total_timeouts": self.total_timeouts,
            "total_bans": self.total_bans,
            "total_deletes": self.total_deletes,
            "by_moderator": [
                {"actor": m.actor, "timeouts": m.timeouts, "bans": m.bans,
                 "deletes": m.deletes, "total": m.total}
                for m in self.by_moderator
            ],
            "recent": [
                {"created_at": r.created_at, "actor": r.actor, "action": r.action,
                 "scope": r.scope, "succeeded": r.succeeded, "failed": r.failed}
                for r in self.recent
            ],
        }


@dataclass(frozen=True, slots=True)
class QueueItem:
    """Одно задание из mod_action_queue, разобранное из строки БД.

    payload остаётся сырым dict — его валидирует и типизирует
    executor.parse_payload(), store.py не знает о вокабуляре действий
    (BAN/TIMEOUT/DELETE_MESSAGES), это забота слоя executor.
    """

    id: int
    requested_by: str
    requested_role: str
    payload: dict[str, Any]


class ModerationStore:
    def __init__(self, path: str):
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        # WAL вместо стандартного rollback-журнала: коммит не переписывает
        # весь журнал целиком, а дописывает в конец — заметно дешевле при
        # частых мелких записях (вердикт на каждое сообщение чата).
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await migrate(self._conn)

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()

    @property
    def _db(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("ModerationStore.connect() ещё не вызван")
        return self._conn

    # -- пользователи ---------------------------------------------------

    async def upsert_user(self, event: ChatEvent) -> None:
        await self._db.execute(
            """
            INSERT INTO mod_users (user_id, login, display_name, first_seen, last_seen, message_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(user_id) DO UPDATE SET
                login = excluded.login,
                display_name = excluded.display_name,
                last_seen = excluded.last_seen,
                message_count = message_count + 1
            """,
            (event.user_id, event.login, event.display_name or None, event.timestamp, event.timestamp),
        )
        await self._db.commit()

    async def set_account_created_at(self, user_id: str, created_at: float) -> None:
        """Вызывается, когда Helix ответил на запрос возраста аккаунта —
        обычно уже ПОСЛЕ первого вердикта (см. Verdict.is_provisional)."""
        await self._db.execute(
            "UPDATE mod_users SET account_created_at = ? WHERE user_id = ?",
            (created_at, user_id),
        )
        await self._db.commit()

    async def increment_prior_timeouts(self, user_id: str) -> int:
        """Увеличить mod_users.prior_timeouts и вернуть новое значение.
        Вызывается executor.py после успешного Helix-запроса, не раньше —
        неудавшийся таймаут не должен эскалировать следующий. Поле в схеме
        с самого начала (migrations.py), но без писателя нигде в коде до
        направления 03 master-plan.html ("Прогрессивные таймауты")."""
        await self._db.execute(
            "UPDATE mod_users SET prior_timeouts = prior_timeouts + 1 WHERE user_id = ?",
            (user_id,),
        )
        await self._db.commit()
        cursor = await self._db.execute(
            "SELECT prior_timeouts FROM mod_users WHERE user_id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def get_user_state(self, user_id: str) -> UserState | None:
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute("SELECT * FROM mod_users WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return UserState(
            user_id=row["user_id"],
            login=row["login"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            message_count=row["message_count"],
            trust_level=TrustLevel(row["trust_level"]),
            account_created_at=row["account_created_at"],
            prior_timeouts=row["prior_timeouts"],
            prior_warnings=row["prior_warnings"],
            marked_safe=bool(row["marked_safe"]),
        )

    async def list_users(
        self, *, search: str = "", limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Список зрителей для экрана Users панели — самые активные
        (по message_count) первыми, т.к. это самый частый порядок, в
        котором модератор ищет "кто это вообще такой". search фильтрует по
        подстроке login (без учёта регистра) — точечный поиск конкретного
        зрителя, не полнотекстовый индекс, канал не настолько велик, чтобы
        LIKE по индексированному login был узким местом."""
        self._db.row_factory = aiosqlite.Row
        if search:
            cursor = await self._db.execute(
                """
                SELECT user_id, login, display_name, account_created_at, first_seen,
                       last_seen, message_count, trust_level, prior_timeouts,
                       prior_warnings, marked_safe, marked_safe_at, marked_safe_by, note
                FROM mod_users
                WHERE login LIKE ?
                ORDER BY message_count DESC
                LIMIT ? OFFSET ?
                """,
                (f"%{search.lower()}%", limit, offset),
            )
        else:
            cursor = await self._db.execute(
                """
                SELECT user_id, login, display_name, account_created_at, first_seen,
                       last_seen, message_count, trust_level, prior_timeouts,
                       prior_warnings, marked_safe, marked_safe_at, marked_safe_by, note
                FROM mod_users
                ORDER BY message_count DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
        rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            row["trust_level"] = TrustLevel(row["trust_level"]).name
            row["marked_safe"] = bool(row["marked_safe"])
        return rows

    # -- сообщения --------------------------------------------------------

    async def save_message(self, event: ChatEvent, fp: MessageFingerprint) -> int:
        cursor = await self._db.execute(
            """
            INSERT INTO mod_messages
                (user_id, login, text, normalized, skeleton, created_at,
                 is_first_message, is_subscriber, is_moderator, is_vip, domains,
                 twitch_message_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.user_id, event.login, event.text, fp.normalized, fp.skeleton,
                event.timestamp, int(event.is_first_message), int(event.is_subscriber),
                int(event.is_moderator), int(event.is_vip),
                json.dumps(list(fp.domains)) if fp.domains else None,
                event.message_id or None,
            ),
        )
        await self._db.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_messages не вернул id")
        return cursor.lastrowid

    # -- вердикты ------------------------------------------------------

    async def save_verdict(self, verdict: Verdict, *, message_id: int | None = None) -> int:
        cursor = await self._db.execute(
            """
            INSERT INTO mod_verdicts
                (created_at, user_id, login, message_id, risk_score, confidence,
                 families_triggered, recommended_action, reason, cluster_id,
                 is_provisional, blocked_by, mode, engine_version, config_version, pattern_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verdict.timestamp, verdict.user_id, verdict.login, message_id,
                verdict.risk_score, verdict.confidence, verdict.families_triggered,
                verdict.recommended_action.value, verdict.reason, verdict.cluster_id,
                int(verdict.is_provisional), verdict.blocked_by or None,
                verdict.mode.value, verdict.engine_version or None,
                verdict.config_version or None, verdict.pattern_id,
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_verdicts не вернул id")
        verdict_id = cursor.lastrowid

        if verdict.signals:
            await self._db.executemany(
                """
                INSERT INTO mod_signals (verdict_id, name, family, weight, value, evidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (verdict_id, s.name, s.family.value, s.weight, s.value, s.evidence)
                    for s in verdict.signals
                ],
            )

        await self._db.commit()
        return verdict_id

    # -- кластеры --------------------------------------------------------

    async def save_cluster(self, cluster: ClusterInfo) -> int:
        """Всегда INSERT новой строки — низкоуровневый примитив.

        НЕ вызывается напрямую из engine.py (см. upsert_cluster_by_members
        ниже) — clustering.find_clusters() пересчитывает состав кластера
        заново на КАЖДОЕ сообщение окна и выдаёт локальный cluster_id,
        стартующий с 1 при каждом вызове (см. докстринг clustering.py). Без
        upsert-обёртки один растущий рой из 20 ботов, пишущих по одному
        сообщению, создавал бы до 20 разных строк mod_clusters — разных
        частичных снимков ОДНОГО инцидента, все разом в status='active'
        (BUG-002 аудита). Оставлен как примитив для тестов и для
        replay.py/report.py, где стабильность между вызовами не нужна.
        """
        cursor = await self._db.execute(
            """
            INSERT INTO mod_clusters
                (created_at, size, risk_score, confidence, similarity_score,
                 arrival_window_sec, first_message_ratio, new_account_ratio, shared_domains,
                 pattern_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cluster.created_at, cluster.size, cluster.risk_score, cluster.confidence,
                cluster.similarity_score, cluster.arrival_window_sec,
                cluster.first_message_ratio, cluster.new_account_ratio,
                json.dumps(list(cluster.shared_domains)) if cluster.shared_domains else None,
                cluster.pattern_id,
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_clusters не вернул id")
        cluster_id = cursor.lastrowid

        await self._db.executemany(
            """
            INSERT OR IGNORE INTO mod_cluster_members (cluster_id, user_id, login, joined_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                (cluster_id, uid, login, cluster.created_at)
                for uid, login in zip(cluster.user_ids, cluster.logins, strict=True)
            ],
        )
        await self._db.commit()
        return cluster_id

    async def upsert_cluster_by_members(self, cluster: ClusterInfo) -> int:
        """То, что реально должен вызывать engine.py на каждый observe().

        Ищет уже существующий АКТИВНЫЙ кластер, чьи участники (mod_cluster_members)
        пересекаются хотя бы одним user_id с новым набором — если находит,
        обновляет метрики этой же строки и добавляет только новых участников
        (INSERT OR IGNORE), не создавая вторую запись. Если пересечения нет
        (новый, не связанный ни с чем инцидент) — создаёт новую строку через
        save_cluster(), как раньше.

        Пересечение по ЛЮБОМУ общему участнику, а не по точному совпадению
        множества — union-find в clustering.py гарантирует, что если у двух
        последовательных вызовов общий участник, то это один и тот же
        реальный компонент связности (или его надмножество/подмножество за
        счёт вытеснения старых сообщений из окна), а не случайное совпадение:
        рёбра между сообщениями требуют реального сходства контента/домена/
        структуры, не одной лишь синхронности по времени.

        Для различения "новый инцидент vs рост уже известного" (нужно
        Discord-алерту — направление 01 master-plan.html: триггер только на
        новый активный кластер, не на каждое обновление) есть
        upsert_cluster_by_members_ex(), которая возвращает ту же пару
        значений явно. Эта функция возвращает только id — существующие
        вызывающие места (engine.py, тесты) не переписаны под кортеж, чтобы
        не трогать их без необходимости.
        """
        cluster_id, _is_new = await self.upsert_cluster_by_members_ex(cluster)
        return cluster_id

    async def upsert_cluster_by_members_ex(self, cluster: ClusterInfo) -> tuple[int, bool]:
        """upsert_cluster_by_members(), но возвращает (cluster_id, is_new)."""
        placeholders = ",".join("?" for _ in cluster.user_ids)
        cursor = await self._db.execute(
            f"""
            SELECT DISTINCT cluster_id FROM mod_cluster_members
            WHERE user_id IN ({placeholders})
              AND cluster_id IN (SELECT id FROM mod_clusters WHERE status = 'active')
            ORDER BY cluster_id
            LIMIT 1
            """,
            cluster.user_ids,
        )
        row = await cursor.fetchone()

        if row is None:
            new_id = await self.save_cluster(cluster)
            return new_id, True

        existing_id = int(row[0])
        await self._db.execute(
            """
            UPDATE mod_clusters
            SET size = ?, risk_score = ?, confidence = ?, similarity_score = ?,
                arrival_window_sec = ?, first_message_ratio = ?, new_account_ratio = ?,
                shared_domains = ?, pattern_id = ?
            WHERE id = ?
            """,
            (
                cluster.size, cluster.risk_score, cluster.confidence, cluster.similarity_score,
                cluster.arrival_window_sec, cluster.first_message_ratio, cluster.new_account_ratio,
                json.dumps(list(cluster.shared_domains)) if cluster.shared_domains else None,
                cluster.pattern_id, existing_id,
            ),
        )
        await self._db.executemany(
            """
            INSERT OR IGNORE INTO mod_cluster_members (cluster_id, user_id, login, joined_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                (existing_id, uid, login, cluster.created_at)
                for uid, login in zip(cluster.user_ids, cluster.logins, strict=True)
            ],
        )
        await self._db.commit()
        return existing_id, False

    async def get_cluster_member_ids(self, cluster_id: int) -> list[str]:
        """Актуальный состав кластера ПРЯМО СЕЙЧАС, из mod_cluster_members —
        источник правды для валидации BAN ALL/TIMEOUT ALL (BUG-001 аудита),
        а не то, что клиент прислал в запросе. Кластер может расти между
        тем, как модератор открыл панель, и тем, как нажал подтверждение —
        эта функция всегда отвечает на вопрос "кто в кластере #N сейчас"."""
        cursor = await self._db.execute(
            "SELECT user_id FROM mod_cluster_members WHERE cluster_id = ?", (cluster_id,)
        )
        return [row[0] for row in await cursor.fetchall()]

    # -- очередь действий (панель/автоправило -> бот, этап 7) -------------

    async def enqueue_action(
        self, *, requested_by: str, requested_role: str, payload: dict[str, Any]
    ) -> int:
        cursor = await self._db.execute(
            """
            INSERT INTO mod_action_queue (created_at, requested_by, requested_role, payload_json, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (time.time(), requested_by, requested_role, json.dumps(payload)),
        )
        await self._db.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_action_queue не вернул id")
        return cursor.lastrowid

    async def get_pending_actions(self, *, limit: int = 10) -> list[QueueItem]:
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            "SELECT id, requested_by, requested_role, payload_json FROM mod_action_queue "
            "WHERE status = 'pending' ORDER BY id LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [
            QueueItem(
                id=row["id"],
                requested_by=row["requested_by"],
                requested_role=row["requested_role"],
                payload=json.loads(row["payload_json"]),
            )
            for row in rows
        ]

    async def mark_action_started(self, queue_id: int) -> None:
        await self._db.execute(
            "UPDATE mod_action_queue SET status = 'running', started_at = ? WHERE id = ?",
            (time.time(), queue_id),
        )
        await self._db.commit()

    async def reclaim_stuck_actions(self, *, timeout_seconds: float) -> int:
        """BUG-003 аудита: если бот падает/перезапускается между
        mark_action_started() и complete_action() (например, посреди
        батча банов кластера в 40 человек), задание навсегда застревает в
        status='running' — get_pending_actions() смотрит только на
        'pending' и никогда больше его не увидит, прогресс "12/40" остаётся
        висеть без объяснений.

        Возвращает такие задания обратно в 'pending', если с started_at
        прошло больше timeout_seconds — process_pending() подхватит их на
        следующем цикле и попробует снова. Безопасно с точки зрения
        повторного исполнения: ban_user()/timeout_user() в Twitch Helix
        идемпотентны (повторный бан уже забаненного просто не меняет
        состояние или возвращает ту же ошибку, не банит "дважды сильнее") —
        см. cigilbot/twitch_api.py. Возвращает число реклеймленных
        заданий (для логирования вызывающим кодом)."""
        cutoff = time.time() - timeout_seconds
        cursor = await self._db.execute(
            "UPDATE mod_action_queue SET status = 'pending', started_at = NULL "
            "WHERE status = 'running' AND started_at IS NOT NULL AND started_at < ?",
            (cutoff,),
        )
        await self._db.commit()
        return cursor.rowcount if cursor.rowcount is not None and cursor.rowcount > 0 else 0

    async def update_action_progress(self, queue_id: int, done: int, total: int) -> None:
        await self._db.execute(
            "UPDATE mod_action_queue SET progress_done = ?, progress_total = ? WHERE id = ?",
            (done, total, queue_id),
        )
        await self._db.commit()

    async def complete_action(
        self, queue_id: int, *, status: str, result: dict[str, Any]
    ) -> None:
        await self._db.execute(
            "UPDATE mod_action_queue SET status = ?, finished_at = ?, result_json = ? WHERE id = ?",
            (status, time.time(), json.dumps(result), queue_id),
        )
        await self._db.commit()

    # -- чтение для панели (этап 8) ---------------------------------------

    async def get_active_clusters(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """Активные кластеры для главного экрана панели, отсортированы по
        риску. `status='active'` — кластеры, по которым ещё не нажимали
        действие и не помечали safe/ignore (см. mod_clusters.status)."""
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            """
            SELECT id, created_at, size, risk_score, confidence, similarity_score,
                   arrival_window_sec, first_message_ratio, new_account_ratio,
                   shared_domains, status, pattern_id
            FROM mod_clusters
            WHERE status = 'active'
            ORDER BY risk_score DESC, created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        clusters = [dict(row) for row in await cursor.fetchall()]

        for cluster in clusters:
            cluster["shared_domains"] = (
                json.loads(cluster["shared_domains"]) if cluster["shared_domains"] else []
            )
            members_cursor = await self._db.execute(
                "SELECT user_id, login FROM mod_cluster_members WHERE cluster_id = ?",
                (cluster["id"],),
            )
            members = await members_cursor.fetchall()
            cluster["user_ids"] = [m["user_id"] for m in members]
            cluster["logins"] = [m["login"] for m in members]

        return clusters

    async def set_cluster_status(self, cluster_id: int, status: str) -> None:
        await self._db.execute(
            "UPDATE mod_clusters SET status = ?, closed_at = ? WHERE id = ?",
            (status, time.time(), cluster_id),
        )
        await self._db.commit()

    async def get_recent_verdicts(
        self, *, min_risk_level: int = 30, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Лента подозрительных вердиктов для экрана Live — не всё подряд
        (каждое сообщение чата даёт вердикт), а только risk_score выше
        порога, иначе лента захлёстывает обычной перепиской."""
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            """
            SELECT v.id, v.created_at, v.user_id, v.login, v.risk_score, v.confidence,
                   v.families_triggered, v.recommended_action, v.reason, v.cluster_id,
                   v.is_provisional, v.blocked_by, v.mode, v.pattern_id, m.text AS message_text
            FROM mod_verdicts v
            LEFT JOIN mod_messages m ON m.id = v.message_id
            WHERE v.risk_score >= ?
            ORDER BY v.created_at DESC
            LIMIT ?
            """,
            (min_risk_level, limit),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        if not rows:
            return rows

        ids = [row["id"] for row in rows]
        placeholders = ",".join("?" for _ in ids)
        sig_cursor = await self._db.execute(
            f"SELECT verdict_id, name, evidence FROM mod_signals WHERE verdict_id IN ({placeholders})",
            ids,
        )
        signals_by_verdict: dict[int, list[str]] = {}
        evidence_by_verdict: dict[int, list[str]] = {}
        for sig_row in await sig_cursor.fetchall():
            signals_by_verdict.setdefault(sig_row["verdict_id"], []).append(sig_row["name"])
            # evidence — конкретный наблюдаемый факт за сигналом (см.
            # types.py::Signal docstring), не только его условное имя —
            # без этого "почему сработало" читалось только из английского
            # идентификатора вроде synchronized_arrival (#2611, третий заход).
            evidence_by_verdict.setdefault(sig_row["verdict_id"], []).append(sig_row["evidence"])
        for row in rows:
            row["signal_names"] = signals_by_verdict.get(row["id"], [])
            row["signal_evidence"] = evidence_by_verdict.get(row["id"], [])
        return rows

    async def get_action_audit(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Журнал 'кто нажал что и по какому правилу' для экрана Audit."""
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            """
            SELECT id, created_at, actor, actor_role, action, scope, cluster_id,
                   pattern_id, reason, confirmation, succeeded, failed, details_json
            FROM mod_actions
            -- см. get_signal_fp_penalty: равный created_at у записей одного
            -- тика часов делает порядок без id DESC недетерминированным
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            row["details"] = json.loads(row.pop("details_json")) if row["details_json"] else {}
        return rows

    # -- роли доступа к панели (этап 8) ------------------------------------

    async def get_panel_role(self, login: str) -> str | None:
        cursor = await self._db.execute(
            "SELECT role FROM mod_panel_users WHERE login = ?", (login.lower(),)
        )
        row = await cursor.fetchone()
        return row[0] if row else None

    async def upsert_panel_user(self, login: str, role: str) -> None:
        await self._db.execute(
            """
            INSERT INTO mod_panel_users (login, role, created_at, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(login) DO UPDATE SET role = excluded.role, last_seen = excluded.last_seen
            """,
            (login.lower(), role, time.time(), time.time()),
        )
        await self._db.commit()

    async def list_panel_users(self) -> list[dict[str, Any]]:
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            "SELECT login, role, created_at, last_seen FROM mod_panel_users ORDER BY login"
        )
        return [dict(row) for row in await cursor.fetchall()]

    # -- доверенные пользователи (этап 9a, ручной MARK SAFE) ---------------

    async def mark_trusted(self, user_id: str, *, added_by: str, reason: str = "") -> None:
        """Помечает пользователя доверенным: пишет запись в mod_trusted (для
        аудита "кто и когда") и одновременно marked_safe=1 в mod_users —
        именно последнее поле читает store.get_user_state() и превращает в
        UserState.marked_safe, на которое смотрит policy.is_protected.

        SEC-005 аудита: раньше этот докстринг ЗАЯВЛЯЛ "панель всегда
        работает со списком реально видимых пользователей", но код это не
        проверял — INSERT в mod_trusted проходил для любого user_id, даже
        никогда не появлявшегося в чате этого канала (Twitch user_id
        глобален, не привязан к каналу). Практический риск невысок (нужна
        уже авторизованная роль MODERATOR+), но раз докстринг обещает
        инвариант — теперь он проверяется явно, а не держится на честном
        слове вызывающего кода."""
        exists = await self.get_user_state(user_id)
        if exists is None:
            raise ValueError(
                f"user_id={user_id!r} не найден в mod_users этого канала — "
                "нельзя пометить доверенным пользователя, которого система ни разу не видела"
            )

        now = time.time()
        await self._db.execute(
            """
            INSERT INTO mod_trusted (user_id, added_by, added_at, reason)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                added_by = excluded.added_by, added_at = excluded.added_at, reason = excluded.reason
            """,
            (user_id, added_by, now, reason),
        )
        await self._db.execute(
            """
            UPDATE mod_users
            SET marked_safe = 1, marked_safe_at = ?, marked_safe_by = ?
            WHERE user_id = ?
            """,
            (now, added_by, user_id),
        )
        await self._db.commit()

    async def unmark_trusted(self, user_id: str) -> None:
        await self._db.execute("DELETE FROM mod_trusted WHERE user_id = ?", (user_id,))
        await self._db.execute(
            """
            UPDATE mod_users
            SET marked_safe = 0, marked_safe_at = NULL, marked_safe_by = NULL
            WHERE user_id = ?
            """,
            (user_id,),
        )
        await self._db.commit()

    async def is_trusted(self, user_id: str) -> bool:
        cursor = await self._db.execute(
            "SELECT 1 FROM mod_trusted WHERE user_id = ?", (user_id,)
        )
        return await cursor.fetchone() is not None

    async def list_trusted(self) -> list[dict[str, Any]]:
        """login/message_count — из mod_users, для экрана "Доверенные
        зрители" (направление 04 master-plan.html): без них панель не
        может показать ник и историю активности, только голый user_id."""
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            # rowid, а не id: у mod_trusted первичный ключ — user_id (TEXT),
            # отдельной колонки id нет, но неявный rowid растёт по порядку
            # вставки и годится как разрыв ничьей. Ничья здесь обычная:
            # added_at приходит из time.time(), см. get_signal_fp_penalty.
            """
            SELECT t.user_id, t.added_by, t.added_at, t.reason,
                   u.login, u.message_count
            FROM mod_trusted t
            LEFT JOIN mod_users u ON u.user_id = t.user_id
            ORDER BY t.added_at DESC, t.rowid DESC
            """
        )
        return [dict(row) for row in await cursor.fetchall()]

    # -- Bot Pattern Library (этап 9b) --------------------------------------

    async def create_pattern(self, pattern: PatternInput) -> int:
        cursor = await self._db.execute(
            """
            INSERT INTO mod_patterns
                (name, description, required_signal_names, min_families, min_risk_score,
                 min_confidence, min_cluster_size, enabled, auto_enabled, weight,
                 created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pattern.name, pattern.description,
                json.dumps(list(pattern.required_signal_names)),
                pattern.min_families, pattern.min_risk_score, pattern.min_confidence,
                pattern.min_cluster_size, int(pattern.enabled), int(pattern.auto_enabled),
                pattern.weight, pattern.created_by, time.time(),
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_patterns не вернул id")
        await self._db.commit()
        return cursor.lastrowid

    async def list_patterns(self, *, enabled_only: bool = False) -> list[Pattern]:
        self._db.row_factory = aiosqlite.Row
        where = "WHERE enabled = 1" if enabled_only else ""
        cursor = await self._db.execute(
            f"""
            SELECT id, name, description, required_signal_names, min_families,
                   min_risk_score, min_confidence, min_cluster_size, enabled,
                   auto_enabled, weight, created_by, created_at
            FROM mod_patterns {where}
            ORDER BY weight DESC
            """
        )
        rows = await cursor.fetchall()
        return [_row_to_pattern(row) for row in rows]

    async def set_pattern_enabled(self, pattern_id: int, enabled: bool) -> None:
        await self._db.execute(
            "UPDATE mod_patterns SET enabled = ? WHERE id = ?", (int(enabled), pattern_id)
        )
        await self._db.commit()

    async def delete_pattern(self, pattern_id: int) -> None:
        await self._db.execute("DELETE FROM mod_patterns WHERE id = ?", (pattern_id,))
        await self._db.commit()

    # -- Attack Mode (этап 9c) -----------------------------------------------

    async def activate_attack_mode(
        self, *, activated_by: str, duration_seconds: float
    ) -> AttackModeStatus:
        now = time.time()
        expires_at = now + duration_seconds
        await self._db.execute(
            """
            INSERT INTO mod_attack_mode (id, activated_by, activated_at, expires_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                activated_by = excluded.activated_by,
                activated_at = excluded.activated_at,
                expires_at = excluded.expires_at
            """,
            (activated_by, now, expires_at),
        )
        await self._db.commit()
        return AttackModeStatus(activated_by=activated_by, activated_at=now, expires_at=expires_at)

    async def deactivate_attack_mode(self) -> None:
        await self._db.execute("DELETE FROM mod_attack_mode WHERE id = 1")
        await self._db.commit()

    async def get_active_attack_mode(self) -> AttackModeStatus | None:
        """None если не активирован ИЛИ уже истёк — проверка expires_at
        здесь, а не в вызывающем коде: любой читатель (engine.py, панель)
        получает уже отфильтрованный по времени статус, не отдельно
        "запись есть" и отдельно "но она устарела"."""
        cursor = await self._db.execute(
            "SELECT activated_by, activated_at, expires_at FROM mod_attack_mode WHERE id = 1"
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        activated_by, activated_at, expires_at = row
        if expires_at <= time.time():
            return None
        return AttackModeStatus(activated_by=activated_by, activated_at=activated_at, expires_at=expires_at)

    # -- Giveaway Mode (FALSE-BAN-001 аудита) --------------------------------

    async def activate_giveaway_mode(
        self, *, activated_by: str, duration_seconds: float
    ) -> GiveawayModeStatus:
        now = time.time()
        expires_at = now + duration_seconds
        await self._db.execute(
            """
            INSERT INTO mod_giveaway_mode (id, activated_by, activated_at, expires_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                activated_by = excluded.activated_by,
                activated_at = excluded.activated_at,
                expires_at = excluded.expires_at
            """,
            (activated_by, now, expires_at),
        )
        await self._db.commit()
        return GiveawayModeStatus(activated_by=activated_by, activated_at=now, expires_at=expires_at)

    async def deactivate_giveaway_mode(self) -> None:
        await self._db.execute("DELETE FROM mod_giveaway_mode WHERE id = 1")
        await self._db.commit()

    async def get_active_giveaway_mode(self) -> GiveawayModeStatus | None:
        cursor = await self._db.execute(
            "SELECT activated_by, activated_at, expires_at FROM mod_giveaway_mode WHERE id = 1"
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        activated_by, activated_at, expires_at = row
        if expires_at <= time.time():
            return None
        return GiveawayModeStatus(activated_by=activated_by, activated_at=activated_at, expires_at=expires_at)

    # -- feedback loop / FP-статистика (этап 9d) -----------------------------

    async def record_feedback(
        self,
        *,
        signal_name: str,
        moderator: str,
        decision: str,
        verdict_id: int | None = None,
        cluster_id: int | None = None,
        user_id: str | None = None,
        pattern_id: int | None = None,
    ) -> int:
        """decision: 'FALSE_POSITIVE' | 'CONFIRMED_BOT'. Не валидируется
        здесь через enum — это забота вызывающего слоя (panel/executor.py
        parse_payload паттерн), store.py остаётся тонким слоем поверх SQL."""
        cursor = await self._db.execute(
            """
            INSERT INTO mod_feedback
                (created_at, signal_name, verdict_id, cluster_id, user_id,
                 pattern_id, moderator, decision)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(), signal_name, verdict_id, cluster_id, user_id,
                pattern_id, moderator, decision,
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_feedback не вернул id")
        await self._db.commit()
        return cursor.lastrowid

    async def get_signal_fp_penalty(self, signal_name: str, *, sample_size: int = 50) -> float:
        """Доля FALSE_POSITIVE среди последних sample_size решений по
        конкретному сигналу — confidence.py умножает confidence на
        (1 - fp_penalty), см. докстринг ConfidenceConfig. 0.0, если
        фидбека по этому сигналу ещё нет (система не наказывает то, что
        ещё не проверено модератором)."""
        cursor = await self._db.execute(
            """
            SELECT decision FROM mod_feedback
            WHERE signal_name = ?
            -- id DESC обязателен, а не косметика: created_at приходит из
            -- time.time(), у которого на Windows шаг ~15 мс, поэтому все
            -- записи, сделанные модератором в пределах одного тика, имеют
            -- РАВНЫЙ created_at. Без вторичной сортировки LIMIT отбирал из
            -- них произвольные, и "последние sample_size решений"
            -- оказывались случайной выборкой — fp_penalty считался не по
            -- тем записям и гулял между вызовами на одних и тех же данных.
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (signal_name, sample_size),
        )
        rows = list(await cursor.fetchall())
        if not rows:
            return 0.0
        false_positives = sum(1 for (decision,) in rows if decision == "FALSE_POSITIVE")
        return false_positives / len(rows)

    async def list_feedback(self, *, limit: int = 100) -> list[dict[str, Any]]:
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            """
            SELECT id, created_at, signal_name, verdict_id, cluster_id, user_id,
                   pattern_id, moderator, decision
            FROM mod_feedback
            -- см. get_signal_fp_penalty: равный created_at у записей одного
            -- тика часов делает порядок без id DESC недетерминированным
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    # -- дневная статистика (этап 9d) ----------------------------------------

    async def increment_daily_stats(self, *, date: str, **counters: int) -> None:
        """date в формате YYYY-MM-DD (UTC). counters — любое подмножество
        колонок mod_stats_daily (total_messages, suspicious, would_timeout,
        would_ban, actual_timeouts, actual_bans, clusters, false_positives);
        каждый вызов ДОБАВЛЯЕТ к текущему значению, не перезаписывает —
        engine.py/panel вызывают это по одному счётчику за раз по мере
        появления событий, а не пересчитывают всё разом."""
        allowed = {
            "total_messages", "suspicious", "would_timeout", "would_ban",
            "actual_timeouts", "actual_bans", "clusters", "false_positives",
        }
        unknown = set(counters) - allowed
        if unknown:
            raise ValueError(f"Неизвестные счётчики mod_stats_daily: {sorted(unknown)}")
        if not counters:
            return

        await self._db.execute(
            f"""
            INSERT INTO mod_stats_daily (date, {", ".join(counters)})
            VALUES (?, {", ".join("?" for _ in counters)})
            ON CONFLICT(date) DO UPDATE SET
                {", ".join(f"{col} = mod_stats_daily.{col} + excluded.{col}" for col in counters)}
            """,
            (date, *counters.values()),
        )
        await self._db.commit()

    async def get_daily_stats(self, *, days: int = 30) -> list[dict[str, Any]]:
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            "SELECT * FROM mod_stats_daily ORDER BY date DESC LIMIT ?", (days,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    # -- аудит действий ----------------------------------------------------

    async def record_action_audit(
        self,
        *,
        actor: str,
        actor_role: str,
        action: str,
        scope: str,
        reason: str,
        confirmation: str,
        succeeded: int,
        failed: int,
        details: dict[str, Any],
        cluster_id: int | None = None,
        pattern_id: int | None = None,
    ) -> int:
        """Кто, что и по какому правилу — главный ответ раздела 10 ТЗ
        ("Я хочу всегда видеть, кто нажал кнопку массового бана")."""
        cursor = await self._db.execute(
            """
            INSERT INTO mod_actions
                (created_at, actor, actor_role, action, scope, cluster_id, pattern_id,
                 reason, confirmation, succeeded, failed, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(), actor, actor_role, action, scope, cluster_id, pattern_id,
                reason, confirmation, succeeded, failed, json.dumps(details),
            ),
        )
        await self._db.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_actions не вернул id")
        return cursor.lastrowid

    # -- Discord-webhook (направление 01 master-plan.html) -------------------

    async def set_discord_webhook(
        self, *, url: str, enabled: bool, updated_by: str
    ) -> DiscordWebhookConfig:
        now = time.time()
        await self._db.execute(
            """
            INSERT INTO mod_discord_webhook (id, url, enabled, updated_by, updated_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                url = excluded.url,
                enabled = excluded.enabled,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (url, int(enabled), updated_by, now),
        )
        await self._db.commit()
        return DiscordWebhookConfig(url=url, enabled=enabled, updated_by=updated_by, updated_at=now)

    async def get_discord_webhook(self) -> DiscordWebhookConfig | None:
        cursor = await self._db.execute(
            "SELECT url, enabled, updated_by, updated_at, last_digest_sent_at, "
            "last_escalation_sent_at, alert_confidence_threshold FROM mod_discord_webhook WHERE id = 1"
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        (
            url, enabled, updated_by, updated_at,
            last_digest_sent_at, last_escalation_sent_at, alert_confidence_threshold,
        ) = row
        return DiscordWebhookConfig(
            url=url,
            enabled=bool(enabled),
            updated_by=updated_by,
            updated_at=updated_at,
            last_digest_sent_at=last_digest_sent_at,
            last_escalation_sent_at=last_escalation_sent_at,
            alert_confidence_threshold=alert_confidence_threshold,
        )

    async def set_alert_confidence_threshold(self, *, threshold: float) -> None:
        """Меняет только порог, не трогая url/enabled/cooldown-поля —
        отдельный вызов от set_discord_webhook(), потому что панель
        предлагает их как разные действия (адрес webhook и чувствительность
        алерта настраиваются независимо друг от друга).

        UPDATE, не UPSERT: требует, чтобы webhook уже был настроен (строка
        существует) — настраивать чувствительность алерта, которого ещё
        нет, бессмысленно, панель прячет это поле до set_discord_webhook()."""
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"alert_confidence_threshold должен быть в [0, 1], получено {threshold}")
        cursor = await self._db.execute(
            "UPDATE mod_discord_webhook SET alert_confidence_threshold = ? WHERE id = 1",
            (threshold,),
        )
        if cursor.rowcount == 0:
            raise ValueError("Discord-webhook ещё не настроен — сначала укажите url")
        await self._db.commit()

    async def mark_digest_sent(self, *, sent_at: float | None = None) -> None:
        """Вызывается после успешной отправки ежедневного digest — без
        этого рестарт бота (ChannelPipeline поднимается заново после
        каждого падения/деплоя) отправил бы второй digest в тот же день,
        как только фоновый поллер снова стартует с нуля."""
        await self._db.execute(
            "UPDATE mod_discord_webhook SET last_digest_sent_at = ? WHERE id = 1",
            (sent_at if sent_at is not None else time.time(),),
        )
        await self._db.commit()

    async def mark_escalation_sent(self, *, sent_at: float | None = None) -> None:
        """Вызывается после отправки эскалации — cooldown, чтобы 4-й, 5-й,
        6-й кластер сверх порога не слали новую эскалацию каждый раз (см.
        докстринг миграции 012)."""
        await self._db.execute(
            "UPDATE mod_discord_webhook SET last_escalation_sent_at = ? WHERE id = 1",
            (sent_at if sent_at is not None else time.time(),),
        )
        await self._db.commit()

    async def count_recent_new_clusters(self, *, since: float) -> int:
        """Сколько НОВЫХ кластеров возникло с since — created_at пишется
        только save_cluster() (см. upsert_cluster_by_members_ex), рост уже
        существующего кластера новыми участниками сюда не попадает."""
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM mod_clusters WHERE created_at >= ?", (since,)
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def get_digest_stats(self, *, since: float) -> DigestStats:
        """Сводка активности за период [since, сейчас) — см. докстринг
        DigestStats про то, почему не mod_stats_daily."""
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM mod_messages WHERE created_at >= ?", (since,)
        )
        row = await cursor.fetchone()
        total_messages = int(row[0]) if row else 0

        # "Подозрительное" здесь — recommended_action, требующее внимания
        # (TIMEOUT/BAN), не OBSERVE/NOTHING: OBSERVE срабатывает часто на
        # безобидные сообщения (см. Action в types.py, "порядок = возрастание
        # строгости") и раздул бы цифру до бессмысленной на активном чате.
        cursor = await self._db.execute(
            "SELECT "
            "SUM(CASE WHEN recommended_action = 'TIMEOUT' THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN recommended_action = 'BAN' THEN 1 ELSE 0 END) "
            "FROM mod_verdicts WHERE created_at >= ? AND recommended_action IN ('TIMEOUT', 'BAN')",
            (since,),
        )
        row = await cursor.fetchone()
        would_timeout = int(row[0]) if row and row[0] is not None else 0
        would_ban = int(row[1]) if row and row[1] is not None else 0
        suspicious_verdicts = would_timeout + would_ban

        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM mod_clusters WHERE created_at >= ?", (since,)
        )
        row = await cursor.fetchone()
        new_clusters = int(row[0]) if row else 0

        return DigestStats(
            total_messages=total_messages,
            suspicious_verdicts=suspicious_verdicts,
            would_timeout=would_timeout,
            would_ban=would_ban,
            new_clusters=new_clusters,
        )

    async def get_moderator_activity_stats(
        self, *, since: float, recent_limit: int = 10
    ) -> ModeratorActivityStats:
        """Сводка по ручным действиям модераторов за период (пользователь
        2026-08-13: "можем сводку отправлять в дискорд по работе
        модераторов?") — источник mod_actions, единственная таблица, куда
        и executor.py, и ручные действия из панели пишут аудит
        (record_action_audit). action здесь — строки QueueAction
        (executor.py): "TIMEOUT"/"BAN"/"DELETE_MESSAGES", не Action из
        types.py (тот описывает рекомендацию движка, этот — что реально
        было исполнено)."""
        cursor = await self._db.execute(
            "SELECT "
            "SUM(CASE WHEN action = 'TIMEOUT' THEN succeeded ELSE 0 END), "
            "SUM(CASE WHEN action = 'BAN' THEN succeeded ELSE 0 END), "
            "SUM(CASE WHEN action = 'DELETE_MESSAGES' THEN succeeded ELSE 0 END) "
            "FROM mod_actions WHERE created_at >= ?",
            (since,),
        )
        row = await cursor.fetchone()
        total_timeouts = int(row[0]) if row and row[0] is not None else 0
        total_bans = int(row[1]) if row and row[1] is not None else 0
        total_deletes = int(row[2]) if row and row[2] is not None else 0

        cursor = await self._db.execute(
            "SELECT actor, "
            "SUM(CASE WHEN action = 'TIMEOUT' THEN succeeded ELSE 0 END), "
            "SUM(CASE WHEN action = 'BAN' THEN succeeded ELSE 0 END), "
            "SUM(CASE WHEN action = 'DELETE_MESSAGES' THEN succeeded ELSE 0 END) "
            "FROM mod_actions WHERE created_at >= ? "
            "GROUP BY actor "
            "ORDER BY (SUM(succeeded)) DESC",
            (since,),
        )
        by_moderator = tuple(
            ModeratorActionSummary(actor=r[0], timeouts=int(r[1] or 0), bans=int(r[2] or 0), deletes=int(r[3] or 0))
            for r in await cursor.fetchall()
        )

        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            "SELECT created_at, actor, action, scope, succeeded, failed "
            "FROM mod_actions WHERE created_at >= ? "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (since, recent_limit),
        )
        recent = tuple(
            RecentModeratorAction(
                created_at=r["created_at"], actor=r["actor"], action=r["action"],
                scope=r["scope"], succeeded=r["succeeded"], failed=r["failed"],
            )
            for r in await cursor.fetchall()
        )

        return ModeratorActivityStats(
            total_timeouts=total_timeouts, total_bans=total_bans, total_deletes=total_deletes,
            by_moderator=by_moderator, recent=recent,
        )

    # -- Content Rules (словарный детектор — Rule Engine) --------------------

    async def list_content_rules(self, *, enabled_only: bool = False) -> tuple[ContentRule, ...]:
        """Правила, отсортированные по строгости категории (RACISM/THREATS
        раньше ADVERTISING) — check_content() возвращает первое совпадение,
        порядок определяет, какая категория выигрывает при пересечении
        формулировок в разных правилах."""
        self._db.row_factory = aiosqlite.Row
        where = "WHERE enabled = 1" if enabled_only else ""
        order = (
            "CASE category "
            "WHEN 'racism' THEN 0 WHEN 'threats' THEN 0 WHEN 'advertising' THEN 1 ELSE 2 END"
        )
        cursor = await self._db.execute(
            f"SELECT id, category, phrase, enabled FROM mod_content_rules {where} "
            f"ORDER BY {order}, id"
        )
        rows = await cursor.fetchall()
        return tuple(
            ContentRule(
                id=row["id"],
                category=ContentCategory(row["category"]),
                phrase=row["phrase"],
                enabled=bool(row["enabled"]),
            )
            for row in rows
        )

    async def add_content_rule(
        self, *, category: ContentCategory, phrase: str, created_by: str
    ) -> ContentRule:
        phrase = phrase.strip()
        if not phrase:
            raise ValueError("Фраза не может быть пустой")
        now = time.time()
        cursor = await self._db.execute(
            """
            INSERT INTO mod_content_rules (category, phrase, enabled, created_by, created_at)
            VALUES (?, ?, 1, ?, ?)
            """,
            (category.value, phrase, created_by, now),
        )
        await self._db.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_content_rules не вернул id")
        return ContentRule(id=cursor.lastrowid, category=category, phrase=phrase, enabled=True)

    async def set_content_rule_enabled(self, rule_id: int, enabled: bool) -> None:
        await self._db.execute(
            "UPDATE mod_content_rules SET enabled = ? WHERE id = ?", (int(enabled), rule_id)
        )
        await self._db.commit()

    async def delete_content_rule(self, rule_id: int) -> None:
        await self._db.execute("DELETE FROM mod_content_rules WHERE id = ?", (rule_id,))
        await self._db.commit()

    # -- Content Settings (режим наблюдателя) --------------------------------

    async def get_content_settings(self) -> ContentSettings:
        """Singleton-настройка, как mod_attack_mode — по умолчанию enabled=False
        (см. миграцию 014): пока никто явно не включил через панель, словарный
        детектор всегда работает в режиме наблюдателя (см. content/policy.py)."""
        cursor = await self._db.execute(
            "SELECT enabled, updated_by, updated_at FROM mod_content_settings WHERE id = 1"
        )
        row = await cursor.fetchone()
        if row is None:
            return ContentSettings(enabled=False, updated_by="", updated_at=0.0)
        enabled, updated_by, updated_at = row
        return ContentSettings(enabled=bool(enabled), updated_by=updated_by, updated_at=updated_at)

    async def set_content_moderation_enabled(self, enabled: bool, *, updated_by: str) -> None:
        now = time.time()
        await self._db.execute(
            """
            INSERT INTO mod_content_settings (id, enabled, updated_by, updated_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                enabled = excluded.enabled,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (int(enabled), updated_by, now),
        )
        await self._db.commit()

    # -- Content Violations (эскалация по категории) -------------------------

    async def get_content_violation_count(self, user_id: str, category: ContentCategory) -> int:
        cursor = await self._db.execute(
            "SELECT violation_count FROM mod_content_violations WHERE user_id = ? AND category = ?",
            (user_id, category.value),
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def record_content_violation(self, user_id: str, category: ContentCategory) -> int:
        """Увеличить счётчик нарушений категории для пользователя и вернуть
        новое значение. Отдельная таблица от mod_users.prior_timeouts/
        prior_warnings (пользователь: "отдельный счётчик на категорию") —
        те поля не инкрементируются нигде в коде (проверено), а эскалация
        content-нарушений должна считаться по каждой категории независимо:
        реклама не должна приближать бан за расизм."""
        now = time.time()
        await self._db.execute(
            """
            INSERT INTO mod_content_violations (user_id, category, violation_count, last_violation_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(user_id, category) DO UPDATE SET
                violation_count = violation_count + 1,
                last_violation_at = excluded.last_violation_at
            """,
            (user_id, category.value, now),
        )
        await self._db.commit()
        return await self.get_content_violation_count(user_id, category)

    async def record_content_event(
        self,
        *,
        user_id: str,
        login: str,
        message_id: int | None,
        category: ContentCategory,
        matched_phrase: str,
        action: str,
        prior_violations: int,
        blocked_by: str,
        enforced: bool,
    ) -> int:
        """Аудит срабатывания словарного детектора — отдельно от save_verdict
        (см. докстринг миграции 014 про то, почему не mod_verdicts).
        enforced=False в режиме наблюдателя и при любом blocked_by."""
        cursor = await self._db.execute(
            """
            INSERT INTO mod_content_events
                (created_at, user_id, login, message_id, category, matched_phrase,
                 action, prior_violations, blocked_by, enforced)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(), user_id, login, message_id, category.value, matched_phrase,
                action, prior_violations, blocked_by, int(enforced),
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT в mod_content_events не вернул id")
        await self._db.commit()
        return cursor.lastrowid

    async def list_content_events(self, *, limit: int = 50) -> list[dict[str, object]]:
        """Последние срабатывания словарного детектора, новые сначала —
        формат для панели (см. /content_events в panel/moderation_api.py).

        LEFT JOIN на mod_messages за twitch_message_id — нужен ручному
        модерированию из ленты Content (кнопка "Удалить сообщение" зовёт
        Helix DELETE /moderation/chat, которому нужен настоящий Twitch ID,
        не внутренний mod_content_events.message_id). LEFT, не INNER: старое
        событие могло быть записано до миграции 015, когда колонки ещё не
        было — тогда twitch_message_id придёт NULL, кнопка "Удалить" в
        панели просто не покажется для этой строки, остальные поля целы.

        manual_action/manual_action_by/manual_action_at (миграция 016) —
        пометка "по этой строке уже нажали кнопку в панели", переживает
        обновление страницы (см. mark_content_event_manual_action)."""
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            """
            SELECT e.id, e.created_at, e.user_id, e.login, e.category, e.matched_phrase,
                   e.action, e.prior_violations, e.blocked_by, e.enforced,
                   e.manual_action, e.manual_action_by, e.manual_action_at,
                   m.twitch_message_id
            FROM mod_content_events e
            LEFT JOIN mod_messages m ON m.id = e.message_id
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "user_id": row["user_id"],
                "login": row["login"],
                "category": row["category"],
                "matched_phrase": row["matched_phrase"],
                "action": row["action"],
                "prior_violations": row["prior_violations"],
                "blocked_by": row["blocked_by"],
                "enforced": bool(row["enforced"]),
                "twitch_message_id": row["twitch_message_id"],
                "manual_action": row["manual_action"],
                "manual_action_by": row["manual_action_by"],
                "manual_action_at": row["manual_action_at"],
            }
            for row in rows
        ]

    async def mark_content_event_manual_action(
        self, event_id: int, *, action: str, actor: str
    ) -> None:
        """Пометить строку ленты Content как разобранную вручную —
        вызывается сразу после успешной постановки задания в mod_action_queue
        из UI (не после реального исполнения executor'ом: тот же принцип,
        что тост "Задание поставлено в очередь" — панель не ждёт Helix,
        видимая пометка тоже не должна)."""
        await self._db.execute(
            """
            UPDATE mod_content_events
            SET manual_action = ?, manual_action_by = ?, manual_action_at = ?
            WHERE id = ?
            """,
            (action, actor, time.time(), event_id),
        )
        await self._db.commit()

    # -- Paste Wipe (ручная зачистка волны копипасты) ------------------------

    async def list_recent_messages(self, *, limit: int = 15) -> list[dict[str, object]]:
        """Последние сообщения чата, новые сначала, без фильтра по
        risk_score — источник для клика "вставить как образец пасты" в
        UI (пользователь 2026-08-13: "сделай привязку к чату, чтобы на
        1 кнопку нажал и паста вставилась, чтобы не копировать и
        вставлять"). Копирование текста из внешнего чат-виджета руками
        цепляло мусор (ник, время — см. предыдущее сообщение пользователя
        с "ЫЫЫЫ75): " в начале образца) — список из самой БД гарантирует
        точный текст, без ручной правки."""
        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            "SELECT login, text, created_at FROM mod_messages ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [{"login": r["login"], "text": r["text"], "created_at": r["created_at"]} for r in rows]

    async def find_paste_wave(
        self, *, sample_text: str, window_seconds: float, similarity_threshold: float = 0.6
    ) -> list[dict[str, object]]:
        """Найти всех пользователей, написавших текст, похожий на
        sample_text, за последние window_seconds — источник для функции
        "Зачистить пасту" (пользователь 2026-08-13): модератор вставляет
        образец копипасты вручную, система находит все совпадения без
        оглядки на risk_score — паста от доверенных зрителей не проходит
        через ленту Live (там фильтр risk_score >= 30), значит искать нужно
        по mod_messages напрямую, не по вердиктам.

        MinHash-похожесть, не точное совпадение — та же техника, что уже
        ловит изменённые копии дублей в кластеризации (см. normalize.py),
        здесь просто применена к произвольному образцу текста вместо
        сравнения сообщений друг с другом. similarity_threshold=0.6 мягче,
        чем near_duplicate_threshold детектора (0.75 по умолчанию в config.py)
        — цена пропустить перефразированную копию здесь выше цены найти
        лишнего: модератор сам видит список найденных перед подтверждением
        таймаута, ложное совпадение просто останется в списке некликнутым
        (если UI это допускает) или будет исправлено — здесь без
        авто-исполнения, ручное подтверждение остаётся за вызывающим кодом.

        Один результат на пользователя — если человек написал пасту
        трижды, попадает в список один раз (последнее сообщение)."""
        sample_hash = minhash(sample_text)
        since = time.time() - window_seconds

        self._db.row_factory = aiosqlite.Row
        cursor = await self._db.execute(
            "SELECT user_id, login, text, created_at FROM mod_messages "
            "WHERE created_at >= ? ORDER BY created_at DESC",
            (since,),
        )
        rows = await cursor.fetchall()

        seen_users: set[str] = set()
        matches: list[dict[str, object]] = []
        for row in rows:
            if row["user_id"] in seen_users:
                continue
            score = similarity(sample_hash, minhash(row["text"]))
            if score >= similarity_threshold:
                seen_users.add(row["user_id"])
                matches.append(
                    {
                        "user_id": row["user_id"],
                        "login": row["login"],
                        "text": row["text"],
                        "created_at": row["created_at"],
                        "similarity": round(score, 3),
                    }
                )
        return matches
