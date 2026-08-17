"""Движок модерации внутри процесса чат-бота.

Раньше между чтением чата и модерацией стояла граница процессов: main.py
писал каждое сообщение в mod_inbox (таблицу в своей же bot.db), а
отдельный процесс cigilbot/consumer.py читал её в фоне — по процессу на
канал, под управлением supervisor'а. Теперь движок живёт прямо в процессе
бота, и очередь стала очередью в памяти.

Что при этом сохранено намеренно
--------------------------------
Чтение чата НЕ ждёт модерацию. `submit()` — не корутина: она кладёт
событие в asyncio.Queue и возвращается немедленно, разбор идёт в фоновой
задаче. Если бы `event_message` ждал `observe()`, каждое сообщение чата
оплачивало бы запись в SQLite и (для новых аккаунтов) поход в Helix.

Состояние по-прежнему не смешивается между каналами: один
ChannelPipeline на broadcaster_id, свой ModerationEngine, своя очередь,
своя mod.<broadcaster_id>.db. Движок стейтфул (скользящее окно, кластеры),
и общий на все каналы он был бы неверен, а не просто медленнее.

Порядок обработки внутри канала строгий: одна задача-потребитель на
очередь, без параллелизма. Обработка не по порядку исказила бы
кластеризацию.

Что потеряно, и это осознанная цена
-----------------------------------
Очередь больше не переживает падение процесса и не безгранична. mod_inbox
лежала на диске: если модерация стояла, сообщения копились, и ничего не
терялось. Очередь в памяти ограничена QUEUE_MAXSIZE, и при переполнении
события ОТБРАСЫВАЮТСЯ — ждать нельзя, иначе backpressure дойдёт до чтения
IRC, ровно того, чего вся конструкция избегает. Каждый сброс считается
(`dropped`) и логируется, потому что молча потерянная модерация выглядит
как работающая.

Падение движка тоже больше не изолировано процессом. Компенсировано тем,
что каждая фоновая задача ловит исключения внутри своего цикла и сбой
одного канала не трогает другие, — но общий процесс у них теперь один.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import paths
from cigilbot.domain.config import load_channel_profile
from cigilbot.domain.config import load_config as load_moderation_config
from cigilbot.domain.types import ChatEvent, Mode, RiskLevel
from cigilbot.integrations.alerts import send_digest
from cigilbot.integrations.mod_token import ModTokenError, ModTokenManager, load_mod_token_manager
from cigilbot.integrations.twitch_api import HelixClient
from cigilbot.orchestration.engine import ModerationEngine
from cigilbot.orchestration.executor import ActionExecutor, process_pending
from cigilbot.storage.fingerprints_store import FingerprintStore
from cigilbot.storage.registry_store import ChannelRecord, RegistryStore
from cigilbot.storage.store import ModerationStore

log = logging.getLogger("cigilbot.pipeline")

STATE_SYNC_SECONDS = 10
ACTION_QUEUE_POLL_SECONDS = 2.0
FP_PENALTY_SYNC_EVERY_N_TICKS = 10
ACCOUNT_AGE_POLL_SECONDS = 5.0
ACCOUNT_AGE_BATCH_SIZE = 100  # лимит get_users() на один Helix-запрос

# Ежедневный digest (направление 01 master-plan.html). Поллер проверяет раз
# в час, не пора ли слать, вместо одного asyncio.sleep(24 часа) — тот подход
# не пережил бы рестарт бота корректно (после падения на 23-м часу таймер
# начал бы отсчёт заново, и день, когда бот перезапускали, никогда не
# получил бы digest). Час — достаточная точность для "раз в сутки", не
# нагружает БД (2 SELECT COUNT на тик).
DIGEST_CHECK_INTERVAL_SECONDS = 60 * 60
DIGEST_PERIOD_SECONDS = 24 * 60 * 60

# Сколько сообщений одного канала может ждать разбора. Потолок нужен именно
# потому, что очередь теперь в памяти: без него зависший движок съел бы
# память процесса, который параллельно обслуживает чат.
#
# 10 000 — это порядка часа очень активного чата (3 сообщения в секунду).
# Столько отставания движок в норме не набирает: observe() занимает
# миллисекунды. Если очередь всё же полна, это не всплеск, а поломка, и
# дальше важно не потерять сам чат.
QUEUE_MAXSIZE = 10_000

# Как часто сверять желаемое состояние каналов с фактическим.
RECONCILE_INTERVAL_SECONDS = 10.0

# Ретеншен mod_messages/mod_verdicts (bug-аудит 2026-08-15, HIGH #16) — обе
# таблицы росли неограниченно, за месяцы работы деградировали все
# аналитические запросы панели. Тот же принцип "проверять периодически, не
# спать интервал целиком", что DIGEST_CHECK_INTERVAL_SECONDS — DELETE WHERE
# created_at < cutoff идемпотентен, повторный вызов на уже почищенных
# данных просто ничего не находит, поэтому не нужно хранить "когда чистили
# в последний раз" отдельным полем в БД, в отличие от digest.
RETENTION_CHECK_INTERVAL_SECONDS = 60 * 60
RETENTION_DAYS = 30.0


class ChannelPipeline:
    """Один канал: движок, очередь и фоновые задачи вокруг них.

    Замена одного процесса cigilbot/consumer.py. Набор фоновых задач тот
    же, что был там, минус разбор mod_inbox — события приходят через
    submit() напрямую.
    """

    def __init__(
        self, *, broadcaster_id: str, channel: str, mod_db_path: Path, fingerprints_db_path: Path
    ) -> None:
        self.broadcaster_id = broadcaster_id
        self.channel = channel
        self.store = ModerationStore(str(mod_db_path))
        # Cross-Channel Bot Fingerprint (направление 03 master-plan.html):
        # ActionExecutor пишет сюда после успешного BAN. Отдельное соединение
        # от ModerationHub._fingerprints, тот читает всю таблицу раз в тик
        # для detection-кеша, этот только пишет по одной записи за раз.
        self.fingerprint_store = FingerprintStore(str(fingerprints_db_path))
        self.engine: ModerationEngine | None = None
        self.mod_token_manager: ModTokenManager | None = None
        self.helix_client: HelixClient | None = None
        # Отдельный клиент только для get_users() (возраст аккаунта) — та
        # ручка работает по App Access Token (client_id/secret), без scope
        # и без токена модератора, поэтому не завязана на mod_token_manager
        # и доступна даже до того, как токен бота получен через панель.
        self.account_age_client: HelixClient | None = None
        # user_id, которым ещё не резолвили account_created_at (Verdict
        # пришёл is_provisional). Set, не list — одно и то же сообщение от
        # активного чаттера не должно добавлять дубликаты на каждый вердикт.
        self._pending_account_age: set[str] = set()

        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self._tasks: list[asyncio.Task[None]] = []
        self.dropped = 0
        self._drop_logged_at = 0.0

    # -- жизненный цикл ----------------------------------------------------

    async def start(self) -> None:
        await self.store.connect()
        await self.fingerprint_store.connect()

        self.engine = ModerationEngine(
            load_moderation_config(),
            load_channel_profile(self.channel),
            self.store,
            mode=Mode.SHADOW,
        )
        await self.engine.reload_patterns()
        await self.engine.sync_attack_mode()
        await self.engine.sync_giveaway_mode()
        await self.engine.reload_fp_penalties()
        await self.engine.reload_content_rules()
        await self.engine.sync_content_settings()

        self._setup_twitch_clients()

        self._tasks = [
            asyncio.create_task(self._consume_queue(), name=f"mod-consume-{self.broadcaster_id}"),
            asyncio.create_task(self._poll_state_sync(), name=f"mod-sync-{self.broadcaster_id}"),
            asyncio.create_task(self._poll_action_queue(), name=f"mod-actions-{self.broadcaster_id}"),
            asyncio.create_task(self._poll_account_age(), name=f"mod-age-{self.broadcaster_id}"),
            asyncio.create_task(self._poll_digest(), name=f"mod-digest-{self.broadcaster_id}"),
            asyncio.create_task(self._poll_retention(), name=f"mod-retention-{self.broadcaster_id}"),
        ]
        log.info(
            "Модерация канала запущена (broadcaster_id=%s, канал=%s, SHADOW)",
            self.broadcaster_id, self.channel,
        )

    def _setup_twitch_clients(self) -> None:
        """Токен модератора живёт в КОРНЕВОМ .env (одна панель, одна кнопка
        получения токена, см. panel/auth.py::/auth/bot/login)."""
        client_id = os.environ.get("PANEL_TWITCH_CLIENT_ID", "")
        client_secret = os.environ.get("PANEL_TWITCH_CLIENT_SECRET", "")
        if not (client_id and client_secret):
            log.info(
                "PANEL_TWITCH_CLIENT_ID/SECRET не заданы — возраст аккаунта не "
                "резолвится (детектор new_account останется на is_provisional-"
                "эвристиках), очередь действий не исполняется"
            )
            return

        self.account_age_client = HelixClient(client_id, client_secret)
        self.mod_token_manager = load_mod_token_manager(
            client_id=client_id,
            client_secret=client_secret,
            env_file=paths.REPO_ROOT / ".env",
        )
        if self.mod_token_manager is not None:
            self.helix_client = HelixClient(client_id, client_secret)
            log.info("Токен модератора настроен — очередь действий будет исполняться")
        else:
            log.info(
                "Токен модератора не настроен — очередь действий из панели "
                "накапливается, но не исполняется (получите токен в Settings панели)"
            )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        # gather с return_exceptions: задачи отменяются, CancelledError здесь
        # ожидаем и не является сбоем остановки.
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        await self.store.close()
        await self.fingerprint_store.close()
        # helix_client/account_age_client создаются в _setup_twitch_clients
        # только когда PANEL_TWITCH_CLIENT_ID/SECRET заданы — без этой
        # проверки stop() без предшествующего start() (например, повторный
        # вызов) падал бы на None.close().
        if self.helix_client is not None:
            await self.helix_client.close()
        if self.account_age_client is not None:
            await self.account_age_client.close()
        log.info("Модерация канала остановлена (broadcaster_id=%s)", self.broadcaster_id)

    # -- вход --------------------------------------------------------------

    def submit(self, payload: dict[str, Any]) -> bool:
        """Кладёт событие в очередь. НЕ корутина и никогда не блокирует —
        вызывается прямо из обработчика сообщения чата.

        Возвращает False, если очередь переполнена и событие отброшено.
        Ждать здесь нельзя: ожидание дошло бы до чтения IRC, то есть чат
        начал бы тормозить из-за модерации.
        """
        try:
            self._queue.put_nowait(payload)
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            # Раз в минуту на канал: при переполнении сообщения сыплются
            # пачками, и лог на каждое отброшенное сам стал бы нагрузкой.
            now = time.monotonic()
            if now - self._drop_logged_at > 60:
                self._drop_logged_at = now
                log.error(
                    "Очередь модерации канала %s переполнена (%d в очереди) — "
                    "события отбрасываются, всего отброшено: %d",
                    self.channel, self._queue.qsize(), self.dropped,
                )
            return False

    # -- фоновые задачи ----------------------------------------------------

    async def _consume_queue(self) -> None:
        """Строго последовательный разбор очереди: движок стейтфул
        (скользящее окно), обработка не по порядку исказила бы
        кластеризацию. Было consumer.py::_poll_inbox, только источник
        событий сменился с таблицы в чужой БД на очередь в памяти."""
        while True:
            payload = await self._queue.get()
            try:
                await self._handle_event(payload)
            except Exception:
                log.exception("Сбой движка модерации на событии канала %s", self.channel)
            finally:
                self._queue.task_done()

    async def _handle_event(self, payload: dict[str, Any]) -> None:
        assert self.engine is not None
        kind = payload.get("kind")
        if kind == "raid_started":
            # FALSE-BAN-001 аудита: снижает чувствительность на время рейда
            # (см. engine.py, RAID_CONTEXT_SECONDS).
            self.engine.mark_raid_started()
            return
        if kind != "chat_message":
            log.warning("Неизвестный тип события модерации: %r", kind)
            return

        event = ChatEvent(
            user_id=payload["user_id"],
            login=payload["login"],
            text=payload["text"],
            timestamp=payload["timestamp"],
            channel=payload.get("channel", ""),
            display_name=payload.get("display_name", ""),
            message_id=payload.get("message_id", ""),
            is_first_message=payload.get("is_first_message", False),
            is_returning_chatter=payload.get("is_returning_chatter", False),
            is_subscriber=payload.get("is_subscriber", False),
            is_moderator=payload.get("is_moderator", False),
            is_vip=payload.get("is_vip", False),
            is_broadcaster=payload.get("is_broadcaster", False),
            badges=tuple(payload.get("badges", ())),
        )
        verdict = await self.engine.observe(event)

        if verdict.is_provisional:
            self._pending_account_age.add(event.user_id)

        if verdict.risk_level != RiskLevel.LOW:
            log.info(
                "[MODERATION][%s] %s risk=%d conf=%.2f action=%s signals=%s",
                verdict.mode.value,
                event.login,
                verdict.risk_score,
                verdict.confidence,
                verdict.recommended_action.value,
                ", ".join(verdict.signal_names),
            )

    async def _poll_state_sync(self) -> None:
        """Панель — по-прежнему отдельный процесс, меняющий Attack Mode/
        Pattern Library/feedback через ту же mod.<broadcaster_id>.db. Движок
        не видит эти изменения автоматически, поэтому перечитывает их
        периодически. Слияние движка с ботом этого не отменило: панель с
        ним не объединялась.

        Частоты как в исходнике: Attack Mode/Pattern Library каждый тик
        (10 сек, панический режим должен реагировать быстро), fp_penalty
        реже (копится медленно)."""
        assert self.engine is not None
        tick = 0
        while True:
            try:
                await self.engine.reload_patterns()
                await self.engine.sync_attack_mode()
                await self.engine.sync_giveaway_mode()
                await self.engine.reload_content_rules()
                await self.engine.sync_content_settings()
                if tick % FP_PENALTY_SYNC_EVERY_N_TICKS == 0:
                    await self.engine.reload_fp_penalties()
            except Exception:
                log.exception("Не удалось обновить состояние модерации из БД")
            tick += 1
            await asyncio.sleep(STATE_SYNC_SECONDS)

    async def _poll_account_age(self) -> None:
        """Резолвит account_created_at для пользователей, чей вердикт пришёл
        is_provisional (см. store.py::set_account_created_at). Без этого
        detectors/account.py::new_account никогда не срабатывает по-настоящему
        — is_provisional остаётся True навсегда, а не только до первого
        ответа Helix, как задумано (см. ChatEvent docstring в types.py).

        Батчит по ACCOUNT_AGE_BATCH_SIZE (лимит get_users() за один запрос)
        вместо запроса на каждого пользователя — при активном чате новых
        зрителей может быть много одновременно, отдельный запрос на каждого
        быстро упёрся бы в rate limit Helix.

        Вызывает engine.update_account_age(), а не store.set_account_created_at()
        напрямую — движок держит свой in-memory кэш UserState (self._users)
        и не перечитывает БД для уже закэшированных пользователей; прямая
        запись в store прошла бы мимо этого кэша и не изменила бы
        следующий вердикт активного чаттера."""
        if self.account_age_client is None:
            return
        assert self.engine is not None
        while True:
            try:
                if self._pending_account_age:
                    batch = list(self._pending_account_age)[:ACCOUNT_AGE_BATCH_SIZE]
                    users = await self.account_age_client.get_users(user_ids=batch)
                    for u in users:
                        await self.engine.update_account_age(u.id, u.created_at)
                        self._pending_account_age.discard(u.id)
                    # user_id, которых Helix не вернул (аккаунт удалён/забанен
                    # на стороне Twitch) — не повторять запрос бесконечно.
                    for user_id in batch:
                        self._pending_account_age.discard(user_id)
            except Exception:
                log.exception("Не удалось резолвить возраст аккаунта через Helix")
            await asyncio.sleep(ACCOUNT_AGE_POLL_SECONDS)

    async def _poll_action_queue(self) -> None:
        """Исполняет задания, которые панель кладёт в mod_action_queue
        (BAN ALL/TIMEOUT ALL). Пересоздаёт ActionExecutor на каждый цикл со
        свежим access_token — тот сам решает, нужно ли реально идти в Twitch
        за обновлением.

        broadcaster_id — self.broadcaster_id ЭТОГО канала, не
        state.broadcaster_id из общего токена (BUG-005 аудита): токен
        модератора один на весь процесс (User Access Token аккаунта бота,
        годен для любого канала, где бот реально модератор — Twitch сам
        проверяет права по scope, не по значению в .env), но
        TWITCH_MOD_BROADCASTER_ID записывался туда один раз, для канала,
        который был выбран при получении токена. При двух и более каналах
        под одной панелью задания на ВТОРОЙ канал всё равно исполнялись бы
        с broadcaster_id ПЕРВОГО — таймаут визуально уходил "не туда"
        (нашёл на реальном инциденте: taймаут для paverpapa исполнился на
        dobriy_yura, потому что токен получали с dobriy_yura в адресной
        строке)."""
        if self.mod_token_manager is None or self.helix_client is None:
            return
        while True:
            try:
                access_token = await self.mod_token_manager.get_valid_access_token()
                state = self.mod_token_manager.state
                executor = ActionExecutor(
                    self.helix_client,
                    self.store,
                    broadcaster_id=self.broadcaster_id,
                    moderator_id=state.bot_user_id,
                    user_token=access_token,
                    fingerprint_store=self.fingerprint_store,
                    channel_login=self.channel,
                )
                processed = await process_pending(executor, self.store)
                if processed:
                    log.info("Обработано заданий из очереди модерации: %d", processed)
            except ModTokenError:
                log.exception(
                    "Токен модератора недействителен — получите новый в панели "
                    "(Settings -> Twitch: получить токен бота)"
                )
            except Exception:
                log.exception("Сбой обработки очереди действий модерации")
            await asyncio.sleep(ACTION_QUEUE_POLL_SECONDS)

    async def _poll_digest(self) -> None:
        """Ежедневная сводка активности в Discord (направление 01
        master-plan.html). Проверяет раз в час, прошли ли сутки с
        last_digest_sent_at — см. DIGEST_CHECK_INTERVAL_SECONDS про то,
        почему не один asyncio.sleep(24 часа)."""
        while True:
            try:
                webhook = await self.store.get_discord_webhook()
                if webhook is not None and webhook.enabled:
                    now = time.time()
                    due = (
                        webhook.last_digest_sent_at is None
                        or now - webhook.last_digest_sent_at >= DIGEST_PERIOD_SECONDS
                    )
                    if due:
                        since = webhook.last_digest_sent_at or (now - DIGEST_PERIOD_SECONDS)
                        stats = await self.store.get_digest_stats(since=since)
                        moderator_stats = await self.store.get_moderator_activity_stats(since=since)
                        hours = (now - since) / 3600
                        await send_digest(
                            webhook, stats, channel=self.channel, hours=hours,
                            moderator_stats=moderator_stats,
                        )
                        await self.store.mark_digest_sent(sent_at=now)
            except Exception:
                log.exception("Сбой ежедневного digest в Discord (канал %s)", self.channel)
            await asyncio.sleep(DIGEST_CHECK_INTERVAL_SECONDS)

    async def _poll_retention(self) -> None:
        """Чистит mod_verdicts/mod_messages старше RETENTION_DAYS раз в
        RETENTION_CHECK_INTERVAL_SECONDS (bug-аудит 2026-08-15, HIGH #16).

        В отличие от _poll_digest, не хранит "когда чистили в последний
        раз" — DELETE WHERE created_at < cutoff идемпотентен, повторный
        вызов на уже почищенных данных просто ничего не находит, поэтому
        проверка на каждом тике не требует отдельного состояния в БД."""
        while True:
            try:
                verdicts_deleted, messages_deleted = await self.store.purge_old_records(
                    older_than_days=RETENTION_DAYS
                )
                if verdicts_deleted or messages_deleted:
                    log.info(
                        "Ретеншен канала %s: удалено вердиктов=%d, сообщений=%d (старше %.0f дней)",
                        self.channel, verdicts_deleted, messages_deleted, RETENTION_DAYS,
                    )
            except Exception:
                log.exception("Сбой ретеншена БД модерации (канал %s)", self.channel)
            await asyncio.sleep(RETENTION_CHECK_INTERVAL_SECONDS)


class ModerationHub:
    """Держит по ChannelPipeline на активный канал и сверяет их состав с
    Channel Registry.

    Замена cigilbot/supervisor.py. Тот следил за ОС-процессами: запускал
    consumer.py через subprocess, держал pid-файлы и защищался от петли
    рестартов. Здесь всё то же самое сводится к запуску и остановке
    asyncio-задач, поэтому нет ни pid-файлов, ни taskkill, ни защиты от
    restart loop — падение задачи не роняет процесс и не требует внешнего
    перезапуска (циклы задач ловят исключения внутри себя).

    process_status/pid в registry.db всё равно пишутся: панель показывает
    по ним состояние канала. pid теперь у всех каналов один — процесса
    бота, и это честно отражает устройство.
    """

    def __init__(
        self,
        *,
        registry_db_path: Path,
        fingerprints_db_path: Path | None = None,
        moderation_enabled: bool = True,
    ) -> None:
        self._registry_db_path = registry_db_path
        self._fingerprints_db_path = fingerprints_db_path or paths.FINGERPRINTS_DB
        self._enabled = moderation_enabled
        self._registry: RegistryStore | None = None
        # Cross-Channel Bot Fingerprint (направление 03 master-plan.html) —
        # одно соединение на весь хаб, не по одному на канал: читает всю
        # таблицу раз в тик и раздаёт снимок каждому ChannelPipeline.engine.
        # Отдельно от ChannelPipeline.fingerprint_store, который только
        # пишет после BAN (см. докстринг там).
        self._fingerprints: FingerprintStore | None = None
        self._pipelines: dict[str, ChannelPipeline] = {}
        # login -> broadcaster_id: события из чата приходят с именем канала
        # (twitchio знает login, не числовой id), а пайплайны разложены по
        # broadcaster_id — он стабилен к переименованию канала.
        self._by_login: dict[str, str] = {}
        self._reconcile_task: asyncio.Task[None] | None = None
        self._fingerprint_sync_task: asyncio.Task[None] | None = None
        self.dropped_unknown_channel = 0

    async def start(self) -> None:
        if not self._enabled:
            log.info("MODERATION_ENABLED=false — движок модерации не запускается")
            return
        self._registry = RegistryStore(str(self._registry_db_path))
        await self._registry.connect()
        self._fingerprints = FingerprintStore(str(self._fingerprints_db_path))
        await self._fingerprints.connect()
        await self._reconcile()
        await self._sync_fingerprints()
        self._reconcile_task = asyncio.create_task(self._reconcile_loop(), name="mod-reconcile")
        self._fingerprint_sync_task = asyncio.create_task(
            self._sync_fingerprints_loop(), name="mod-fingerprints"
        )
        log.info("Модерация запущена в процессе бота (каналов: %d)", len(self._pipelines))

    async def stop(self) -> None:
        if self._reconcile_task is not None:
            self._reconcile_task.cancel()
            await asyncio.gather(self._reconcile_task, return_exceptions=True)
            self._reconcile_task = None
        if self._fingerprint_sync_task is not None:
            self._fingerprint_sync_task.cancel()
            await asyncio.gather(self._fingerprint_sync_task, return_exceptions=True)
            self._fingerprint_sync_task = None
        for pipeline in list(self._pipelines.values()):
            await pipeline.stop()
        self._pipelines.clear()
        self._by_login.clear()
        if self._registry is not None:
            await self._registry.close()
            self._registry = None
        if self._fingerprints is not None:
            await self._fingerprints.close()
            self._fingerprints = None

    # -- вход --------------------------------------------------------------

    def submit(self, payload: dict[str, Any]) -> bool:
        """Маршрутизирует событие в пайплайн его канала. Не корутина: см.
        ChannelPipeline.submit."""
        channel = str(payload.get("channel", "")).lstrip("#").lower()
        broadcaster_id = self._by_login.get(channel)
        if broadcaster_id is None:
            # Канала нет в Registry или он остановлен. Не ошибка: бот может
            # сидеть в канале, модерация которого выключена через панель.
            self.dropped_unknown_channel += 1
            return False
        return self._pipelines[broadcaster_id].submit(payload)

    def mark_raid(self, channel: str) -> bool:
        return self.submit({"kind": "raid_started", "channel": channel})

    @property
    def active_channels(self) -> list[str]:
        return sorted(self._by_login)

    # -- Cross-Channel Bot Fingerprint (направление 03 master-plan.html) ---

    async def _sync_fingerprints_loop(self) -> None:
        """Читает fingerprints.db целиком раз в тик и раздаёт снимок каждому
        активному движку. Один общий тик на весь хаб, не per-channel — та
        же частота, что RECONCILE_INTERVAL_SECONDS, независимый цикл, чтобы
        сбой одного не откладывал другой."""
        while True:
            await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
            try:
                await self._sync_fingerprints()
            except Exception:
                log.exception("Ошибка синхронизации Cross-Channel Bot Fingerprint")

    async def _sync_fingerprints(self) -> None:
        assert self._fingerprints is not None
        actors = await self._fingerprints.list_all()
        known_ids = frozenset(a.user_id for a in actors)
        for pipeline in self._pipelines.values():
            if pipeline.engine is not None:
                pipeline.engine.sync_known_bad_actors(known_ids)

    # -- сверка с Registry -------------------------------------------------

    async def _reconcile_loop(self) -> None:
        while True:
            await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
            try:
                await self._reconcile()
            except Exception:
                log.exception("Ошибка сверки каналов модерации — продолжаю следующий тик")

    async def _reconcile(self) -> None:
        assert self._registry is not None
        channels = await self._registry.list_channels(status="active")
        wanted = {c.broadcaster_id: c for c in channels if c.desired_state == "running"}

        for broadcaster_id in list(self._pipelines):
            if broadcaster_id not in wanted:
                await self._stop_channel(broadcaster_id)

        for broadcaster_id, record in wanted.items():
            if broadcaster_id not in self._pipelines:
                await self._start_channel(record)
            else:
                # Канал мог быть переименован — login меняется, id нет.
                self._refresh_login(record)
                await self._registry.update_process_state(
                    broadcaster_id, process_status="running", pid=os.getpid()
                )

    def _refresh_login(self, record: ChannelRecord) -> None:
        login = record.login.lstrip("#").lower()
        pipeline = self._pipelines[record.broadcaster_id]
        if pipeline.channel != login:
            self._by_login.pop(pipeline.channel, None)
            pipeline.channel = login
            self._by_login[login] = record.broadcaster_id

    async def _start_channel(self, record: ChannelRecord) -> None:
        assert self._registry is not None
        login = record.login.lstrip("#").lower()
        pipeline = ChannelPipeline(
            broadcaster_id=record.broadcaster_id,
            channel=login,
            mod_db_path=paths.mod_db(record.broadcaster_id),
            fingerprints_db_path=paths.FINGERPRINTS_DB,
        )
        try:
            await pipeline.start()
        except Exception:
            # Сбой запуска одного канала не должен мешать остальным и тем
            # более ронять бота: чат важнее модерации одного канала.
            log.exception("Не удалось запустить модерацию канала %s", record.login)
            await self._registry.update_process_state(
                record.broadcaster_id, process_status="crashed", pid=None
            )
            return
        self._pipelines[record.broadcaster_id] = pipeline
        self._by_login[login] = record.broadcaster_id
        await self._registry.update_process_state(
            record.broadcaster_id, process_status="running", pid=os.getpid()
        )

    async def _stop_channel(self, broadcaster_id: str) -> None:
        assert self._registry is not None
        pipeline = self._pipelines.pop(broadcaster_id)
        self._by_login.pop(pipeline.channel, None)
        try:
            await pipeline.stop()
        except Exception:
            log.exception("Сбой остановки модерации канала %s", pipeline.channel)
        await self._registry.update_process_state(
            broadcaster_id, process_status="stopped", pid=None
        )
