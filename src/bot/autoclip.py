"""Автоклип: три независимых триггера — любой создаёт клип через Twitch
Helix Clips API.

  - Всплеск активности чата (BurstWindow, autoclip_window.py) — уникальных
    авторов за окно достаточно, чтобы считать это реакцией толпы, а не
    флудом одного человека.
  - Ключевая фраза в чате (normalize_for_matching из cigilbot.domain.normalize
    — та же нормализация, что уже используется в движке модерации).
  - Голосовая команда стримера (VoiceQueue, bot/voice_queue.py) — обходит
    кулдаун канала, потому что это явное намерение стримера, а не эвристика.

Живёт в процессе бота как AutoclipHub, по образцу
cigilbot.orchestration.pipeline.ModerationHub, но с полностью независимым
состоянием (своя очередь, свой Helix-клиент, свой токен) — сигнал и
намерение другие: хайп/явная команда, а не спам. AutoclipHub только ЧИТАЕТ
Channel Registry (list_channels), не пишет process_status/pid — тот один
писатель уже есть, и это ModerationHub (см. registry_store.py).

Кулдаун общий на канал для burst/keyword (ChannelAutoclip._last_clip_at),
голос его не проверяет вовсе — кулдаун-проверка целиком живёт в
submit_chat_message, а не в общем пути постановки в очередь, чтобы "голос
обходит кулдаун" было структурным свойством, а не веткой if, которую легко
случайно сломать будущей правкой.

Вкл/выкл и пороги на канале — двухуровневые: значение в
config/channels/<канал>.yml (дефолт, требует правки файла) и
mod_autoclip_settings в mod.<broadcaster_id>.db (живые настройки из
панели, POST /api/moderation/autoclip_settings и .../thresholds, без
рестарта бота). AutoclipHub._sync_overrides перечитывает второе на каждом
тике _reconcile_loop (как ChannelPipeline._poll_state_sync читает Attack
Mode) и применяет к уже существующему ChannelAutoclip на месте — не
пересоздаёт объект, чтобы не терять BurstWindow и кулдаун. Каждое поле
override независимо: не заданное в панели (NULL в БД) поле берётся из
YAML — см. _merge_config.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import paths
from bot.autoclip_config import (
    AutoclipChannelConfig,
    BurstTriggerConfig,
    KeywordTriggerConfig,
    VoiceTriggerConfig,
    load_autoclip_channel_config,
)
from bot.autoclip_window import BurstWindow
from cigilbot.domain.normalize import normalize_for_matching
from cigilbot.integrations.clip_token import (
    ClipTokenError,
    ClipTokenManager,
    load_clip_token_manager,
)
from cigilbot.integrations.twitch_api import HelixClient
from cigilbot.storage.registry_store import RegistryStore
from cigilbot.storage.store import AutoclipSettings, ModerationStore

log = logging.getLogger("bot.autoclip")

# Триггеры редки относительно сырого потока чата (в отличие от модерации,
# которая квеит КАЖДОЕ сообщение) — переполнение здесь означает зависший
# consumer, а не всплеск нагрузки.
QUEUE_MAXSIZE = 1000

RECONCILE_INTERVAL_SECONDS = 10.0

# Число зрителей не нужно знать с точностью до 10 секунд (в отличие от
# enabled/порогов из панели, которые модератор ждёт увидеть применёнными
# сразу) — отдельный, более редкий таймер экономит Helix-запросы. Реакция
# на резкий рейд/скачок всё равно укладывается в пределах пары минут.
VIEWER_COUNT_POLL_INTERVAL_SECONDS = 90.0


def _merge_config(
    yaml_config: AutoclipChannelConfig, settings: AutoclipSettings, *, enabled: bool
) -> AutoclipChannelConfig:
    """Живые пороги из панели (settings) поверх YAML — каждое поле
    независимо: None в settings значит "панель не трогала этот параметр",
    берём значение из yaml_config. enabled передаётся отдельным явным
    параметром (не settings.enabled и не yaml_config.enabled напрямую) —
    вызывающий код уже посчитал итоговое значение по своим правилам
    (см. AutoclipHub._sync_overrides/_start_channel), эта функция им не
    занимается, чтобы не дублировать ту же логику "None -> дефолт" дважды
    с двумя разными источниками дефолта."""
    burst = BurstTriggerConfig(
        enabled=yaml_config.burst.enabled,
        window_seconds=(
            yaml_config.burst.window_seconds
            if settings.burst_window_seconds is None
            else settings.burst_window_seconds
        ),
        unique_authors_threshold=(
            yaml_config.burst.unique_authors_threshold
            if settings.burst_unique_authors_threshold is None
            else settings.burst_unique_authors_threshold
        ),
        # Авто-режим сам по себе, включая проценты/границы, приходит из
        # панели тем же принципом None -> YAML, что и остальные поля.
        # Пересчёт unique_authors_threshold по формуле — отдельный шаг
        # (_apply_auto_scale), выполняется поверх уже собранного здесь
        # BurstTriggerConfig, потому что этой функции неоткуда взять
        # текущий viewer_count (она не делает сетевых вызовов).
        auto_scale_enabled=(
            yaml_config.burst.auto_scale_enabled
            if settings.burst_auto_scale_enabled is None
            else settings.burst_auto_scale_enabled
        ),
        auto_scale_percent=(
            yaml_config.burst.auto_scale_percent
            if settings.burst_auto_scale_percent is None
            else settings.burst_auto_scale_percent
        ),
        auto_scale_min=(
            yaml_config.burst.auto_scale_min
            if settings.burst_auto_scale_min is None
            else settings.burst_auto_scale_min
        ),
        auto_scale_max=(
            yaml_config.burst.auto_scale_max
            if settings.burst_auto_scale_max is None
            else settings.burst_auto_scale_max
        ),
    )
    keyword = KeywordTriggerConfig(
        enabled=yaml_config.keyword.enabled,
        phrases=yaml_config.keyword.phrases if settings.keyword_phrases is None else settings.keyword_phrases,
    )
    voice = VoiceTriggerConfig(
        enabled=yaml_config.voice.enabled,
        phrases=yaml_config.voice.phrases if settings.voice_phrases is None else settings.voice_phrases,
    )
    cooldown_seconds = (
        yaml_config.cooldown_seconds if settings.cooldown_seconds is None else settings.cooldown_seconds
    )
    capture_delay_seconds = (
        yaml_config.capture_delay_seconds
        if settings.capture_delay_seconds is None
        else settings.capture_delay_seconds
    )
    return AutoclipChannelConfig(
        enabled=enabled, cooldown_seconds=cooldown_seconds, capture_delay_seconds=capture_delay_seconds,
        burst=burst, keyword=keyword, voice=voice,
    )


def _scaled_burst_threshold(*, viewer_count: int, burst: BurstTriggerConfig) -> int:
    """Порог всплеска как доля текущих зрителей, зажатая в [min, max] —
    round(), не int(), чтобы 0.5 не всегда округлялось вниз (иначе крошечные
    каналы систематически получали бы порог на 1 ниже расчётного)."""
    raw = round(viewer_count * burst.auto_scale_percent)
    return max(burst.auto_scale_min, min(burst.auto_scale_max, raw))


def _apply_auto_scale(config: AutoclipChannelConfig, *, viewer_count: int | None) -> AutoclipChannelConfig:
    """Пересчитывает burst.unique_authors_threshold по формуле, если у
    канала включена авто-подстройка (config.burst.auto_scale_enabled) — в
    любом другом случае конфиг возвращается как есть.

    viewer_count=None (стрим оффлайн или Twitch ещё не опрошен ни разу) —
    тоже возвращает конфиг без изменений: последнее известное значение
    unique_authors_threshold (уже посчитанное на предыдущем успешном опросе
    и хранящееся в текущем self.config канала) остаётся в силе, чем молча
    откатываться на дефолт 12 каждый раз, когда стример уходит в оффлайн
    между стримами."""
    if not config.burst.auto_scale_enabled or viewer_count is None:
        return config
    threshold = _scaled_burst_threshold(viewer_count=viewer_count, burst=config.burst)
    if threshold == config.burst.unique_authors_threshold:
        return config
    burst = BurstTriggerConfig(
        enabled=config.burst.enabled,
        window_seconds=config.burst.window_seconds,
        unique_authors_threshold=threshold,
        auto_scale_enabled=config.burst.auto_scale_enabled,
        auto_scale_percent=config.burst.auto_scale_percent,
        auto_scale_min=config.burst.auto_scale_min,
        auto_scale_max=config.burst.auto_scale_max,
    )
    return AutoclipChannelConfig(
        enabled=config.enabled, cooldown_seconds=config.cooldown_seconds,
        capture_delay_seconds=config.capture_delay_seconds,
        burst=burst, keyword=config.keyword, voice=config.voice,
    )


@dataclass(frozen=True, slots=True)
class ClipTriggerEvent:
    """Единое событие для очереди автоклипа — всплеск, ключевая фраза и
    голос порождают его одинаково, различие только в поле reason."""

    channel: str
    broadcaster_id: str
    text: str
    timestamp: float
    reason: str  # "burst" | "keyword" | "voice"


class ChannelAutoclip:
    """Состояние одного канала: burst-окно, кулдаун, очередь, consumer.

    Один инстанс на канал — по аналогии с ChannelPipeline, состояние
    каналов не смешивается (см. pipeline.py).
    """

    def __init__(
        self,
        *,
        channel: str,
        broadcaster_id: str,
        config: AutoclipChannelConfig,
        clip_token_manager: ClipTokenManager,
        helix_client: HelixClient,
        store: ModerationStore,
    ) -> None:
        self.channel = channel
        self.broadcaster_id = broadcaster_id
        self.config = config
        # Отдельно от config.enabled: config приходит из YAML и не меняется
        # после старта канала, а это поле — живой рубильник, который панель
        # переключает через mod_autoclip_settings без пересоздания объекта
        # (см. AutoclipHub._sync_enabled_overrides) — пересоздание сбросило
        # бы BurstWindow и кулдаун, а простое включение/выключение не
        # должно их терять.
        self.enabled: bool = config.enabled
        self._clip_token_manager = clip_token_manager
        self._helix_client = helix_client
        # Переиспользует уже открытое соединение AutoclipHub._settings_stores
        # (см. AutoclipHub._start_channel) — не открывает своё: то соединение
        # и так живёт между тиками на этом же канале, второе было бы лишним.
        # Персистентность результата клипа (bug-аудит 2026-08-18) — см.
        # _create_clip и докстринг миграции 024.
        self._store = store
        self._burst_window = BurstWindow(config.burst.window_seconds)
        # None = ещё не клипали в этом процессе. Не 0.0: событие с
        # timestamp=0.0 (в частности в тестах) иначе сразу считалось бы
        # "в кулдауне" (0.0 - 0.0 < cooldown_seconds).
        self._last_clip_at: float | None = None
        self._queue: asyncio.Queue[ClipTriggerEvent] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self._task: asyncio.Task[None] | None = None

    def apply_config(self, config: AutoclipChannelConfig) -> None:
        """Заменяет пороги (burst/keyword/voice/cooldown) на месте — как
        enabled, без пересоздания объекта: BurstWindow и кулдаун-таймер
        переживают смену конфига, меняется только порог, с которым они
        сравниваются дальше. Вызывается из
        AutoclipHub._sync_threshold_overrides на каждом reconcile-тике.

        enabled сюда НЕ входит — тот отдельно управляется через self.enabled
        (см. __init__), apply_config его не трогает, чтобы смена порогов не
        могла случайно включить/выключить канал."""
        self.config = config
        self._burst_window.window_seconds = config.burst.window_seconds

    # -- жизненный цикл ------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.create_task(
            self._consume(), name=f"autoclip-consume-{self.broadcaster_id}"
        )

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    # -- вход ------------------------------------------------------------

    def submit_chat_message(self, *, author_id: str, text: str, timestamp: float) -> None:
        """НЕ корутина — тот же контракт, что ModerationHub.submit().

        Триггер оценивается синхронно здесь же (normalize_for_matching +
        deque — дёшево, без фингерпринтинга и кластеризации), в очередь
        кладём только при реальном срабатывании, и кулдаун проверяем сразу
        тут же — иначе два одинаковых триггера успели бы оба попасть в
        очередь до завершения первого клипа.
        """
        if not self.enabled:
            return
        if self._in_cooldown(timestamp):
            return

        reason = self._match_burst(author_id=author_id, timestamp=timestamp) or self._match_keyword(text)
        if reason is None:
            return

        self._enqueue(text=text, timestamp=timestamp, reason=reason)

    def submit_voice_command(self, *, text: str, timestamp: float) -> None:
        """Голосовая команда обходит кулдаун по построению: проверка
        кулдауна есть только в submit_chat_message, этот путь идёт в
        очередь напрямую."""
        if not self.enabled or not self.config.voice.enabled:
            return
        normalized = normalize_for_matching(text)
        if not any(normalize_for_matching(phrase) in normalized for phrase in self.config.voice.phrases):
            return
        self._enqueue(text=text, timestamp=timestamp, reason="voice")

    def _match_burst(self, *, author_id: str, timestamp: float) -> str | None:
        if not self.config.burst.enabled:
            return None
        count = self._burst_window.add(author_id=author_id, timestamp=timestamp)
        if count >= self.config.burst.unique_authors_threshold:
            return "burst"
        return None

    def _match_keyword(self, text: str) -> str | None:
        if not self.config.keyword.enabled:
            return None
        normalized = normalize_for_matching(text)
        if any(normalize_for_matching(phrase) in normalized for phrase in self.config.keyword.phrases):
            return "keyword"
        return None

    def _in_cooldown(self, now: float) -> bool:
        if self._last_clip_at is None:
            return False
        return now - self._last_clip_at < self.config.cooldown_seconds

    def _enqueue(self, *, text: str, timestamp: float, reason: str) -> None:
        event = ClipTriggerEvent(
            channel=self.channel,
            broadcaster_id=self.broadcaster_id,
            text=text,
            timestamp=timestamp,
            reason=reason,
        )
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.error(
                "Очередь автоклипа канала %s переполнена — событие (%s) отброшено",
                self.channel, reason,
            )

    # -- фоновая задача ----------------------------------------------------

    async def _consume(self) -> None:
        """Строго последовательно, без параллелизма — как
        ChannelPipeline._consume_queue: два клипа подряд не должны гнаться
        друг за другом через параллельные запросы к Helix.

        Стартовая уборка (bug-аудит 2026-08-18) — ДО первого self._queue.get():
        любая запись mod_clips со status='pending' на этот момент принадлежит
        прошлому процессу (текущий ещё не успел создать ни одной новой) —
        см. докстринг store.mark_stale_pending_clips_unknown про то, почему
        здесь не нужен cutoff по времени, в отличие от reclaim_stuck_actions."""
        try:
            reclaimed = await self._store.mark_stale_pending_clips_unknown()
            if reclaimed:
                log.warning(
                    "Канал %s: %d незавершённых попыток клипа из прошлого "
                    "запуска помечены unknown — исход неизвестен, автоматически "
                    "не пересоздаются",
                    self.channel, reclaimed,
                )
        except Exception:
            log.exception("Не удалось выполнить стартовую уборку mod_clips на канале %s", self.channel)

        while True:
            event = await self._queue.get()
            try:
                await self._create_clip(event)
            except Exception:
                log.exception("Сбой создания клипа на канале %s", self.channel)
            finally:
                self._queue.task_done()

    async def _create_clip(self, event: ClipTriggerEvent) -> None:
        # Запись создаётся ДО capture_delay_seconds-паузы и ДО обращения к
        # Helix — не после (bug-аудит 2026-08-18): если процесс падает
        # прямо во время паузы или во время самого HTTP-запроса, запись
        # уже существует в БД со status='pending' и при следующем старте
        # канала честно станет 'unknown', а не пропадёт бесследно. См.
        # докстринг миграции 024 (migrations.py) про все статусы.
        try:
            attempt_id = await self._store.create_clip_attempt(
                created_at=event.timestamp, trigger_reason=event.reason, trigger_text=event.text,
            )
        except Exception:
            # Если даже саму попытку не удалось записать — ничего не
            # остаётся, кроме как отказаться от клипа: без attempt_id
            # некуда записывать дальнейший исход, а идти в Helix без
            # персистентности значило бы вернуться к исходной проблеме
            # аудита (клип создан, но бот о нём не узнает).
            log.exception(
                "Не удалось создать запись mod_clips на канале %s — клип не запрашивается",
                self.channel,
            )
            return

        # См. AutoclipChannelConfig.capture_delay_seconds: Twitch сам решает
        # окно клипа относительно момента вызова API, поэтому единственный
        # способ захватить то, что было ДО реакции стримера — самим
        # придержать вызов create_clip() на эту паузу.
        if self.config.capture_delay_seconds > 0:
            await asyncio.sleep(self.config.capture_delay_seconds)

        try:
            access_token = await self._clip_token_manager.get_valid_access_token()
        except ClipTokenError:
            log.exception(
                "Токен для клиппинга недействителен — получите новый в панели "
                "(Settings -> Twitch: получить токен для клиппинга)"
            )
            await self._mark_failed_safely(attempt_id, error="токен для клиппинга недействителен")
            return

        result = await self._helix_client.create_clip(
            broadcaster_id=event.broadcaster_id, user_token=access_token
        )

        if result.outcome == "created":
            try:
                await self._store.mark_clip_created(
                    attempt_id, clip_id=result.clip_id, edit_url=result.edit_url
                )
            except Exception:
                # Twitch ТОЧНО подтвердил (clip_id/edit_url уже в result,
                # процесс ЖИВ) — это не неопределённость, а сбой самой
                # записи. Вторая попытка с теми же данными, отдельным
                # статусом (см. докстринг mark_clip_lost_after_success).
                log.exception(
                    "Клип создан на канале %s (id=%s, %s), но не удалось сохранить "
                    "результат в БД — записываю как lost_after_success",
                    self.channel, result.clip_id, result.edit_url,
                )
                with contextlib.suppress(Exception):
                    await self._store.mark_clip_lost_after_success(
                        attempt_id, clip_id=result.clip_id, edit_url=result.edit_url,
                        error="запись mod_clips не удалась после успешного создания клипа",
                    )
            # Кулдаун обновляется ПОСЛЕ попытки создания, а не в submit_* —
            # иначе гонка при двух триггерах, всплывших в одном тике до
            # завершения первого запроса к Helix. Выставляется независимо
            # от того, удалась ли запись в БД — клип реально создан на
            # Twitch, канал должен уйти в кулдаун в любом случае.
            self._last_clip_at = event.timestamp
            log.info(
                "Клип создан на канале %s (причина=%s, id=%s, %s)",
                event.channel, event.reason, result.clip_id, result.edit_url,
            )
        else:
            # Кулдаун НЕ выставляется при неудаче/неопределённости (стрим
            # офлайн, истёкший scope, транзиентная ошибка Helix) — иначе
            # канал уходит в полноценный cooldown_seconds как будто клип
            # реально создан, и следующий genuine-триггер молча
            # отбрасывается _in_cooldown() без единого сигнала оператору
            # (bug-аудит 2026-08-15, CRITICAL #2 — ранее не найденная
            # вторая причина инцидента "клипы не создаются на paverpapa",
            # отдельная от общего/per-channel токена). Следующий триггер
            # получает шанс попробовать снова — НЕ автоматический retry
            # этого события, а независимая новая попытка (bug-аудит
            # 2026-08-18: устойчивость к неопределённости, не
            # идемпотентность, см. докстринг ClipResult.outcome).
            log.error(
                "Не удалось создать клип на канале %s (причина=%s, исход=%s): %s",
                event.channel, event.reason, result.outcome, result.error,
            )
            if result.outcome == "failed":
                await self._mark_failed_safely(attempt_id, error=result.error)
            else:
                await self._mark_unknown_safely(attempt_id, error=result.error)

    async def _mark_failed_safely(self, attempt_id: int, *, error: str) -> None:
        """Обёртка вокруг store.mark_clip_failed — сбой самой записи здесь
        не должен уронить _consume() (тот же принцип, что try/except в
        _consume вокруг всего _create_clip, но точечно и с логом,
        объясняющим, что именно не записалось)."""
        try:
            await self._store.mark_clip_failed(attempt_id, error=error)
        except Exception:
            log.exception(
                "Не удалось записать status='failed' для попытки клипа #%d на канале %s",
                attempt_id, self.channel,
            )

    async def _mark_unknown_safely(self, attempt_id: int, *, error: str) -> None:
        """См. _mark_failed_safely. unknown здесь пишется ЖИВЫМ процессом
        (HelixClient сам классифицировал исход как неопределённый) — не
        путать со стартовой уборкой mark_stale_pending_clips_unknown,
        которая не знает причину."""
        try:
            await self._store.mark_clip_unknown(attempt_id, error=error)
        except Exception:
            log.exception(
                "Не удалось записать status='unknown' для попытки клипа #%d на канале %s",
                attempt_id, self.channel,
            )


class AutoclipHub:
    """AutoclipHub на каждый канал, по образцу ModerationHub.

    Реконсилируется с Channel Registry так же, как ModerationHub —
    включение/выключение канала в панели автоматически стартует/стопит
    автоклип. В отличие от ModerationHub, НЕ пишет process_status/pid в
    Registry — тот писатель уже есть (ModerationHub), а второй одновременно
    пишущий процесс в те же поля был бы лишней путаницей без пользы.
    """

    def __init__(
        self,
        *,
        registry_db_path: Path,
        autoclip_enabled: bool,
        channels_dir: Path | None = None,
    ) -> None:
        self._registry_db_path = registry_db_path
        self._enabled = autoclip_enabled
        # None -> дефолт load_autoclip_channel_config (config/channels/) —
        # явный параметр, а не полагание на модульную DEFAULT_CHANNELS_DIR,
        # нужен тестам: тот дефолт зафиксирован в сигнатуре функции на
        # момент импорта модуля, monkeypatch переменной его не подменяет.
        self._channels_dir = channels_dir
        self._registry: RegistryStore | None = None
        # broadcaster_id -> свой менеджер токена клиппинга — токен per-
        # channel (см. докстринг clip_token.py), не один общий на процесс:
        # Twitch принимает клип только от токена, принадлежащего именно
        # этому broadcaster'у/его модератору.
        self._clip_token_managers: dict[str, ClipTokenManager] = {}
        # broadcaster_id -> соединение для чтения mod_autoclip_settings —
        # раньше _read_settings открывало новый ModerationStore (полная
        # прогонка миграций) на каждый канал на каждом reconcile-тике
        # (RECONCILE_INTERVAL_SECONDS=10 сек), bug-аудит 2026-08-15, HIGH.
        # Держится открытым между тиками, тем же приёмом, что
        # _clip_token_managers — закрывается в _stop_channel/stop().
        self._settings_stores: dict[str, ModerationStore] = {}
        self._client_id = ""
        self._client_secret = ""
        self._helix_client: HelixClient | None = None
        self._channels: dict[str, ChannelAutoclip] = {}
        self._by_login: dict[str, str] = {}
        self._reconcile_task: asyncio.Task[None] | None = None
        self._viewer_count_task: asyncio.Task[None] | None = None
        # broadcaster_id -> последний известный viewer_count. Не трогается,
        # пока канал оффлайн или Twitch недоступен (см. _poll_viewer_counts)
        # — последнее известное значение остаётся в силе, а не сбрасывается
        # молча на "нет данных" между стримами.
        self._viewer_counts: dict[str, int] = {}

    async def start(self) -> None:
        if not self._enabled:
            log.info("AUTOCLIP_ENABLED=false — автоклип не запускается")
            return

        client_id = os.environ.get("PANEL_TWITCH_CLIENT_ID", "")
        client_secret = os.environ.get("PANEL_TWITCH_CLIENT_SECRET", "")
        if not (client_id and client_secret):
            log.info("PANEL_TWITCH_CLIENT_ID/SECRET не заданы — автоклип не запускается")
            return
        self._client_id = client_id
        self._client_secret = client_secret

        # Токен клиппинга теперь per-channel (mod.<broadcaster_id>.db, см.
        # clip_token.py) — Hub стартует независимо от того, настроен ли он
        # хоть на одном канале; _start_channel решает по каждому каналу
        # отдельно, пропуская те, где токена ещё нет.
        self._helix_client = HelixClient(client_id, client_secret)
        self._registry = RegistryStore(str(self._registry_db_path))
        await self._registry.connect()
        await self._reconcile()
        self._reconcile_task = asyncio.create_task(self._reconcile_loop(), name="autoclip-reconcile")
        self._viewer_count_task = asyncio.create_task(
            self._viewer_count_loop(), name="autoclip-viewer-count"
        )
        log.info("Автоклип запущен (каналов: %d)", len(self._channels))

    async def stop(self) -> None:
        if self._reconcile_task is not None:
            self._reconcile_task.cancel()
            await asyncio.gather(self._reconcile_task, return_exceptions=True)
            self._reconcile_task = None
        if self._viewer_count_task is not None:
            self._viewer_count_task.cancel()
            await asyncio.gather(self._viewer_count_task, return_exceptions=True)
            self._viewer_count_task = None
        for autoclip in list(self._channels.values()):
            await autoclip.stop()
        self._channels.clear()
        self._by_login.clear()
        if self._registry is not None:
            await self._registry.close()
            self._registry = None
        for manager in self._clip_token_managers.values():
            await manager.close()
        self._clip_token_managers.clear()
        for store in self._settings_stores.values():
            await store.close()
        self._settings_stores.clear()
        if self._helix_client is not None:
            await self._helix_client.close()
            self._helix_client = None

    # -- вход ------------------------------------------------------------

    def submit_chat_message(self, *, channel: str, author_id: str, text: str, timestamp: float) -> None:
        login = channel.lstrip("#").lower()
        autoclip = self._channels.get(self._by_login.get(login, ""))
        if autoclip is not None:
            autoclip.submit_chat_message(author_id=author_id, text=text, timestamp=timestamp)

    def submit_voice_command(self, *, channel: str, text: str, timestamp: float) -> None:
        login = channel.lstrip("#").lower()
        autoclip = self._channels.get(self._by_login.get(login, ""))
        if autoclip is not None:
            autoclip.submit_voice_command(text=text, timestamp=timestamp)

    @property
    def active_channels(self) -> list[str]:
        return sorted(self._by_login)

    # -- число зрителей для авто-подстройки порога --------------------------

    async def _viewer_count_loop(self) -> None:
        while True:
            await asyncio.sleep(VIEWER_COUNT_POLL_INTERVAL_SECONDS)
            try:
                await self._poll_viewer_counts()
            except Exception:
                log.exception("Ошибка опроса числа зрителей — продолжаю следующий тик")

    async def _poll_viewer_counts(self) -> None:
        """Опрашивает Twitch только за каналами, где реально используется
        auto_scale (self._channels уже живые ChannelAutoclip с
        config.burst.auto_scale_enabled) — не тратит Helix-запросы на
        каналы, где авто-режим выключен и порог фиксированный.

        Оффлайн-канал (HelixStream.is_live=False) НЕ удаляется из
        self._viewer_counts — последнее известное число зрителей остаётся
        актуальным для _apply_auto_scale до следующего успешного опроса,
        см. её докстринг."""
        assert self._helix_client is not None
        targets = [
            bid for bid, autoclip in self._channels.items()
            if autoclip.config.burst.auto_scale_enabled
        ]
        if not targets:
            return

        streams = await self._helix_client.get_streams(broadcaster_ids=targets)
        for stream in streams:
            if not stream.is_live:
                continue
            self._viewer_counts[stream.broadcaster_id] = stream.viewer_count
            await self._write_viewer_count(stream.broadcaster_id, stream.viewer_count)

    async def _write_viewer_count(self, broadcaster_id: str, viewer_count: int) -> None:
        store = ModerationStore(str(paths.mod_db(broadcaster_id)))
        try:
            await store.connect()
            await store.update_autoclip_viewer_count(viewer_count)
        except Exception:
            log.exception(
                "Не удалось сохранить число зрителей канала %s — используется только в памяти",
                broadcaster_id,
            )
        finally:
            await store.close()

    # -- сверка с Registry -------------------------------------------------

    async def _reconcile_loop(self) -> None:
        while True:
            await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
            try:
                await self._reconcile()
            except Exception:
                log.exception("Ошибка сверки каналов автоклипа — продолжаю следующий тик")

    async def _reconcile(self) -> None:
        assert self._registry is not None
        channels = await self._registry.list_channels(status="active")
        wanted = {c.broadcaster_id: c for c in channels if c.desired_state == "running"}

        for broadcaster_id in list(self._channels):
            if broadcaster_id not in wanted:
                await self._stop_channel(broadcaster_id)

        for broadcaster_id, record in wanted.items():
            login = record.login.lstrip("#").lower()
            if broadcaster_id not in self._channels:
                await self._start_channel(broadcaster_id=broadcaster_id, login=login)
            elif self._channels[broadcaster_id].channel != login:
                # Канал мог быть переименован — login меняется, id нет.
                self._by_login.pop(self._channels[broadcaster_id].channel, None)
                self._channels[broadcaster_id].channel = login
                self._by_login[login] = broadcaster_id

        await self._sync_overrides()

    async def _sync_overrides(self) -> None:
        """Живые настройки из панели (mod_autoclip_settings) поверх YAML —
        тот же принцип, что ChannelPipeline._poll_state_sync для Attack
        Mode: панель пишет в mod.<broadcaster_id>.db, здесь раз в
        RECONCILE_INTERVAL_SECONDS перечитываем и применяем к уже живым
        ChannelAutoclip (enabled и пороги — раздельно, apply_config не
        трогает enabled, см. ChannelAutoclip.apply_config)."""
        for broadcaster_id, autoclip in list(self._channels.items()):
            yaml_config = self._load_yaml_config(autoclip.channel)
            settings = await self._read_settings(broadcaster_id)

            enabled = yaml_config.enabled if settings.enabled is None else settings.enabled
            if autoclip.enabled != enabled:
                autoclip.enabled = enabled
                log.info(
                    "Автоклип канала %s переключён из панели: enabled=%s", autoclip.channel, enabled
                )

            # enabled=autoclip.enabled (не пересчитанный выше enabled) —
            # поле нужно только чтобы собрать валидный AutoclipChannelConfig,
            # реальное вкл/выкл живёт в autoclip.enabled отдельно (см.
            # ChannelAutoclip.apply_config), сравнение объектов ниже не
            # должно зависеть от него.
            new_config = _merge_config(yaml_config, settings, enabled=autoclip.enabled)
            new_config = _apply_auto_scale(
                new_config, viewer_count=self._viewer_counts.get(broadcaster_id)
            )
            if new_config != autoclip.config:
                autoclip.apply_config(new_config)
                log.info("Пороги автоклипа канала %s обновлены из панели", autoclip.channel)

    def _load_yaml_config(self, login: str) -> AutoclipChannelConfig:
        if self._channels_dir is not None:
            return load_autoclip_channel_config(login, channels_dir=self._channels_dir)
        return load_autoclip_channel_config(login)

    async def _read_settings(self, broadcaster_id: str) -> AutoclipSettings:
        """Настройки канала из mod_autoclip_settings — пустые (все поля
        None) при сбое чтения (БД ещё не создана, диск недоступен), не
        исключение: временная недоступность не должна валить reconcile-цикл
        для остальных каналов.

        Соединение из self._settings_stores переиспользуется между тиками
        (см. докстринг поля в __init__) — при сбое чтения (например, файл
        БД временно недоступен) кэш сбрасывается, чтобы следующий тик
        начал с чистого соединения, а не повторял ошибку на протухшем."""
        store = self._settings_stores.get(broadcaster_id)
        if store is None:
            store = ModerationStore(str(paths.mod_db(broadcaster_id)))
            try:
                await store.connect()
            except Exception:
                log.exception("Не удалось открыть БД настроек автоклипа канала %s", broadcaster_id)
                return AutoclipSettings(enabled=None, updated_by="", updated_at=0.0)
            self._settings_stores[broadcaster_id] = store

        try:
            return await store.get_autoclip_settings()
        except Exception:
            log.exception("Не удалось прочитать настройки автоклипа канала %s", broadcaster_id)
            self._settings_stores.pop(broadcaster_id, None)
            await store.close()
            return AutoclipSettings(enabled=None, updated_by="", updated_at=0.0)

    async def _start_channel(self, *, broadcaster_id: str, login: str) -> None:
        assert self._helix_client is not None
        yaml_config = self._load_yaml_config(login)
        settings = await self._read_settings(broadcaster_id)
        enabled = yaml_config.enabled if settings.enabled is None else settings.enabled

        if not enabled:
            # Ни YAML, ни панель не включили автоклип на этом канале —
            # ChannelAutoclip не создаётся вовсе (экономит consumer-задачу
            # и очередь для каналов, где автоклип не используется). Если
            # панель включит его позже, следующий _reconcile увидит канал
            # всё ещё отсутствующим в self._channels и вызовет
            # _start_channel заново — на этот раз enabled уже будет True.
            return

        manager = await load_clip_token_manager(
            client_id=self._client_id,
            client_secret=self._client_secret,
            db_path=str(paths.mod_db(broadcaster_id)),
        )
        if manager is None:
            log.info(
                "Токен для клиппинга не настроен на канале %s — автоклип не запущен "
                "(получите токен в панели, экран Автоклип: получить токен для клиппинга)",
                login,
            )
            return

        # _read_settings(broadcaster_id) выше уже должно было открыть и
        # закэшировать store в self._settings_stores — переиспользуем то же
        # соединение для персистентности клипов (bug-аудит 2026-08-18), не
        # открываем новое. Ключа может не быть, если store.connect() внутри
        # _read_settings упал (БД временно недоступна, см. её докстринг) —
        # тогда тот же паттерн, что ниже для manager is None: не запускаем
        # канал сейчас, следующий _reconcile-тик попробует снова.
        store = self._settings_stores.get(broadcaster_id)
        if store is None:
            log.info(
                "БД канала %s временно недоступна — автоклип не запущен на этом тике",
                login,
            )
            return

        config = _merge_config(yaml_config, settings, enabled=enabled)
        config = _apply_auto_scale(config, viewer_count=self._viewer_counts.get(broadcaster_id))
        autoclip = ChannelAutoclip(
            channel=login,
            broadcaster_id=broadcaster_id,
            config=config,
            clip_token_manager=manager,
            helix_client=self._helix_client,
            store=store,
        )
        autoclip.start()
        self._channels[broadcaster_id] = autoclip
        self._by_login[login] = broadcaster_id
        self._clip_token_managers[broadcaster_id] = manager
        log.info("Автоклип канала запущен (broadcaster_id=%s, канал=%s)", broadcaster_id, login)

    async def _stop_channel(self, broadcaster_id: str) -> None:
        autoclip = self._channels.pop(broadcaster_id)
        self._by_login.pop(autoclip.channel, None)
        self._viewer_counts.pop(broadcaster_id, None)
        await autoclip.stop()
        manager = self._clip_token_managers.pop(broadcaster_id, None)
        if manager is not None:
            await manager.close()
        store = self._settings_stores.pop(broadcaster_id, None)
        if store is not None:
            await store.close()
        log.info("Автоклип канала остановлен (broadcaster_id=%s)", broadcaster_id)
