"""Единственная точка входа движка модерации: observe(event) -> Verdict.

Оркестрирует цепочку из архитектуры (docs/moderation-plan.md, раздел 3):

    Normalizer -> Feature Extraction -> Detection Engine -> Cluster Detection
    -> Risk Score -> Confidence -> Moderation Policy -> Audit Logger

ModerationEngine ничего не исполняет в Twitch — только вычисляет Verdict и
(если передан store) пишет аудит. Действия по вердикту выполняет executor.py
(этап 7), причём только когда это разрешено режимом (SHADOW/SIMULATION
никогда не действуют) и подтверждено дальше по цепочке (модератором или
явно включённым автоправилом).

Один экземпляр ModerationEngine держит состояние ОДНОГО канала (окно чата,
кеш состояний пользователей) между вызовами observe() — создаётся один раз
на запуск бота, а не на сообщение.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import replace

from cigilbot.content import policy as content_policy
from cigilbot.content.detector import ContentRule, check_content
from cigilbot.detectors import run_all
from cigilbot.detectors.base import DetectionContext
from cigilbot.domain import policy
from cigilbot.domain.clustering import find_clusters
from cigilbot.domain.confidence import confidence as compute_confidence
from cigilbot.domain.config import ChannelProfile, ModerationConfig
from cigilbot.domain.normalize import MessageFingerprint, fingerprint
from cigilbot.domain.patterns import Pattern, match_patterns
from cigilbot.domain.scoring import families_triggered, risk_score
from cigilbot.domain.types import (
    Action,
    ChannelContext,
    ChatEvent,
    ClusterInfo,
    Mode,
    Sensitivity,
    Signal,
    TrustLevel,
    UserState,
    Verdict,
)
from cigilbot.domain.window import SlidingWindow
from cigilbot.integrations.alerts import send_cluster_alert, send_escalation
from cigilbot.storage.store import (
    AttackModeStatus,
    ContentSettings,
    DiscordWebhookConfig,
    GiveawayModeStatus,
    ModerationStore,
)

log = logging.getLogger("moderation.engine")

ENGINE_VERSION = "1"

# Сколько секунд после реального IRC-события рейда (USERNOTICE msg-id=raid)
# ChannelContext.is_raid остаётся True (FALSE-BAN-001 аудита). 10 минут —
# достаточно, чтобы покрыть типичный всплеск новых зрителей сразу после
# рейда (первые сообщения, знакомство с чатом), но не настолько долго,
# чтобы случайно занизить confidence для атаки, начавшейся уже после того,
# как реальный рейд давно закончился.
RAID_CONTEXT_SECONDS = 600.0

# Порог эвристики "это хайп-момент?" — сообщений/мин в канале, выше
# которого context_factor начинает применяться, даже если ни Attack Mode,
# ни Giveaway Mode, ни реальный рейд не активны. Подобрано с запасом выше
# normal-чата (см. burst.py: типичный порог всплеска канала — 30 сообщений
# за 10 сек, т.е. 180/мин) — это ниже, специально: hype должен ловить
# оживление чата ДО того, как отдельные burst-сигналы начнут срабатывать
# на полную, чтобы context_factor успел применить скидку раньше.
HYPE_MESSAGES_PER_MINUTE_THRESHOLD = 90.0

# BUG-004 аудита: self._users раньше рос без ограничений на весь процесс
# бота — многомесячный аптайм на активном канале означал неограниченную
# утечку памяти. LRU-кеш на разумный запас активных чаттеров; store уже
# был единственным источником правды при промахе кеша (см.
# _get_or_create_user), так что вытеснение старых записей не теряет данные,
# только требует одного лишнего похода в БД при возврате вытесненного юзера.
MAX_CACHED_USERS = 20_000

# Эскалация при повторных атаках (направление 01 master-plan.html): 3+
# новых кластера за 1 час значит, что обычные пороги детекции не
# справляются с волной — сигнал отдельный и громче обычного алерта на
# кластер, не его замена.
ESCALATION_CLUSTER_THRESHOLD = 3
ESCALATION_WINDOW_SECONDS = 3600.0

# Порог confidence для Discord-алерта на новый кластер (направление 01
# master-plan.html) настраивается per-channel через панель
# (mod_discord_webhook.alert_confidence_threshold), не жёсткая константа
# здесь — см. DiscordWebhookConfig.alert_confidence_threshold в store.py
# про дефолт. Кластеры с низким confidence всё равно видны на экране Live
# панели независимо от порога — он решает только "отвлекать ли алертом".


def _window_horizon(config: ModerationConfig) -> float:
    """Сколько секунд истории реально нужно держать в памяти.

    Берём максимум из всех окон, которые запрашивают детекторы и
    кластеризация, плюс запас — иначе самый долгий из них будет молча
    получать урезанные данные из-за того, что SlidingWindow вытеснил
    сообщения раньше, чем они стали не нужны.
    """
    return (
        max(
            config.cluster.window_seconds,
            config.detectors.duplicate.window_seconds,
            config.detectors.links.shared_link_window_seconds,
            config.detectors.burst.channel_window_seconds,
            config.detectors.burst.user_window_seconds,
        )
        + 10.0
    )


class ModerationEngine:
    def __init__(
        self,
        config: ModerationConfig,
        channel_profile: ChannelProfile,
        store: ModerationStore | None = None,
        *,
        mode: Mode = Mode.SHADOW,
    ) -> None:
        self._config = config
        self._channel_profile = channel_profile
        self._store = store
        self._mode = mode
        self._window = SlidingWindow(max_age_seconds=_window_horizon(config))
        # Кеш в памяти — быстрый путь для детекторов и кластеризации внутри
        # одной сессии бота; переживает между сообщениями, но не рестарт
        # процесса (это даёт store, см. _get_or_create_user). OrderedDict с
        # move_to_end на каждом обращении + вытеснение самых старых сверх
        # MAX_CACHED_USERS (BUG-004 аудита) — без этого self._users рос без
        # границ на весь процесс бота.
        self._users: OrderedDict[str, UserState] = OrderedDict()
        # Bot Pattern Library (этап 9b) — загружается явно через
        # reload_patterns(), не на каждое сообщение: паттерны меняются через
        # панель редко, а список короткий, перечитывать БД на каждый
        # observe() было бы лишней задержкой без пользы. Пусто по умолчанию,
        # движок без вызова reload_patterns() просто не подставляет pattern_id.
        self._patterns: list[Pattern] = []
        # Attack Mode (этап 9c) — кешируем саму запись (не bool), чтобы на
        # каждом observe() дешёво сравнивать expires_at с текущим временем
        # БЕЗ похода в БД; синхронизируется через sync_attack_mode() при
        # включении/выключении панелью, а не перечитывается на каждое сообщение.
        self._attack_mode: AttackModeStatus | None = None
        # Giveaway Mode (FALSE-BAN-001 аудита) — тот же кеш-паттерн, что
        # Attack Mode выше, но противоположный по эффекту: снижает, а не
        # повышает чувствительность на время розыгрыша.
        self._giveaway_mode: GiveawayModeStatus | None = None
        # Реальный IRC-рейд (USERNOTICE msg-id=raid) — main.py вызывает
        # mark_raid_started() из своего обработчика события, движок сам
        # ничего не подписывает (у него нет доступа к twitchio Client).
        # Раздельно от Attack/Giveaway Mode: это не переключатель "вкл/выкл
        # до явной команды", а разовое событие с фиксированным окном
        # действия (raid_context_seconds), после которого сигнал сам гаснет
        # без необходимости отдельного deactivate.
        self._raid_started_at: float | None = None
        # Feedback loop (этап 9d) — fp_penalty на сигнал, пересчитывается
        # периодически из mod_feedback (тот же явный reload-паттерн, что
        # patterns/attack_mode: перечитывать историю FP на каждое сообщение
        # было бы N запросов к БД на каждый observe(), где N — число
        # сработавших сигналов). Пусто по умолчанию -> confidence() получает
        # fp_penalty=0.0, как и раньше до этого подэтапа.
        self._fp_penalties: dict[str, float] = {}
        # Content Rules (Rule Engine, cigilbot/content/) — тот же явный
        # reload-паттерн, что Pattern Library выше: список фраз меняется
        # через панель редко, перечитывать БД на каждое сообщение было бы
        # лишней задержкой. Пусто по умолчанию -> check_content() ничего не
        # находит, пока reload_content_rules() не вызван хотя бы раз.
        self._content_rules: tuple[ContentRule, ...] = ()
        # ContentSettings.enabled=False по умолчанию (см. миграцию 014) —
        # то же значение, что даёт get_content_settings() на пустой БД, до
        # первого sync_content_settings(). Двойная защита режима
        # наблюдателя: даже если вызывающий код забудет вызвать sync
        # (движок без store, тесты) — content_moderation_enabled остаётся
        # False, а не неопределённым.
        self._content_settings = ContentSettings(enabled=False, updated_by="", updated_at=0.0)
        # Cross-Channel Bot Fingerprint (направление 03 master-plan.html) —
        # снимок известных забаненных user_id across каналов оператора.
        # В отличие от остальных кешей выше, движок не читает fingerprints.db
        # сам (он про ОДИН канал и не владеет across-каналов store) —
        # ModerationHub читает раз в тик и раздаёт снимок каждому движку
        # через sync_known_bad_actors().
        self._known_bad_actor_ids: frozenset[str] = frozenset()

    def sync_known_bad_actors(self, user_ids: frozenset[str]) -> None:
        self._known_bad_actor_ids = user_ids

    async def reload_content_rules(self) -> None:
        """Перечитывает включённые правила словаря из store. Вызывается
        явно — панелью после добавления/удаления правила, или периодически
        внешним кодом (main.py, тот же поллер, что reload_patterns())."""
        if self._store is not None:
            self._content_rules = await self._store.list_content_rules(enabled_only=True)

    async def sync_content_settings(self) -> None:
        """Перечитывает выключатель content-модерации из store — вызывается
        явно после изменения через панель (тот же паттерн, что
        sync_attack_mode())."""
        if self._store is not None:
            self._content_settings = await self._store.get_content_settings()

    async def reload_patterns(self) -> None:
        """Перечитывает включённые паттерны из store. Вызывается явно —
        панелью после создания/изменения паттерна, или периодически внешним
        кодом (main.py), а не автоматически на каждое сообщение."""
        if self._store is not None:
            self._patterns = await self._store.list_patterns(enabled_only=True)

    async def reload_fp_penalties(self) -> None:
        """Пересчитывает fp_penalty для каждого известного конфигу сигнала
        по истории mod_feedback. Вызывается периодически (main.py, тот же
        поллер, что reload_patterns()/sync_attack_mode()) — не на каждое
        сообщение."""
        if self._store is None:
            return
        self._fp_penalties = {
            name: await self._store.get_signal_fp_penalty(name)
            for name in self._config.signal_weights
        }

    async def sync_attack_mode(self) -> None:
        """Перечитывает текущий статус Attack Mode из store — вызывается
        явно после activate/deactivate через панель (см. reload_patterns()
        для того же паттерна с Pattern Library)."""
        if self._store is not None:
            self._attack_mode = await self._store.get_active_attack_mode()

    @property
    def attack_mode_active(self) -> bool:
        """Дешёвая проверка БЕЗ похода в БД — сравнивает закешированный
        expires_at с текущим временем. Может расходиться с БД на секунды
        между sync_attack_mode() вызовами (тот же компромисс, что и у
        Pattern Library) — не проблема для panic-режима, который включают
        вручную и который живёт минуты, не секунды."""
        return self._attack_mode is not None and self._attack_mode.expires_at > time.time()

    async def sync_giveaway_mode(self) -> None:
        """Перечитывает текущий статус Giveaway Mode из store — тот же
        явный reload-паттерн, что sync_attack_mode() (см. FALSE-BAN-001
        аудита)."""
        if self._store is not None:
            self._giveaway_mode = await self._store.get_active_giveaway_mode()

    @property
    def giveaway_mode_active(self) -> bool:
        return self._giveaway_mode is not None and self._giveaway_mode.expires_at > time.time()

    def mark_raid_started(self, *, now: float | None = None) -> None:
        """Вызывается main.py из обработчика реального IRC-события Twitch
        (USERNOTICE msg-id=raid) — движок не подписывается на события сам
        (нет доступа к twitchio Client, см. докстринг модуля про
        detection/action). Отдельно от Attack/Giveaway Mode: разовая метка
        времени с фиксированным окном действия (RAID_CONTEXT_SECONDS), не
        переключатель, который нужно явно выключать."""
        self._raid_started_at = now if now is not None else time.time()

    @property
    def raid_active(self) -> bool:
        if self._raid_started_at is None:
            return False
        return time.time() - self._raid_started_at <= RAID_CONTEXT_SECONDS

    def channel_activity(self, *, now: float | None = None) -> tuple[float, int]:
        """(сообщений/мин, уникальных чаттеров за последнюю минуту) —
        публичный доступ к метрикам SlidingWindow, нужен вызывающему коду
        (main.py) для эвристики "это хайп-момент?" (FALSE-BAN-001 аудита:
        ChannelContext.is_hype раньше никогда не выставлялся, потому что
        main.py не имел доступа к внутреннему self._window движка, чтобы
        решить, когда его включать). Окно — те же 60 сек, что unique_chatters
        обычно используется в клиентском коде для "последняя минута"."""
        now = now if now is not None else time.time()
        rate = self._window.channel_rate_per_minute(60.0, now=now)
        unique = len(self._window.unique_chatters(60.0, now=now))
        return rate, unique

    def _auto_channel_context(self, now: float) -> ChannelContext:
        """Строит ChannelContext из собственного состояния движка, когда
        вызывающий код (main.py) не передал контекст явно (FALSE-BAN-001
        аудита). is_raid и is_giveaway взаимоисключающие по смыслу с hype в
        ChannelContext.label (см. types.py) — если активны рейд/розыгрыш,
        is_hype не выставляем поверх них, это не добавляет новой информации
        и не меняет context_factor (у raid/giveaway приоритет в _context_factor)."""
        rate, unique = self.channel_activity(now=now)
        is_raid = self.raid_active
        is_giveaway = self.giveaway_mode_active
        is_hype = (
            not is_raid
            and not is_giveaway
            and rate >= HYPE_MESSAGES_PER_MINUTE_THRESHOLD
        )
        return ChannelContext(
            is_raid=is_raid,
            is_giveaway=is_giveaway,
            is_hype=is_hype,
            messages_per_minute=rate,
            unique_chatters_last_minute=unique,
        )

    async def update_account_age(self, user_id: str, created_at: float) -> None:
        """Записывает account_created_at, полученный от Helix уже ПОСЛЕ
        первого вердикта (см. Verdict.is_provisional), и в БД, и в
        in-memory кэш self._users, если пользователь там уже есть.

        Без этого второй шаг сам по себе бесполезен: _get_or_create_user
        ниже отдаёт объект из self._users, если он уже закэширован, и
        никогда не перечитывает БД повторно — значит store.py
        ::set_account_created_at() сам по себе обновил бы только строку
        в SQLite, а движок продолжал бы видеть account_created_at=None
        в памяти для каждого следующего сообщения активного чаттера,
        пока тот не выпадет из LRU-кэша (MAX_CACHED_USERS)."""
        if self._store is not None:
            await self._store.set_account_created_at(user_id, created_at)
        cached = self._users.get(user_id)
        if cached is not None:
            cached.account_created_at = created_at

    async def _get_or_create_user(self, event: ChatEvent) -> UserState:
        user = self._users.get(event.user_id)
        if user is not None:
            self._users.move_to_end(event.user_id)
        if user is None and self._store is not None:
            user = await self._store.get_user_state(event.user_id)
        if user is None:
            user = UserState(
                user_id=event.user_id,
                login=event.login,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                message_count=0,
            )
        # Сообщения одного пользователя приходят по одному TCP-соединению
        # IRC строго по порядку, поэтому конкурентная порча этого счётчика
        # двумя одновременными вызовами observe() для одного user_id не
        # ожидается — блокировку ради этого не заводим.
        user.login = event.login
        user.last_seen = event.timestamp
        user.message_count += 1

        # Автоматическое доверие по истории (этап 9a): только UNKNOWN -> REGULAR,
        # никогда не понижаем и не трогаем TRUSTED/PRIVILEGED, выставленные
        # вручную или через is_privileged — это односторонний подъём.
        trust_cfg = self._config.trust
        if (
            trust_cfg.enabled
            and user.trust_level == TrustLevel.UNKNOWN
            and user.qualifies_for_regular(
                min_messages=trust_cfg.min_messages_for_regular,
                min_days=trust_cfg.min_days_for_regular,
                now=event.timestamp,
            )
        ):
            user.trust_level = TrustLevel.REGULAR

        self._users[event.user_id] = user
        self._users.move_to_end(event.user_id)
        if len(self._users) > MAX_CACHED_USERS:
            self._users.popitem(last=False)
        return user

    def _notify_new_cluster(self, cluster: ClusterInfo) -> None:
        """Ставит отправку Discord-алерта в фон и сразу возвращает
        управление — observe() не ждёт сеть (CLAUDE.md: чтение чата никогда
        не ждёт). Сам webhook читается из store внутри задачи, а не здесь,
        по той же причине: ещё один поход в БД не должен блокировать
        observe(). Порог confidence тоже проверяется внутри задачи — он
        настраивается per-channel через панель (mod_discord_webhook.
        alert_confidence_threshold), не жёсткая константа, значит без похода
        в БД сравнивать не с чем."""
        if self._store is None:
            return
        asyncio.create_task(self._send_new_cluster_alert(cluster))

    async def _send_new_cluster_alert(self, cluster: ClusterInfo) -> None:
        assert self._store is not None
        try:
            webhook = await self._store.get_discord_webhook()
        except Exception:
            log.exception("Не удалось прочитать настройки Discord-webhook")
            return
        # Эскалация считается независимо от того, прошёл ли ЭТОТ кластер
        # confidence-фильтр алерта, и независимо от enabled/наличия webhook:
        # "3+ атаки за час" истинно вне зависимости от того, настроены ли
        # уведомления — count_recent_new_clusters всегда доступен через
        # store напрямую, без похода в webhook.
        if webhook is not None:
            await self._maybe_send_escalation(webhook)
        if webhook is None or not webhook.enabled:
            return
        if cluster.confidence < webhook.alert_confidence_threshold:
            return
        await send_cluster_alert(webhook, cluster, channel=self._channel_profile.channel)

    async def _maybe_send_escalation(self, webhook: DiscordWebhookConfig) -> None:
        """Эскалация при повторных атаках (направление 01 master-plan.html):
        ESCALATION_CLUSTER_THRESHOLD+ новых кластеров за ESCALATION_WINDOW_SECONDS
        сигналят, что обычные пороги детекции не справляются с волной, не с
        единичным всплеском — план явно называет это "алертится отдельно",
        а не дублированием обычного алерта на кластер.

        Cooldown через last_escalation_sent_at — без него 4-й, 5-й, 6-й
        кластер сверх порога слали бы новую эскалацию на каждый, хотя план
        просит один алерт на волну."""
        assert self._store is not None
        now = time.time()
        if (
            webhook.last_escalation_sent_at is not None
            and now - webhook.last_escalation_sent_at < ESCALATION_WINDOW_SECONDS
        ):
            return
        count = await self._store.count_recent_new_clusters(since=now - ESCALATION_WINDOW_SECONDS)
        if count < ESCALATION_CLUSTER_THRESHOLD:
            return
        await send_escalation(
            webhook,
            channel=self._channel_profile.channel,
            cluster_count=count,
            window_hours=ESCALATION_WINDOW_SECONDS / 3600,
        )
        await self._store.mark_escalation_sent(sent_at=now)

    async def observe(
        self, event: ChatEvent, *, channel_context: ChannelContext | None = None
    ) -> Verdict:
        # FALSE-BAN-001 аудита: раньше main.py никогда не передавал сюда
        # channel_context, поэтому раздел confidence.py::_context_factor и
        # скидка burst.py::is_special для рейда/розыгрыша/хайпа не
        # срабатывали ни разу в проде — только в тестах, где вызывающий код
        # явно строит ChannelContext(is_raid=True) руками. Теперь, если
        # вызывающий код не передал свой контекст явно (обычный путь из
        # main.py), движок строит его сам: is_raid — из реального IRC-события
        # (mark_raid_started), is_giveaway — из ручного Giveaway Mode
        # (панель), is_hype — из эвристики по фактической скорости чата.
        # Явно переданный channel_context (тесты, будущие вызывающие с более
        # точным знанием контекста) полностью уважается и не переопределяется.
        #
        # observe() — диспетчер, стадии конвейера (docs/moderation-plan.md,
        # раздел 3: Normalizer -> Feature Extraction -> Detection Engine ->
        # Cluster Detection -> Risk Score -> Confidence -> Moderation Policy
        # -> Audit Logger) вынесены в именованные приватные методы ниже —
        # порядок вызовов и все обоснования конкретных решений сохранены
        # дословно на местах, где они были (architecture-аудит 2026-08-15,
        # MEDIUM #15: 149-строчный observe() затруднял точечное тестирование
        # отдельных стадий и требовал читать весь метод целиком на любое
        # изменение одной стадии).
        channel_context = channel_context or self._auto_channel_context(event.timestamp)
        fp = fingerprint(event.text)
        user = await self._get_or_create_user(event)

        if self._store is not None:
            await self._store.upsert_user(event)

        signals, own_cluster = self._run_detection_and_clustering(
            event, fp, user, channel_context
        )
        score, conf = self._score_and_assess_confidence(
            signals, user, own_cluster, channel_context
        )
        families = families_triggered(signals)
        action, blocked_by, reason = self._decide_action(score, conf, signals, families, user, event)

        own_cluster = self._match_cluster_pattern(own_cluster)
        stable_cluster_id = await self._persist_cluster(own_cluster)

        verdict = self._build_verdict(
            event, score, conf, signals, families, action, reason, stable_cluster_id, blocked_by, user
        )

        message_id = await self._persist(verdict, event, fp)
        await self._check_content(event, user, message_id=message_id)
        return verdict

    def _run_detection_and_clustering(
        self,
        event: ChatEvent,
        fp: MessageFingerprint,
        user: UserState,
        channel_context: ChannelContext,
    ) -> tuple[list[Signal], ClusterInfo | None]:
        detection_ctx = DetectionContext(
            event=event,
            fingerprint=fp,
            user=user,
            window=self._window,
            config=self._config,
            channel_profile=self._channel_profile,
            channel_context=channel_context,
            known_bad_actor_ids=self._known_bad_actor_ids,
        )
        signals: list[Signal] = list(run_all(detection_ctx))

        # Детекторы выше оценивают состояние окна ДО этого сообщения
        # (иначе burst.py считал бы текущее сообщение вместе с самим собой
        # как "уже случившийся" всплеск). Кластеризация, наоборот, должна
        # видеть его — окно пополняем строго между этими двумя шагами.
        self._window.add(event, fp)

        # Кластеризация на каждое сообщение — O(размер окна²); при реальной
        # атаке в сотни сообщений это всё ещё быстро (окна секунды-минуты),
        # но если станет узким местом, первый кандидат на оптимизацию —
        # считать кластеры раз в N сообщений/секунд, а не на каждое.
        clusters = find_clusters(
            self._window,
            self._config,
            user_states=self._users,
            channel_context=channel_context,
            now=event.timestamp,
        )
        own_cluster = next((c for c in clusters if event.user_id in c.user_ids), None)
        if own_cluster is not None:
            signals.extend(own_cluster.signals)

        return signals, own_cluster

    def _score_and_assess_confidence(
        self,
        signals: list[Signal],
        user: UserState,
        own_cluster: ClusterInfo | None,
        channel_context: ChannelContext,
    ) -> tuple[int, float]:
        # Attack Mode (этап 9c) — только повышает Sensitivity для расчёта
        # risk_score, как и AGGRESSIVE. Не трогает MIN_FAMILIES_FOR_BAN и
        # confidence-пороги в policy.py — тот инвариант заперт константой,
        # физически недостижим отсюда независимо от режима.
        sensitivity = Sensitivity.ATTACK if self.attack_mode_active else self._config.sensitivity
        score = risk_score(
            signals,
            self._config,
            sensitivity=sensitivity,
            regular_user=user.trust_level == TrustLevel.REGULAR,
        )
        # Feedback loop (этап 9d): самое ненадёжное из сработавших правил
        # определяет итоговую скидку confidence — берём МАКСИМАЛЬНЫЙ
        # fp_penalty среди сигналов, а не средний. Средний размыл бы сигнал
        # с высокой историей ошибок среди остальных, надёжных; максимум —
        # консервативнее и соответствует духу false-positive-guard'а
        # (раздел 9 ТЗ: лучше пропустить, чем ошибочно понизить доверие
        # к системе целиком).
        fp_penalty = max((self._fp_penalties.get(s.name, 0.0) for s in signals), default=0.0)
        conf = compute_confidence(
            signals,
            self._config,
            channel_context,
            sample_size=own_cluster.size if own_cluster is not None else 1,
            fp_penalty=fp_penalty,
        )
        return score, conf

    def _decide_action(
        self,
        score: int,
        conf: float,
        signals: list[Signal],
        families: int,
        user: UserState,
        event: ChatEvent,
    ) -> tuple[Action, str, str]:
        action, blocked_by = policy.decide(
            risk_score=score,
            confidence=conf,
            families_triggered=families,
            config=self._config,
            user=user,
            event=event,
            is_provisional=user.account_created_at is None,
        )
        reason = policy.build_reason(action, tuple(signals), blocked_by)
        return action, blocked_by, reason

    def _match_cluster_pattern(self, own_cluster: ClusterInfo | None) -> ClusterInfo | None:
        # Bot Pattern Library (этап 9b) — классифицирует уже готовый
        # вердикт/кластер названием шаблона, ничего не пересчитывает и не
        # может изменить action/risk/confidence выше.
        if own_cluster is None:
            return None
        cluster_pattern = match_patterns(own_cluster, self._patterns)
        if cluster_pattern is not None:
            return replace(own_cluster, pattern_id=cluster_pattern.id)
        return own_cluster

    async def _persist_cluster(self, own_cluster: ClusterInfo | None) -> int | None:
        # Стабильный cluster_id ДО создания Verdict (BUG-002 аудита):
        # clustering.find_clusters() пересчитывает состав кластера заново на
        # каждое сообщение и выдаёт локальный счётчик id, стартующий с 1 при
        # каждом вызове — сохранять его в Verdict.cluster_id напрямую значило
        # бы, что панель видит новый "кластер" почти на каждое сообщение
        # атаки, хотя реально это один растущий инцидент. Со store —
        # upsert_cluster_by_members() находит уже открытый активный кластер
        # по общим участникам и обновляет ЕГО, возвращая тот же id, что был
        # выдан при первом обнаружении. Без store (SHADOW-тесты, replay.py)
        # используем локальный id как раньше — стабильность через процессы
        # тогда всё равно недостижима.
        if own_cluster is None:
            return None
        stable_cluster_id = own_cluster.cluster_id
        if self._store is None:
            return stable_cluster_id
        try:
            stable_cluster_id, is_new_cluster = await self._store.upsert_cluster_by_members_ex(
                own_cluster
            )
        except Exception:
            log.exception("Не удалось сохранить/обновить кластер в БД")
        else:
            if is_new_cluster:
                self._notify_new_cluster(replace(own_cluster, cluster_id=stable_cluster_id))
        return stable_cluster_id

    def _build_verdict(
        self,
        event: ChatEvent,
        score: int,
        conf: float,
        signals: list[Signal],
        families: int,
        action: Action,
        reason: str,
        stable_cluster_id: int | None,
        blocked_by: str,
        user: UserState,
    ) -> Verdict:
        verdict = Verdict(
            user_id=event.user_id,
            login=event.login,
            risk_score=score,
            confidence=conf,
            signals=tuple(signals),
            recommended_action=action,
            reason=reason,
            timestamp=event.timestamp,
            families_triggered=families,
            cluster_id=stable_cluster_id,
            is_provisional=user.account_created_at is None,
            blocked_by=blocked_by,
            mode=self._mode,
            engine_version=ENGINE_VERSION,
            config_version=str(self._config.version),
        )
        matched_pattern = match_patterns(verdict, self._patterns)
        if matched_pattern is not None:
            verdict = replace(verdict, pattern_id=matched_pattern.id)
        return verdict

    async def _persist(
        self,
        verdict: Verdict,
        event: ChatEvent,
        fp: MessageFingerprint,
    ) -> int | None:
        store = self._store
        if store is None:
            return None
        try:
            message_id = await store.save_message(event, fp)
            await store.save_verdict(verdict, message_id=message_id)
        except Exception:
            # Сбой записи аудита не должен ронять обработку чата — движок
            # уже посчитал вердикт, потерять стоит запись, а не сообщение.
            log.exception("Не удалось записать аудит модерации в БД")
            return None
        return message_id

    async def _check_content(
        self, event: ChatEvent, user: UserState, *, message_id: int | None
    ) -> None:
        """Rule Engine (cigilbot/content/) — отдельный путь от risk_score,
        см. докстринг content/policy.py. Ничего не возвращает и не влияет
        на Verdict: сейчас это только наблюдение, записанное в
        mod_content_events, executor.py его не читает и не исполняет (см.
        РЕЖИМ НАБЛЮДАТЕЛЯ в content/policy.py) — совпадение видно в панели,
        реальное действие не выполняется независимо от content_moderation_
        enabled, пока сама панель/executor не научатся ставить его в
        mod_action_queue.
        """
        if self._store is None or not self._content_rules:
            return
        match = check_content(event.text, self._content_rules)
        if match is None:
            return

        try:
            prior = await self._store.get_content_violation_count(event.user_id, match.category)
            decision = content_policy.decide_content(
                match,
                user=user,
                event=event,
                prior_violations=prior,
                content_moderation_enabled=self._content_settings.enabled,
            )
            # Счётчик растёт и в режиме наблюдателя (blocked_by ==
            # "content_moderation_disabled") — иначе включение реальных
            # действий позже стартовало бы эскалацию с нуля, будто
            # нарушений в режиме наблюдения не было. Не растёт только для
            # privileged/protected: для них это не нарушение вовсе, а не
            # нарушение, которое решили не наказывать.
            if decision.blocked_by not in ("privileged_user", "trusted_or_marked_safe"):
                await self._store.record_content_violation(event.user_id, match.category)
            await self._store.record_content_event(
                user_id=event.user_id,
                login=event.login,
                message_id=message_id,
                category=match.category,
                matched_phrase=match.matched_phrase,
                action=decision.action.value,
                prior_violations=decision.prior_violations,
                blocked_by=decision.blocked_by,
                enforced=False,
            )
        except Exception:
            # Тот же принцип, что _persist: сбой аудита content-детектора не
            # должен ронять обработку чата.
            log.exception("Не удалось обработать совпадение словарного детектора")
