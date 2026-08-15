"""Исполнитель действий модерации: разбирает очередь mod_action_queue,
вызывает Helix, пишет прогресс и аудит.

Ничего не решает сам — только исполняет то, что уже прошло через
Moderation Policy и, для ручных действий, подтверждение модератора
(раздел 19 ТЗ: DETECT -> SHOW MODERATOR -> CONFIRM -> EXECUTE). Кто и
зачем положил задание в очередь — забота панели (этап 8) и/или
auto-правил (этап 9), этот модуль про них ничего не знает.

Ban User / Timeout User — не батчевый эндпоинт Helix (см. блокер #4 в
docs/moderation-plan.md): кластер из 50 участников — это 50 отдельных
запросов. Поэтому результат — не бинарный success/fail на всё задание,
а по каждому пользователю отдельно: "14/17 забанено, 3 не удалось"
(раздел 7 ТЗ), с прогрессом, обновляемым по ходу выполнения.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cigilbot.integrations.twitch_api import ActionResult, HelixClient
from cigilbot.storage.fingerprints_store import FingerprintStore
from cigilbot.storage.store import ModerationStore, QueueItem

log = logging.getLogger("moderation.executor")

# Дефолт, если задание не указало свою длительность — 10 минут, безопасная
# "мягкая" реакция, а не сразу максимум в 2 недели.
DEFAULT_TIMEOUT_DURATION_SECONDS = 600

# Прогрессивные таймауты (направление 03 master-plan.html): удвоение за
# каждый предыдущий таймаут — 1-й 10мин, 2-й 20мин, 3-й 40мин, 4-й 80мин,
# потолок здесь — лимит самого Twitch на timeout. Считается только когда
# модератор не указал duration_seconds сам — ручной выбор его не трогает.
MAX_TIMEOUT_DURATION_SECONDS = 7 * 24 * 3600


def escalated_timeout_duration(prior_timeouts: int) -> int:
    doubled = DEFAULT_TIMEOUT_DURATION_SECONDS * (1 << prior_timeouts)
    return min(doubled, MAX_TIMEOUT_DURATION_SECONDS)


# BUG-003 аудита: задание, застрявшее в status='running' дольше этого —
# почти наверняка след упавшего/перезапущенного бота, не медленный прогресс.
# Даже кластер на 200 (MAX_MANUAL_BULK_TARGETS в moderation_api.py) целей
# при консервативном рейт-лимите Helix (8 req/сек, twitch_api.py) исполняется
# за ~25 сек — 2 минуты оставляют кратный запас и всё ещё быстро возвращают
# зависшее задание в оборот, а не ждут часами.
STUCK_ACTION_TIMEOUT_SECONDS = 120.0


class QueueAction(str, Enum):
    """Вокабуляр действий очереди — шире, чем types.Action (NOTHING/OBSERVE/
    TIMEOUT/BAN): то список РЕКОМЕНДАЦИЙ policy.py, а это то, что реально
    умеет исполнить executor. UNBAN/MARK_SAFE/WATCHLIST из раздела 10 ТЗ
    сюда сознательно не добавлены — они завязаны на Trusted Users (этап 9),
    добавятся вместе с той функциональностью, а не заранее про запас."""

    BAN = "BAN"
    TIMEOUT = "TIMEOUT"
    DELETE_MESSAGES = "DELETE_MESSAGES"


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """Провалидированный payload_json одного элемента очереди."""

    action: QueueAction
    target_user_ids: tuple[str, ...]
    reason: str
    duration_seconds: int | None
    cluster_id: int | None
    message_ids: tuple[str, ...]


def _require_str_list(raw: object, field: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ValueError(f"payload.{field} должен быть списком строк")
    return raw


def parse_payload(raw: dict[str, Any]) -> ActionRequest:
    """Разобрать сырой payload_json из очереди в типизированный запрос.

    Данные пришли через JSON от внешнего вызывающего (панель, автоправило),
    поэтому здесь настоящая валидация во время исполнения, а не просто
    успокоить mypy: некорректное задание должно провалиться с понятной
    причиной, а не уронить исполнитель или тихо сделать не то.
    """
    action_raw = raw.get("action")
    if not isinstance(action_raw, str):
        raise ValueError(f"payload.action должен быть строкой, получено {action_raw!r}")
    try:
        action = QueueAction(action_raw)
    except ValueError as exc:
        raise ValueError(f"payload.action={action_raw!r} — неизвестное действие") from exc

    target_user_ids = _require_str_list(raw.get("target_user_ids"), "target_user_ids")
    message_ids = _require_str_list(raw.get("message_ids"), "message_ids")

    duration_raw = raw.get("duration_seconds")
    if duration_raw is not None and not isinstance(duration_raw, int):
        raise ValueError("payload.duration_seconds должен быть целым числом")

    cluster_id_raw = raw.get("cluster_id")
    if cluster_id_raw is not None and not isinstance(cluster_id_raw, int):
        raise ValueError("payload.cluster_id должен быть целым числом")

    if action == QueueAction.DELETE_MESSAGES and not message_ids:
        raise ValueError("DELETE_MESSAGES требует непустой message_ids")
    if action in (QueueAction.BAN, QueueAction.TIMEOUT) and not target_user_ids:
        raise ValueError(f"{action.value} требует непустой target_user_ids")

    return ActionRequest(
        action=action,
        target_user_ids=tuple(target_user_ids),
        reason=str(raw.get("reason", "")),
        # duration_raw as-is, не с дефолтом: None здесь — сигнал execute()
        # считать прогрессивную длительность (см. escalated_timeout_duration).
        duration_seconds=duration_raw,
        cluster_id=cluster_id_raw,
        message_ids=tuple(message_ids),
    )


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    succeeded: tuple[str, ...]
    failed: tuple[tuple[str, str], ...]  # (id, причина)

    @property
    def total(self) -> int:
        return len(self.succeeded) + len(self.failed)

    @property
    def summary(self) -> str:
        if not self.failed:
            return f"{len(self.succeeded)}/{self.total} выполнено"
        return f"{len(self.succeeded)}/{self.total} выполнено, {len(self.failed)} с ошибкой"


class ActionExecutor:
    def __init__(
        self,
        helix: HelixClient,
        store: ModerationStore,
        *,
        broadcaster_id: str,
        moderator_id: str,
        user_token: str,
        fingerprint_store: FingerprintStore | None = None,
        channel_login: str = "",
    ) -> None:
        self._helix = helix
        self._store = store
        self._broadcaster_id = broadcaster_id
        self._moderator_id = moderator_id
        self._user_token = user_token
        # Cross-Channel Bot Fingerprint (направление 03 master-plan.html):
        # опционально, потому что не любой вызывающий код (тесты, будущие
        # сценарии) обязан знать про across-каналов состояние — по умолчанию
        # запись в fingerprints.db просто не происходит.
        self._fingerprint_store = fingerprint_store
        self._channel_login = channel_login

    async def _ban_one(self, user_id: str, *, reason: str) -> ActionResult:
        """Один BAN-запрос. При успехе, если fingerprint_store подключён
        (см. ActionExecutor.__init__), записывает аккаунт как известного
        бота across каналов оператора (направление 03 master-plan.html) —
        только BAN, не TIMEOUT: временная мера не означает окончательного
        решения о пользователе."""
        result = await self._helix.ban_user(
            broadcaster_id=self._broadcaster_id,
            moderator_id=self._moderator_id,
            user_id=user_id,
            reason=reason,
            user_token=self._user_token,
        )
        if result.success and self._fingerprint_store is not None:
            # Бан на Twitch УЖЕ состоялся и необратим к этому моменту — сбой
            # здесь (например, SQLite locked без busy_timeout) не должен
            # превращать успешный бан в ActionResult(success=False):
            # _run_per_target записал бы цель в failed, хотя реального
            # провала действия не было, только потеря fingerprint-записи
            # (bug-аудит 2026-08-15, MEDIUM #10 — тот же принцип, что
            # CLAUDE.md уже требует для модерации: потеря вспомогательной
            # записи не должна маскировать состоявшееся действие).
            try:
                state = await self._store.get_user_state(user_id)
                login = state.login if state is not None else user_id
                await self._fingerprint_store.record_ban(
                    user_id=user_id,
                    login=login,
                    banned_on_broadcaster_id=self._broadcaster_id,
                    banned_on_login=self._channel_login,
                    reason=reason,
                )
            except Exception:
                log.exception(
                    "Бан user_id=%s состоялся, но запись в fingerprint_store не удалась",
                    user_id,
                )
        return result

    async def _timeout_one(
        self, user_id: str, *, duration_seconds: int | None, reason: str
    ) -> ActionResult:
        """Один TIMEOUT-запрос с прогрессивной длительностью (направление 03
        master-plan.html). Явный duration_seconds от модератора идёт как
        есть. Без него — читаем prior_timeouts до вызова Helix, чтобы
        участники одного batch не видели чужой инкремент, и увеличиваем
        счётчик только при успехе: неудавшийся таймаут не эскалирует
        следующий."""
        if duration_seconds is not None:
            duration = duration_seconds
        else:
            state = await self._store.get_user_state(user_id)
            prior = state.prior_timeouts if state is not None else 0
            duration = escalated_timeout_duration(prior)

        result = await self._helix.timeout_user(
            broadcaster_id=self._broadcaster_id,
            moderator_id=self._moderator_id,
            user_id=user_id,
            duration=duration,
            reason=reason,
            user_token=self._user_token,
        )
        if duration_seconds is None and result.success:
            await self._store.increment_prior_timeouts(user_id)
        return result

    async def execute(
        self,
        request: ActionRequest,
        *,
        actor: str,
        actor_role: str,
        queue_id: int | None = None,
    ) -> ExecutionOutcome:
        call: Callable[[str], Awaitable[ActionResult]]
        target_ids: tuple[str, ...]

        if request.action == QueueAction.BAN:
            target_ids = request.target_user_ids
            call = lambda uid: self._ban_one(uid, reason=request.reason)  # noqa: E731
        elif request.action == QueueAction.TIMEOUT:
            target_ids = request.target_user_ids
            call = lambda uid: self._timeout_one(  # noqa: E731
                uid, duration_seconds=request.duration_seconds, reason=request.reason
            )
        else:
            target_ids = request.message_ids
            call = lambda mid: self._helix.delete_chat_messages(  # noqa: E731
                broadcaster_id=self._broadcaster_id,
                moderator_id=self._moderator_id,
                user_token=self._user_token,
                message_id=mid,
            )

        outcome = await self._run_per_target(target_ids, call, queue_id=queue_id)

        await self._store.record_action_audit(
            actor=actor,
            actor_role=actor_role,
            action=request.action.value,
            scope="cluster" if request.cluster_id is not None else "user",
            cluster_id=request.cluster_id,
            reason=request.reason,
            confirmation="MANUAL",
            succeeded=len(outcome.succeeded),
            failed=len(outcome.failed),
            details={"succeeded": list(outcome.succeeded), "failed": list(outcome.failed)},
        )
        return outcome

    async def _run_per_target(
        self,
        ids: tuple[str, ...],
        call: Callable[[str], Awaitable[ActionResult]],
        *,
        queue_id: int | None,
    ) -> ExecutionOutcome:
        succeeded: list[str] = []
        failed: list[tuple[str, str]] = []
        total = len(ids)

        for i, target_id in enumerate(ids):
            try:
                result = await call(target_id)
            except Exception as exc:
                # Без этого try/except необработанное исключение (например,
                # в _ban_one — сам бан на Twitch УЖЕ прошёл успешно, но
                # последующий self._store.get_user_state/record_ban упал)
                # всплывает из process_pending, всё задание целиком
                # помечается status="failed", а record_action_audit для уже
                # состоявшихся реальных банов не вызывается вовсе — аудит
                # теряет их безвозвратно (bug-аудит 2026-08-15, MEDIUM #10).
                # Здесь сбой одной цели не должен прерывать оставшиеся и не
                # должен стирать уже собранные succeeded/failed.
                log.exception("Сбой обработки цели %s в задании", target_id)
                failed.append((target_id, str(exc)))
            else:
                if result.success:
                    succeeded.append(target_id)
                else:
                    failed.append((target_id, result.error))

            if queue_id is not None:
                await self._store.update_action_progress(queue_id, i + 1, total)

        return ExecutionOutcome(succeeded=tuple(succeeded), failed=tuple(failed))


async def process_pending(
    executor: ActionExecutor,
    store: ModerationStore,
    *,
    limit: int = 5,
    stuck_timeout_seconds: float = STUCK_ACTION_TIMEOUT_SECONDS,
) -> int:
    """Обработать очередной пакет заданий из очереди. Возвращает их число.

    Рассчитан на периодический вызов (поллинг раз в ~0.5 сек, см. раздел 7
    docs/moderation-plan.md), а не на постоянную блокировку — сам цикл
    поллинга живёт в вызывающем коде (main.py, когда появится панель).

    BUG-003 аудита: перед выборкой pending-заданий возвращает в очередь те,
    что застряли в status='running' дольше stuck_timeout_seconds — типичный
    след падения/перезапуска бота посреди исполнения (см. докстринг
    store.reclaim_stuck_actions). Без этого шага задание, прерванное на
    середине банов кластера, никогда больше не появится в get_pending_actions()
    и останется в аудите как вечно "выполняется".
    """
    reclaimed = await store.reclaim_stuck_actions(timeout_seconds=stuck_timeout_seconds)
    if reclaimed:
        log.warning(
            "Восстановлено %d зависших заданий из очереди (running дольше %.0f сек, "
            "вероятно бот перезапускался посреди исполнения)",
            reclaimed, stuck_timeout_seconds,
        )

    items: list[QueueItem] = await store.get_pending_actions(limit=limit)

    for item in items:
        await store.mark_action_started(item.id)

        try:
            request = parse_payload(item.payload)
        except ValueError as exc:
            log.error("Некорректное задание в очереди #%d: %s", item.id, exc)
            await store.complete_action(item.id, status="failed", result={"error": str(exc)})
            continue

        try:
            outcome = await executor.execute(
                request, actor=item.requested_by, actor_role=item.requested_role, queue_id=item.id
            )
        except Exception:
            log.exception("Сбой исполнения задания #%d", item.id)
            await store.complete_action(
                item.id, status="failed", result={"error": "внутренняя ошибка исполнителя"}
            )
            continue

        log.info("Задание #%d (%s): %s", item.id, request.action.value, outcome.summary)
        await store.complete_action(
            item.id,
            status="completed",
            result={"succeeded": list(outcome.succeeded), "failed": list(outcome.failed)},
        )

    return len(items)
