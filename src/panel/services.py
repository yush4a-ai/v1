"""Доменные операции панели, вынесенные из HTTP-роутов.

Роут отвечает за HTTP: разбор запроса, коды ответа, сериализацию. Правила
предметной области — здесь. Разделение не эстетическое: инварианты
безопасности, живущие в теле хендлера, защищены только тем, что запрос
прошёл через этот конкретный роут. Два таких инварианта уже описаны в
moderation_api.py как последствия реальных инцидентов (BUG-001 — клиент
диктовал, кого банить; SEC-002 — массовое действие без верхнего предела), и
оба были одной строкой от того, чтобы быть забытыми в новом эндпоинте.

Слой намеренно тонкий: функции принимают уже открытый ModerationStore и
возвращают обычные данные, не Response. Они ничего не знают про FastAPI,
поэтому вызываются и тестируются без HTTP-клиента, а роут остаётся
диспетчером на несколько строк.

Исключения — ValueError/LookupError, не HTTPException: слой не выбирает
HTTP-коды. Роут переводит их в 400/404 (см. moderation_api.py), а
panel/server.py уже держит глобальный обработчик ValueError -> 400 как
последнюю сеть.
"""

from __future__ import annotations

import time
from typing import Any

from cigilbot.orchestration.executor import parse_payload
from cigilbot.storage.registry_store import ChannelRecord
from cigilbot.storage.store import ModerationStore

# SEC-002 аудита: без верхнего предела на размер ручного массового действия
# один запрос мог адресовать сколь угодно много пользователей — потенциальный
# DoS через executor (последовательные запросы к Helix) и просто риск огромной
# ошибки одним кликом. Значение с запасом больше типичного размера кластера
# (десятки), но не позволяет случайно/умышленно адресовать тысячи.
MAX_MANUAL_BULK_TARGETS = 200

# Иерархия ролей раздела 7 плана. Числа только для сравнения "достаточно ли
# прав", наружу (в JSON) не уходят — там всегда сама строка роли.
ROLE_RANK = {"VIEWER": 0, "MODERATOR": 1, "ADMIN": 2, "OWNER": 3}


class ClusterNotFoundError(LookupError):
    """Кластер отсутствует или пуст — роут переводит в 404."""


async def enqueue_moderation_action(
    store: ModerationStore,
    *,
    action: str,
    target_user_ids: list[str],
    message_ids: list[str],
    reason: str,
    duration_seconds: int | None,
    cluster_id: int | None,
    requested_by: str,
    requested_role: str,
) -> tuple[int, int]:
    """Ставит ручное действие модератора в очередь. Возвращает (queue_id,
    сколько целей реально адресовано).

    BUG-001 аудита: для BAN/TIMEOUT с указанным cluster_id состав целей
    берётся ИЗ БД на момент исполнения, а присланный клиентом
    target_user_ids полностью игнорируется. Раньше executor.py банил ровно
    тот список, что прислал браузер, никогда не сверяя его с фактическим
    mod_cluster_members — это давало и обычный баг (модератор действовал по
    устаревшему снимку карточки), и возможность эксплуатации (клиент
    диктует, кого банить, в обход детектора).

    SEC-002 аудита: лимит MAX_MANUAL_BULK_TARGETS проверяется ПОСЛЕ
    подстановки состава кластера — ограничивать нужно то, что реально уйдёт
    в Helix, а не то, что прислал клиент.
    """
    if cluster_id is not None and action in ("BAN", "TIMEOUT"):
        current_members = await store.get_cluster_member_ids(cluster_id)
        if not current_members:
            raise ClusterNotFoundError(
                f"Кластер #{cluster_id} не найден или пуст — "
                "возможно, уже обработан или устарел"
            )
        target_user_ids = current_members

    if len(target_user_ids) > MAX_MANUAL_BULK_TARGETS:
        raise ValueError(
            f"Слишком много целей за одно действие: {len(target_user_ids)} "
            f"(максимум {MAX_MANUAL_BULK_TARGETS})"
        )

    raw: dict[str, Any] = {
        "action": action,
        "target_user_ids": target_user_ids,
        "message_ids": message_ids,
        "reason": reason,
        "duration_seconds": duration_seconds,
        "cluster_id": cluster_id,
    }
    # Валидируем ДО записи в очередь — понятная ошибка сразу, а не при
    # разборе задания внутри процесса бота, где её увидит только лог.
    parse_payload(raw)

    queue_id = await store.enqueue_action(
        requested_by=requested_by, requested_role=requested_role, payload=raw
    )
    if cluster_id is not None:
        # BAN ALL/TIMEOUT ALL с этого кластера — он обработан, больше не
        # должен маячить на главном экране как "активный".
        await store.set_cluster_status(cluster_id, "actioned")
    return queue_id, len(target_user_ids)


def resolve_panel_user_role(*, requested_role: str, caller_role: str) -> str:
    """Проверяет, вправе ли caller_role назначить requested_role, и
    возвращает нормализованную (upper) роль.

    Только OWNER может выдавать OWNER — иначе ADMIN мог бы сам себя повысить
    до высшей роли. Остальные проверки прав (ADMIN+ на канале) делает роут
    через channel_store: это вопрос доступа к эндпоинту, а не правило
    иерархии ролей.
    """
    new_role = requested_role.upper()
    if new_role not in ROLE_RANK:
        raise ValueError(f"Неизвестная роль: {requested_role!r}")
    if new_role == "OWNER" and ROLE_RANK[caller_role] < ROLE_RANK["OWNER"]:
        raise PermissionError("Роль OWNER может выдавать только OWNER")
    return new_role


def channel_status(*, attack_active: bool, active_clusters: int) -> str:
    """attack > live > idle — статус карточки канала на Operator Home."""
    if attack_active:
        return "attack"
    return "live" if active_clusters else "idle"


async def build_overview(
    channels: list[ChannelRecord],
    *,
    hours: float,
    open_store: Any,
    db_exists: Any,
    alerts_limit: int = 20,
) -> dict[str, object]:
    """Operator Home (направление 06 master-plan.html): KPI across всех
    каналов Registry, карточка на канал, лента последних алертов — одним
    запросом вместо N, как раньше делал loadChannels() в JS.

    open_store/db_exists передаются вызывающим, а не импортируются здесь:
    путь к mod.<broadcaster_id>.db строит moderation_api._db_path(), который
    в тестах монкейпатчится через ROOT. Тянуть эту деталь в сервисный слой
    значило бы завязать его на конкретную раскладку файлов панели.

    Алерт-лента строится из mod_clusters (created_at, статус active), не из
    отдельного лога — своей таблицы для истории алертов нет, а отправленные
    в Discord алерты (cigilbot/alerts.py::send_cluster_alert) триггерятся на
    то же событие "новый кластер".
    """
    since = time.time() - hours * 3600
    channel_cards: list[dict[str, object]] = []
    alerts: list[dict[str, object]] = []
    totals = {"new_clusters": 0, "would_timeout": 0, "would_ban": 0, "total_messages": 0}

    for c in channels:
        if not db_exists(c.broadcaster_id):
            channel_cards.append(
                {
                    "profile": c.broadcaster_id,
                    "channel": c.login,
                    "status": "offline",
                    "active_clusters": 0,
                    "new_clusters": 0,
                    "would_timeout": 0,
                    "would_ban": 0,
                }
            )
            continue

        store = await open_store(c.broadcaster_id)
        try:
            digest = await store.get_digest_stats(since=since)
            active_clusters = await store.get_active_clusters(limit=5)
            attack = await store.get_active_attack_mode()
        finally:
            await store.close()

        totals["new_clusters"] += digest.new_clusters
        totals["would_timeout"] += digest.would_timeout
        totals["would_ban"] += digest.would_ban
        totals["total_messages"] += digest.total_messages

        channel_cards.append(
            {
                "profile": c.broadcaster_id,
                "channel": c.login,
                "status": channel_status(
                    attack_active=attack is not None, active_clusters=len(active_clusters)
                ),
                "active_clusters": len(active_clusters),
                "new_clusters": digest.new_clusters,
                "would_timeout": digest.would_timeout,
                "would_ban": digest.would_ban,
            }
        )

        alerts.extend(
            {
                "channel": c.login,
                "profile": c.broadcaster_id,
                "cluster_id": cluster["id"],
                "created_at": cluster["created_at"],
                "size": cluster["size"],
                "risk_score": cluster["risk_score"],
            }
            for cluster in active_clusters
        )

    alerts.sort(key=lambda a: a["created_at"], reverse=True)  # type: ignore[arg-type,return-value]

    return {
        "kpi": {
            "channels_connected": len(channels),
            "new_clusters": totals["new_clusters"],
            "would_timeout": totals["would_timeout"],
            "would_ban": totals["would_ban"],
            "total_messages": totals["total_messages"],
            "hours": hours,
        },
        "channels": channel_cards,
        "alerts": alerts[:alerts_limit],
    }
