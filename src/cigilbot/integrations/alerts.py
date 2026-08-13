"""Discord-алерты для канала (направление 01 master-plan.html): новый
кластер, ежедневный digest, эскалация при повторных атаках.

Триггер алерта на кластер — только новый кластер (см.
store.upsert_cluster_by_members_ex), не каждое сообщение и не каждый
вердикт: это единственный естественный фильтр от шума, о который явно
просит план. Отправка не должна ронять и не должна ждать — engine.observe()
запускает send_cluster_alert()/send_escalation() через asyncio.create_task и
сразу возвращается (CLAUDE.md: чтение чата никогда не ждёт), а сбой сети
здесь — тот же log.exception + проглотить, что и везде в путях
модерации/аудита (см. engine.py::_persist).
"""

from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from cigilbot.domain.types import ClusterInfo
from cigilbot.storage.store import DigestStats, DiscordWebhookConfig, ModeratorActivityStats

log = logging.getLogger("moderation.alerts")

_REQUEST_TIMEOUT_SECONDS = 10.0
_MAX_SIGNALS_SHOWN = 4
_MAX_LOGINS_SHOWN = 8

# Панель сейчас существует только как процесс на машине оператора — нет
# развёртывания с публичным доменом (см. docs/master-plan.html: панель
# работает локально, port 8766). Ссылка полезна ровно там, где Discord
# открывается тем же оператором на том же компьютере — то же ограничение,
# что у "Получить токен бота" в Settings (тоже localhost-редирект).
PANEL_BASE_URL = "http://localhost:8766"


def build_deep_link(*, channel: str, cluster_id: int) -> str:
    """/moderation?channel=X&cluster=Y — панель открывает Live этого канала
    и подсвечивает кластер (направление 01 master-plan.html: deep-link)."""
    return f"{PANEL_BASE_URL}/moderation?channel={quote(channel)}&cluster={cluster_id}"


def build_embed(cluster: ClusterInfo, *, channel: str) -> dict[str, object]:
    """Discord embed для нового кластера — канал, число ботов, топ-сигналы,
    ссылка в панель, как описано в плане. logins режутся до
    _MAX_LOGINS_SHOWN, потому что Discord обрезает embed целиком при
    превышении лимита символов поля, а атака на полсотни ботов — обычный
    случай, не редкий."""
    logins = list(cluster.logins[:_MAX_LOGINS_SHOWN])
    if len(cluster.logins) > _MAX_LOGINS_SHOWN:
        logins.append(f"+{len(cluster.logins) - _MAX_LOGINS_SHOWN}")

    top_signals = sorted(cluster.signals, key=lambda s: s.value, reverse=True)[:_MAX_SIGNALS_SHOWN]

    return {
        "title": f"{channel}: новый кластер, {cluster.size} ботов",
        "url": build_deep_link(channel=channel, cluster_id=cluster.cluster_id),
        "color": 0xF0546B,
        "fields": [
            {"name": "Риск", "value": str(cluster.risk_score), "inline": True},
            {"name": "Уверенность", "value": f"{cluster.confidence * 100:.0f}%", "inline": True},
            {"name": "Участники", "value": ", ".join(logins) or "—", "inline": False},
            {
                "name": "Сигналы",
                "value": "\n".join(s.evidence for s in top_signals) or "—",
                "inline": False,
            },
        ],
    }


def build_digest_embed(stats: DigestStats, *, channel: str, hours: float) -> dict[str, object]:
    """Ежедневная сводка (направление 01 master-plan.html) — активность
    канала + сам факт, что digest вообще пришёл, доказывает, что процесс
    бота жив. Тихо упавший процесс не пришлёт ничего — план явно называет
    это целью digest, отдельной от алерта на атаку, который триггерится
    только событием и молчит, если событий не было."""
    return {
        "title": f"{channel}: сводка за {hours:.0f}ч",
        "url": f"{PANEL_BASE_URL}/moderation?channel={quote(channel)}",
        "color": 0x6C87FF,
        "fields": [
            {"name": "Сообщений", "value": str(stats.total_messages), "inline": True},
            {"name": "Новых кластеров", "value": str(stats.new_clusters), "inline": True},
            {"name": "Тайм-ауты предложены", "value": str(stats.would_timeout), "inline": True},
            {"name": "Баны предложены", "value": str(stats.would_ban), "inline": True},
        ],
    }


_MAX_DIGEST_MODERATOR_ROWS = 10
_MAX_DIGEST_RECENT_ACTIONS = 8

_MANUAL_ACTION_RU = {"TIMEOUT": "таймаут", "BAN": "бан", "DELETE_MESSAGES": "удаление"}


def build_moderator_activity_embed(
    stats: ModeratorActivityStats, *, channel: str, hours: float
) -> dict[str, object]:
    """Сводка по работе модераторов (пользователь 2026-08-13: "можем
    сводку отправлять в дискорд по работе модераторов на канале?") —
    отдельный embed от build_digest_embed в том же сообщении, не смешанные
    поля: тот описывает, что нашёл бот, этот — что сделали люди руками.
    Отсутствует из payload целиком, если за период действий не было (см.
    send_digest) — пустая сводка модераторов не несёт информации, только
    занимает место рядом с содержательной сводкой бота."""
    top_moderators = stats.by_moderator[:_MAX_DIGEST_MODERATOR_ROWS]
    moderators_text = (
        "\n".join(f"{m.actor}: {m.total} ({m.timeouts}т/{m.bans}б/{m.deletes}у)" for m in top_moderators)
        or "—"
    )
    recent_text = (
        "\n".join(
            f"{r.actor} → {_MANUAL_ACTION_RU.get(r.action, r.action)} ({r.succeeded}/{r.succeeded + r.failed})"
            for r in stats.recent[:_MAX_DIGEST_RECENT_ACTIONS]
        )
        or "—"
    )
    return {
        "title": f"{channel}: работа модераторов за {hours:.0f}ч",
        "url": f"{PANEL_BASE_URL}/moderation?channel={quote(channel)}",
        "color": 0x3ECB8E,
        "fields": [
            {"name": "Таймаутов", "value": str(stats.total_timeouts), "inline": True},
            {"name": "Банов", "value": str(stats.total_bans), "inline": True},
            {"name": "Удалений сообщений", "value": str(stats.total_deletes), "inline": True},
            {"name": "По модераторам", "value": moderators_text, "inline": False},
            {"name": "Последние действия", "value": recent_text, "inline": False},
        ],
    }


async def send_digest(
    webhook: DiscordWebhookConfig,
    stats: DigestStats,
    *,
    channel: str,
    hours: float,
    moderator_stats: ModeratorActivityStats | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Отправляет ежедневную сводку. Тот же контракт, что
    send_cluster_alert(): молчит на выключенном webhook, глотает сбои сети —
    вызывающий код (pipeline.py) не должен падать из-за недоступного
    Discord.

    moderator_stats — опционально (пользователь 2026-08-13): второй embed
    в том же сообщении, только если за период было хотя бы одно ручное
    действие — total==0 значит модераторы не вмешивались, отдельный embed
    с одними нулями не добавляет ценности рядом со сводкой бота."""
    if not webhook.enabled:
        return
    embeds = [build_digest_embed(stats, channel=channel, hours=hours)]
    if moderator_stats is not None and (
        moderator_stats.total_timeouts or moderator_stats.total_bans or moderator_stats.total_deletes
    ):
        embeds.append(build_moderator_activity_embed(moderator_stats, channel=channel, hours=hours))
    payload = {"embeds": embeds}
    try:
        async with httpx.AsyncClient(transport=transport, timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(webhook.url, json=payload)
            resp.raise_for_status()
    except Exception:
        log.exception("Не удалось отправить ежедневный digest в Discord (канал %s)", channel)


def build_escalation_embed(*, channel: str, cluster_count: int, window_hours: float) -> dict[str, object]:
    """Эскалация при повторных атаках (направление 01 master-plan.html) —
    отдельный, громче обычного алерт: 3+ новых кластера за короткое время
    значит, что обычные пороги детекции не справляются с волной, не с
    единичным всплеском."""
    return {
        "title": f"{channel}: {cluster_count} кластеров за {window_hours:.0f}ч — базовая защита не справляется",
        "url": f"{PANEL_BASE_URL}/moderation?channel={quote(channel)}",
        "color": 0xFF3B58,
        "fields": [
            {"name": "Новых кластеров", "value": str(cluster_count), "inline": True},
            {"name": "За период", "value": f"{window_hours:.0f}ч", "inline": True},
        ],
    }


async def send_escalation(
    webhook: DiscordWebhookConfig,
    *,
    channel: str,
    cluster_count: int,
    window_hours: float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Отправляет алерт эскалации. Тот же контракт, что send_cluster_alert():
    молчит на выключенном webhook, глотает сбои сети."""
    if not webhook.enabled:
        return
    payload = {
        "embeds": [
            build_escalation_embed(channel=channel, cluster_count=cluster_count, window_hours=window_hours)
        ]
    }
    try:
        async with httpx.AsyncClient(transport=transport, timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(webhook.url, json=payload)
            resp.raise_for_status()
    except Exception:
        log.exception("Не удалось отправить эскалацию в Discord (канал %s)", channel)


async def send_cluster_alert(
    webhook: DiscordWebhookConfig,
    cluster: ClusterInfo,
    *,
    channel: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Отправляет embed через Discord webhook. Молча выходит, если алерты
    выключены — вызывающий код (engine.py) не обязан сам проверять
    webhook.enabled перед вызовом. transport — тот же паттерн внедрения,
    что HelixClient (cigilbot/twitch_api.py): None в проде, httpx.MockTransport
    в тестах."""
    if not webhook.enabled:
        return
    payload = {"embeds": [build_embed(cluster, channel=channel)]}
    try:
        async with httpx.AsyncClient(transport=transport, timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(webhook.url, json=payload)
            resp.raise_for_status()
    except Exception:
        log.exception("Не удалось отправить алерт в Discord (канал %s)", channel)
