"""Тесты Discord-алертов на новый кластер (направление 01 master-plan.html).

Ни один тест не обращается к реальному Discord — send_cluster_alert()
принимает transport тем же паттерном, что HelixClient (см. test_twitch_api.py).
"""

from __future__ import annotations

import time
from typing import Any, cast

import httpx

from cigilbot.domain.types import ClusterInfo, Signal, SignalFamily
from cigilbot.integrations.alerts import (
    PANEL_BASE_URL,
    build_deep_link,
    build_digest_embed,
    build_embed,
    build_escalation_embed,
    build_moderator_activity_embed,
    send_cluster_alert,
    send_digest,
    send_escalation,
)
from cigilbot.storage.store import (
    DigestStats,
    DiscordWebhookConfig,
    ModeratorActionSummary,
    ModeratorActivityStats,
    RecentModeratorAction,
)


def _fields(embed: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], embed["fields"])


def make_signal(name: str, value: float, evidence: str) -> Signal:
    return Signal(name=name, family=SignalFamily.NETWORK, weight=10.0, value=value, evidence=evidence)


def make_cluster(**overrides: object) -> ClusterInfo:
    defaults: dict[str, object] = {
        "cluster_id": 1,
        "user_ids": ("1", "2", "3"),
        "logins": ("bot1", "bot2", "bot3"),
        "similarity_score": 0.9,
        "arrival_window_sec": 5.0,
        "first_message_ratio": 1.0,
        "new_account_ratio": 1.0,
        "shared_domains": (),
        "signals": (make_signal("synchronized_arrival", 0.9, "3 бота за 5с"),),
        "risk_score": 85,
        "confidence": 0.75,
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return ClusterInfo(**defaults)  # type: ignore[arg-type]


def make_webhook(**overrides: object) -> DiscordWebhookConfig:
    defaults: dict[str, object] = {
        "url": "https://discord.com/api/webhooks/1/abc",
        "enabled": True,
        "updated_by": "dobriy_yura",
        "updated_at": time.time(),
    }
    defaults.update(overrides)
    return DiscordWebhookConfig(**defaults)  # type: ignore[arg-type]


def make_digest_stats(**overrides: object) -> DigestStats:
    defaults: dict[str, object] = {
        "total_messages": 1200,
        "suspicious_verdicts": 5,
        "would_timeout": 3,
        "would_ban": 2,
        "new_clusters": 1,
    }
    defaults.update(overrides)
    return DigestStats(**defaults)  # type: ignore[arg-type]


def make_moderator_stats(**overrides: object) -> ModeratorActivityStats:
    defaults: dict[str, object] = {
        "total_timeouts": 5,
        "total_bans": 2,
        "total_deletes": 1,
        "by_moderator": (
            ModeratorActionSummary(actor="mod1", timeouts=3, bans=1, deletes=1),
            ModeratorActionSummary(actor="mod2", timeouts=2, bans=1, deletes=0),
        ),
        "recent": (
            RecentModeratorAction(
                created_at=time.time(), actor="mod1", action="TIMEOUT",
                scope="user", succeeded=1, failed=0,
            ),
        ),
    }
    defaults.update(overrides)
    return ModeratorActivityStats(**defaults)  # type: ignore[arg-type]


class TestBuildEmbed:
    def test_includes_channel_and_size_in_title(self) -> None:
        cluster = make_cluster(logins=("bot1", "bot2", "bot3"))
        embed = build_embed(cluster, channel="paverpapa")
        title = cast(str, embed["title"])
        assert "paverpapa" in title
        assert "3" in title

    def test_lists_all_logins_when_under_limit(self) -> None:
        cluster = make_cluster(user_ids=("1", "2"), logins=("bot1", "bot2"))
        embed = build_embed(cluster, channel="x")
        participants = next(f for f in _fields(embed) if f["name"] == "Участники")
        assert participants["value"] == "bot1, bot2"

    def test_truncates_long_login_list(self) -> None:
        # Атака на полсотни ботов — обычный случай, не редкий: Discord
        # обрезает embed целиком при превышении лимита символов поля.
        user_ids = tuple(str(i) for i in range(20))
        logins = tuple(f"bot{i}" for i in range(20))
        cluster = make_cluster(user_ids=user_ids, logins=logins)
        embed = build_embed(cluster, channel="x")
        participants = next(f for f in _fields(embed) if f["name"] == "Участники")
        assert "+12" in participants["value"]

    def test_shows_signal_evidence_not_just_names(self) -> None:
        cluster = make_cluster(
            signals=(make_signal("exact_duplicate", 1.0, "3 идентичных сообщения"),)
        )
        embed = build_embed(cluster, channel="x")
        signals_field = next(f for f in _fields(embed) if f["name"] == "Сигналы")
        assert "3 идентичных сообщения" in signals_field["value"]

    def test_empty_signals_shows_placeholder_not_crash(self) -> None:
        cluster = make_cluster(signals=())
        embed = build_embed(cluster, channel="x")
        signals_field = next(f for f in _fields(embed) if f["name"] == "Сигналы")
        assert signals_field["value"] == "—"

    def test_url_matches_deep_link_for_same_cluster(self) -> None:
        # Заголовок embed'а в Discord кликабелен ровно за счёт top-level
        # "url" — без него ссылка нигде не появляется в сообщении.
        cluster = make_cluster(cluster_id=42)
        embed = build_embed(cluster, channel="paverpapa")
        assert embed["url"] == build_deep_link(channel="paverpapa", cluster_id=42)


class TestBuildDeepLink:
    def test_includes_channel_and_cluster_id(self) -> None:
        link = build_deep_link(channel="paverpapa", cluster_id=7)
        assert link == f"{PANEL_BASE_URL}/moderation?channel=paverpapa&cluster=7"

    def test_escapes_special_characters_in_channel(self) -> None:
        # login теоретически может прийти с символами, значимыми для query
        # string (& или пробел не бывают в реальных Twitch-логинах, но
        # проверка защищает от неверно собранной ссылки в принципе).
        link = build_deep_link(channel="a&b", cluster_id=1)
        assert "channel=a%26b" in link


class TestBuildDigestEmbed:
    def test_includes_channel_and_period_in_title(self) -> None:
        embed = build_digest_embed(make_digest_stats(), channel="paverpapa", hours=24)
        title = cast(str, embed["title"])
        assert "paverpapa" in title
        assert "24" in title

    def test_reports_all_four_counters(self) -> None:
        stats = make_digest_stats(
            total_messages=500, new_clusters=2, would_timeout=4, would_ban=1
        )
        embed = build_digest_embed(stats, channel="x", hours=24)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert values["Сообщений"] == "500"
        assert values["Новых кластеров"] == "2"
        assert values["Тайм-ауты предложены"] == "4"
        assert values["Баны предложены"] == "1"

    def test_zero_activity_shows_zeros_not_crash(self) -> None:
        stats = make_digest_stats(
            total_messages=0, suspicious_verdicts=0, would_timeout=0, would_ban=0, new_clusters=0
        )
        embed = build_digest_embed(stats, channel="x", hours=24)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert values["Сообщений"] == "0"


class TestBuildModeratorActivityEmbed:
    """Пользователь 2026-08-13: "можем сводку отправлять в дискорд по
    работе модераторов на канале?" """

    def test_includes_channel_and_period_in_title(self) -> None:
        embed = build_moderator_activity_embed(make_moderator_stats(), channel="paverpapa", hours=24)
        title = cast(str, embed["title"])
        assert "paverpapa" in title
        assert "24" in title

    def test_reports_totals(self) -> None:
        stats = make_moderator_stats(total_timeouts=7, total_bans=3, total_deletes=2)
        embed = build_moderator_activity_embed(stats, channel="x", hours=24)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert values["Таймаутов"] == "7"
        assert values["Банов"] == "3"
        assert values["Удалений сообщений"] == "2"

    def test_moderator_ranking_included(self) -> None:
        stats = make_moderator_stats(
            by_moderator=(
                ModeratorActionSummary(actor="mod1", timeouts=3, bans=1, deletes=0),
                ModeratorActionSummary(actor="mod2", timeouts=1, bans=0, deletes=0),
            )
        )
        embed = build_moderator_activity_embed(stats, channel="x", hours=24)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert "mod1" in values["По модераторам"]
        assert "mod2" in values["По модераторам"]

    def test_recent_actions_included(self) -> None:
        stats = make_moderator_stats(
            recent=(
                RecentModeratorAction(
                    created_at=time.time(), actor="mod1", action="BAN",
                    scope="user", succeeded=1, failed=0,
                ),
            )
        )
        embed = build_moderator_activity_embed(stats, channel="x", hours=24)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert "mod1" in values["Последние действия"]

    def test_no_activity_shows_dash_not_crash(self) -> None:
        stats = make_moderator_stats(by_moderator=(), recent=())
        embed = build_moderator_activity_embed(stats, channel="x", hours=24)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert values["По модераторам"] == "—"
        assert values["Последние действия"] == "—"


class TestSendDigest:
    async def test_posts_to_webhook_url(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(204)

        webhook = make_webhook(url="https://discord.com/api/webhooks/1/abc")
        await send_digest(
            webhook,
            make_digest_stats(),
            channel="paverpapa",
            hours=24,
            transport=httpx.MockTransport(handler),
        )

        assert len(calls) == 1
        assert str(calls[0].url) == "https://discord.com/api/webhooks/1/abc"

    async def test_disabled_webhook_sends_nothing(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(204)

        webhook = make_webhook(enabled=False)
        await send_digest(
            webhook, make_digest_stats(), channel="x", hours=24, transport=httpx.MockTransport(handler)
        )

        assert calls == []

    async def test_network_failure_does_not_raise(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        webhook = make_webhook()
        await send_digest(
            webhook, make_digest_stats(), channel="x", hours=24, transport=httpx.MockTransport(handler)
        )

    async def test_includes_moderator_embed_when_activity_present(self) -> None:
        captured: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json
            captured.append({"body": _json.loads(request.content)})
            return httpx.Response(204)

        webhook = make_webhook()
        await send_digest(
            webhook, make_digest_stats(), channel="x", hours=24,
            moderator_stats=make_moderator_stats(total_timeouts=3),
            transport=httpx.MockTransport(handler),
        )

        body = cast("dict[str, Any]", captured[0]["body"])
        assert len(body["embeds"]) == 2

    async def test_omits_moderator_embed_when_no_activity(self) -> None:
        captured: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json
            captured.append({"body": _json.loads(request.content)})
            return httpx.Response(204)

        webhook = make_webhook()
        empty_stats = make_moderator_stats(total_timeouts=0, total_bans=0, total_deletes=0)
        await send_digest(
            webhook, make_digest_stats(), channel="x", hours=24,
            moderator_stats=empty_stats,
            transport=httpx.MockTransport(handler),
        )

        body = cast("dict[str, Any]", captured[0]["body"])
        assert len(body["embeds"]) == 1

    async def test_omits_moderator_embed_when_none_passed(self) -> None:
        captured: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json
            captured.append({"body": _json.loads(request.content)})
            return httpx.Response(204)

        webhook = make_webhook()
        await send_digest(
            webhook, make_digest_stats(), channel="x", hours=24,
            transport=httpx.MockTransport(handler),
        )

        body = cast("dict[str, Any]", captured[0]["body"])
        assert len(body["embeds"]) == 1


class TestBuildEscalationEmbed:
    def test_includes_channel_count_and_window(self) -> None:
        embed = build_escalation_embed(channel="paverpapa", cluster_count=5, window_hours=1)
        title = cast(str, embed["title"])
        assert "paverpapa" in title
        assert "5" in title
        assert "1" in title

    def test_reports_cluster_count_field(self) -> None:
        embed = build_escalation_embed(channel="x", cluster_count=4, window_hours=1)
        values = {f["name"]: f["value"] for f in _fields(embed)}
        assert values["Новых кластеров"] == "4"


class TestSendEscalation:
    async def test_posts_to_webhook_url(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(204)

        webhook = make_webhook(url="https://discord.com/api/webhooks/1/abc")
        await send_escalation(
            webhook,
            channel="paverpapa",
            cluster_count=4,
            window_hours=1,
            transport=httpx.MockTransport(handler),
        )

        assert len(calls) == 1
        assert str(calls[0].url) == "https://discord.com/api/webhooks/1/abc"

    async def test_disabled_webhook_sends_nothing(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(204)

        webhook = make_webhook(enabled=False)
        await send_escalation(
            webhook, channel="x", cluster_count=4, window_hours=1, transport=httpx.MockTransport(handler)
        )

        assert calls == []

    async def test_network_failure_does_not_raise(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        webhook = make_webhook()
        await send_escalation(
            webhook, channel="x", cluster_count=4, window_hours=1, transport=httpx.MockTransport(handler)
        )


class TestSendClusterAlert:
    async def test_posts_to_webhook_url(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(204)

        webhook = make_webhook(url="https://discord.com/api/webhooks/1/abc")
        await send_cluster_alert(
            webhook, make_cluster(), channel="paverpapa", transport=httpx.MockTransport(handler)
        )

        assert len(calls) == 1
        assert str(calls[0].url) == "https://discord.com/api/webhooks/1/abc"

    async def test_disabled_webhook_sends_nothing(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(204)

        webhook = make_webhook(enabled=False)
        await send_cluster_alert(
            webhook, make_cluster(), channel="x", transport=httpx.MockTransport(handler)
        )

        assert calls == []

    async def test_network_failure_does_not_raise(self) -> None:
        # engine.observe() запускает это как фоновую задачу — сбой сети не
        # должен долетать до вызывающего кода как исключение (см. докстринг
        # cigilbot/alerts.py).
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        webhook = make_webhook()
        await send_cluster_alert(
            webhook, make_cluster(), channel="x", transport=httpx.MockTransport(handler)
        )

    async def test_discord_error_response_does_not_raise(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Unknown Webhook")

        webhook = make_webhook()
        await send_cluster_alert(
            webhook, make_cluster(), channel="x", transport=httpx.MockTransport(handler)
        )
