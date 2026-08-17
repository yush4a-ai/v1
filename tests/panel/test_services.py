"""Тесты panel/services.py — доменных правил, вынесенных из HTTP-роутов.

Смысл выделения слоя в том, что инварианты безопасности перестают зависеть
от того, через какой роут пришёл запрос. Поэтому и тесты здесь без
HTTP-клиента: сервис вызывается напрямую, как его вызовет любой будущий
эндпоинт. HTTP-обёртка (коды 400/403/404) проверяется отдельно, в
test_moderation_api.py.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cigilbot.domain.types import ClusterInfo
from cigilbot.storage.store import ModerationStore
from panel import services


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "services_test.db"))
    await s.connect()
    return s


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
        "signals": (),
        "risk_score": 55,
        "confidence": 0.6,
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return ClusterInfo(**defaults)  # type: ignore[arg-type]


class TestEnqueueModerationAction:
    """BUG-001/SEC-002 аудита — оба инварианта раньше жили в теле HTTP-роута
    и были защищены только тем, что запрос прошёл именно через него."""

    async def test_cluster_members_come_from_db_not_from_client(
        self, store: ModerationStore
    ) -> None:
        """BUG-001: для BAN/TIMEOUT с cluster_id присланный клиентом список
        целей игнорируется полностью — источник правды только БД."""
        cluster_id = await store.upsert_cluster_by_members(
            make_cluster(user_ids=("real1", "real2"), logins=("a", "b"))
        )

        _queue_id, target_count = await services.enqueue_moderation_action(
            store,
            action="BAN",
            target_user_ids=["подделка1", "подделка2", "подделка3"],
            message_ids=[],
            reason="test",
            duration_seconds=None,
            cluster_id=cluster_id,
            requested_by="mod1",
            requested_role="MODERATOR",
        )

        assert target_count == 2  # из БД, не три присланных клиентом
        pending = await store.get_pending_actions(limit=10)
        assert sorted(pending[0].payload["target_user_ids"]) == ["real1", "real2"]

    async def test_missing_cluster_raises_not_found(self, store: ModerationStore) -> None:
        with pytest.raises(services.ClusterNotFoundError):
            await services.enqueue_moderation_action(
                store,
                action="BAN",
                target_user_ids=["1"],
                message_ids=[],
                reason="test",
                duration_seconds=None,
                cluster_id=99999,
                requested_by="mod1",
                requested_role="MODERATOR",
            )

    async def test_bulk_limit_enforced(self, store: ModerationStore) -> None:
        """SEC-002: верхний предел на размер одного ручного действия."""
        too_many = [str(i) for i in range(services.MAX_MANUAL_BULK_TARGETS + 1)]

        with pytest.raises(ValueError, match="Слишком много целей"):
            await services.enqueue_moderation_action(
                store,
                action="TIMEOUT",
                target_user_ids=too_many,
                message_ids=[],
                reason="test",
                duration_seconds=600,
                cluster_id=None,
                requested_by="mod1",
                requested_role="MODERATOR",
            )

    async def test_bulk_limit_checked_after_cluster_substitution(
        self, store: ModerationStore
    ) -> None:
        """Лимит применяется к тому, что реально уйдёт в Helix, — то есть
        уже ПОСЛЕ подстановки состава из БД, а не к присланному списку."""
        big = tuple(str(i) for i in range(services.MAX_MANUAL_BULK_TARGETS + 5))
        cluster_id = await store.upsert_cluster_by_members(
            make_cluster(user_ids=big, logins=big)
        )

        with pytest.raises(ValueError, match="Слишком много целей"):
            await services.enqueue_moderation_action(
                store,
                action="BAN",
                target_user_ids=["один"],  # клиент прислал одну цель
                message_ids=[],
                reason="test",
                duration_seconds=None,
                cluster_id=cluster_id,
                requested_by="mod1",
                requested_role="MODERATOR",
            )

    async def test_cluster_marked_actioned_after_enqueue(
        self, store: ModerationStore
    ) -> None:
        cluster_id = await store.upsert_cluster_by_members(make_cluster())

        await services.enqueue_moderation_action(
            store,
            action="BAN",
            target_user_ids=[],
            message_ids=[],
            reason="test",
            duration_seconds=None,
            cluster_id=cluster_id,
            requested_by="mod1",
            requested_role="MODERATOR",
        )

        active = await store.get_active_clusters(limit=10)
        assert all(c["id"] != cluster_id for c in active)

    async def test_invalid_payload_rejected_before_enqueue(
        self, store: ModerationStore
    ) -> None:
        """parse_payload вызывается ДО записи в очередь — иначе ошибку
        увидел бы только лог процесса бота при разборе задания."""
        with pytest.raises(ValueError):
            await services.enqueue_moderation_action(
                store,
                action="НЕИЗВЕСТНОЕ_ДЕЙСТВИЕ",
                target_user_ids=["1"],
                message_ids=[],
                reason="test",
                duration_seconds=None,
                cluster_id=None,
                requested_by="mod1",
                requested_role="MODERATOR",
            )

        assert await store.get_pending_actions(limit=10) == []


class TestResolvePanelUserRole:
    def test_normalizes_to_upper(self) -> None:
        assert services.resolve_panel_user_role(
            requested_role="moderator", caller_role="ADMIN"
        ) == "MODERATOR"

    def test_unknown_role_rejected(self) -> None:
        with pytest.raises(ValueError, match="Неизвестная роль"):
            services.resolve_panel_user_role(requested_role="БОСС", caller_role="OWNER")

    def test_admin_cannot_grant_owner(self) -> None:
        """Иначе ADMIN мог бы повысить сам себя до высшей роли."""
        with pytest.raises(PermissionError):
            services.resolve_panel_user_role(requested_role="OWNER", caller_role="ADMIN")

    def test_owner_can_grant_owner(self) -> None:
        assert services.resolve_panel_user_role(
            requested_role="OWNER", caller_role="OWNER"
        ) == "OWNER"


class TestChannelStatus:
    def test_attack_wins_over_everything(self) -> None:
        assert services.channel_status(attack_active=True, active_clusters=0) == "attack"
        assert services.channel_status(attack_active=True, active_clusters=5) == "attack"

    def test_live_when_clusters_present(self) -> None:
        assert services.channel_status(attack_active=False, active_clusters=3) == "live"

    def test_idle_when_quiet(self) -> None:
        assert services.channel_status(attack_active=False, active_clusters=0) == "idle"
