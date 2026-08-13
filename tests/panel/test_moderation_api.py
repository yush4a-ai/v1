"""Тесты роутера panel/moderation_api.py: роли/права, REST-эндпоинты, аудит.

Аутентификация — через conftest.login_as() (пишет сессию напрямую, минуя
реальный Twitch OAuth — см. докстринг conftest.py). Анонимный app_client
без login_as() эквивалентен браузеру, который ещё не проходил /auth/login.

WebSocket не тестируется здесь TestClient'ом на постоянный поток (это
скорее интеграционный сценарий) — но однократное подключение/сообщение
проверяется отдельным тестом ниже через TestClient.websocket_connect,
который умеет короткие сессии без реального сетевого сокета.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from cigilbot.registry_store import RegistryStore
from cigilbot.store import ModerationStore, PatternInput
from cigilbot.types import (
    Action,
    ChatEvent,
    ClusterInfo,
    Mode,
    Signal,
    SignalFamily,
    Verdict,
)
from tests.panel.conftest import login_as


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
        "signals": (
            Signal(
                name="synchronized_arrival",
                family=SignalFamily.TIMING,
                weight=25,
                value=1.0,
                evidence="3 участника за 5 сек",
            ),
        ),
        "risk_score": 70,
        "confidence": 0.85,
        "created_at": time.time(),
    }
    defaults.update(overrides)
    return ClusterInfo(**defaults)  # type: ignore[arg-type]


def make_verdict(**overrides: object) -> Verdict:
    defaults: dict[str, object] = {
        "user_id": "1",
        "login": "bot1",
        "risk_score": 70,
        "confidence": 0.85,
        "signals": (),
        "recommended_action": Action.TIMEOUT,
        "reason": "тестовый вердикт",
        "timestamp": time.time(),
        "mode": Mode.SHADOW,
    }
    defaults.update(overrides)
    return Verdict(**defaults)  # type: ignore[arg-type]


class TestReadEndpointsRequireLogin:
    async def test_clusters_without_session_401(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/clusters")
        assert resp.status_code == 401

    async def test_verdicts_without_session_401(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/verdicts")
        assert resp.status_code == 401

    async def test_audit_without_session_401(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/audit")
        assert resp.status_code == 401


class TestClustersEndpoint:
    async def test_empty_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/clusters")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_active_cluster(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.save_cluster(make_cluster())
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/clusters")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["risk_score"] == 70
        assert data[0]["logins"] == ["bot1", "bot2", "bot3"]

    async def test_actioned_cluster_not_returned(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        cluster_id = await store.save_cluster(make_cluster())
        await store.set_cluster_status(cluster_id, "actioned")
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/clusters")

        assert resp.json() == []

    async def test_unknown_instance_db_404(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        # profile "other" -> mod.other.db, который никто не создавал (в
        # отличие от profile "main"/DEFAULT_TEST_BROADCASTER_ID — БД которого
        # создаёт фикстура db_path). Регистрация в Registry не нужна для
        # этого теста — _db_path строит путь по broadcaster_id напрямую,
        # без обращения к Registry (см. panel/moderation_api.py::_db_path).
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/clusters?profile=other")

        assert resp.status_code == 404


def make_event(**overrides: object) -> ChatEvent:
    defaults: dict[str, object] = {
        "user_id": "1", "login": "viewer1", "text": "hello", "timestamp": time.time(),
    }
    defaults.update(overrides)
    return ChatEvent(**defaults)  # type: ignore[arg-type]


class TestUsersEndpoint:
    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/users")
        assert resp.status_code == 401

    async def test_empty_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/users")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_created_users(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.upsert_user(make_event(user_id="1", login="viewer1"))
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/users")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["login"] == "viewer1"
        assert data[0]["trust_level"] == "UNKNOWN"

    async def test_search_query_param(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.upsert_user(make_event(user_id="1", login="alice"))
        await store.upsert_user(make_event(user_id="2", login="bob"))
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/users?search=ali")

        data = resp.json()
        assert len(data) == 1
        assert data[0]["login"] == "alice"


class TestVerdictsEndpoint:
    async def test_filters_by_min_risk(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.save_verdict(make_verdict(risk_score=10))
        await store.save_verdict(make_verdict(risk_score=50))
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/verdicts?min_risk=30")

        data = resp.json()
        assert len(data) == 1
        assert data[0]["risk_score"] == 50

    async def test_includes_signal_names(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        signal = Signal(
            name="exact_duplicate", family=SignalFamily.CONTENT,
            weight=25, value=1.0, evidence="test",
        )
        await store.save_verdict(make_verdict(risk_score=60, signals=(signal,)))
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/verdicts?min_risk=30")

        data = resp.json()
        assert data[0]["signal_names"] == ["exact_duplicate"]


class TestRolesAndPermissions:
    async def test_action_requires_moderator_role(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        assert resp.status_code == 403

    async def test_action_without_session_401(self, app_client: TestClient) -> None:
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        assert resp.status_code == 401

    async def test_moderator_can_enqueue_action(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "MODERATOR", login="mod1")
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": ["1", "2"], "reason": "spam"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "pending"

        items = await store.get_pending_actions()
        assert len(items) == 1
        assert items[0].requested_by == "mod1"
        assert items[0].requested_role == "MODERATOR"

    async def test_invalid_payload_rejected_before_queueing(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": []},
        )
        assert resp.status_code == 400
        assert await store.get_pending_actions() == []

    async def test_action_with_cluster_id_marks_cluster_actioned(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        cluster_id = await store.save_cluster(make_cluster())
        login_as(app_client, "MODERATOR")

        resp = app_client.post(
            "/api/moderation/actions",
            json={
                "action": "TIMEOUT",
                "target_user_ids": ["1"],
                "reason": "x",
                "cluster_id": cluster_id,
            },
        )
        assert resp.status_code == 200

        active = await store.get_active_clusters()
        assert active == []


class TestPerChannelRoleIsolation:
    """Мульти-канальные роли: вошедший может быть MODERATOR на канале
    одного профиля бота и никем на канале другого — роль в сессии теперь
    словарь {channel: role} (см. panel/auth.py::_resolve_roles_by_channel),
    а не одна строка на весь вход. Здесь login_as кладёт роль только под
    DEFAULT_TEST_CHANNEL (канал профиля "main", conftest.tmp_root) — второй
    профиль с другим каналом должен остаться недоступен для действий, даже
    хотя обычная роль MODERATOR формально "есть" в сессии."""

    async def test_moderator_on_main_channel_cannot_act_on_other_channel_profile(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        registry = RegistryStore(str(tmp_root / "registry.db"))
        await registry.connect()
        await registry.upsert_channel(broadcaster_id="other", login="other_channel")
        await registry.close()
        other_db = tmp_root / "mod.other.db"
        other_store = ModerationStore(str(other_db))
        await other_store.connect()
        await other_store.close()

        # MODERATOR только на канале профиля "main" (DEFAULT_TEST_CHANNEL) —
        # login_as пишет roles={DEFAULT_TEST_CHANNEL: "MODERATOR"}, канал
        # профиля "other" в этот словарь не попадает вообще.
        login_as(app_client, "MODERATOR")

        resp = app_client.post(
            "/api/moderation/actions",
            json={
                "profile": "other",
                "action": "BAN",
                "target_user_ids": ["1"],
                "reason": "x",
            },
        )
        assert resp.status_code == 403

    async def test_moderator_on_main_channel_can_still_act_on_main_profile(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        # Контрольный тест на тот же сценарий: роль на "своём" канале
        # (профиль "main") по-прежнему работает как раньше — по-канальность
        # не должна была случайно занизить права там, где они законны.
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        assert resp.status_code == 200

    async def test_admin_role_is_global_unlike_moderator(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        # ADMIN — ручной оверрайд (mod_panel_users), не статус Twitch за
        # конкретный канал, поэтому в реальном коде (_resolve_roles_by_channel)
        # применяется одинаково на каждый известный канал, в отличие от
        # MODERATOR/OWNER выше в этом классе. Контраст с
        # test_moderator_on_main_channel_cannot_act_on_other_channel_profile —
        # по-канальность не должна была случайно занизить ADMIN-права там,
        # где прод их действительно даёт.
        registry = RegistryStore(str(tmp_root / "registry.db"))
        await registry.connect()
        await registry.upsert_channel(broadcaster_id="other", login="other_channel")
        await registry.close()
        other_db = tmp_root / "mod.other.db"
        other_store = ModerationStore(str(other_db))
        await other_store.connect()
        await other_store.close()

        login_as(app_client, "ADMIN")

        resp = app_client.post(
            "/api/moderation/attack_mode/activate",
            json={"profile": "other", "duration_seconds": 60},
        )
        assert resp.status_code == 200


class TestClusterActionTargetsFromServer:
    """BUG-001 аудита: target_user_ids для BAN/TIMEOUT с cluster_id должен
    браться сервером из mod_cluster_members, а не из тела запроса клиента —
    иначе клиент может продиктовать произвольный список целей под видом
    "это состав кластера #N", в том числе устаревший или вовсе выдуманный."""

    async def test_client_supplied_ids_are_ignored_and_replaced_by_db_members(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        cluster_id = await store.save_cluster(
            make_cluster(user_ids=("11", "22", "33"), logins=("a", "b", "c"))
        )
        login_as(app_client, "MODERATOR")

        # Клиент присылает совсем не тот список, что реально в кластере —
        # имитирует и устаревший снимок, и злонамеренную подмену.
        resp = app_client.post(
            "/api/moderation/actions",
            json={
                "action": "BAN",
                "target_user_ids": ["999", "888"],
                "reason": "x",
                "cluster_id": cluster_id,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["target_count"] == 3

        items = await store.get_pending_actions()
        assert len(items) == 1
        assert sorted(items[0].payload["target_user_ids"]) == ["11", "22", "33"]

    async def test_cluster_grown_since_client_snapshot_uses_current_members(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        # Симулирует ровно сценарий BUG-001: модератор открыл панель с
        # кластером из 2 участников, кластер вырос до 4 (upsert_cluster_by_members),
        # модератор нажимает BAN ALL с устаревшим клиентским снимком из 2.
        cluster_id = await store.upsert_cluster_by_members(
            make_cluster(user_ids=("1", "2"), logins=("a", "b"))
        )
        await store.upsert_cluster_by_members(
            make_cluster(user_ids=("2", "3", "4"), logins=("b", "c", "d"))
        )
        login_as(app_client, "MODERATOR")

        resp = app_client.post(
            "/api/moderation/actions",
            json={
                "action": "BAN",
                "target_user_ids": ["1", "2"],  # устаревший снимок клиента
                "reason": "x",
                "cluster_id": cluster_id,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["target_count"] == 4  # актуальный состав, не 2

    async def test_unknown_cluster_id_returns_404_not_empty_ban(
        self, app_client: TestClient
    ) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/actions",
            json={
                "action": "BAN",
                "target_user_ids": ["1", "2"],
                "reason": "x",
                "cluster_id": 999999,
            },
        )
        assert resp.status_code == 404

    async def test_ignore_cluster_action_falls_back_to_client_target_ids(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        # Без cluster_id (точечное действие не по кластеру) клиентский
        # список по-прежнему используется — сервер подменяет только когда
        # действие явно привязано к конкретному кластеру.
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": ["42"], "reason": "точечный бан"},
        )
        assert resp.status_code == 200
        assert resp.json()["target_count"] == 1


class TestMassActionSizeLimit:
    """SEC-002 аудита: сервер должен отклонять действие с числом целей
    больше жёсткого предела, даже если он пришёл напрямую в target_user_ids
    (без cluster_id) — не полагаться только на ограничения UI."""

    async def test_rejects_oversized_manual_target_list(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "MODERATOR")
        huge_list = [str(i) for i in range(201)]
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": huge_list, "reason": "x"},
        )
        assert resp.status_code == 400
        assert await store.get_pending_actions() == []

    async def test_accepts_list_at_exactly_the_limit(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "MODERATOR")
        exact_list = [str(i) for i in range(200)]
        resp = app_client.post(
            "/api/moderation/actions",
            json={"action": "BAN", "target_user_ids": exact_list, "reason": "x"},
        )
        assert resp.status_code == 200


class TestClusterDecisions:
    async def test_ignore_requires_moderator(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        cluster_id = await store.save_cluster(make_cluster())
        login_as(app_client, "VIEWER")
        resp = app_client.post(
            f"/api/moderation/clusters/{cluster_id}/ignore",
            json={},
        )
        assert resp.status_code == 403

    async def test_mark_safe_removes_from_active(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        cluster_id = await store.save_cluster(make_cluster())
        login_as(app_client, "MODERATOR")

        resp = app_client.post(
            f"/api/moderation/clusters/{cluster_id}/mark_safe",
            json={},
        )

        assert resp.status_code == 200
        assert await store.get_active_clusters() == []


class TestPanelUserRoles:
    async def test_set_role_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/panel_users",
            json={"login": "mod1", "role": "MODERATOR"},
        )
        assert resp.status_code == 403

    async def test_admin_can_grant_moderator(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/panel_users",
            json={"login": "mod1", "role": "MODERATOR"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"login": "mod1", "role": "MODERATOR"}

        role = await store.get_panel_role("mod1")
        assert role == "MODERATOR"

    async def test_admin_cannot_grant_owner(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/panel_users",
            json={"login": "mod1", "role": "OWNER"},
        )
        assert resp.status_code == 403

    async def test_owner_can_grant_owner(self, app_client: TestClient) -> None:
        login_as(app_client, "OWNER")
        resp = app_client.post(
            "/api/moderation/panel_users",
            json={"login": "mod1", "role": "OWNER"},
        )
        assert resp.status_code == 200

    async def test_unknown_role_value_rejected(self, app_client: TestClient) -> None:
        login_as(app_client, "OWNER")
        resp = app_client.post(
            "/api/moderation/panel_users",
            json={"login": "mod1", "role": "SUPERADMIN"},
        )
        assert resp.status_code == 400


class TestAuditEndpoint:
    async def test_records_actor_and_role(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.record_action_audit(
            actor="mod1",
            actor_role="MODERATOR",
            action="BAN",
            scope="cluster",
            reason="spam",
            confirmation="MANUAL",
            succeeded=3,
            failed=0,
            details={"succeeded": ["1", "2", "3"], "failed": []},
            cluster_id=1,
        )
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/audit")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["actor"] == "mod1"
        assert data[0]["actor_role"] == "MODERATOR"
        assert data[0]["succeeded"] == 3
        assert data[0]["details"]["succeeded"] == ["1", "2", "3"]


class TestTrustedUsersEndpoints:
    async def test_mark_safe_requires_moderator(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post("/api/moderation/users/1/mark_safe", json={})
        assert resp.status_code == 403

    async def test_mark_safe_without_session_401(self, app_client: TestClient) -> None:
        resp = app_client.post("/api/moderation/users/1/mark_safe", json={})
        assert resp.status_code == 401

    async def test_moderator_can_mark_safe(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.upsert_user(make_event(user_id="1", login="viewer1"))
        login_as(app_client, "MODERATOR", login="mod1")

        resp = app_client.post(
            "/api/moderation/users/1/mark_safe", json={"reason": "known regular"}
        )

        assert resp.status_code == 200
        assert resp.json() == {"user_id": "1", "trusted": True}
        assert await store.is_trusted("1") is True

    async def test_mark_safe_unknown_user_id_404(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        # SEC-005 аудита: user_id, которого система ни разу не видела в этом
        # канале, нельзя пометить доверенным — чистый 404, не голый 500.
        login_as(app_client, "MODERATOR")

        resp = app_client.post("/api/moderation/users/ghost/mark_safe", json={})

        assert resp.status_code == 404
        assert await store.is_trusted("ghost") is False

    async def test_records_actor_from_session_not_client_input(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.upsert_user(make_event(user_id="1", login="viewer1"))
        login_as(app_client, "MODERATOR", login="real_moderator")

        app_client.post("/api/moderation/users/1/mark_safe", json={"reason": "x"})

        rows = await store.list_trusted()
        assert rows[0]["added_by"] == "real_moderator"

    async def test_unmark_safe(self, app_client: TestClient, store: ModerationStore) -> None:
        await store.upsert_user(make_event(user_id="1", login="viewer1"))
        login_as(app_client, "MODERATOR")
        app_client.post("/api/moderation/users/1/mark_safe", json={})

        resp = app_client.post("/api/moderation/users/1/unmark_safe", json={})

        assert resp.status_code == 200
        assert resp.json() == {"user_id": "1", "trusted": False}
        assert await store.is_trusted("1") is False

    async def test_list_trusted_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/trusted")
        assert resp.status_code == 401

    async def test_list_trusted_returns_entries(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.upsert_user(make_event(user_id="1", login="viewer1"))
        await store.mark_trusted("1", added_by="mod1", reason="regular")
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/trusted")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["user_id"] == "1"
        assert data[0]["login"] == "viewer1"


class TestPatternsEndpoints:
    def _pattern_payload(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": "mass registration",
            "description": "many new accounts at once",
            "required_signal_names": ["synchronized_arrival"],
            "min_families": 2,
            "min_risk_score": 60,
            "min_confidence": 0.7,
            "min_cluster_size": 10,
            "enabled": True,
            "auto_enabled": False,
            "weight": 5.0,
        }
        payload.update(overrides)
        return payload

    async def test_list_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/patterns")
        assert resp.status_code == 401

    async def test_create_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post("/api/moderation/patterns", json=self._pattern_payload())
        assert resp.status_code == 403

    async def test_admin_can_create_and_list(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        create_resp = app_client.post("/api/moderation/patterns", json=self._pattern_payload())
        assert create_resp.status_code == 200
        pattern_id = create_resp.json()["id"]

        list_resp = app_client.get("/api/moderation/patterns")
        assert list_resp.status_code == 200
        data = list_resp.json()
        assert len(data) == 1
        assert data[0]["id"] == pattern_id
        assert data[0]["name"] == "mass registration"
        assert data[0]["created_by"] == "admin1"

    async def test_set_enabled_requires_admin(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        pattern_id = await store.create_pattern(_pattern_input_for_test())
        login_as(app_client, "MODERATOR")

        resp = app_client.post(
            f"/api/moderation/patterns/{pattern_id}/enabled", json={"enabled": False}
        )
        assert resp.status_code == 403

    async def test_admin_can_disable_pattern(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        pattern_id = await store.create_pattern(_pattern_input_for_test())
        login_as(app_client, "ADMIN")

        resp = app_client.post(
            f"/api/moderation/patterns/{pattern_id}/enabled", json={"enabled": False}
        )

        assert resp.status_code == 200
        patterns = await store.list_patterns()
        assert patterns[0].enabled is False

    async def test_admin_can_delete_pattern(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        pattern_id = await store.create_pattern(_pattern_input_for_test())
        login_as(app_client, "ADMIN")

        resp = app_client.post(f"/api/moderation/patterns/{pattern_id}/delete", json={})

        assert resp.status_code == 200
        assert await store.list_patterns() == []


def _pattern_input_for_test() -> PatternInput:
    return PatternInput(
        name="test pattern", description="", required_signal_names=(),
        min_families=0, min_risk_score=0, min_confidence=0.0, min_cluster_size=0,
        enabled=True, auto_enabled=False, weight=1.0, created_by="mod1",
    )


class TestAttackModeEndpoints:
    async def test_status_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/attack_mode")
        assert resp.status_code == 401

    async def test_inactive_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/attack_mode")
        assert resp.status_code == 200
        assert resp.json() == {"active": False}

    async def test_activate_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post("/api/moderation/attack_mode/activate", json={})
        assert resp.status_code == 403

    async def test_admin_can_activate(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post(
            "/api/moderation/attack_mode/activate", json={"duration_seconds": 1800}
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["activated_by"] == "admin1"

        status_resp = app_client.get("/api/moderation/attack_mode")
        assert status_resp.json()["active"] is True

    async def test_activate_records_actor_from_session(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "OWNER", login="real_owner")

        app_client.post("/api/moderation/attack_mode/activate", json={})

        status = await store.get_active_attack_mode()
        assert status is not None
        assert status.activated_by == "real_owner"

    async def test_rejects_non_positive_duration(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/attack_mode/activate", json={"duration_seconds": 0}
        )
        assert resp.status_code == 400

    async def test_default_duration_is_30_minutes(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/attack_mode/activate", json={})

        status = await store.get_active_attack_mode()
        assert status is not None
        assert 1799 <= status.expires_at - status.activated_at <= 1801

    async def test_deactivate_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post("/api/moderation/attack_mode/deactivate", json={})
        assert resp.status_code == 403

    async def test_admin_can_deactivate(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.activate_attack_mode(activated_by="admin1", duration_seconds=1800)
        login_as(app_client, "ADMIN")

        resp = app_client.post("/api/moderation/attack_mode/deactivate", json={})

        assert resp.status_code == 200
        assert await store.get_active_attack_mode() is None


class TestGiveawayModeEndpoints:
    """FALSE-BAN-001 аудита — тот же набор гарантий, что Attack Mode выше,
    но противоположный по эффекту (снижает, а не повышает чувствительность)."""

    async def test_status_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/giveaway_mode")
        assert resp.status_code == 401

    async def test_inactive_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/giveaway_mode")
        assert resp.status_code == 200
        assert resp.json() == {"active": False}

    async def test_activate_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post("/api/moderation/giveaway_mode/activate", json={})
        assert resp.status_code == 403

    async def test_admin_can_activate(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post(
            "/api/moderation/giveaway_mode/activate", json={"duration_seconds": 900}
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["activated_by"] == "admin1"

        status_resp = app_client.get("/api/moderation/giveaway_mode")
        assert status_resp.json()["active"] is True

    async def test_activate_records_actor_from_session(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "OWNER", login="real_owner")

        app_client.post("/api/moderation/giveaway_mode/activate", json={})

        status = await store.get_active_giveaway_mode()
        assert status is not None
        assert status.activated_by == "real_owner"

    async def test_rejects_non_positive_duration(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/giveaway_mode/activate", json={"duration_seconds": 0}
        )
        assert resp.status_code == 400

    async def test_default_duration_is_15_minutes(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/giveaway_mode/activate", json={})

        status = await store.get_active_giveaway_mode()
        assert status is not None
        assert 899 <= status.expires_at - status.activated_at <= 901

    async def test_deactivate_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post("/api/moderation/giveaway_mode/deactivate", json={})
        assert resp.status_code == 403

    async def test_admin_can_deactivate(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.activate_giveaway_mode(activated_by="admin1", duration_seconds=900)
        login_as(app_client, "ADMIN")

        resp = app_client.post("/api/moderation/giveaway_mode/deactivate", json={})

        assert resp.status_code == 200
        assert await store.get_active_giveaway_mode() is None

    async def test_independent_from_attack_mode_endpoints(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/attack_mode/activate", json={})
        app_client.post("/api/moderation/giveaway_mode/activate", json={})

        assert app_client.get("/api/moderation/attack_mode").json()["active"] is True
        assert app_client.get("/api/moderation/giveaway_mode").json()["active"] is True

        app_client.post("/api/moderation/attack_mode/deactivate", json={})

        assert app_client.get("/api/moderation/attack_mode").json()["active"] is False
        assert app_client.get("/api/moderation/giveaway_mode").json()["active"] is True


class TestDiscordWebhookEndpoints:
    """Направление 01 master-plan.html — тот же уровень доступа, что
    Attack/Giveaway Mode: меняет ADMIN+, читают все аутентифицированные."""

    async def test_get_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/discord_webhook")
        assert resp.status_code == 401

    async def test_unconfigured_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/discord_webhook")
        assert resp.status_code == 200
        assert resp.json() == {"configured": False}

    async def test_set_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc"},
        )
        assert resp.status_code == 403

    async def test_admin_can_set(self, app_client: TestClient, store: ModerationStore) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc"},
        )

        assert resp.status_code == 200
        config = await store.get_discord_webhook()
        assert config is not None
        assert config.url == "https://discord.com/api/webhooks/1/abc"
        assert config.updated_by == "admin1"

    async def test_get_masks_url(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/12345/verylongsecrettoken"},
        )

        resp = app_client.get("/api/moderation/discord_webhook")

        body = resp.json()
        assert body["configured"] is True
        assert "verylongsecrettoken" not in body["url"] or body["url"].endswith("token")
        assert "•" in body["url"]

    async def test_rejects_non_discord_url_when_enabling(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://evil.example.com/steal", "enabled": True},
        )
        assert resp.status_code == 400

    async def test_disabling_does_not_validate_url_shape(self, app_client: TestClient) -> None:
        # Выключение — не создание нового webhook, поэтому не должно
        # спотыкаться о валидацию формата (модератор мог настроить его
        # раньше в другом формате, до появления этой проверки).
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc", "enabled": False},
        )
        assert resp.status_code == 200

    async def test_can_toggle_enabled_without_changing_url(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc", "enabled": True},
        )

        app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc", "enabled": False},
        )

        config = await store.get_discord_webhook()
        assert config is not None
        assert config.enabled is False
        assert config.url == "https://discord.com/api/webhooks/1/abc"


class TestAlertThresholdEndpoint:
    """Направление 01 master-plan.html — порог confidence для алерта на
    кластер, тот же уровень доступа, что остальные Discord-настройки:
    меняет ADMIN+."""

    async def test_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/discord_webhook/alert_threshold", json={"threshold": 0.7}
        )
        assert resp.status_code == 403

    async def test_admin_can_set_threshold(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc", "enabled": True},
        )

        resp = app_client.post(
            "/api/moderation/discord_webhook/alert_threshold", json={"threshold": 0.7}
        )

        assert resp.status_code == 200
        config = await store.get_discord_webhook()
        assert config is not None
        assert config.alert_confidence_threshold == 0.7

    async def test_rejects_out_of_range_threshold(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/discord_webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc", "enabled": True},
        )

        resp = app_client.post(
            "/api/moderation/discord_webhook/alert_threshold", json={"threshold": 1.5}
        )

        assert resp.status_code == 400

    async def test_fails_when_webhook_not_configured(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/discord_webhook/alert_threshold", json={"threshold": 0.7}
        )
        assert resp.status_code == 400


class TestFeedbackEndpoints:
    async def test_record_requires_moderator(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post(
            "/api/moderation/feedback",
            json={"signal_name": "unexpected_language", "decision": "FALSE_POSITIVE"},
        )
        assert resp.status_code == 403

    async def test_record_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.post(
            "/api/moderation/feedback",
            json={"signal_name": "unexpected_language", "decision": "FALSE_POSITIVE"},
        )
        assert resp.status_code == 401

    async def test_moderator_can_record(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "MODERATOR", login="mod1")

        resp = app_client.post(
            "/api/moderation/feedback",
            json={"signal_name": "unexpected_language", "decision": "FALSE_POSITIVE"},
        )

        assert resp.status_code == 200
        rows = await store.list_feedback()
        assert len(rows) == 1
        assert rows[0]["moderator"] == "mod1"

    async def test_invalid_decision_rejected(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/feedback",
            json={"signal_name": "unexpected_language", "decision": "MAYBE"},
        )
        assert resp.status_code == 400

    async def test_list_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/feedback")
        assert resp.status_code == 401

    async def test_list_returns_entries(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.record_feedback(
            signal_name="exact_duplicate", moderator="mod1", decision="CONFIRMED_BOT"
        )
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/feedback")

        assert resp.status_code == 200
        assert len(resp.json()) == 1


class TestDailyStatsEndpoint:
    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/stats/daily")
        assert resp.status_code == 401

    async def test_returns_stats(self, app_client: TestClient, store: ModerationStore) -> None:
        await store.increment_daily_stats(date="2026-08-08", total_messages=42)
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/stats/daily")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["total_messages"] == 42


class TestOverviewEndpoint:
    """Operator Home (направление 06 master-plan.html) — KPI across каналов,
    карточка на канал, лента алертов. DEFAULT_TEST_BROADCASTER_ID/CHANNEL
    из conftest уже зарегистрированы в Registry фикстурой tmp_root."""

    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/overview")
        assert resp.status_code == 401

    async def test_no_activity_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/overview")

        assert resp.status_code == 200
        data = resp.json()
        assert data["kpi"]["channels_connected"] == 1
        assert data["kpi"]["new_clusters"] == 0
        assert data["alerts"] == []
        assert len(data["channels"]) == 1
        assert data["channels"][0]["profile"] == "main"
        assert data["channels"][0]["status"] == "idle"

    async def test_active_cluster_feeds_kpi_and_alerts(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.save_cluster(make_cluster())
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/overview")

        assert resp.status_code == 200
        data = resp.json()
        assert data["kpi"]["new_clusters"] == 1
        assert data["channels"][0]["status"] == "live"
        assert data["channels"][0]["active_clusters"] == 1
        assert len(data["alerts"]) == 1
        assert data["alerts"][0]["channel"] == "test_channel"
        assert data["alerts"][0]["risk_score"] == 70

    async def test_attack_mode_overrides_status(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        await store.activate_attack_mode(activated_by="test_user", duration_seconds=600)
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/overview")

        assert resp.status_code == 200
        assert resp.json()["channels"][0]["status"] == "attack"

    async def test_channel_without_db_reports_offline(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        registry = RegistryStore(str(tmp_root / "registry.db"))
        await registry.connect()
        await registry.upsert_channel(
            broadcaster_id="second", login="second_channel", registered_by="manual"
        )
        await registry.close()
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/overview")

        assert resp.status_code == 200
        by_profile = {c["profile"]: c for c in resp.json()["channels"]}
        assert by_profile["second"]["status"] == "offline"
        assert by_profile["second"]["active_clusters"] == 0


MINIMAL_VALID_YAML = "version: 1\nmode: BALANCED\n"


class TestConfigEndpoints:
    async def test_get_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/config")
        assert resp.status_code == 401

    async def test_get_404_when_no_config_file(self, app_client: TestClient) -> None:
        # tmp_root не создаёт config/moderation.yml сам по себе.
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/config")
        assert resp.status_code == 404

    async def test_get_returns_parsed_fields(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        config_dir = tmp_root / "config"
        config_dir.mkdir()
        (config_dir / "moderation.yml").write_text(
            "version: 1\nmode: AGGRESSIVE\nrisk_thresholds: {observe: 20, timeout: 50, ban: 90}\n",
            encoding="utf-8",
        )
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/config")

        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "AGGRESSIVE"
        assert body["risk_thresholds"] == {"observe": 20, "timeout": 50, "ban": 90}
        assert body["parse_error"] is None

    async def test_get_reports_parse_error_without_crashing(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        config_dir = tmp_root / "config"
        config_dir.mkdir()
        (config_dir / "moderation.yml").write_text("mode: NOT_A_REAL_MODE\n", encoding="utf-8")
        login_as(app_client, "VIEWER")

        resp = app_client.get("/api/moderation/config")

        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] is None
        assert body["parse_error"] is not None

    async def test_save_requires_admin(self, app_client: TestClient, tmp_root: Path) -> None:
        config_dir = tmp_root / "config"
        config_dir.mkdir()
        (config_dir / "moderation.yml").write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        login_as(app_client, "MODERATOR")

        resp = app_client.post("/api/moderation/config", json={"yaml_text": MINIMAL_VALID_YAML})

        assert resp.status_code == 403

    async def test_save_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.post("/api/moderation/config", json={"yaml_text": MINIMAL_VALID_YAML})
        assert resp.status_code == 401

    async def test_admin_can_save_valid_config(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        config_dir = tmp_root / "config"
        config_dir.mkdir()
        config_file = config_dir / "moderation.yml"
        config_file.write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        login_as(app_client, "ADMIN")

        new_yaml = "version: 1\nmode: SAFE\n"
        resp = app_client.post("/api/moderation/config", json={"yaml_text": new_yaml})

        assert resp.status_code == 200
        assert resp.json() == {"ok": True, "restart_required": True}
        assert config_file.read_text(encoding="utf-8") == new_yaml

    async def test_invalid_config_rejected_and_not_written(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        config_dir = tmp_root / "config"
        config_dir.mkdir()
        config_file = config_dir / "moderation.yml"
        config_file.write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        login_as(app_client, "ADMIN")

        resp = app_client.post(
            "/api/moderation/config", json={"yaml_text": "mode: TOTALLY_INVALID\n"}
        )

        assert resp.status_code == 400
        # исходный файл не тронут при провалившейся валидации
        assert config_file.read_text(encoding="utf-8") == MINIMAL_VALID_YAML

    async def test_no_leftover_tmp_validate_file(
        self, app_client: TestClient, tmp_root: Path
    ) -> None:
        config_dir = tmp_root / "config"
        config_dir.mkdir()
        (config_dir / "moderation.yml").write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        login_as(app_client, "ADMIN")

        app_client.post("/api/moderation/config", json={"yaml_text": MINIMAL_VALID_YAML})

        assert not (config_dir / "moderation.yml.tmp-validate").exists()


class TestWebSocket:
    def test_rejects_without_session(self, app_client: TestClient) -> None:
        try:
            with app_client.websocket_connect("/api/moderation/ws"):
                pass
            raised = False
        except Exception:
            raised = True
        assert raised

    def test_sends_snapshot_after_login(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        with app_client.websocket_connect("/api/moderation/ws") as ws:
            ws.send_text("main")
            data = ws.receive_json()
        assert "clusters" in data
        assert "verdicts" in data


class TestContentWebSocket:
    """Отдельный канал от /ws (пользователь 2026-08-13: "не хочу смешивать
    спам атаку и модерацию вместе") — своя лента срабатываний словарного
    детектора для визуального теста."""

    def test_rejects_without_session(self, app_client: TestClient) -> None:
        try:
            with app_client.websocket_connect("/api/moderation/content_ws"):
                pass
            raised = False
        except Exception:
            raised = True
        assert raised

    def test_sends_empty_snapshot_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        with app_client.websocket_connect("/api/moderation/content_ws") as ws:
            ws.send_text("main")
            data = ws.receive_json()
        assert data["events"] == []

    async def test_sends_recorded_event(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        from cigilbot.types import ContentCategory

        await store.record_content_event(
            user_id="1", login="viewer1", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="OBSERVE", prior_violations=0,
            blocked_by="content_moderation_disabled", enforced=False,
        )

        login_as(app_client, "VIEWER")
        with app_client.websocket_connect("/api/moderation/content_ws") as ws:
            ws.send_text("main")
            data = ws.receive_json()

        assert len(data["events"]) == 1
        assert data["events"][0]["login"] == "viewer1"
