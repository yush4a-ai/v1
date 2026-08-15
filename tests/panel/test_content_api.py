"""Тесты API-эндпоинтов Rule Engine (словарный детектор) в panel/moderation_api.py.

Использует общие фикстуры из tests/panel/conftest.py (app_client, login_as,
store) — тот же паттерн, что TestDiscordWebhookEndpoints в
tests/panel/test_moderation_api.py.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from cigilbot.storage.store import ModerationStore
from tests.panel.conftest import login_as


class TestContentRulesEndpoints:
    """Тот же уровень доступа, что Pattern Library: меняет ADMIN+, читает
    MODERATOR+ — список запрещённых слов/фраз тривиально обходится, если
    знаешь список, поэтому не публичная информация (2026-08-15, сужение
    VIEWER-доступа по итогам UX-аудита панели)."""

    async def test_list_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/content_rules")
        assert resp.status_code == 401

    async def test_list_viewer_forbidden(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/content_rules")
        assert resp.status_code == 403

    async def test_empty_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.get("/api/moderation/content_rules")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_add_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "racism", "phrase": "плохое слово"},
        )
        assert resp.status_code == 403

    async def test_admin_can_add(self, app_client: TestClient, store: ModerationStore) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "racism", "phrase": "плохое слово"},
        )

        assert resp.status_code == 200
        rules = await store.list_content_rules()
        assert len(rules) == 1
        assert rules[0].phrase == "плохое слово"

    async def test_rejects_unknown_category(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "unknown_category", "phrase": "слово"},
        )
        assert resp.status_code == 400

    async def test_rejects_empty_phrase(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "racism", "phrase": "   "},
        )
        assert resp.status_code == 400

    async def test_list_reflects_added_rule(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/content_rules",
            json={"category": "threats", "phrase": "угроза"},
        )

        resp = app_client.get("/api/moderation/content_rules")

        body = resp.json()
        assert len(body) == 1
        assert body[0]["category"] == "threats"
        assert body[0]["phrase"] == "угроза"
        assert body[0]["enabled"] is True

    async def test_toggle_enabled_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        created = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "advertising", "phrase": "реклама"},
        ).json()

        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            f"/api/moderation/content_rules/{created['id']}/enabled",
            json={"enabled": False},
        )
        assert resp.status_code == 403

    async def test_admin_can_disable_rule(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        created = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "advertising", "phrase": "реклама"},
        ).json()

        resp = app_client.post(
            f"/api/moderation/content_rules/{created['id']}/enabled",
            json={"enabled": False},
        )

        assert resp.status_code == 200
        rules = await store.list_content_rules()
        assert rules[0].enabled is False

    async def test_admin_can_delete_rule(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN")
        created = app_client.post(
            "/api/moderation/content_rules",
            json={"category": "racism", "phrase": "слово"},
        ).json()

        resp = app_client.post(f"/api/moderation/content_rules/{created['id']}/delete", json={})

        assert resp.status_code == 200
        assert await store.list_content_rules() == ()


class TestContentSettingsEndpoint:
    """Выключатель content-модерации — режим наблюдателя по умолчанию,
    см. чат с пользователем от 2026-08-12."""

    async def test_get_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/content_settings")
        assert resp.status_code == 401

    async def test_disabled_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/content_settings")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    async def test_set_requires_admin(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post("/api/moderation/content_settings", json={"enabled": True})
        assert resp.status_code == 403

    async def test_admin_can_enable(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post("/api/moderation/content_settings", json={"enabled": True})

        assert resp.status_code == 200
        assert resp.json()["enabled"] is True
        settings = await store.get_content_settings()
        assert settings.enabled is True
        assert settings.updated_by == "admin1"

    async def test_admin_can_disable_again(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/content_settings", json={"enabled": True})

        resp = app_client.post("/api/moderation/content_settings", json={"enabled": False})

        assert resp.json()["enabled"] is False


class TestContentEventsEndpoint:
    # MODERATOR, не VIEWER: конкретные логины и категория нарушения
    # (расизм/угрозы/реклама) — личные данные, не публичная лента
    # (2026-08-15, сужение VIEWER-доступа по итогам UX-аудита панели).
    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/content_events")
        assert resp.status_code == 401

    async def test_viewer_forbidden(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/content_events")
        assert resp.status_code == 403

    async def test_empty_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.get("/api/moderation/content_events")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_moderator_can_read(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        from cigilbot.domain.types import ContentCategory

        await store.record_content_event(
            user_id="1", login="viewer1", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="OBSERVE", prior_violations=0,
            blocked_by="content_moderation_disabled", enforced=False,
        )

        login_as(app_client, "MODERATOR")
        resp = app_client.get("/api/moderation/content_events")

        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["login"] == "viewer1"
        assert body[0]["enforced"] is False


class TestContentEventManualActionEndpoint:
    """Пользователь 2026-08-13: "можем как-то помечать сообщения..." —
    та же роль, что у /actions (MODERATOR+), не строже."""

    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.post(
            "/api/moderation/content_events/1/manual_action", json={"action": "BAN"}
        )
        assert resp.status_code == 401

    async def test_viewer_forbidden(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post(
            "/api/moderation/content_events/1/manual_action", json={"action": "BAN"}
        )
        assert resp.status_code == 403

    async def test_rejects_unknown_action(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.post(
            "/api/moderation/content_events/1/manual_action", json={"action": "NOT_REAL"}
        )
        assert resp.status_code == 400

    async def test_moderator_can_mark(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        from cigilbot.domain.types import ContentCategory

        event_id = await store.record_content_event(
            user_id="1", login="viewer1", message_id=None, category=ContentCategory.RACISM,
            matched_phrase="слово", action="TIMEOUT", prior_violations=0, blocked_by="",
            enforced=False,
        )

        login_as(app_client, "MODERATOR", login="mod1")
        resp = app_client.post(
            f"/api/moderation/content_events/{event_id}/manual_action",
            json={"action": "TIMEOUT"},
        )

        assert resp.status_code == 200
        events = await store.list_content_events()
        assert events[0]["manual_action"] == "TIMEOUT"
        assert events[0]["manual_action_by"] == "mod1"
