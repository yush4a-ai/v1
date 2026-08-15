"""Тесты API-эндпоинтов живого рубильника автоклипа в panel/moderation_api.py.

Та же структура, что TestContentSettingsEndpoint в test_content_api.py —
autoclip_settings задуман по тому же singleton-паттерну, что content_settings.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from cigilbot.storage.store import ModerationStore
from tests.panel.conftest import login_as


class TestAutoclipSettingsEndpoint:
    async def test_get_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/autoclip_settings")
        assert resp.status_code == 401

    async def test_none_by_default_not_false(self, app_client: TestClient) -> None:
        """None — панель ещё не трогала канал, отличимо от явного выключения
        (см. AutoclipSettings.enabled в cigilbot/storage/store.py)."""
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/autoclip_settings")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is None

    async def test_set_requires_moderator(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post("/api/moderation/autoclip_settings", json={"enabled": True})
        assert resp.status_code == 403

    async def test_moderator_can_enable(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "MODERATOR", login="mod1")
        resp = app_client.post("/api/moderation/autoclip_settings", json={"enabled": True})
        assert resp.status_code == 200

    async def test_admin_can_enable(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post("/api/moderation/autoclip_settings", json={"enabled": True})

        assert resp.status_code == 200
        assert resp.json()["enabled"] is True
        settings = await store.get_autoclip_settings()
        assert settings.enabled is True
        assert settings.updated_by == "admin1"

    async def test_admin_can_disable_again(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/autoclip_settings", json={"enabled": True})

        resp = app_client.post("/api/moderation/autoclip_settings", json={"enabled": False})

        assert resp.json()["enabled"] is False

    async def test_get_reflects_last_write(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/autoclip_settings", json={"enabled": True})

        resp = app_client.get("/api/moderation/autoclip_settings")

        assert resp.json()["enabled"] is True


class TestAutoclipThresholdsEndpoint:
    """Тот же уровень доступа, что enabled: MODERATOR+ для записи, любая
    аутентифицированная сессия для чтения."""

    async def test_set_requires_moderator(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"burst_unique_authors_threshold": 8},
        )
        assert resp.status_code == 403

    async def test_admin_can_set_all_thresholds(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={
                "burst_unique_authors_threshold": 8,
                "burst_window_seconds": 15.0,
                "keyword_phrases": ["клип", "clip it"],
                "voice_phrases": ["заклипай"],
                "cooldown_seconds": 120.0,
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["burst_unique_authors_threshold"] == 8
        assert body["keyword_phrases"] == ["клип", "clip it"]
        settings = await store.get_autoclip_settings()
        assert settings.updated_by == "admin1"

    async def test_setting_thresholds_does_not_change_enabled(
        self, app_client: TestClient
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post("/api/moderation/autoclip_settings", json={"enabled": True})

        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"burst_unique_authors_threshold": 8},
        )

        assert resp.json()["enabled"] is True

    async def test_rejects_zero_burst_threshold(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"burst_unique_authors_threshold": 0},
        )
        assert resp.status_code == 400

    async def test_rejects_zero_burst_window(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"burst_window_seconds": 0},
        )
        assert resp.status_code == 400

    async def test_rejects_negative_cooldown(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"cooldown_seconds": -1},
        )
        assert resp.status_code == 400

    async def test_rejects_empty_keyword_phrase(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"keyword_phrases": ["клип", "   "]},
        )
        assert resp.status_code == 400

    async def test_partial_update_leaves_other_fields_none(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")

        resp = app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"burst_unique_authors_threshold": 5},
        )

        body = resp.json()
        assert body["burst_unique_authors_threshold"] == 5
        assert body["keyword_phrases"] is None


class TestAutoclipAutoScaleEndpoint:
    async def test_set_requires_moderator(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "percent": 0.04, "minimum": 4, "maximum": 200},
        )
        assert resp.status_code == 403

    async def test_admin_can_enable(self, app_client: TestClient, store: ModerationStore) -> None:
        login_as(app_client, "ADMIN", login="admin1")

        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "percent": 0.04, "minimum": 4, "maximum": 200},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["burst_auto_scale_enabled"] is True
        assert body["burst_auto_scale_percent"] == 0.04
        settings = await store.get_autoclip_settings()
        assert settings.updated_by == "admin1"

    async def test_admin_can_disable(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "percent": 0.04, "minimum": 4, "maximum": 200},
        )

        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": False},
        )

        assert resp.status_code == 200
        assert resp.json()["burst_auto_scale_enabled"] is False

    async def test_enabling_without_percent_rejected(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "minimum": 4, "maximum": 200},
        )
        assert resp.status_code == 400

    async def test_percent_out_of_range_rejected(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "percent": 1.5, "minimum": 4, "maximum": 200},
        )
        assert resp.status_code == 400

    async def test_maximum_below_minimum_rejected(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "percent": 0.04, "minimum": 100, "maximum": 10},
        )
        assert resp.status_code == 400

    async def test_disabling_does_not_require_bounds(self, app_client: TestClient) -> None:
        login_as(app_client, "ADMIN")
        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": False},
        )
        assert resp.status_code == 200

    async def test_auto_scale_does_not_touch_manual_thresholds(
        self, app_client: TestClient
    ) -> None:
        login_as(app_client, "ADMIN")
        app_client.post(
            "/api/moderation/autoclip_settings/thresholds",
            json={"burst_unique_authors_threshold": 8},
        )

        resp = app_client.post(
            "/api/moderation/autoclip_settings/auto_scale",
            json={"enabled": True, "percent": 0.04, "minimum": 4, "maximum": 200},
        )

        assert resp.json()["burst_unique_authors_threshold"] == 8
