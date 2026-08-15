"""Тесты API-эндпоинта /paste_wave (пользователь 2026-08-13: "Зачистить пасту").

Использует общие фикстуры из tests/panel/conftest.py, тот же паттерн, что
tests/panel/test_content_api.py.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.types import ChatEvent
from cigilbot.storage.store import ModerationStore
from tests.panel.conftest import login_as

PASTE = "Привет, это я - твой единственный зритель, смотрю тебя годами."


class TestPasteWaveEndpoint:
    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get(f"/api/moderation/paste_wave?sample_text={PASTE}")
        assert resp.status_code == 401

    # MODERATOR, не VIEWER: сообщения других пользователей — личные данные,
    # не публичная информация (2026-08-15, сужение VIEWER-доступа по итогам
    # UX-аудита панели).
    async def test_viewer_forbidden(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get(f"/api/moderation/paste_wave?sample_text={PASTE}")
        assert resp.status_code == 403

    async def test_rejects_empty_sample(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.get("/api/moderation/paste_wave?sample_text=")
        assert resp.status_code == 400

    async def test_moderator_can_search(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        event = ChatEvent(user_id="1", login="viewer1", text=PASTE, timestamp=time.time())
        await store.save_message(event, fingerprint(PASTE))

        login_as(app_client, "MODERATOR")
        resp = app_client.get(f"/api/moderation/paste_wave?sample_text={PASTE}")

        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["login"] == "viewer1"

    async def test_empty_when_no_matches(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.get(f"/api/moderation/paste_wave?sample_text={PASTE}")
        assert resp.status_code == 200
        assert resp.json() == []


class TestRecentMessagesEndpoint:
    """Источник для клика "вставить как образец пасты" в UI (пользователь
    2026-08-13: "сделай привязку к чату, чтобы на 1 кнопку нажал и паста
    вставилась, чтобы не копировать и вставлять")."""

    async def test_requires_session(self, app_client: TestClient) -> None:
        resp = app_client.get("/api/moderation/recent_messages")
        assert resp.status_code == 401

    async def test_viewer_forbidden(self, app_client: TestClient) -> None:
        login_as(app_client, "VIEWER")
        resp = app_client.get("/api/moderation/recent_messages")
        assert resp.status_code == 403

    async def test_empty_by_default(self, app_client: TestClient) -> None:
        login_as(app_client, "MODERATOR")
        resp = app_client.get("/api/moderation/recent_messages")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_moderator_can_read(
        self, app_client: TestClient, store: ModerationStore
    ) -> None:
        event = ChatEvent(user_id="1", login="viewer1", text=PASTE, timestamp=time.time())
        await store.save_message(event, fingerprint(PASTE))

        login_as(app_client, "MODERATOR")
        resp = app_client.get("/api/moderation/recent_messages")

        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["login"] == "viewer1"
        assert body[0]["text"] == PASTE
