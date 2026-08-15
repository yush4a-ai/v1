"""Тесты panel/registry_api.py: sync_channel (внешний вход, токен-guard) и
управление каналом (start/stop/reset_crash) через реестр.

До этой правки (test-coverage-аудит 2026-08-15, HIGH #7) ни один из этих
роутов не имел ни одного теста — sync_channel единственный внешний HTTP-вход
в Channel Registry, защищённый общим секретом INTERNAL_SYNC_TOKEN, и
отсутствие теста означало, что ни проверка токена, ни поведение при
отсутствующем/неверном токене, ни сама логика синхронизации канала не были
защищены от регрессии. bot/status/start/stop уже покрыты
tests/panel/test_bot_control.py — здесь не дублируются.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

import panel.registry_api as registry_api
from cigilbot.storage.registry_store import RegistryStore
from panel.auth import SESSION_KEY


@pytest.fixture
def registry_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, Path]:
    registry_db = tmp_path / "registry.db"
    env_file = tmp_path / ".env"
    env_file.write_text("INTERNAL_SYNC_TOKEN=test-sync-secret\n", encoding="utf-8")

    monkeypatch.setattr(registry_api, "REGISTRY_DB", registry_db)
    monkeypatch.setattr(registry_api, "ENV_FILE", env_file)
    # TestClient не даёт подменить request.client.host (нет параметра для
    # этого в его __init__) — его дефолт "testclient" не входит в реальный
    # _LOCALHOST_IPS. Добавляем его сюда только для теста: проверка токена
    # (то, что реально тестируется этим файлом) не зависит от того, каким
    # именно способом эмулирован "запрос с localhost".
    monkeypatch.setattr(registry_api, "_LOCALHOST_IPS", registry_api._LOCALHOST_IPS | {"testclient"})

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret-not-for-prod")
    app.include_router(registry_api.router)

    @app.post("/test/set_session")
    async def _set_session(request: Request, role: str = "ADMIN") -> dict[str, str]:
        request.session[SESSION_KEY] = {
            "login": "tester", "user_id": "1", "role": role, "roles": {}
        }
        return {"ok": "true"}

    return app, registry_db


def _authed_client(app: FastAPI, *, role: str = "ADMIN") -> TestClient:
    client = TestClient(app)
    assert client.post("/test/set_session", params={"role": role}).status_code == 200
    return client


class TestSyncChannel:
    """POST /api/registry/channels — единственный внешний вход в реестр,
    аутентификация НЕ через cookie-сессию (см. докстринг registry_api.py),
    а через X-Internal-Token + проверку что запрос пришёл с localhost."""

    def test_missing_token_configured_returns_503(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("", encoding="utf-8")  # без INTERNAL_SYNC_TOKEN
        monkeypatch.setattr(registry_api, "REGISTRY_DB", tmp_path / "registry.db")
        monkeypatch.setattr(registry_api, "ENV_FILE", env_file)
        monkeypatch.setattr(
            registry_api, "_LOCALHOST_IPS", registry_api._LOCALHOST_IPS | {"testclient"}
        )
        app = FastAPI()
        app.include_router(registry_api.router)
        client = TestClient(app)

        resp = client.post(
            "/api/registry/channels",
            json={"broadcaster_id": "1", "login": "streamer"},
            headers={"X-Internal-Token": "anything"},
        )

        assert resp.status_code == 503

    def test_wrong_token_rejected(self, registry_app: tuple[FastAPI, Path]) -> None:
        app, _db = registry_app
        client = TestClient(app)

        resp = client.post(
            "/api/registry/channels",
            json={"broadcaster_id": "1", "login": "streamer"},
            headers={"X-Internal-Token": "wrong-token"},
        )

        assert resp.status_code == 401

    def test_missing_token_header_rejected(self, registry_app: tuple[FastAPI, Path]) -> None:
        app, _db = registry_app
        client = TestClient(app)

        resp = client.post(
            "/api/registry/channels", json={"broadcaster_id": "1", "login": "streamer"}
        )

        assert resp.status_code == 401

    def test_correct_token_registers_new_channel(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, db = registry_app
        client = TestClient(app)

        resp = client.post(
            "/api/registry/channels",
            json={"broadcaster_id": "1", "login": "streamer", "display_name": "Streamer"},
            headers={"X-Internal-Token": "test-sync-secret"},
        )

        # HTTP-код 201 — единственный надёжный признак "создан, не обновлён"
        # в текущем ответе: тело { "status": "registered"|"updated",
        # **_channel_to_dict(record) } распаковывает record.status
        # ("active"/"inactive" — состояние канала) ПОСЛЕ ключа "status" со
        # значением операции ("registered"/"updated") с тем же именем —
        # второй молча перетирает первый (dead-code/bug-аудит 2026-08-15,
        # найдено этим тестом; не входит в согласованный список правок,
        # поэтому зафиксировано тестом под текущим поведением, а не
        # исправлено самим кодом).
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "active"
        assert body["broadcaster_id"] == "1"
        assert body["login"] == "streamer"

    async def test_correct_token_updates_existing_channel(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, db = registry_app
        registry = RegistryStore(str(db))
        await registry.connect()
        await registry.upsert_channel(broadcaster_id="1", login="oldname", registered_by="manual")
        await registry.close()

        client = TestClient(app)
        resp = client.post(
            "/api/registry/channels",
            json={"broadcaster_id": "1", "login": "newname"},
            headers={"X-Internal-Token": "test-sync-secret"},
        )

        # См. комментарий в test_correct_token_registers_new_channel —
        # HTTP-код 200 отличает "обновлён" от 201 "создан", тело этого не
        # делает (status в JSON — record.status, не статус операции).
        assert resp.status_code == 200
        body = resp.json()
        assert body["login"] == "newname"

    def test_blank_fields_rejected(self, registry_app: tuple[FastAPI, Path]) -> None:
        app, _db = registry_app
        client = TestClient(app)

        resp = client.post(
            "/api/registry/channels",
            json={"broadcaster_id": "  ", "login": "streamer"},
            headers={"X-Internal-Token": "test-sync-secret"},
        )

        assert resp.status_code == 422


class TestChannelLifecycle:
    """start/stop/reset_crash — desired_state, исполняет бот отдельно
    (ModerationHub на следующем тике сверки), не эти хендлеры."""

    async def test_start_sets_desired_state_running(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, db = registry_app
        registry = RegistryStore(str(db))
        await registry.connect()
        await registry.upsert_channel(broadcaster_id="1", login="streamer", registered_by="manual")
        await registry.close()

        resp = _authed_client(app).post("/api/registry/channels/1/start")

        assert resp.status_code == 200
        assert resp.json()["desired_state"] == "running"

    async def test_stop_sets_desired_state_stopped(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, db = registry_app
        registry = RegistryStore(str(db))
        await registry.connect()
        await registry.upsert_channel(broadcaster_id="1", login="streamer", registered_by="manual")
        await registry.set_desired_state("1", "running")
        await registry.close()

        resp = _authed_client(app).post("/api/registry/channels/1/stop")

        assert resp.status_code == 200
        assert resp.json()["desired_state"] == "stopped"

    def test_start_unknown_channel_returns_404(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, _db = registry_app
        resp = _authed_client(app).post("/api/registry/channels/does-not-exist/start")
        assert resp.status_code == 404

    def test_start_requires_admin(self, registry_app: tuple[FastAPI, Path]) -> None:
        app, _db = registry_app
        resp = _authed_client(app, role="MODERATOR").post("/api/registry/channels/1/start")
        assert resp.status_code == 403

    async def test_reset_crash_clears_restart_count(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, db = registry_app
        registry = RegistryStore(str(db))
        await registry.connect()
        await registry.upsert_channel(broadcaster_id="1", login="streamer", registered_by="manual")
        await registry.close()

        resp = _authed_client(app).post("/api/registry/channels/1/reset_crash")

        assert resp.status_code == 200
        assert resp.json()["restart_count"] == 0

    def test_reset_crash_unknown_channel_returns_404(
        self, registry_app: tuple[FastAPI, Path]
    ) -> None:
        app, _db = registry_app
        resp = _authed_client(app).post("/api/registry/channels/does-not-exist/reset_crash")
        assert resp.status_code == 404
