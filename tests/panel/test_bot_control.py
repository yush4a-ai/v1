"""Управление процессом бота с экрана Registry.

Появилось вместе с run.py — единственной командой запуска, при которой
панель живёт ВНУТРИ процесса бота. В этом режиме кнопки «запустить» и
«остановить» бота теряют смысл и становятся опасными: запуск поднял бы
второй main.py со вторым ModerationHub на те же mod.<id>.db и ту же
mod_action_queue, то есть задвоенные вердикты и — когда включат реальное
исполнение — задвоенные баны.

Раньше от этого защищал pid-lock consumer-процессов, который исчез вместе
с ними при переносе движка внутрь бота. Здесь проверяется замена: панель
в общем процессе отвечает 409 вместо тихого запуска дубля.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

import panel.registry_api as registry_api
from cigilbot.integrations import bot_process_control
from panel.auth import SESSION_KEY


def _client(*, in_bot_process: bool, role: str = "ADMIN") -> TestClient:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret-not-for-prod")
    app.include_router(registry_api.router)
    if in_bot_process:
        app.state.in_bot_process = True

    @app.post("/test/set_session")
    async def _set_session(request: Request) -> dict[str, str]:
        request.session[SESSION_KEY] = {
            "login": "tester", "user_id": "1", "role": role, "roles": {}
        }
        return {"ok": "true"}

    client = TestClient(app)
    assert client.post("/test/set_session").status_code == 200
    return client


class TestPanelInsideBotProcess:
    def test_start_refuses_instead_of_spawning_a_duplicate(self) -> None:
        resp = _client(in_bot_process=True).post("/api/registry/bot/start")
        assert resp.status_code == 409
        # Сообщение должно объяснять причину, а не просто отказывать:
        # оператор видит кнопку и вправе ждать, что она работает.
        assert "run.py" in resp.json()["detail"]

    def test_stop_refuses_instead_of_killing_the_panel_itself(self) -> None:
        resp = _client(in_bot_process=True).post("/api/registry/bot/stop")
        assert resp.status_code == 409
        assert "run.py" in resp.json()["detail"]

    def test_status_reports_the_running_process_honestly(self) -> None:
        """Бот жив по определению: панель выполняется в его же процессе.
        Опрашивать pid-файл здесь было бы неверно — его пишет другой путь
        запуска, и он пуст."""
        body = _client(in_bot_process=True).get("/api/registry/bot/status").json()
        assert body == {"running": True, "pid": os.getpid(), "in_process": True}


class TestPanelStandalone:
    """`python -m panel.server` без бота — режим для разработки панели:
    можно перезапускать её, не роняя IRC-подключение и не стирая прогретое
    состояние движка. Здесь кнопки обязаны работать по-старому."""

    def test_status_falls_back_to_pid_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bot_process_control, "is_running", lambda: False)
        monkeypatch.setattr(bot_process_control, "get_pid", lambda: None)

        body = _client(in_bot_process=False).get("/api/registry/bot/status").json()
        assert body == {"running": False, "pid": None}

    def test_start_still_spawns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bot_process_control, "start_bot", lambda: 4242)

        body = _client(in_bot_process=False).post("/api/registry/bot/start").json()
        assert body == {"running": True, "pid": 4242}

    def test_start_requires_admin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bot_process_control, "start_bot", lambda: 4242)

        resp = _client(in_bot_process=False, role="MODERATOR").post("/api/registry/bot/start")
        assert resp.status_code == 403
