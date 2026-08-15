"""Тесты panel/auth.py: конфиг, резолвер ролей, полный OAuth callback на моках.

Ни одного реального запроса к Twitch — panel.auth._test_transport
подменяется на httpx.MockTransport, тот же приём, что в
bot/moderation/test_twitch_api.py.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

import panel.auth as auth
import paths
from cigilbot.storage.registry_store import RegistryStore
from cigilbot.storage.store import ModerationStore
from paths import PanelRoots


class TestPanelAuthConfig:
    def test_not_configured_when_empty(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("", encoding="utf-8")
        cfg = auth.load_panel_auth_config(tmp_path)
        assert cfg.configured is False

    def test_configured_reads_from_env_file(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "PANEL_TWITCH_CLIENT_ID=abc\n"
            "PANEL_TWITCH_CLIENT_SECRET=xyz\n"
            "PANEL_TWITCH_CHANNEL=#SomeChannel\n",
            encoding="utf-8",
        )
        cfg = auth.load_panel_auth_config(tmp_path)
        assert cfg.configured is True
        assert cfg.client_id == "abc"
        # канал нормализуется: без # и в нижнем регистре
        assert cfg.channel == "somechannel"

    def test_default_redirect_uri(self, tmp_path: Path) -> None:
        # 8766 — порт единственной панели. Раньше умолчанием было 8765
        # (панель нейроботов), а 8766 приходилось передавать явно вторым
        # процессом; процесс теперь один, и умолчание стало его портом.
        (tmp_path / ".env").write_text("", encoding="utf-8")
        cfg = auth.load_panel_auth_config(tmp_path)
        assert cfg.redirect_uri == "http://localhost:8766/auth/callback"

    def test_reads_from_custom_env_filename(self, tmp_path: Path) -> None:
        # env_filename остался параметром ради тестов: .env теперь один на
        # монорепо, и разносить PANEL_* по файлам больше незачем.
        (tmp_path / ".env").write_text("PANEL_TWITCH_CLIENT_ID=wrong\n", encoding="utf-8")
        (tmp_path / ".env.moderation").write_text(
            "PANEL_TWITCH_CLIENT_ID=mod_cid\n"
            "PANEL_TWITCH_CLIENT_SECRET=mod_csecret\n"
            "PANEL_TWITCH_CHANNEL=streamer\n",
            encoding="utf-8",
        )
        cfg = auth.load_panel_auth_config(tmp_path, env_filename=".env.moderation")
        assert cfg.client_id == "mod_cid"

    def test_custom_default_port_used_when_redirect_uri_not_set(self, tmp_path: Path) -> None:
        (tmp_path / ".env.moderation").write_text("", encoding="utf-8")
        cfg = auth.load_panel_auth_config(tmp_path, env_filename=".env.moderation", default_port=8766)
        assert cfg.redirect_uri == "http://localhost:8766/auth/callback"
        assert cfg.bot_redirect_uri == "http://localhost:8766/auth/bot/callback"

    def test_explicit_redirect_uri_overrides_default_port(self, tmp_path: Path) -> None:
        # Явный PANEL_TWITCH_REDIRECT_URI в .env.moderation всегда побеждает
        # default_port — тот только подставляет умолчание, когда переменная
        # не задана вовсе.
        (tmp_path / ".env.moderation").write_text(
            "PANEL_TWITCH_REDIRECT_URI=http://localhost:9999/auth/callback\n", encoding="utf-8"
        )
        cfg = auth.load_panel_auth_config(tmp_path, env_filename=".env.moderation", default_port=8766)
        assert cfg.redirect_uri == "http://localhost:9999/auth/callback"


class TestResolveRole:
    def test_broadcaster_is_owner(self) -> None:
        role = auth._resolve_role(
            login="streamer", is_broadcaster=True, is_moderator=False, admin_override=None
        )
        assert role == "OWNER"

    def test_moderator_gets_moderator(self) -> None:
        role = auth._resolve_role(
            login="mod1", is_broadcaster=False, is_moderator=True, admin_override=None
        )
        assert role == "MODERATOR"

    def test_regular_viewer_gets_viewer(self) -> None:
        role = auth._resolve_role(
            login="viewer1", is_broadcaster=False, is_moderator=False, admin_override=None
        )
        assert role == "VIEWER"

    def test_admin_override_beats_broadcaster_status(self) -> None:
        # admin_override приходит из mod_panel_users — ручное решение
        # OWNER/ADMIN панели, применяется поверх статуса на Twitch.
        role = auth._resolve_role(
            login="someone", is_broadcaster=False, is_moderator=False, admin_override="ADMIN"
        )
        assert role == "ADMIN"

    def test_unrecognized_override_value_ignored(self) -> None:
        # Значения вроде "MODERATOR" в mod_panel_users не должны обходить
        # обычную логику ролей — override работает только для ADMIN/OWNER.
        role = auth._resolve_role(
            login="mod1", is_broadcaster=False, is_moderator=True, admin_override="MODERATOR"
        )
        assert role == "MODERATOR"


@pytest.fixture
def auth_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, Path]:
    # panel.rate_limit.limiter — модульный singleton (см. её докстринг: один
    # объект на всё приложение, не по одному на роутер), и его in-memory
    # storage переживает между тестами в рамках одного pytest-процесса.
    # Без сброса тесты, идущие позже в файле, начинают падать с "ratelimit
    # exceeded" на /auth/login (10/minute) не из-за своей логики, а из-за
    # накопленных попыток входа от предыдущих тестов этого же файла.
    from panel.rate_limit import limiter as _rate_limiter

    _rate_limiter.reset()

    (tmp_path / ".env").write_text(
        "PANEL_TWITCH_CLIENT_ID=cid\n"
        "PANEL_TWITCH_CLIENT_SECRET=csecret\n"
        "PANEL_TWITCH_CHANNEL=streamer\n",
        encoding="utf-8",
    )
    db = tmp_path / "mod.db"

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.state.panel_auth_config = auth.load_panel_auth_config(tmp_path)
    app.state.panel_roots = PanelRoots.all_at(tmp_path)
    app.state.moderation_store_factory = lambda: ModerationStore(str(db))
    app.include_router(auth.router)
    return app, db


class TestLoginRedirect:
    def test_redirects_to_twitch_with_state(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/login", follow_redirects=False)
        assert resp.status_code in (302, 307)
        assert "id.twitch.tv/oauth2/authorize" in resp.headers["location"]
        assert "state=" in resp.headers["location"]

    def test_503_when_not_configured(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("", encoding="utf-8")
        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key="test-secret")
        app.state.panel_auth_config = auth.load_panel_auth_config(tmp_path)
        app.state.moderation_store_factory = lambda: ModerationStore(str(tmp_path / "mod.db"))
        app.include_router(auth.router)
        client = TestClient(app)

        resp = client.get("/auth/login", follow_redirects=False)

        assert resp.status_code == 503


class TestCallback:
    def test_unknown_state_rejected(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/callback?code=x&state=not-a-real-state")
        assert resp.status_code == 400

    def test_full_flow_broadcaster_becomes_owner(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(200, json={"access_token": "user-token"})
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                auth_header = request.headers["Authorization"]
                if auth_header == "Bearer user-token":
                    return httpx.Response(
                        200, json={"data": [{"login": "streamer", "id": "1"}]}
                    )
                # App token lookup by ?login=streamer -> сам канал
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        assert resp.status_code in (302, 307)
        me = client.get("/auth/me")
        assert me.json()["authenticated"] is True
        assert me.json()["role"] == "OWNER"
        assert me.json()["login"] == "streamer"

    def test_full_flow_moderator_role(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                token = "user-token" if form.get("grant_type") == "authorization_code" else "app-token"
                return httpx.Response(200, json={"access_token": token})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer user-token":
                    return httpx.Response(200, json={"data": [{"login": "mod1", "id": "2"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                # mod1 (user_id=2) модерирует канал с broadcaster_id="1" (streamer)
                return httpx.Response(200, json={"data": [{"broadcaster_id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        me = client.get("/auth/me")
        assert me.json()["role"] == "MODERATOR"

    def test_full_flow_regular_viewer(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                token = "user-token" if form.get("grant_type") == "authorization_code" else "app-token"
                return httpx.Response(200, json={"access_token": token})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer user-token":
                    return httpx.Response(200, json={"data": [{"login": "viewer1", "id": "3"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                # Обычный зритель не модерирует никакие каналы.
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        me = client.get("/auth/me")
        assert me.json()["role"] == "VIEWER"

    def test_admin_override_from_mod_panel_users(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, db = auth_app
        store = ModerationStore(str(db))

        async def seed() -> None:
            await store.connect()
            await store.upsert_panel_user("viewer1", "ADMIN")
            await store.close()

        asyncio.run(seed())

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer tok":
                    return httpx.Response(200, json={"data": [{"login": "viewer1", "id": "3"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        me = client.get("/auth/me")
        assert me.json()["role"] == "ADMIN"


class TestLogout:
    def test_clears_session(self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch) -> None:
        app, db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.path == "/helix/users":
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]
        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
        assert client.get("/auth/me").json()["authenticated"] is True

        client.get("/auth/logout", follow_redirects=False)

        assert client.get("/auth/me").json()["authenticated"] is False


class TestMeWithoutSession:
    def test_reports_not_authenticated(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/me")
        assert resp.json() == {"authenticated": False, "login_configured": True}


def _login_as_owner(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Проходит обычный /auth/login+/callback как broadcaster (-> OWNER),
    самая простая роль ADMIN+ для тестов bot-token flow, которые требуют
    существующей аутентифицированной сессии."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            return httpx.Response(200, json={"access_token": "owner-tok"})
        if request.url.path == "/helix/users":
            return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
        if request.url.path == "/helix/moderation/channels":
            return httpx.Response(200, json={"data": []})
        raise AssertionError(f"unexpected request {request.url}")

    monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))
    login_resp = client.get("/auth/login", follow_redirects=False)
    state = login_resp.headers["location"].split("state=")[1].split("&")[0]
    client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)


class TestBotTokenLogin:
    def test_requires_authenticated_session(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/bot/login", follow_redirects=False)
        assert resp.status_code == 401

    def test_viewer_forbidden(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                token = "user-tok" if form.get("grant_type") == "authorization_code" else "app-tok"
                return httpx.Response(200, json={"access_token": token})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer user-tok":
                    return httpx.Response(200, json={"data": [{"login": "viewer1", "id": "3"}]})
                # App token lookup по ?login=streamer -> сам канал, не viewer1
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))
        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]
        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        resp = client.get("/auth/bot/login", follow_redirects=False)
        assert resp.status_code == 403

    def test_owner_redirects_to_twitch_with_bot_scopes(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/bot/login", follow_redirects=False)

        assert resp.status_code in (302, 307)
        location = resp.headers["location"]
        assert "id.twitch.tv/oauth2/authorize" in location
        assert "moderator%3Amanage%3Abanned_users" in location
        assert "auth%2Fbot%2Fcallback" in location


class TestBotTokenCallback:
    def test_unknown_state_rejected(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/bot/callback?code=x&state=not-a-real-state")
        assert resp.status_code == 400

    def test_full_flow_writes_env_and_reports_moderator(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "bot-access", "refresh_token": "bot-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer bot-access":
                    return httpx.Response(200, json={"data": [{"login": "mybot", "id": "99"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                # mybot (user_id=99) модерирует канал streamer (broadcaster_id="1")
                return httpx.Response(200, json={"data": [{"broadcaster_id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/bot/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/bot/callback.json?code=abc&state={state}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["bot_login"] == "mybot"
        assert body["is_moderator"] is True
        assert body["warning"] is None

        env_text = (app.state.panel_roots.repo / ".env").read_text(encoding="utf-8")
        assert "TWITCH_MOD_ACCESS_TOKEN=bot-access" in env_text
        assert "TWITCH_MOD_REFRESH_TOKEN=bot-refresh" in env_text
        assert "TWITCH_MOD_BOT_LOGIN=mybot" in env_text
        assert "TWITCH_MOD_BROADCASTER_ID=1" in env_text

    def test_warns_when_bot_account_not_moderator(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "bot-access", "refresh_token": "bot-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer bot-access":
                    return httpx.Response(200, json={"data": [{"login": "notamod", "id": "42"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/bot/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/bot/callback.json?code=abc&state={state}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["is_moderator"] is False
        assert body["warning"] is not None
        assert "notamod" in body["warning"]

    def test_html_callback_renders_page_on_success(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "bot-access", "refresh_token": "bot-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer bot-access":
                    return httpx.Response(200, json={"data": [{"login": "mybot", "id": "99"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": [{"broadcaster_id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/bot/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/bot/callback?code=abc&state={state}")

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "mybot" in resp.text

    def test_html_callback_renders_error_page_on_bad_state(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/bot/callback?code=abc&state=not-a-real-state")

        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]


class TestBotTokenStatus:
    def test_not_configured_by_default(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/bot/status")
        assert resp.json() == {"configured": False, "bot_login": ""}

    def test_configured_after_env_written(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        (app.state.panel_roots.repo / ".env").write_text(
            (app.state.panel_roots.repo / ".env").read_text(encoding="utf-8")
            + "TWITCH_MOD_ACCESS_TOKEN=x\nTWITCH_MOD_REFRESH_TOKEN=y\nTWITCH_MOD_BOT_LOGIN=mybot\n",
            encoding="utf-8",
        )
        client = TestClient(app)

        resp = client.get("/auth/bot/status")

        assert resp.json() == {"configured": True, "bot_login": "mybot"}


# Chat-токен (TWITCH_BOT_TOKEN/TWITCH_BOT_REFRESH_TOKEN, chat:read/chat:edit)
# — третий из трёх независимых OAuth-флоу в этом файле, до этой правки не
# имел ни одного теста (test-coverage-аудит 2026-08-15, HIGH #7): state-
# валидация и запись токена в .env для этой ветки не были защищены
# регрессионным тестом, при том что рассинхронизация именно этого файла —
# задокументированный класс инцидента ("баны начинают падать с 401").
class TestBotChatTokenLogin:
    def test_requires_authenticated_session(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/bot/chat_login", follow_redirects=False)
        assert resp.status_code == 401

    def test_viewer_forbidden(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                token = "user-tok" if form.get("grant_type") == "authorization_code" else "app-tok"
                return httpx.Response(200, json={"access_token": token})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer user-tok":
                    return httpx.Response(200, json={"data": [{"login": "viewer1", "id": "3"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))
        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]
        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        resp = client.get("/auth/bot/chat_login", follow_redirects=False)
        assert resp.status_code == 403

    def test_owner_redirects_to_twitch_with_chat_scopes(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/bot/chat_login", follow_redirects=False)

        assert resp.status_code in (302, 307)
        location = resp.headers["location"]
        assert "id.twitch.tv/oauth2/authorize" in location
        assert "chat%3Aread" in location
        assert "chat%3Aedit" in location
        assert "auth%2Fbot%2Fcallback" in location


class TestBotChatTokenCallback:
    def test_unknown_state_rejected(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/bot/callback?code=x&state=not-a-real-state")
        assert resp.status_code == 400

    def test_full_flow_writes_env_without_moderator_check(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """purpose="chat" в _process_bot_callback пропускает вызов
        _fetch_moderated_channel_ids целиком (chat:edit не требует прав
        модератора — только валидный токен) — mock не регистрирует
        /helix/moderation/channels вовсе, чтобы AssertionError сам поймал
        регрессию, если этот путь начнёт его дёргать."""
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "chat-access", "refresh_token": "chat-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer chat-access":
                    return httpx.Response(200, json={"data": [{"login": "mybot", "id": "99"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/bot/chat_login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/bot/callback.json?code=abc&state={state}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["purpose"] == "chat"
        assert body["bot_login"] == "mybot"
        assert body["is_moderator"] is True
        assert body["warning"] is None

        env_text = (app.state.panel_roots.repo / ".env").read_text(encoding="utf-8")
        assert "TWITCH_BOT_TOKEN=chat-access" in env_text
        assert "TWITCH_BOT_REFRESH_TOKEN=chat-refresh" in env_text
        assert "TWITCH_BOT_NICK=mybot" in env_text
        # Chat-flow не пишет TWITCH_MOD_* — разные ключи, разное назначение.
        assert "TWITCH_MOD_ACCESS_TOKEN=chat-access" not in env_text

    def test_html_callback_renders_chat_title_on_success(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "chat-access", "refresh_token": "chat-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer chat-access":
                    return httpx.Response(200, json={"data": [{"login": "mybot", "id": "99"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/bot/chat_login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/bot/callback?code=abc&state={state}")

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Чат-токен бота получен" in resp.text
        assert "mybot" in resp.text


class TestBotChatTokenStatus:
    def test_not_configured_by_default(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/bot/chat_status")
        assert resp.json() == {"configured": False, "bot_login": ""}

    def test_configured_after_env_written(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        (app.state.panel_roots.repo / ".env").write_text(
            (app.state.panel_roots.repo / ".env").read_text(encoding="utf-8")
            + "TWITCH_BOT_TOKEN=x\nTWITCH_BOT_REFRESH_TOKEN=y\nTWITCH_BOT_NICK=mybot\n",
            encoding="utf-8",
        )
        client = TestClient(app)

        resp = client.get("/auth/bot/chat_status")

        assert resp.json() == {"configured": True, "bot_login": "mybot"}

    def test_independent_of_mod_token_status(self, auth_app: tuple[FastAPI, Path]) -> None:
        """chat_status и status (mod-токен) читают разные ключи одного
        .env — настроенность одного не должна влиять на другой."""
        app, _db = auth_app
        (app.state.panel_roots.repo / ".env").write_text(
            (app.state.panel_roots.repo / ".env").read_text(encoding="utf-8")
            + "TWITCH_MOD_ACCESS_TOKEN=x\nTWITCH_MOD_REFRESH_TOKEN=y\nTWITCH_MOD_BOT_LOGIN=modbot\n",
            encoding="utf-8",
        )
        client = TestClient(app)

        resp = client.get("/auth/bot/chat_status")

        assert resp.json() == {"configured": False, "bot_login": ""}


async def _register_clip_channel(
    app: FastAPI, *, broadcaster_id: str = "1", login: str = "streamer"
) -> None:
    """Заводит канал в Channel Registry — /auth/clip/login и callback
    (per-channel, см. миграцию 020) проверяют, что broadcaster_id из
    profile/state реально существует в реестре, прежде чем выпускать
    state или писать токен."""
    registry = RegistryStore(str(app.state.panel_roots.registry_db))
    await registry.connect()
    await registry.upsert_channel(broadcaster_id=broadcaster_id, login=login)
    await registry.close()


class TestClipTokenLogin:
    def test_requires_authenticated_session(self, auth_app: tuple[FastAPI, Path]) -> None:
        app, _db = auth_app
        client = TestClient(app)
        resp = client.get("/auth/clip/login?profile=1", follow_redirects=False)
        assert resp.status_code == 401

    def test_viewer_forbidden(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                token = "user-tok" if form.get("grant_type") == "authorization_code" else "app-tok"
                return httpx.Response(200, json={"access_token": token})
            if request.url.path == "/helix/users":
                if request.headers["Authorization"] == "Bearer user-tok":
                    return httpx.Response(200, json={"data": [{"login": "viewer1", "id": "3"}]})
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            if request.url.path == "/helix/moderation/channels":
                return httpx.Response(200, json={"data": []})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))
        client = TestClient(app)
        login_resp = client.get("/auth/login", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]
        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

        resp = client.get("/auth/clip/login?profile=1", follow_redirects=False)
        assert resp.status_code == 403

    async def test_unknown_channel_rejected(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """profile, отсутствующий в Channel Registry — 404, не тихая
        запись куда попало."""
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/clip/login?profile=999", follow_redirects=False)

        assert resp.status_code == 404

    async def test_owner_redirects_to_twitch_with_clip_scope(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        await _register_clip_channel(app)
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/clip/login?profile=1", follow_redirects=False)

        assert resp.status_code in (302, 307)
        location = resp.headers["location"]
        assert "id.twitch.tv/oauth2/authorize" in location
        assert "clips%3Aedit" in location
        assert "auth%2Fclip%2Fcallback" in location


class TestClipTokenCallback:
    def test_unknown_state_rejected(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/clip/callback?code=x&state=not-a-real-state")
        assert resp.status_code == 400

    async def test_full_flow_writes_token_when_broadcaster(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        monkeypatch.setattr(paths, "MOD_VAR", app.state.panel_roots.var)
        await _register_clip_channel(app)
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "clip-access", "refresh_token": "clip-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/clip/login?profile=1", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/clip/callback.json?code=abc&state={state}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["user_login"] == "streamer"
        assert body["is_broadcaster"] is True
        assert body["warning"] is None

        store = ModerationStore(str(paths.mod_db("1")))
        await store.connect()
        token = await store.get_clip_token()
        await store.close()
        assert token is not None
        assert token.access_token == "clip-access"
        assert token.refresh_token == "clip-refresh"
        assert token.user_login == "streamer"

    async def test_warns_when_account_not_broadcaster(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        monkeypatch.setattr(paths, "MOD_VAR", app.state.panel_roots.var)
        await _register_clip_channel(app)
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "clip-access", "refresh_token": "clip-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                return httpx.Response(200, json={"data": [{"login": "mybot", "id": "99"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/clip/login?profile=1", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/clip/callback.json?code=abc&state={state}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["is_broadcaster"] is False
        assert body["warning"] is not None
        assert "mybot" in body["warning"]

    async def test_html_callback_renders_page_on_success(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        monkeypatch.setattr(paths, "MOD_VAR", app.state.panel_roots.var)
        await _register_clip_channel(app)
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/oauth2/token":
                form = dict(x.split("=") for x in request.content.decode().split("&"))
                if form.get("grant_type") == "authorization_code":
                    return httpx.Response(
                        200, json={"access_token": "clip-access", "refresh_token": "clip-refresh"}
                    )
                return httpx.Response(200, json={"access_token": "app-token"})
            if request.url.path == "/helix/users":
                return httpx.Response(200, json={"data": [{"login": "streamer", "id": "1"}]})
            raise AssertionError(f"unexpected request {request.url}")

        monkeypatch.setattr(auth, "_test_transport", httpx.MockTransport(handler))

        login_resp = client.get("/auth/clip/login?profile=1", follow_redirects=False)
        state = login_resp.headers["location"].split("state=")[1].split("&")[0]

        resp = client.get(f"/auth/clip/callback?code=abc&state={state}")

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "streamer" in resp.text

    def test_html_callback_renders_error_page_on_bad_state(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/clip/callback?code=abc&state=not-a-real-state")

        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]


class TestClipTokenStatus:
    def test_not_configured_by_default(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        monkeypatch.setattr(paths, "MOD_VAR", app.state.panel_roots.var)
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)
        resp = client.get("/auth/clip/status?profile=1")
        assert resp.json() == {"configured": False, "user_login": ""}

    async def test_configured_after_token_written(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app, _db = auth_app
        monkeypatch.setattr(paths, "MOD_VAR", app.state.panel_roots.var)
        store = ModerationStore(str(paths.mod_db("1")))
        await store.connect()
        await store.set_clip_token(
            access_token="x", refresh_token="y", user_login="streamer", user_id="1"
        )
        await store.close()
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)

        resp = client.get("/auth/clip/status?profile=1")

        assert resp.json() == {"configured": True, "user_login": "streamer"}

    def test_different_channel_sees_no_token(
        self, auth_app: tuple[FastAPI, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """profile без своей строки в mod_clip_token — "не настроен",
        даже если у другого канала есть токен (per-channel изоляция)."""
        app, _db = auth_app
        monkeypatch.setattr(paths, "MOD_VAR", app.state.panel_roots.var)
        client = TestClient(app)
        _login_as_owner(client, monkeypatch)
        resp = client.get("/auth/clip/status?profile=2")
        assert resp.json() == {"configured": False, "user_login": ""}
