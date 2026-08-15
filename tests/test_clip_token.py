"""Тесты ClipTokenManager: чтение/обновление токена клиппинга per-channel
через ModerationStore (mod_clip_token, mod.<broadcaster_id>.db), на моках
httpx.MockTransport — тот же принцип, что test_mod_token.py, но хранилище
теперь SQLite, не .env (см. миграцию 020 и её докстринг про инцидент,
из-за которого общий .env-токен на все каналы был заменён на per-channel).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from cigilbot.integrations.clip_token import (
    ClipTokenError,
    ClipTokenManager,
    ClipTokenState,
    load_clip_token_manager,
)
from cigilbot.storage.store import ModerationStore


async def make_store_with_token(tmp_path: Path, **overrides: str) -> str:
    db_path = str(tmp_path / "mod.test.db")
    store = ModerationStore(db_path)
    await store.connect()
    values = {
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "user_login": "mybot",
        "user_id": "99",
    }
    values.update(overrides)
    await store.set_clip_token(**values)
    await store.close()
    return db_path


async def make_empty_store(tmp_path: Path) -> str:
    db_path = str(tmp_path / "mod.test.db")
    store = ModerationStore(db_path)
    await store.connect()
    await store.close()
    return db_path


class TestLoadClipTokenManager:
    async def test_none_when_not_configured(self, tmp_path: Path) -> None:
        db_path = await make_empty_store(tmp_path)
        manager = await load_clip_token_manager(client_id="cid", client_secret="csecret", db_path=db_path)
        assert manager is None

    async def test_returns_manager_when_configured(self, tmp_path: Path) -> None:
        db_path = await make_store_with_token(tmp_path)
        manager = await load_clip_token_manager(client_id="cid", client_secret="csecret", db_path=db_path)
        assert manager is not None
        assert manager.state.configured is True
        assert manager.state.access_token == "access-1"
        await manager.close()


class TestGetValidAccessToken:
    async def test_raises_when_no_refresh_token(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "mod.test.db")
        state = ClipTokenState(access_token="", refresh_token="", user_login="", user_id="")
        manager = ClipTokenManager(client_id="cid", client_secret="csecret", db_path=db_path, state=state)
        with pytest.raises(ClipTokenError):
            await manager.get_valid_access_token()
        await manager.close()

    async def test_refreshes_on_first_use(self, tmp_path: Path) -> None:
        db_path = await make_store_with_token(tmp_path)
        calls = {"refresh": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["refresh"] += 1
            return httpx.Response(
                200,
                json={
                    "access_token": "access-2",
                    "refresh_token": "refresh-2",
                    "expires_in": 14400,
                },
            )

        state = ClipTokenState(access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99")
        manager = ClipTokenManager(
            client_id="cid", client_secret="csecret", db_path=db_path, state=state,
            transport=httpx.MockTransport(handler),
        )
        token = await manager.get_valid_access_token()
        await manager.close()

        assert token == "access-2"
        assert calls["refresh"] == 1

    async def test_reuses_token_within_validity_window(self, tmp_path: Path) -> None:
        db_path = await make_store_with_token(tmp_path)
        calls = {"refresh": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["refresh"] += 1
            return httpx.Response(
                200,
                json={"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 14400},
            )

        state = ClipTokenState(access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99")
        manager = ClipTokenManager(
            client_id="cid", client_secret="csecret", db_path=db_path, state=state,
            transport=httpx.MockTransport(handler),
        )
        await manager.get_valid_access_token()
        await manager.get_valid_access_token()
        await manager.close()

        assert calls["refresh"] == 1

    async def test_refreshes_again_when_close_to_expiry(self, tmp_path: Path) -> None:
        db_path = await make_store_with_token(tmp_path)
        calls = {"refresh": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["refresh"] += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{calls['refresh']}",
                    "refresh_token": "refresh-x",
                    "expires_in": 60,
                },
            )

        state = ClipTokenState(access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99")
        manager = ClipTokenManager(
            client_id="cid", client_secret="csecret", db_path=db_path, state=state,
            transport=httpx.MockTransport(handler),
        )
        await manager.get_valid_access_token()
        await manager.get_valid_access_token()
        await manager.close()

        assert calls["refresh"] == 2

    async def test_writes_new_token_back_to_store(self, tmp_path: Path) -> None:
        db_path = await make_store_with_token(tmp_path)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 14400},
            )

        state = ClipTokenState(access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99")
        manager = ClipTokenManager(
            client_id="cid", client_secret="csecret", db_path=db_path, state=state,
            transport=httpx.MockTransport(handler),
        )
        await manager.get_valid_access_token()
        await manager.close()

        store = ModerationStore(db_path)
        await store.connect()
        token = await store.get_clip_token()
        await store.close()

        assert token is not None
        assert token.access_token == "access-new"
        assert token.refresh_token == "refresh-new"
        # user_login/user_id не должны потеряться при обновлении только токена
        assert token.user_login == "mybot"
        assert token.user_id == "99"

    async def test_raises_when_refresh_fails(self, tmp_path: Path) -> None:
        db_path = await make_store_with_token(tmp_path)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="invalid refresh token")

        state = ClipTokenState(access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99")
        manager = ClipTokenManager(
            client_id="cid", client_secret="csecret", db_path=db_path, state=state,
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(ClipTokenError):
            await manager.get_valid_access_token()
        await manager.close()


class TestClipTokenState:
    def test_configured_false_when_missing_fields(self) -> None:
        state = ClipTokenState(access_token="x", refresh_token="", user_login="", user_id="")
        assert state.configured is False

    def test_configured_true_when_all_fields_present(self) -> None:
        state = ClipTokenState(access_token="x", refresh_token="y", user_login="mybot", user_id="99")
        assert state.configured is True
