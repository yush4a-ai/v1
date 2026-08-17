"""Тесты ModTokenManager: чтение/обновление токена модератора из .env,
целиком на моках httpx.MockTransport — тот же приём, что test_twitch_api.py.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from cigilbot.integrations.mod_token import (
    ModTokenError,
    ModTokenManager,
    load_mod_token_manager,
)


def write_env(path: Path, **values: str) -> Path:
    env_file = path / ".env"
    env_file.write_text(
        "\n".join(f"{k}={v}" for k, v in values.items()) + "\n", encoding="utf-8"
    )
    return env_file


CONFIGURED_ENV = {
    "TWITCH_MOD_ACCESS_TOKEN": "access-1",
    "TWITCH_MOD_REFRESH_TOKEN": "refresh-1",
    "TWITCH_MOD_BOT_LOGIN": "mybot",
    "TWITCH_MOD_BOT_USER_ID": "99",
    "TWITCH_MOD_BROADCASTER_ID": "1",
}


class TestLoadModTokenManager:
    def test_none_when_not_configured(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, SOME_OTHER_VAR="x")
        manager = load_mod_token_manager(client_id="cid", client_secret="csecret", env_file=env_file)
        assert manager is None

    def test_none_when_partially_configured(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, TWITCH_MOD_ACCESS_TOKEN="access-1")
        manager = load_mod_token_manager(client_id="cid", client_secret="csecret", env_file=env_file)
        assert manager is None

    def test_returns_manager_when_fully_configured(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)
        manager = load_mod_token_manager(client_id="cid", client_secret="csecret", env_file=env_file)
        assert manager is not None
        assert manager.state.configured is True
        assert manager.state.access_token == "access-1"


class TestGetValidAccessToken:
    async def test_raises_when_no_refresh_token(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path)
        manager = ModTokenManager(client_id="cid", client_secret="csecret", env_file=env_file)
        with pytest.raises(ModTokenError):
            await manager.get_valid_access_token()
        await manager.close()

    async def test_refreshes_on_first_use(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)
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

        manager = ModTokenManager(
            client_id="cid", client_secret="csecret", env_file=env_file,
            transport=httpx.MockTransport(handler),
        )
        token = await manager.get_valid_access_token()
        await manager.close()

        assert token == "access-2"
        assert calls["refresh"] == 1

    async def test_reuses_token_within_validity_window(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)
        calls = {"refresh": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["refresh"] += 1
            return httpx.Response(
                200,
                json={"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 14400},
            )

        manager = ModTokenManager(
            client_id="cid", client_secret="csecret", env_file=env_file,
            transport=httpx.MockTransport(handler),
        )
        await manager.get_valid_access_token()
        await manager.get_valid_access_token()
        await manager.close()

        assert calls["refresh"] == 1

    async def test_refreshes_again_when_close_to_expiry(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)
        calls = {"refresh": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["refresh"] += 1
            # expires_in меньше margin (300с) — следующий вызов должен обновить снова
            return httpx.Response(
                200,
                json={"access_token": f"access-{calls['refresh']}", "refresh_token": "refresh-x", "expires_in": 60},
            )

        manager = ModTokenManager(
            client_id="cid", client_secret="csecret", env_file=env_file,
            transport=httpx.MockTransport(handler),
        )
        await manager.get_valid_access_token()
        await manager.get_valid_access_token()
        await manager.close()

        assert calls["refresh"] == 2

    async def test_writes_new_token_back_to_env(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 14400},
            )

        manager = ModTokenManager(
            client_id="cid", client_secret="csecret", env_file=env_file,
            transport=httpx.MockTransport(handler),
        )
        await manager.get_valid_access_token()
        await manager.close()

        text = env_file.read_text(encoding="utf-8")
        assert "TWITCH_MOD_ACCESS_TOKEN=access-new" in text
        assert "TWITCH_MOD_REFRESH_TOKEN=refresh-new" in text
        # остальные ключи не должны потеряться при точечной перезаписи
        assert "TWITCH_MOD_BOT_LOGIN=mybot" in text

    async def test_raises_when_refresh_fails(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="invalid refresh token")

        manager = ModTokenManager(
            client_id="cid", client_secret="csecret", env_file=env_file,
            transport=httpx.MockTransport(handler),
        )
        with pytest.raises(ModTokenError):
            await manager.get_valid_access_token()
        await manager.close()


class TestModTokenState:
    def test_configured_false_when_missing_fields(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, TWITCH_MOD_ACCESS_TOKEN="x")
        manager = ModTokenManager(client_id="cid", client_secret="csecret", env_file=env_file)
        assert manager.state.configured is False


class TestConcurrentManagersOnSharedEnv:
    """bug-аудит 2026-08-17, HIGH: раньше ChannelPipeline создавал свой
    ModTokenManager на каждый канал из одного .env. Twitch ротирует
    refresh_token при каждом обмене — второй независимый менеджер,
    стартующий с тем же refresh_token, что уже использовал первый,
    получает 400 invalid_grant. Фикс — один ModTokenManager на процесс
    (ModerationHub передаёт общий инстанс в каждый ChannelPipeline), эти
    тесты фиксируют проблему на уровне самого менеджера, чтобы будущий
    возврат к "по менеджеру на канал" снова её ловил."""

    async def test_two_independent_managers_on_same_env_race(self, tmp_path: Path) -> None:
        env_file = write_env(tmp_path, **CONFIGURED_ENV)
        valid_refresh = {"token": "refresh-1"}
        exchanges = {"accepted": 0, "rejected": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            body = dict(pair.split("=", 1) for pair in request.content.decode().split("&"))
            presented = body.get("refresh_token", "")
            if presented != valid_refresh["token"]:
                exchanges["rejected"] += 1
                return httpx.Response(400, json={"status": 400, "message": "Invalid refresh token"})
            exchanges["accepted"] += 1
            valid_refresh["token"] = f"refresh-{exchanges['accepted'] + 1}"
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{exchanges['accepted'] + 1}",
                    "refresh_token": valid_refresh["token"],
                    "expires_in": 14400,
                },
            )

        transport = httpx.MockTransport(handler)
        managers = [
            ModTokenManager(client_id="cid", client_secret="csecret", env_file=env_file, transport=transport)
            for _ in range(2)
        ]

        results = await asyncio.gather(
            *(m.get_valid_access_token() for m in managers), return_exceptions=True
        )
        for m in managers:
            await m.close()

        failures = [r for r in results if isinstance(r, Exception)]
        assert len(failures) == 1, (
            "два независимых менеджера на общем .env должны конфликтовать: "
            f"обменов принято={exchanges['accepted']}, отклонено={exchanges['rejected']}"
        )
        assert isinstance(failures[0], ModTokenError)

    async def test_single_shared_manager_has_no_race(self, tmp_path: Path) -> None:
        """Тот же сценарий двух каналов, но с ОДНИМ общим менеджером
        (текущее поведение после фикса) — конфликта быть не должно."""
        env_file = write_env(tmp_path, **CONFIGURED_ENV)
        calls = {"refresh": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["refresh"] += 1
            return httpx.Response(
                200,
                json={"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 14400},
            )

        shared_manager = ModTokenManager(
            client_id="cid", client_secret="csecret", env_file=env_file,
            transport=httpx.MockTransport(handler),
        )

        # Оба "канала" зовут один и тот же объект, как теперь делает
        # ChannelPipeline._poll_action_queue через переданный хабом менеджер.
        results = await asyncio.gather(
            shared_manager.get_valid_access_token(),
            shared_manager.get_valid_access_token(),
            return_exceptions=True,
        )
        await shared_manager.close()

        assert all(not isinstance(r, Exception) for r in results)
        assert calls["refresh"] == 1
