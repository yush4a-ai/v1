"""Минимальный Helix-клиент — только резолв login -> broadcaster_id.

twitch-bots не нужен полный Helix-клиент (баны/таймауты делает Cigilbot
через свой cigilbot/twitch_api.py) — здесь нужен только один метод,
используемый при добавлении канала (панель и scripts/import_registry.py):
превратить введённый оператором никнейм в стабильный числовой ID для
Channel Registry (bot/registry.py). App Access Token (client_credentials),
не требует пользовательского OAuth.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

OAUTH_TOKEN_URL = "https://id.twitch.tv/oauth2/token"
HELIX_USERS_URL = "https://api.twitch.tv/helix/users"


class HelixResolveError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class TwitchUser:
    id: str
    login: str
    display_name: str


class HelixResolver:
    def __init__(self, client_id: str, client_secret: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = httpx.AsyncClient(timeout=15.0)
        self._app_token: str | None = None
        self._app_token_expires_at = 0.0

    async def close(self) -> None:
        await self._http.aclose()

    async def _get_app_token(self) -> str:
        if self._app_token is not None and time.time() < self._app_token_expires_at - 60:
            return self._app_token
        resp = await self._http.post(
            OAUTH_TOKEN_URL,
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
            },
        )
        if resp.status_code != 200:
            raise HelixResolveError(f"не удалось получить App Access Token: {resp.status_code} {resp.text}")
        data = resp.json()
        self._app_token = data["access_token"]
        self._app_token_expires_at = time.time() + data["expires_in"]
        return self._app_token

    async def resolve_logins(self, logins: list[str]) -> list[TwitchUser]:
        """Резолвит до 100 логинов за раз (лимит Helix /users) — на
        практике при импорте/добавлении канала список короткий, батчинг
        сверх одного запроса здесь не нужен."""
        if not logins:
            return []
        if len(logins) > 100:
            raise HelixResolveError("resolve_logins поддерживает максимум 100 логинов за вызов")

        token = await self._get_app_token()
        params = [("login", login) for login in logins]
        resp = await self._http.get(
            HELIX_USERS_URL,
            headers={"Client-ID": self._client_id, "Authorization": f"Bearer {token}"},
            params=params,
        )
        if resp.status_code != 200:
            raise HelixResolveError(f"Helix /users вернул {resp.status_code}: {resp.text}")

        return [
            TwitchUser(id=row["id"], login=row["login"], display_name=row["display_name"])
            for row in resp.json().get("data", [])
        ]
