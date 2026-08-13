"""Токен модератора для реальных действий (executor.py) — с автообновлением.

Отдельно от cigilbot/twitch_api.py::HelixClient._get_app_token()
(App Access Token, client_credentials, не привязан к пользователю): здесь —
User Access Token аккаунта БОТА со scope moderator:manage:banned_users
(+ moderator:manage:chat_messages), который Twitch выдаёт на ограниченное
время (~4 часа) и обязательно требует обновления через refresh_token, иначе
executor.py начнёт получать 401 посреди стрима без ручного вмешательства.

Токен выпускается один раз через браузерный OAuth-flow в panel/auth.py
(/auth/bot/login), результат (access+refresh) кладётся в .env. Этот модуль
дальше живёт в процессе БОТА (main.py, не панели): читает .env при старте,
обновляет токен по истечении, и каждый раз, когда обновляет, записывает
новую пару обратно в .env — иначе рестарт бота между refresh-циклами
подхватил бы уже отозванный Twitch access_token.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

log = logging.getLogger("moderation.mod_token")

TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token"

# Twitch не сообщает точный expires_in для refresh-ответа так же надёжно,
# как хотелось бы полагаться — обновляем заранее, а не впритык к границе,
# чтобы одиночный медленный запрос не попал в окно с уже мёртвым токеном.
_REFRESH_MARGIN_SECONDS = 300

_ENV_KEYS = (
    "TWITCH_MOD_ACCESS_TOKEN",
    "TWITCH_MOD_REFRESH_TOKEN",
    "TWITCH_MOD_BOT_LOGIN",
    "TWITCH_MOD_BOT_USER_ID",
    "TWITCH_MOD_BROADCASTER_ID",
)


class ModTokenError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ModTokenState:
    access_token: str
    refresh_token: str
    bot_user_id: str
    broadcaster_id: str

    @property
    def configured(self) -> bool:
        return bool(self.access_token and self.refresh_token and self.bot_user_id and self.broadcaster_id)


def _read_env_file(env_file: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_file.exists():
        return values
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value
    return values


def _write_env_values(env_file: Path, updates: dict[str, str]) -> None:
    """Точечная запись без потери остального файла — тот же приём, что
    panel/bots_api.py::write_env_values() и panel/auth.py::_write_env_values(),
    продублирован ещё раз намеренно: этот модуль живёт в процессе бота и не
    должен импортировать panel.* (та сторона наоборот может импортировать
    cigilbot.*, обратная зависимость создала бы цикл при желании)."""
    if not env_file.exists():
        env_file.write_text("", encoding="utf-8")
    lines = env_file.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in updates:
            lines[i] = f"{key}={updates[key]}"
            seen.add(key)
    for key, value in updates.items():
        if key not in seen:
            lines.append(f"{key}={value}")
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ModTokenManager:
    """Держит текущий access_token в памяти, обновляет по требованию.

    Один инстанс на процесс бота, создаётся при старте (main.py), передаётся
    в ActionExecutor как источник актуального user_token — executor.py не
    знает про refresh, просто спрашивает get_valid_access_token() перед
    каждым вызовом Helix.
    """

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        env_file: Path,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._env_file = env_file
        self._http = httpx.AsyncClient(timeout=10.0, transport=transport)

        values = _read_env_file(env_file)
        self._access_token = values.get("TWITCH_MOD_ACCESS_TOKEN", "")
        self._refresh_token = values.get("TWITCH_MOD_REFRESH_TOKEN", "")
        self._bot_user_id = values.get("TWITCH_MOD_BOT_USER_ID", "")
        self._broadcaster_id = values.get("TWITCH_MOD_BROADCASTER_ID", "")
        # Токен мог быть выпущен произвольное время назад (даже до рестарта
        # процесса) — считаем его "требующим проверки сейчас", а не свежим,
        # реальный refresh произойдёт лениво при первом реальном использовании.
        self._expires_at = 0.0

    async def close(self) -> None:
        await self._http.aclose()

    @property
    def state(self) -> ModTokenState:
        return ModTokenState(
            access_token=self._access_token,
            refresh_token=self._refresh_token,
            bot_user_id=self._bot_user_id,
            broadcaster_id=self._broadcaster_id,
        )

    async def get_valid_access_token(self) -> str:
        """Текущий access_token, обновлённый заранее, если истекает скоро.

        Поднимает ModTokenError, если токен вообще не настроен (панель ещё
        не проходила /auth/bot/login) — вызывающий код (executor.py через
        main.py) должен явно решить, что делать при отсутствии токена, а не
        получить непонятный 401 от Helix.
        """
        if not self._refresh_token:
            raise ModTokenError(
                "Токен модератора не настроен — получите его в панели "
                "(Settings -> Twitch: получить токен бота)"
            )
        if time.time() < self._expires_at - _REFRESH_MARGIN_SECONDS:
            return self._access_token
        await self._refresh()
        return self._access_token

    async def _refresh(self) -> None:
        resp = await self._http.post(
            TWITCH_TOKEN_URL,
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
            },
        )
        if resp.status_code != 200:
            raise ModTokenError(
                f"Не удалось обновить токен модератора: {resp.status_code} {resp.text[:300]} — "
                "возможно токен отозван, получите новый в панели"
            )
        body = resp.json()
        access_token = body.get("access_token")
        refresh_token = body.get("refresh_token")
        expires_in = body.get("expires_in", 0)
        if not access_token or not refresh_token:
            raise ModTokenError("Twitch не вернул access_token/refresh_token при обновлении")

        self._access_token = str(access_token)
        self._refresh_token = str(refresh_token)
        self._expires_at = time.time() + float(expires_in)

        _write_env_values(
            self._env_file,
            {
                "TWITCH_MOD_ACCESS_TOKEN": self._access_token,
                "TWITCH_MOD_REFRESH_TOKEN": self._refresh_token,
            },
        )
        log.info("Токен модератора обновлён, истекает через %.0f сек", float(expires_in))


def load_mod_token_manager(
    *, client_id: str, client_secret: str, env_file: Path
) -> ModTokenManager | None:
    """None, если токен ни разу не был получен — main.py должен уметь
    работать без него (SHADOW-режим не банит, значит executor можно просто
    не запускать), а не падать при старте."""
    values = _read_env_file(env_file)
    if not all(values.get(key) for key in _ENV_KEYS):
        return None
    return ModTokenManager(client_id=client_id, client_secret=client_secret, env_file=env_file)
