"""Токен для создания клипов (bot/autoclip.py) — с автообновлением.

Отдельная переменная от TWITCH_MOD_* (mod_token.py): тот — scope
moderator:manage:banned_users/chat_messages для бана/таймаута, этот —
clips:edit для POST /helix/clips. Twitch не позволяет добавить scope к уже
выпущенному токену, поэтому это принципиально другой токен, не расширение
существующего.

Per-channel, не в .env (см. миграцию 020,
cigilbot/storage/migrations.py) — единственный общий .env-токен работал
только для того канала, на который был выпущен: Twitch Helix POST
/helix/clips принимает лишь токен, принадлежащий реальному
broadcaster'у/модератору/редактору ИМЕННО ТОГО канала, для которого
создаётся клип. Один инстанс ClipTokenManager на канал, хранит токен в
mod.<broadcaster_id>.db (mod_clip_token, cigilbot/storage/store.py) —
тот же файл и тот же singleton-паттерн, что и mod_autoclip_settings.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx

from cigilbot.integrations.oauth_refresh import OAuthRefreshError, refresh_access_token
from cigilbot.storage.store import ModerationStore

log = logging.getLogger("moderation.clip_token")

# Тот же запас, что и в mod_token.py — обновляем заранее, а не впритык к
# границе, чтобы одиночный медленный запрос не попал в окно с уже мёртвым
# токеном.
_REFRESH_MARGIN_SECONDS = 300


class ClipTokenError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ClipTokenState:
    access_token: str
    refresh_token: str
    user_login: str
    user_id: str

    @property
    def configured(self) -> bool:
        return bool(self.access_token and self.refresh_token)


class ClipTokenManager:
    """Держит текущий access_token в памяти, обновляет по требованию.

    Один инстанс на канал (не на процесс — см. докстринг модуля), создаётся
    при старте автоклипа на конкретном канале (bot/autoclip.py::AutoclipHub),
    передаётся в ChannelAutoclip как источник актуального user_token для
    HelixClient.create_clip().
    """

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        db_path: str,
        state: ClipTokenState,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._db_path = db_path
        self._http = httpx.AsyncClient(timeout=10.0, transport=transport)

        self._access_token = state.access_token
        self._refresh_token = state.refresh_token
        self._user_login = state.user_login
        self._user_id = state.user_id
        # Токен мог быть выпущен произвольное время назад — считаем его
        # "требующим проверки сейчас", реальный refresh произойдёт лениво
        # при первом использовании.
        self._expires_at = 0.0

    async def close(self) -> None:
        await self._http.aclose()

    @property
    def state(self) -> ClipTokenState:
        return ClipTokenState(
            access_token=self._access_token,
            refresh_token=self._refresh_token,
            user_login=self._user_login,
            user_id=self._user_id,
        )

    async def get_valid_access_token(self) -> str:
        """Текущий access_token, обновлённый заранее, если истекает скоро.

        Поднимает ClipTokenError, если токен вообще не настроен (панель ещё
        не проходила /auth/clip/login на этом канале) — вызывающий код
        (autoclip.py) должен явно решить, что делать при отсутствии токена,
        а не получить непонятный 401 от Helix.
        """
        if not self._refresh_token:
            raise ClipTokenError(
                "Токен для клиппинга не настроен на этом канале — получите его в "
                "панели (экран Автоклип: получить токен для клиппинга)"
            )
        if time.time() < self._expires_at - _REFRESH_MARGIN_SECONDS:
            return self._access_token
        await self._refresh()
        return self._access_token

    async def _refresh(self) -> None:
        try:
            access_token, refresh_token, expires_in = await refresh_access_token(
                self._http,
                client_id=self._client_id,
                client_secret=self._client_secret,
                refresh_token=self._refresh_token,
                error_context="токен для клиппинга",
            )
        except OAuthRefreshError as exc:
            raise ClipTokenError(str(exc)) from exc

        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = time.time() + expires_in

        store = ModerationStore(self._db_path)
        await store.connect()
        try:
            await store.update_clip_access_token(
                access_token=self._access_token, refresh_token=self._refresh_token
            )
        finally:
            await store.close()
        log.info("Токен для клиппинга обновлён, истекает через %.0f сек", expires_in)


async def load_clip_token_manager(
    *, client_id: str, client_secret: str, db_path: str
) -> ClipTokenManager | None:
    """None, если токен ни разу не был получен на этом канале — AutoclipHub
    должен уметь не запускать автоклип на канале без токена, не падать при
    старте и не блокировать остальные каналы."""
    store = ModerationStore(db_path)
    await store.connect()
    try:
        token = await store.get_clip_token()
    finally:
        await store.close()
    if token is None:
        return None
    state = ClipTokenState(
        access_token=token.access_token,
        refresh_token=token.refresh_token,
        user_login=token.user_login,
        user_id=token.user_id,
    )
    return ClipTokenManager(client_id=client_id, client_secret=client_secret, db_path=db_path, state=state)
