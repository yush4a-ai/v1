"""Общий HTTP-обмен refresh_token -> access_token, используемый и
ModTokenManager (mod_token.py), и ClipTokenManager (clip_token.py).

Оба менеджера — параллельные, почти идентичные реализации одного и того же
lazy-refresh цикла (запрос к TWITCH_TOKEN_URL с grant_type=refresh_token,
проверка статуса, парсинг access_token/refresh_token/expires_in) с разным
способом персиста (файл .env для mod-токена, singleton-строка в
mod.<broadcaster_id>.db для clip-токена per channel). Дублирование HTTP-
цикла (~50 строк) не было оправдано разницей в персисте — фикс/поведение
Twitch-стороны (например, доп. ретраи при 5xx) пришлось бы вносить в обоих
местах синхронно, без гарантии, что они не разойдутся (bug-аудит
2026-08-15, MEDIUM #11; тот же класс риска, что уже один раз реализовался
для panel/auth.py — идентичный httpx.ConnectTimeout баг чинился дважды).

Вынесена только сама функция обмена, не общий базовый класс с абстрактным
_persist(): у ModTokenManager/ClipTokenManager разные наборы полей состояния
(ModTokenState держит bot_user_id/broadcaster_id, ClipTokenState —
user_login/user_id) и разные конструкторы (env_file: Path vs db_path: str +
state: ClipTokenState) — общий класс потребовал бы либо объединить эти два
разных набора полей в один, либо параметризовать конструктор дженериками,
что усложнило бы код больше, чем экономит. Функция без состояния снаружи
устраняет именно дублирование HTTP-протокола, оставляя персист и state-
классы там, где они осмысленно разные.
"""

from __future__ import annotations

import httpx

TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token"


class OAuthRefreshError(Exception):
    pass


async def refresh_access_token(
    http: httpx.AsyncClient,
    *,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    error_context: str,
) -> tuple[str, str, float]:
    """POST grant_type=refresh_token, возвращает (access_token,
    refresh_token, expires_in). Поднимает OAuthRefreshError на неуспехе —
    вызывающая сторона перехватывает и заворачивает в свой собственный тип
    ошибки (ModTokenError/ClipTokenError), чтобы сообщение оставалось
    контекстным ("токен модератора"/"токен для клиппинга")."""
    resp = await http.post(
        TWITCH_TOKEN_URL,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )
    if resp.status_code != 200:
        raise OAuthRefreshError(
            f"Не удалось обновить {error_context}: {resp.status_code} {resp.text[:300]} — "
            "возможно токен отозван, получите новый в панели"
        )
    body = resp.json()
    access_token = body.get("access_token")
    new_refresh_token = body.get("refresh_token")
    expires_in = body.get("expires_in", 0)
    if not access_token or not new_refresh_token:
        raise OAuthRefreshError(f"Twitch не вернул access_token/refresh_token при обновлении {error_context}")
    return str(access_token), str(new_refresh_token), float(expires_in)
