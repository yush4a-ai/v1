"""Вход в панель через Twitch OAuth.

Один модуль на всю панель. Раньше этот файл существовал в двух копиях —
своя в twitch-bots (порт 8765) и своя в Cigilbot (порт 8766), с одинаковой
логикой и разным хранилищем ADMIN-оверрайдов; правку в одной приходилось
переносить в другую руками, и они успели разойтись (баг с необработанным
httpx.ConnectTimeout в _resolve_roles_by_channel чинился дважды). Панель
теперь одна, копия одна.

Закрывает дыру раздела 11 плана ("Панель без авторизации"): раньше роль в
запросе была тем, что клиент сам о себе заявлял в заголовке X-Panel-Role —
любой в локальной сети мог открыть /moderation, выбрать в выпадающем
списке OWNER и банить кого угодно. Теперь роль выдаёт сервер после
проверки личности через Twitch, а не берёт из непроверенного заголовка.

Flow — стандартный Authorization Code Grant:
  1. GET /auth/login       -> редирект на Twitch с state (CSRF-защита)
  2. Twitch логин юзера, редирект назад на /auth/callback?code=...&state=...
  3. GET /auth/callback    -> обмен code на user token, GET /helix/users
     (кто вошёл), GET /helix/moderation/moderators (модераторы канала) ->
     роль (OWNER/MODERATOR/VIEWER), кладём в подписанную cookie-сессию
  4. GET /auth/logout      -> очищает сессию

Роль не хранится в mod_panel_users как источник правды для входа — она
пересчитывается заново на каждый /auth/callback из актуального списка
модераторов Twitch. mod_panel_users (миграция 003) остаётся для роли
ADMIN, которую автоматически из Twitch не вывести (список админов,
доверенных владельцем панели вручную) — назначается через
POST /api/moderation/panel_users существующим OWNER/ADMIN и подмешивается
к роли из Twitch при следующем логине (см. _resolve_role).

Список ADMIN тоже один. До слияния их было два независимых —
mod_panel_users в mod.db обслуживал панель модерации, panel_admins в
bot.db панель ботов, и выданный в одной ADMIN не действовал в другой.
Победил mod_panel_users: mod.db существует ровно ради состояния панели,
тогда как bot.db принадлежит боту и пересоздаётся им на каждом старте
(bot/database.py делает executescript без версионирования).

Перенос содержимого panel_admins — разовым скриптом
scripts/merge_panel_admins.py, а не миграцией: данные едут между ДВУМЯ
файлами БД, а миграции mod.db (cigilbot/migrations.py) знают только свой
собственный файл и не должны зависеть от того, где лежит чужой.

Отдельное Twitch-приложение (PANEL_TWITCH_CLIENT_ID/SECRET) — не то же
самое, что TWITCH_BOT_TOKEN бота: панели нужен Authorization Code Grant
(редирект браузера), боту — готовый User Access Token для IRC. Смешивать
их значило бы завязать вход в панель на то, есть ли сейчас у бота живой
IRC-токен, что не связанные друг с другом вещи.
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from paths import MAIN_PROFILE, PanelRoots

log = logging.getLogger("panel.auth")

TWITCH_AUTHORIZE_URL = "https://id.twitch.tv/oauth2/authorize"
TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token"
HELIX_BASE = "https://api.twitch.tv/helix"

# Права панели: узнать, кто вошёл, и получить список каналов, где ОН
# модератор (GET /helix/moderation/channels, "Get Moderated Channels"),
# чтобы автоматически выдать роль MODERATOR/OWNER. Никаких прав на
# бан/таймаут здесь не запрашиваем — это отдельный токен бота (twitch_api.py),
# панель только раздаёт задания через очередь, а не ходит в Helix сама.
#
# ВАЖНО: не moderation:read и не moderator:read:moderators — оба scope
# относятся к GET /helix/moderation/moderators ("кто модераторы КАНАЛА"),
# который на практике требует токен именно broadcaster'а: обычный
# модератор получает 401 "The ID in broadcaster_id must match the user ID
# found in the request's OAuth token" (поймано при живом входе модератора
# канала). user:read:moderated_channels — правильный scope для обратного
# вопроса "в каких каналах модератор Я", который и нужен здесь.
OAUTH_SCOPES = "user:read:moderated_channels"

# Права БОТА для реальных действий модерации (executor.py, docs/moderation-plan.md
# раздел 11, блокер #1). Отдельный от OAUTH_SCOPES набор и отдельный flow
# (/auth/bot/login, /auth/bot/callback) — это не вход в панель, а получение
# токена для аккаунта БОТА. Тот, кто проходит этот flow в браузере, должен
# быть залогинен на Twitch именно под ботом, не под своим личным аккаунтом:
# Helix ban/timeout требует moderator_id == user_id владельца токена, и бот
# должен быть модератором канала — иначе тот же 401, что уже ловили на
# panel-login (см. _fetch_moderated_channel_ids).
BOT_TOKEN_OAUTH_SCOPES = "moderator:manage:banned_users moderator:manage:chat_messages"

# Права БОТА для чтения/отправки в IRC-чат (main.py::ChatBot, twitchio) —
# отдельный набор от BOT_TOKEN_OAUTH_SCOPES: тот про Helix-модерацию
# (баны/таймауты через executor.py), этот про обычные сообщения в чате.
CHAT_TOKEN_OAUTH_SCOPES = "chat:read chat:edit"

SESSION_KEY = "panel_user"
_STATE_TTL_SECONDS = 600  # окно на прохождение логина на Twitch

router = APIRouter(prefix="/auth")

# Инъекция транспорта для тестов — тот же приём, что cigilbot/twitch_api.py
# (httpx.MockTransport), чтобы тестировать OAuth-обмен и Helix-проверки без
# единого реального запроса к Twitch. None в проде -> обычный сетевой транспорт.
_test_transport: httpx.AsyncBaseTransport | None = None


def _new_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=10.0, transport=_test_transport)


# state -> момент создания. In-memory достаточно: живёт секунды между
# редиректом на Twitch и возвратом на /auth/callback, переживать рестарт
# панели не требуется.
_pending_states: dict[str, float] = {}

# Отдельное хранилище state для bot-token flow — не смешиваем с входом в
# панель: у них разные callback'и, разные scope, и, что важнее всего,
# разный смысл "кто сейчас на Twitch в браузере" (владелец панели vs
# аккаунт бота). Общий словарь state создал бы риск спутать один код с
# другим, если оба flow запущены почти одновременно в одной панели.
#
# Значение — не только момент создания, но и purpose ("mod"/"chat"):
# оба под-flow используют один и тот же bot_redirect_uri (Twitch требует
# точного совпадения redirect_uri, второй адрес пришлось бы регистрировать
# в Dev Console отдельно), поэтому единственный способ callback'у узнать,
# какой из них завершился — прочитать это из state, не из URL.
_pending_bot_states: dict[str, tuple[float, str]] = {}


def _prune_states() -> None:
    cutoff = time.time() - _STATE_TTL_SECONDS
    for state in [s for s, created in _pending_states.items() if created < cutoff]:
        _pending_states.pop(state, None)


def _prune_bot_states() -> None:
    cutoff = time.time() - _STATE_TTL_SECONDS
    for state in [s for s, (created, _purpose) in _pending_bot_states.items() if created < cutoff]:
        _pending_bot_states.pop(state, None)


@dataclass(frozen=True, slots=True)
class PanelAuthConfig:
    client_id: str
    client_secret: str
    channel: str
    redirect_uri: str
    bot_redirect_uri: str

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.channel)


def load_panel_auth_config(
    root: Path, *, env_filename: str = ".env", default_port: int = 8766
) -> PanelAuthConfig:
    """Читает PANEL_TWITCH_* из .env — тот же построчный парсер, что
    panel/bots_api.py::read_env(), но без завязки на профиль: вход в панель
    один на весь процесс, не за каждый профиль бота отдельно.

    env_filename/default_port раньше были параметрами переносимости между
    двумя панелями на разных портах, у каждой со своим .env и своим
    redirect URI. Панель одна, порт один (8766), .env один — параметры
    остались только затем, чтобы тесты могли подсунуть свой файл."""
    values: dict[str, str] = {}
    env_file = root / env_filename
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            values[key.strip()] = value

    def get(key: str, default: str = "") -> str:
        return os.environ.get(key) or values.get(key, default)

    return PanelAuthConfig(
        client_id=get("PANEL_TWITCH_CLIENT_ID"),
        client_secret=get("PANEL_TWITCH_CLIENT_SECRET"),
        channel=get("PANEL_TWITCH_CHANNEL").strip().lstrip("#").lower(),
        redirect_uri=get(
            "PANEL_TWITCH_REDIRECT_URI", f"http://localhost:{default_port}/auth/callback"
        ),
        bot_redirect_uri=get(
            "PANEL_TWITCH_BOT_REDIRECT_URI", f"http://localhost:{default_port}/auth/bot/callback"
        ),
    )


class TwitchAuthError(Exception):
    pass


async def _exchange_code(cfg: PanelAuthConfig, code: str, *, redirect_uri: str | None = None) -> str:
    """Вход в панель: нужен только access_token для мгновенных Helix-запросов
    в рамках /auth/callback (кто вошёл, модератор ли) — сама сессия панели
    живёт в подписанной cookie, не в этом токене, поэтому refresh_token
    здесь не нужен и не запрашивается как обязательный."""
    body = await _exchange_code_raw(cfg, code, redirect_uri=redirect_uri)
    token = body.get("access_token")
    if not token:
        raise TwitchAuthError("Twitch не вернул access_token")
    return str(token)


async def _exchange_code_with_refresh(
    cfg: PanelAuthConfig, code: str, *, redirect_uri: str | None = None
) -> tuple[str, str]:
    """Возвращает (access_token, refresh_token) — используется ТОЛЬКО
    bot-token flow'ом: тот токен живёт в .env и должен переживать рестарты
    процесса и автообновляться, поэтому refresh_token здесь обязателен, в
    отличие от _exchange_code() для входа в панель."""
    body = await _exchange_code_raw(cfg, code, redirect_uri=redirect_uri)
    token = body.get("access_token")
    refresh_token = body.get("refresh_token")
    if not token or not refresh_token:
        raise TwitchAuthError("Twitch не вернул access_token/refresh_token")
    return str(token), str(refresh_token)


async def _exchange_code_raw(
    cfg: PanelAuthConfig, code: str, *, redirect_uri: str | None = None
) -> dict[str, object]:
    """redirect_uri по умолчанию — вход в панель (cfg.redirect_uri); bot-token
    flow передаёт cfg.bot_redirect_uri явно — Twitch требует точного
    совпадения redirect_uri между запросом авторизации и обменом кода,
    иначе invalid grant."""
    async with _new_http_client() as client:
        resp = await client.post(
            TWITCH_TOKEN_URL,
            data={
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri or cfg.redirect_uri,
            },
        )
    if resp.status_code != 200:
        raise TwitchAuthError(f"Обмен code на токен не удался: {resp.status_code} {resp.text[:200]}")
    result: dict[str, object] = resp.json()
    return result


async def _fetch_viewer(cfg: PanelAuthConfig, user_token: str) -> tuple[str, str]:
    """Логин и user_id вошедшего — по его собственному токену (GET /helix/users
    без параметров возвращает владельца токена)."""
    async with _new_http_client() as client:
        resp = await client.get(
            f"{HELIX_BASE}/users",
            headers={"Client-ID": cfg.client_id, "Authorization": f"Bearer {user_token}"},
        )
    if resp.status_code != 200:
        raise TwitchAuthError(f"Не удалось получить профиль пользователя: {resp.status_code}")
    data = resp.json().get("data", [])
    if not data:
        raise TwitchAuthError("Twitch не вернул данные пользователя")
    return data[0]["login"].lower(), data[0]["id"]


def _list_env_profile_channels(roots: PanelRoots) -> dict[str, str]:
    """{profile: channel_login} по файлам .env / .env.<profile> —
    профильная модель чат-бота (движок модерации отказался от неё в Phase 1
    в пользу Channel Registry, см. CLAUDE.md про две сосуществующие модели
    каналов).

    Профиль "main" живёт в корневом .env, остальные — в .env.<profile>
    рядом с ним: слияние свело к одному файлу общий конфиг, но не профили
    ботов."""
    result: dict[str, str] = {}
    candidates: list[tuple[str, Path]] = [(MAIN_PROFILE, roots.repo / ".env")]
    candidates += [
        (p.name.removeprefix(".env."), p)
        for p in sorted(roots.repo.glob(".env.*"))
        if p.name != ".env.example"
    ]

    for profile, env_file in candidates:
        if not env_file.exists():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("TWITCH_CHANNEL="):
                continue
            channel = stripped.split("=", 1)[1].strip().lstrip("#").lower()
            if channel:
                result[profile] = channel
            break
    return result


async def _list_profile_channels(roots: PanelRoots) -> dict[str, str]:
    """Все каналы, по которым вообще имеет смысл считать роль вошедшего —
    объединение двух моделей каналов, сосуществующих в монорепо:

      * Channel Registry (registry.db) -> {broadcaster_id: login}. Источник
        правды для модерации, ключ — стабильный числовой Twitch-ID (см.
        docs/master-plan.html, направление 00).
      * .env.<profile> в корне проекта -> {profile: login}. Профильная
        модель экрана ботов, ключ — имя профиля.

    Объединение, а не выбор одной из двух: role_for_profile получает ключ
    от вызывающего кода, и это может быть и broadcaster_id (moderation_api),
    и имя профиля. До слияния панелей каждая копия auth.py знала только про
    свою модель, и это работало, пока модели жили в разных процессах.

    Ключ словаря называется "profile" по историческим причинам (см.
    комментарий в panel/moderation_api.py про параметр `profile`).

    Registry читается вторым и затирает совпадения намеренно: если имя
    профиля случайно совпало с broadcaster_id, права должна определять
    модель модерации, а не .env-файл, который правится вручную."""
    from cigilbot.storage.registry_store import RegistryStore

    result = _list_env_profile_channels(roots)

    registry = RegistryStore(str(roots.registry_db))
    await registry.connect()
    try:
        channels = await registry.list_channels(status=None)
    finally:
        await registry.close()
    result.update({c.broadcaster_id: c.login for c in channels})
    return result


async def _fetch_moderated_channel_ids(cfg: PanelAuthConfig, user_token: str, user_id: str) -> set[str]:
    """broadcaster_id всех каналов, где ВОШЕДШИЙ пользователь модератор —
    через GET /helix/moderation/channels ("Get Moderated Channels").

    Это НЕ то же самое, что GET /helix/moderation/moderators ("Get
    Moderators"): тот эндпоинт спрашивает у канала "кто твои модераторы" и
    требует токен именно broadcaster'а (user_id в токене должен совпадать с
    broadcaster_id параметра — обычному модератору Twitch отвечает 401
    "The ID in broadcaster_id must match the user ID found in the request's
    OAuth token", это было реально поймано при живом входе модератора).
    Здесь наоборот: пользователь спрашивает "в каких каналах модератор Я" —
    работает с его же собственным токеном, без прав от лица broadcaster'а.
    Требует scope user:read:moderated_channels, а не moderation:read."""
    async with _new_http_client() as client:
        resp = await client.get(
            f"{HELIX_BASE}/moderation/channels",
            headers={"Client-ID": cfg.client_id, "Authorization": f"Bearer {user_token}"},
            params={"user_id": user_id},
        )
    if resp.status_code != 200:
        log.warning(
            "GET /moderation/channels user_id=%s -> %d: %s",
            user_id, resp.status_code, resp.text[:300],
        )
        return set()
    return {row["broadcaster_id"] for row in resp.json().get("data", [])}


def _resolve_role(*, login: str, is_broadcaster: bool, is_moderator: bool, admin_override: str | None) -> str:
    """Роль для ОДНОГО канала. admin_override — глобальный, не по-канальный
    (см. _resolve_roles_by_channel): ADMIN — это доверенный человек,
    назначенный вручную владельцем панели через mod_panel_users, а не
    статус, который Twitch выдаёт за конкретный канал — так что ADMIN
    остаётся ADMIN везде, а не только там, где он ещё и модератор."""
    if admin_override in ("ADMIN", "OWNER"):
        return admin_override
    if is_broadcaster:
        return "OWNER"
    if is_moderator:
        return "MODERATOR"
    return "VIEWER"


async def _resolve_roles_by_channel(
    cfg: PanelAuthConfig,
    roots: PanelRoots,
    *,
    login: str,
    user_id: str,
    moderated_channel_ids: set[str],
    admin_override: str | None,
) -> dict[str, str]:
    """{channel: role} для КАЖДОГО канала, за которым стоит хотя бы один
    профиль бота — не только cfg.channel. Один вошедший может быть
    модератором канала A и никем на канале B: роль больше не одна строка
    на всю сессию, а словарь, из которого panel/moderation_api.py достаёт
    нужное значение по каналу конкретного запроса (см. role_for_profile).

    broadcaster_id каждого канала запрашивается один раз при входе — не на
    каждый последующий API-запрос, чтобы не звать Helix лишний раз; сессия
    живёт до logout/истечения cookie, актуальность пересчитывается заново
    при следующем /auth/callback, как и раньше для одиночной роли."""
    channels = set((await _list_profile_channels(roots)).values())
    channels.add(cfg.channel)  # канал панели остаётся в игре, даже без профиля бота

    roles: dict[str, str] = {}
    for channel in channels:
        if not channel:
            continue
        try:
            broadcaster_login, broadcaster_id = await _fetch_viewer_by_login(cfg, channel)
        except (TwitchAuthError, httpx.HTTPError):
            # Канал мог быть переименован/удалён с Twitch с момента, как
            # профиль был создан, либо Twitch/сеть временно недоступны
            # (таймаут, обрыв соединения) — не роняем весь вход из-за
            # одного проблемного канала, просто не даём по нему прав.
            # Раньше ловился только TwitchAuthError — реальный сбой сети
            # (httpx.ConnectTimeout и т.п.) не был перехвачен и валил весь
            # /auth/callback с 500 вместо входа без прав на этот канал (тот
            # же баг был найден и исправлен в twitch-bots/panel/auth.py).
            log.warning("Не удалось проверить канал %r для ролей входа", channel, exc_info=True)
            continue
        is_broadcaster = login == broadcaster_login
        is_moderator = broadcaster_id in moderated_channel_ids
        roles[channel] = _resolve_role(
            login=login, is_broadcaster=is_broadcaster, is_moderator=is_moderator,
            admin_override=admin_override,
        )
    return roles


def _write_env_values(root: Path, updates: dict[str, str]) -> None:
    """Точечная запись переменных в корневой .env без потери остального
    файла — тот же приём, что panel/bots_api.py::write_env_values(), но для
    основного профиля напрямую (bot-токен один на процесс панели, как и
    PANEL_TWITCH_*, не за каждый профиль бота отдельно). Продублировано, а
    не импортировано, чтобы избежать циклического импорта: bots_api сам
    импортирует panel.auth (см. moderation_api.py, где применён тот же
    приём для _db_path).

    root здесь — ВСЕГДА PanelRoots.repo, то есть корень монорепо. Сюда
    после входа под аккаунтом бота ложатся TWITCH_MOD_*, и ровно отсюда их
    читает cigilbot/consumer.py. Если передать другой корень, панель
    отрапортует об успешно полученном токене, а баны начнут падать с 401,
    потому что executor прочитает пустое место (см. paths.py)."""
    env_file = root / ".env"
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


SESSION_NEXT_KEY = "panel_auth_next"
DEFAULT_AFTER_LOGIN = "/moderation"


def _safe_next(raw: str) -> str:
    """Куда вернуть пользователя после входа — только внутренний путь.

    Появилось вместе со слиянием панелей: экранов стало два ("/moderation" и
    "/bots"), и жёсткий редирект на модерацию выкидывал бы с экрана ботов
    того, кто входил именно туда.

    Принимаем только пути, начинающиеся с одного "/". "//evil.com" браузер
    трактует как protocol-relative URL, то есть внешний адрес — это классический
    open redirect, и отличается он от нормального пути ровно одним символом."""
    if raw.startswith("/") and not raw.startswith("//"):
        return raw
    return DEFAULT_AFTER_LOGIN


@router.get("/login")
async def auth_login(request: Request, next: str = DEFAULT_AFTER_LOGIN) -> RedirectResponse:
    cfg: PanelAuthConfig = request.app.state.panel_auth_config
    if not cfg.configured:
        raise HTTPException(
            status_code=503,
            detail="Вход через Twitch не настроен: заполните PANEL_TWITCH_CLIENT_ID/"
            "PANEL_TWITCH_CLIENT_SECRET/PANEL_TWITCH_CHANNEL в .env",
        )

    # В сессии, а не в _pending_states: тот словарь хранит время создания
    # state для проверки TTL, и подмешивать туда второе значение значило бы
    # менять тип ради одной строки. Cookie сессии всё равно доезжает до
    # /auth/callback — тем же механизмом, что и сама сессия после входа.
    request.session[SESSION_NEXT_KEY] = _safe_next(next)

    _prune_states()
    state = secrets.token_urlsafe(24)
    _pending_states[state] = time.time()

    params = {
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "response_type": "code",
        "scope": OAUTH_SCOPES,
        "state": state,
    }
    return RedirectResponse(f"{TWITCH_AUTHORIZE_URL}?{urlencode(params)}")


@router.get("/callback")
async def auth_callback(request: Request, code: str = "", state: str = "", error: str = "") -> RedirectResponse:
    if error:
        raise HTTPException(status_code=400, detail=f"Twitch отказал во входе: {error}")

    if state not in _pending_states:
        raise HTTPException(status_code=400, detail="Неизвестный или истёкший state — начните вход заново")
    _pending_states.pop(state, None)

    cfg: PanelAuthConfig = request.app.state.panel_auth_config
    if not cfg.configured:
        raise HTTPException(status_code=503, detail="Вход через Twitch не настроен")

    try:
        user_token = await _exchange_code(cfg, code)
        login, user_id = await _fetch_viewer(cfg, user_token)
        moderated_channel_ids = await _fetch_moderated_channel_ids(cfg, user_token, user_id)
    except TwitchAuthError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    store = request.app.state.moderation_store_factory()
    try:
        await store.connect()
        admin_override = await store.get_panel_role(login)
    finally:
        await store.close()

    roots: PanelRoots = request.app.state.panel_roots
    try:
        roles_by_channel = await _resolve_roles_by_channel(
            cfg, roots, login=login, user_id=user_id,
            moderated_channel_ids=moderated_channel_ids, admin_override=admin_override,
        )
    except TwitchAuthError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # role — обратная совместимость для мест, которые ждут одну строку
    # (например /auth/me для карточки пользователя в сайдбаре): роль на
    # канале самой панели (cfg.channel). Фактические проверки прав в
    # moderation_api.py всегда берут из roles по каналу нужного профиля,
    # не из этого поля — см. role_for_profile.
    role = roles_by_channel.get(cfg.channel, "VIEWER")

    request.session[SESSION_KEY] = {
        "login": login, "user_id": user_id, "role": role, "roles": roles_by_channel,
    }
    # Экран, с которого начали вход (см. _safe_next). pop, а не get: значение
    # относится к одному конкретному входу и в следующем не должно всплыть.
    return RedirectResponse(_safe_next(request.session.pop(SESSION_NEXT_KEY, DEFAULT_AFTER_LOGIN)))


@router.get("/logout")
async def auth_logout(request: Request) -> RedirectResponse:
    request.session.pop(SESSION_KEY, None)
    return RedirectResponse("/moderation")


@router.get("/me")
async def auth_me(request: Request) -> dict[str, object]:
    user = request.session.get(SESSION_KEY)
    if user is None:
        cfg: PanelAuthConfig = request.app.state.panel_auth_config
        return {"authenticated": False, "login_configured": cfg.configured}
    return {"authenticated": True, **user}


async def _fetch_viewer_by_login(cfg: PanelAuthConfig, login: str) -> tuple[str, str]:
    """Тот же /helix/users, но по конкретному login через App Access Token —
    нужен, чтобы узнать user_id канала для проверки broadcaster/модераторов,
    независимо от того, кто именно сейчас логинится."""
    async with _new_http_client() as client:
        token_resp = await client.post(
            TWITCH_TOKEN_URL,
            data={
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "grant_type": "client_credentials",
            },
        )
        if token_resp.status_code != 200:
            raise TwitchAuthError("Не удалось получить App Access Token для проверки канала")
        app_token = token_resp.json()["access_token"]

        resp = await client.get(
            f"{HELIX_BASE}/users",
            headers={"Client-ID": cfg.client_id, "Authorization": f"Bearer {app_token}"},
            params={"login": login},
        )
    if resp.status_code != 200:
        raise TwitchAuthError(f"Не удалось получить данные канала {login!r}: {resp.status_code}")
    data = resp.json().get("data", [])
    if not data:
        raise TwitchAuthError(f"Канал {login!r} не найден на Twitch")
    return data[0]["login"].lower(), data[0]["id"]


def current_session_role(request: Request) -> tuple[str, str]:
    """(role, login) текущей сессии — не заголовок, а подписанная cookie,
    выставленная только в auth_callback после проверки через Twitch.
    Нет сессии -> VIEWER/"аноним", без исключения — используется там, где
    отсутствие входа само по себе не ошибка (сейчас не используется ни
    одним эндпоинтом moderation_api.py напрямую, все read/write require
    require_authenticated; оставлен как вспомогательная функция для
    будущих некритичных мест, например публичного статус-виджета)."""
    user = request.session.get(SESSION_KEY)
    if user is None:
        return "VIEWER", "аноним"
    return str(user.get("role", "VIEWER")), str(user.get("login", "аноним"))


def require_authenticated(request: Request) -> tuple[str, str]:
    """(role, login), только если сессия есть — иначе 401. role здесь — роль
    на канале самой панели (cfg.channel), для мест, которым по-канальность
    не важна (карточка пользователя, общие проверки "вошёл ли вообще").
    Для проверки прав на КОНКРЕТНЫЙ профиль/канал (BAN ALL и любое другое
    модераторское действие) используйте role_for_profile ниже — один
    вошедший может быть MODERATOR на канале профиля A и VIEWER на B."""
    user = request.session.get(SESSION_KEY)
    if user is None:
        raise HTTPException(status_code=401, detail="Требуется вход через Twitch (/auth/login)")
    return str(user.get("role", "VIEWER")), str(user.get("login", "аноним"))


async def role_for_profile(request: Request, profile: str) -> str:
    """Роль вошедшего для канала КОНКРЕТНОГО канала (параметр называется
    "profile" по историческим причинам, значение — broadcaster_id, см.
    комментарий у _list_profile_channels) — не общая роль сессии.
    session["roles"] — {channel_login: role}, посчитанный на все известные
    каналы разом при входе (см. _resolve_roles_by_channel); здесь просто
    достаём канал этого broadcaster_id и смотрим роль по нему.

    ADMIN — исключение из по-канальности: это глобальный ручной оверрайд
    (mod_panel_users), а не Twitch-статус за конкретный канал, поэтому
    _resolve_roles_by_channel уже проставил ADMIN на каждый канал словаря
    одинаково — читать его здесь ничем не отличается от обычного канала.

    Нет сессии или broadcaster_id не найден в Channel Registry -> VIEWER,
    не исключение: канал мог быть удалён из Registry между входом и этим
    запросом, а падать 500 вместо честного "недостаточно прав" на
    устаревший broadcaster_id было бы хуже UX без выигрыша в безопасности."""
    user = request.session.get(SESSION_KEY)
    if user is None:
        raise HTTPException(status_code=401, detail="Требуется вход через Twitch (/auth/login)")
    roles = user.get("roles")
    if not isinstance(roles, dict):
        return "VIEWER"
    roots: PanelRoots = request.app.state.panel_roots
    channel = (await _list_profile_channels(roots)).get(profile, "")
    if not channel:
        return "VIEWER"
    return str(roles.get(channel, "VIEWER"))


# Та же иерархия, что panel/moderation_api.py::_ROLE_RANK — продублирована
# здесь намеренно (не импортирована оттуда), чтобы panel/server.py мог
# использовать проверку роли, не создавая цикл server.py -> moderation_api.py
# -> auth.py -> обратно в server.py (тот уже импортирует auth.py последним).
_ROLE_RANK = {"VIEWER": 0, "MODERATOR": 1, "ADMIN": 2, "OWNER": 3}


def require_role_min(minimum: str) -> tuple[str, str]:
    """Фабрика зависимостей: require_role_min("ADMIN") -> (role, login), либо
    401 (не вошёл), либо 403 (роль ниже minimum). Используется в
    panel/server.py для тех же гарантий, что moderation_api.py::require_role
    даёт своему роутеру, но как единая Depends-зависимость, а не отдельная
    функция-проверка внутри тела эндпоинта — server.py эндпоинты в основном
    синхронные def, а не async, и не всегда явно достают session сами.

    Возвращаемый тип объявлен как tuple[str, str] (не Depends(...)) намеренно:
    FastAPI использует значение по умолчанию параметра только чтобы получить
    саму зависимость через __class__ == Depends, а mypy при этом должен
    видеть тип, который реально придёт в тело эндпоинта после разрешения
    зависимости — то же соглашение, что require_authenticated/current_session_role
    выше в этом файле."""

    def dependency(request: Request) -> tuple[str, str]:
        role, login = require_authenticated(request)
        if _ROLE_RANK[role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=403, detail=f"Требуется роль {minimum}+ (у вас {role})"
            )
        return role, login

    # Формально это Depends(dependency), не tuple[str, str] — но так же, как
    # SessionRole/AuthenticatedRole выше в этом файле, аннотируем возвращаемым
    # типом того, что реально придёт в тело эндпоинта, а не типом самого
    # объекта Depends. FastAPI не смотрит на аннотацию значения по умолчанию,
    # только на factory-функцию внутри Depends(), так что рантайм-поведение
    # не зависит от этого cast.
    return cast("tuple[str, str]", Depends(dependency))


SessionRole = Depends(current_session_role)
AuthenticatedRole = Depends(require_authenticated)


# ---------------------------------------------------------------------------
# Bot-token OAuth (docs/moderation-plan.md, раздел 11, блокер #1). Отдельный
# flow от входа в панель выше: тот отвечает на "кто ты", этот — "дай токен
# для реальных действий модерации". ADMIN+ обязателен на login, иначе любой
# VIEWER мог бы инициировать перезапись боевого токена бота в .env через
# один открытый в браузере URL.
#
# Кто именно должен нажать "Войти как бот" — решает человек с доступом к
# аккаунту бота: Twitch OAuth-экран покажет логин ТЕКУЩЕЙ сессии браузера
# на Twitch, и именно под этим логином придёт токен. Если в браузере
# сейчас открыт личный аккаунт владельца панели — токен получится на его
# имя, а не на бота, и последующий ban_user() будет падать (moderator_id
# должен совпадать с владельцем токена, см. cigilbot/twitch_api.py).
# Мы не можем это предотвратить программно (Twitch не даёt выбрать логин
# заранее), поэтому auth_bot_callback только предупреждает в ответе, если
# вошедший — сам broadcaster, а не отдельный аккаунт бота.
# ---------------------------------------------------------------------------


@router.get("/bot/login")
async def auth_bot_login(request: Request) -> RedirectResponse:
    cfg: PanelAuthConfig = request.app.state.panel_auth_config
    if not cfg.configured:
        raise HTTPException(
            status_code=503,
            detail="Вход через Twitch не настроен: заполните PANEL_TWITCH_CLIENT_ID/"
            "PANEL_TWITCH_CLIENT_SECRET/PANEL_TWITCH_CHANNEL в .env",
        )
    role, _login = require_authenticated(request)
    if role not in ("ADMIN", "OWNER"):
        raise HTTPException(status_code=403, detail="Получение токена бота требует роль ADMIN+")

    _prune_bot_states()
    state = secrets.token_urlsafe(24)
    _pending_bot_states[state] = (time.time(), "mod")

    params = {
        "client_id": cfg.client_id,
        "redirect_uri": cfg.bot_redirect_uri,
        "response_type": "code",
        "scope": BOT_TOKEN_OAUTH_SCOPES,
        "state": state,
        # force_verify заставляет Twitch показать экран логина заново, даже
        # если в браузере уже есть активная сессия (например, только что
        # логинились как VIEWER для входа в панель) — снижает риск случайно
        # выпустить токен на неверный аккаунт молча.
        "force_verify": "true",
    }
    return RedirectResponse(f"{TWITCH_AUTHORIZE_URL}?{urlencode(params)}")


@router.get("/bot/chat_login")
async def auth_bot_chat_login(request: Request) -> RedirectResponse:
    """Тот же flow, что /bot/login, но для чат-токена бота (TWITCH_BOT_TOKEN,
    IRC chat:read/chat:edit) — не Helix moderator:manage:* из BOT_TOKEN_OAUTH_SCOPES.

    Раньше TWITCH_BOT_TOKEN выпускался вручную (сторонний генератор токена)
    и не имел refresh_token вовсе — истекал молча: чтение чата продолжало
    работать на уже установленном IRC-соединении, а PRIVMSG (отправка)
    Twitch тихо отклонял без ошибки на клиенте (см. main.py::MessageQueue).
    Этот flow и mod_token.py-подобное автообновление (main.py::ChatTokenManager)
    заменяют его тем же паттерном, что уже работает для токена модерации."""
    cfg: PanelAuthConfig = request.app.state.panel_auth_config
    if not cfg.configured:
        raise HTTPException(
            status_code=503,
            detail="Вход через Twitch не настроен: заполните PANEL_TWITCH_CLIENT_ID/"
            "PANEL_TWITCH_CLIENT_SECRET/PANEL_TWITCH_CHANNEL в .env",
        )
    role, _login = require_authenticated(request)
    if role not in ("ADMIN", "OWNER"):
        raise HTTPException(status_code=403, detail="Получение токена бота требует роль ADMIN+")

    _prune_bot_states()
    state = secrets.token_urlsafe(24)
    _pending_bot_states[state] = (time.time(), "chat")

    params = {
        "client_id": cfg.client_id,
        "redirect_uri": cfg.bot_redirect_uri,
        "response_type": "code",
        "scope": CHAT_TOKEN_OAUTH_SCOPES,
        "state": state,
        "force_verify": "true",
    }
    return RedirectResponse(f"{TWITCH_AUTHORIZE_URL}?{urlencode(params)}")


async def _process_bot_callback(
    request: Request, *, code: str, state: str, error: str
) -> dict[str, object]:
    """Логика обмена code -> токен бота + запись в .env, без привязки к
    формату ответа — используется и JSON-, и HTML-эндпоинтом ниже, чтобы
    не дублировать сам OAuth-обмен.

    Один callback на оба под-flow (mod-токен для банов, chat-токен для IRC)
    — Twitch требует точного совпадения redirect_uri с тем, что был указан
    при запросе авторизации, поэтому оба используют bot_redirect_uri, а
    какой именно flow завершился, читаем из purpose, сохранённого в state
    при /bot/login или /bot/chat_login."""
    if error:
        raise HTTPException(status_code=400, detail=f"Twitch отказал во входе: {error}")

    if state not in _pending_bot_states:
        raise HTTPException(status_code=400, detail="Неизвестный или истёкший state — начните вход заново")
    _created_at, purpose = _pending_bot_states.pop(state)

    cfg: PanelAuthConfig = request.app.state.panel_auth_config
    if not cfg.configured:
        raise HTTPException(status_code=503, detail="Вход через Twitch не настроен")

    try:
        access_token, refresh_token = await _exchange_code_with_refresh(
            cfg, code, redirect_uri=cfg.bot_redirect_uri
        )
        bot_login, bot_user_id = await _fetch_viewer(cfg, access_token)
        broadcaster_login, broadcaster_id = await _fetch_viewer_by_login(cfg, cfg.channel)
        is_broadcaster = bot_login == broadcaster_login

        if purpose == "chat":
            is_moderator = True  # IRC chat:edit не требует прав модератора — только валидный токен
        else:
            moderated_channel_ids = await _fetch_moderated_channel_ids(cfg, access_token, bot_user_id)
            is_moderator = broadcaster_id in moderated_channel_ids
    except TwitchAuthError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    roots: PanelRoots = request.app.state.panel_roots
    if purpose == "chat":
        _write_env_values(
            roots.repo,
            {
                "TWITCH_BOT_TOKEN": access_token,
                "TWITCH_BOT_REFRESH_TOKEN": refresh_token,
                "TWITCH_BOT_NICK": bot_login,
            },
        )
    else:
        _write_env_values(
            roots.repo,
            {
                "TWITCH_MOD_ACCESS_TOKEN": access_token,
                "TWITCH_MOD_REFRESH_TOKEN": refresh_token,
                "TWITCH_MOD_BOT_LOGIN": bot_login,
                "TWITCH_MOD_BOT_USER_ID": bot_user_id,
                "TWITCH_MOD_BROADCASTER_ID": broadcaster_id,
            },
        )

    warning = None
    if purpose != "chat" and not is_moderator and not is_broadcaster:
        warning = (
            f"Аккаунт {bot_login!r}, под которым вы только что вошли, НЕ модератор канала "
            f"{cfg.channel!r} — реальные баны через Helix вернут 401, пока не выдадите ему "
            f"права модератора командой /mod {bot_login} в чате."
        )

    return {
        "ok": True,
        "purpose": purpose,
        "bot_login": bot_login,
        "is_broadcaster": is_broadcaster,
        "is_moderator": is_moderator,
        "warning": warning,
    }


@router.get("/bot/callback")
async def auth_bot_callback(request: Request, code: str = "", state: str = "", error: str = "") -> HTMLResponse:
    """Реальный OAuth redirect target (совпадает с PanelAuthConfig.bot_redirect_uri,
    зарегистрированным в Twitch Dev Console) — отдаёт человекочитаемую
    страницу, а не голый JSON, т.к. открывается прямо в браузере после
    экрана логина Twitch."""
    try:
        result = await _process_bot_callback(request, code=code, state=state, error=error)
    except HTTPException as exc:
        body = (
            f"<h2>Не удалось получить токен бота</h2><p>{exc.detail}</p>"
            '<p><a href="/moderation">Вернуться в панель</a></p>'
        )
        return HTMLResponse(body, status_code=exc.status_code)

    warning_html = f'<p style="color:#f5b942">{result["warning"]}</p>' if result["warning"] else ""
    ok_html = (
        '<p style="color:#34d399">Аккаунт модератор канала — токен готов к использованию.</p>'
        if result["is_moderator"] or result["is_broadcaster"]
        else ""
    )
    title = "Чат-токен бота получен" if result["purpose"] == "chat" else "Токен бота получен"
    body = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:24px;">
      <h2>{title}</h2>
      <p>Вошли как: <b>{result["bot_login"]}</b></p>
      {ok_html}
      {warning_html}
      <p><a href="/moderation">Вернуться в панель</a></p>
    </div>
    """
    return HTMLResponse(body)


@router.get("/bot/callback.json")
async def auth_bot_callback_json(
    request: Request, code: str = "", state: str = "", error: str = ""
) -> dict[str, object]:
    """Тот же обмен, но JSON-ответ — для тестов и программных клиентов,
    которым нужен структурированный результат, а не HTML для браузера."""
    return await _process_bot_callback(request, code=code, state=state, error=error)


@router.get("/bot/status")
async def auth_bot_status(request: Request) -> dict[str, object]:
    """Есть ли уже сохранённый токен бота — панель читает .env заново на
    каждый запрос (не кеширует), чтобы отразить ручное редактирование
    файла или обновление токена в фоне executor'ом."""
    roots: PanelRoots = request.app.state.panel_roots
    env_file = roots.repo / ".env"
    values: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            values[key.strip()] = value

    has_token = bool(values.get("TWITCH_MOD_ACCESS_TOKEN") and values.get("TWITCH_MOD_REFRESH_TOKEN"))
    return {
        "configured": has_token,
        "bot_login": values.get("TWITCH_MOD_BOT_LOGIN", ""),
    }


@router.get("/bot/chat_status")
async def auth_bot_chat_status(request: Request) -> dict[str, object]:
    """Есть ли уже чат-токен (TWITCH_BOT_TOKEN/TWITCH_BOT_REFRESH_TOKEN) —
    тот же принцип, что auth_bot_status: читает .env заново на каждый
    запрос, ничего не кеширует."""
    roots: PanelRoots = request.app.state.panel_roots
    env_file = roots.repo / ".env"
    values: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            values[key.strip()] = value

    has_token = bool(values.get("TWITCH_BOT_TOKEN") and values.get("TWITCH_BOT_REFRESH_TOKEN"))
    return {
        "configured": has_token,
        "bot_login": values.get("TWITCH_BOT_NICK", ""),
    }
