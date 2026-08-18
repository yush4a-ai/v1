"""Тонкий клиент Twitch Helix API — независимый от twitchio.

Не переиспользует объектную модель twitchio (PartialUser.ban_user() и т.п.)
намеренно: та требует живого IRC-соединения и связанного client_id внутри
объекта Client, из-за чего её нельзя протестировать без поднятия сессии.
Здесь — обычный httpx-клиент с инъекцией транспорта, поэтому весь модуль
тестируется моками, без единого реального запроса к Twitch.

Два разных токена нужны для разных вещей:
  - App Access Token (client_credentials, без пользователя) — для
    GET /helix/users. Не требует scope и выдаётся по одним client_id +
    client_secret, полученным на dev.twitch.tv/console/apps.
  - User Access Token модератора со scope moderator:manage:banned_users
    (+ moderator:manage:chat_messages для удаления сообщений) — для
    ban/timeout/delete. Именно этого токена сейчас у бота нет (см.
    docs/moderation-plan.md, раздел 11) — методы построены и протестированы
    на моках, но вызов с текущим chat-only токеном вернёт 401, и это
    ожидаемо, а не баг.

Ban User и Timeout User — один и тот же эндпоинт (POST /helix/moderation/bans),
без duration — бан, с duration — таймаут. Эндпоинт НЕ батчевый: один
пользователь на запрос (см. блокер #4 в плане) — отсюда необходимость
executor.py делать по вызову на каждого участника кластера и агрегировать
результат.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import httpx

log = logging.getLogger("moderation.twitch_api")

HELIX_BASE = "https://api.twitch.tv/helix"
OAUTH_TOKEN_URL = "https://id.twitch.tv/oauth2/token"

# Один запрос — максимум 100 login/id суммарно (жёсткий лимит Twitch).
MAX_USERS_PER_REQUEST = 100

# Консервативный дефолт: общий лимит Helix — 800 points/min на client_id,
# но для конкретно moderation/bans Twitch отдельный лимит не документирует.
# Держимся заметно ниже общего лимита, чтобы не задеть его даже при
# параллельных вызовах других частей бота к тому же client_id.
DEFAULT_MAX_REQUESTS_PER_SECOND = 8.0
MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 1.0


class HelixError(Exception):
    """Ошибка Helix API — с кодом статуса и телом ответа для диагностики.

    status_code=0 означает чистую транспортную ошибку (обрыв соединения,
    DNS-сбой, таймаут) — ни одного HTTP-ответа получено не было. Ненулевой
    status_code при исчерпании ретраев (см. _request) — последний код,
    который вернул Helix перед тем, как попытки закончились (429/5xx).
    Различие важно для create_clip(): 429 означает "запрос отклонён до
    создания клипа" (failed), 5xx/0 — "исход неизвестен" (unknown), см.
    bug-аудит 2026-08-18."""

    def __init__(self, status_code: int, message: str, body: str = "") -> None:
        super().__init__(f"Helix {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.body = body


@dataclass(frozen=True, slots=True)
class HelixUser:
    id: str
    login: str
    display_name: str
    created_at: float  # unix timestamp


@dataclass(frozen=True, slots=True)
class HelixStream:
    """Live-статус канала — для авто-подстройки порога всплеска автоклипа
    под текущее число зрителей (bot/autoclip.py). Twitch не отдаёт отдельное
    булево поле "в эфире ли канал": пустой data[] в ответе /streams И ЕСТЬ
    сигнал "оффлайн" — get_streams() сам разворачивает это в HelixStream
    с is_live=False, а не пустой список/None, чтобы вызывающему коду не
    приходилось помнить это соглашение Twitch каждый раз заново."""

    broadcaster_id: str
    is_live: bool
    viewer_count: int = 0


@dataclass(frozen=True, slots=True)
class ActionResult:
    """Результат одного действия над одним пользователем.

    executor.py агрегирует список таких результатов в "14/17 забанено,
    3 не удалось" (раздел 7 ТЗ) — по одному ActionResult на пользователя,
    а не общий success/fail на весь запрос.
    """

    user_id: str
    success: bool
    error: str = ""


@dataclass(frozen=True, slots=True)
class ClipResult:
    """Результат создания клипа — отдельно от ActionResult: edit_url это
    клип-специфичные данные, которых нет у бана/таймаута/удаления
    сообщения, тащить их через ActionResult.error было бы слоевым хаком.

    outcome — не идемпотентность (Twitch Clips API её не даёт), а честная
    классификация неопределённости (bug-аудит 2026-08-18):
      created — Twitch подтвердил (202), clip_id/edit_url заполнены
      failed  — Twitch синхронно отклонил запрос (4xx кроме 429, или 429
                — оба означают "клип не начал создаваться на стороне
                Twitch"), исход точно известен
      unknown — 5xx или транспортная ошибка при исчерпании ретраев:
                сервер мог упасть и до, и после фактического создания
                клипа, _request не различает эти случаи технически
    success=True эквивалентно outcome="created", оставлено для мест, где
    важен только факт успеха, не причина неуспеха."""

    broadcaster_id: str
    success: bool
    clip_id: str = ""
    edit_url: str = ""
    error: str = ""
    outcome: Literal["created", "failed", "unknown"] = "failed"


def _parse_iso8601(value: str) -> float:
    # Twitch отдаёт created_at в формате "2016-12-14T20:32:28Z"
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()


class _RateLimiter:
    """Простой ограничитель частоты запросов — не даёт executor'у делать
    больше N запросов в секунду, даже если очередь просит забанить сотню
    пользователей разом (см. раздел 16 ТЗ "Rate Limiting").

    HelixClient — один инстанс на канал, но внутри канала его используют
    параллельно несколько фоновых задач (_poll_account_age и
    _poll_action_queue в pipeline.py, каждая своим циклом). Без лока
    read-sleep-write не атомарен: несколько корутин читают одно и то же
    _last_request, спят на основе него и лишь потом пишут — все просыпаются
    одновременно и лимит нарушается пропорционально числу конкурентных
    вызовов (bug-аудит 2026-08-17, HIGH; воспроизведено — 5 конкурентных
    запросов уходили за 0.2с вместо заявленных 0.8с при 5 rps)."""

    def __init__(self, max_per_second: float) -> None:
        self._min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.0
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            remaining = self._min_interval - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_request = time.monotonic()


class HelixClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        max_requests_per_second: float = DEFAULT_MAX_REQUESTS_PER_SECOND,
        backoff_base_seconds: float = BACKOFF_BASE_SECONDS,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = httpx.AsyncClient(transport=transport, timeout=15.0)
        self._rate_limiter = _RateLimiter(max_requests_per_second)
        # Настраиваемо, чтобы тесты на реальный retry-путь не ждали секунды
        # экспоненциального backoff — в проде используется дефолт.
        self._backoff_base = backoff_base_seconds
        self._app_token: str | None = None
        self._app_token_expires_at = 0.0

    async def close(self) -> None:
        await self._http.aclose()

    # -- аутентификация --------------------------------------------------

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
            raise HelixError(resp.status_code, "не удалось получить App Access Token", resp.text)

        data = resp.json()
        token: str = data["access_token"]
        self._app_token = token
        self._app_token_expires_at = time.time() + data["expires_in"]
        return token

    # -- низкоуровневый запрос с ретраями и рейт-лимитом ------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        params: Sequence[tuple[str, str | int | float | bool | None]] | None = None,
        json_body: dict[str, object] | None = None,
        retry: bool = True,
    ) -> httpx.Response:
        """retry=False — ровно одна попытка, без ретраев на 429/5xx/
        TransportError (bug-аудит 2026-08-18): create_clip() передаёт это
        явно — Twitch Clips API не даёт idempotency-key, повторный POST
        после потерянного ответа физически создал бы второй клип на
        стороне Twitch. Остальные вызывающие (ban_user, get_users и т.д.)
        не передают retry — их поведение не меняется."""
        headers = {"Client-ID": self._client_id, "Authorization": f"Bearer {token}"}
        attempts = MAX_RETRIES if retry else 1

        last_error: Exception | None = None
        # 0 — чистая транспортная ошибка (ни одного HTTP-ответа не было).
        # Ненулевое значение — последний код, который вернул Helix перед
        # тем, как попытки закончились (см. HelixError про то, зачем это
        # нужно create_clip() для различения failed/unknown).
        last_status_code = 0
        for attempt in range(attempts):
            await self._rate_limiter.wait()
            try:
                resp = await self._http.request(
                    method,
                    f"{HELIX_BASE}{path}",
                    headers=headers,
                    params=tuple(params) if params is not None else None,
                    json=json_body,
                )
            except httpx.TransportError as exc:
                last_error = exc
                if attempt + 1 == attempts:
                    break
                await asyncio.sleep(self._backoff_base * (2**attempt))
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                last_status_code = resp.status_code
                if attempt + 1 == attempts:
                    break
                delay = self._backoff_base * (2**attempt)
                # Ratelimit-Reset — момент сброса счётчика запросов, валиден
                # только для 429 (превышен лимит). Раньше применялся и к
                # 5xx одинаково (bug-аудит 2026-08-15, HIGH #11) — заголовок
                # для 5xx семантически не при чём (внутренняя ошибка сервера
                # Twitch, не про рейт-лимит), но мог содержать устаревшее
                # значение из предыдущего ответа и раздувать задержку до
                # 60 сек НА КАЖДУЮ попытку. _run_per_target исполняет цели
                # строго последовательно — при кластере в 40 человек и
                # временно нездоровом Helix (несколько 5xx подряд) это
                # растягивало батч банов на часы, что превышает
                # STUCK_ACTION_TIMEOUT_SECONDS=120.0 и провоцирует
                # reclaim_stuck_actions вернуть задание в pending посреди
                # ещё живого исполнения (executor.py) — задвоенный аудит,
                # задвоенная эскалация прогрессивных таймаутов.
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Ratelimit-Reset")
                    if retry_after is not None:
                        with contextlib.suppress(ValueError):
                            delay = max(delay, float(retry_after) - time.time())
                log.warning(
                    "Helix %s %s -> %d, повтор через %.1f сек (попытка %d/%d)",
                    method, path, resp.status_code, delay, attempt + 1, attempts,
                )
                await asyncio.sleep(max(0.0, delay))
                continue

            return resp

        raise HelixError(
            last_status_code, f"исчерпаны попытки запроса к {path}", str(last_error or "")
        )

    # -- публичные методы --------------------------------------------------

    async def get_users(
        self, *, logins: list[str] | None = None, user_ids: list[str] | None = None
    ) -> list[HelixUser]:
        """Данные пользователей батчами по MAX_USERS_PER_REQUEST — включая
        created_at, который резолвит Verdict.is_provisional. Не требует
        scope, работает по App Access Token."""
        params: list[tuple[str, str]] = [("login", v) for v in (logins or [])]
        params += [("id", v) for v in (user_ids or [])]
        if not params:
            return []

        token = await self._get_app_token()
        results: list[HelixUser] = []

        for offset in range(0, len(params), MAX_USERS_PER_REQUEST):
            batch = params[offset : offset + MAX_USERS_PER_REQUEST]
            resp = await self._request("GET", "/users", token=token, params=batch)
            if resp.status_code != 200:
                raise HelixError(resp.status_code, "get_users не удался", resp.text)

            for row in resp.json().get("data", []):
                results.append(
                    HelixUser(
                        id=row["id"],
                        login=row["login"],
                        display_name=row["display_name"],
                        created_at=_parse_iso8601(row["created_at"]),
                    )
                )

        return results

    async def get_streams(self, *, broadcaster_ids: list[str]) -> list[HelixStream]:
        """Live-статус и число зрителей батчем по MAX_USERS_PER_REQUEST
        (тот же лимит Twitch, что у /users). Не требует scope, работает по
        App Access Token. Каналы, не входящие в ответ Twitch (offline),
        возвращаются явно как HelixStream(is_live=False) — вызывающий код
        не должен сам восстанавливать "молчание = оффлайн" по недостающим id."""
        if not broadcaster_ids:
            return []

        token = await self._get_app_token()
        live: dict[str, int] = {}

        for offset in range(0, len(broadcaster_ids), MAX_USERS_PER_REQUEST):
            batch = broadcaster_ids[offset : offset + MAX_USERS_PER_REQUEST]
            params = [("user_id", v) for v in batch]
            resp = await self._request("GET", "/streams", token=token, params=params)
            if resp.status_code != 200:
                raise HelixError(resp.status_code, "get_streams не удался", resp.text)

            for row in resp.json().get("data", []):
                live[row["user_id"]] = int(row["viewer_count"])

        return [
            HelixStream(broadcaster_id=bid, is_live=bid in live, viewer_count=live.get(bid, 0))
            for bid in broadcaster_ids
        ]

    async def ban_user(
        self, *, broadcaster_id: str, moderator_id: str, user_id: str, reason: str, user_token: str
    ) -> ActionResult:
        return await self._ban_or_timeout(
            broadcaster_id=broadcaster_id, moderator_id=moderator_id, user_id=user_id,
            reason=reason, user_token=user_token, duration=None,
        )

    async def timeout_user(
        self, *, broadcaster_id: str, moderator_id: str, user_id: str, duration: int,
        reason: str, user_token: str,
    ) -> ActionResult:
        return await self._ban_or_timeout(
            broadcaster_id=broadcaster_id, moderator_id=moderator_id, user_id=user_id,
            reason=reason, user_token=user_token, duration=duration,
        )

    async def _ban_or_timeout(
        self, *, broadcaster_id: str, moderator_id: str, user_id: str, reason: str,
        user_token: str, duration: int | None,
    ) -> ActionResult:
        body: dict[str, object] = {"user_id": user_id, "reason": reason[:500]}
        if duration is not None:
            body["duration"] = duration

        try:
            resp = await self._request(
                "POST", "/moderation/bans", token=user_token,
                params=[("broadcaster_id", broadcaster_id), ("moderator_id", moderator_id)],
                json_body={"data": body},
            )
        except HelixError as exc:
            return ActionResult(user_id=user_id, success=False, error=str(exc))

        if resp.status_code == 200:
            return ActionResult(user_id=user_id, success=True)
        return ActionResult(user_id=user_id, success=False, error=f"{resp.status_code}: {resp.text[:300]}")

    async def delete_chat_messages(
        self, *, broadcaster_id: str, moderator_id: str, user_token: str, message_id: str | None = None,
    ) -> ActionResult:
        """message_id=None удаляет ВСЕ сообщения пользователя-модератора в
        чате — здесь message_id обязателен для точечного удаления, вызывающий
        код должен явно передать конкретное сообщение."""
        params = [("broadcaster_id", broadcaster_id), ("moderator_id", moderator_id)]
        if message_id is not None:
            params.append(("message_id", message_id))

        try:
            resp = await self._request("DELETE", "/moderation/chat", token=user_token, params=params)
        except HelixError as exc:
            return ActionResult(user_id=message_id or "", success=False, error=str(exc))

        if resp.status_code == 204:
            return ActionResult(user_id=message_id or "", success=True)
        return ActionResult(
            user_id=message_id or "", success=False, error=f"{resp.status_code}: {resp.text[:300]}"
        )

    async def create_clip(self, *, broadcaster_id: str, user_token: str) -> ClipResult:
        """POST /helix/clips — 202 Accepted означает, что Twitch поставил
        нарезку в очередь (сама нарезка асинхронна на их стороне, готовый
        клип появляется не мгновенно). Требует User Access Token со scope
        clips:edit, принадлежащий вещателю, модератору или редактору канала
        — не App Access Token и не токен модератора банов (другой scope).

        retry=False (bug-аудит 2026-08-18): Twitch Clips API не даёт
        idempotency-key. Если первый физический POST дошёл до Twitch и
        создал клип, а ответ потерялся (обрыв/5xx после факта) — retry
        внутри _request послал бы ВТОРОЙ POST и создал второй, отдельный
        клип. Одна попытка — не идемпотентность (её тут физически нельзя
        обеспечить), а отказ от автоматического дублирования: при неудаче
        вызывающий код (bot/autoclip.py) записывает исход как
        failed/unknown и не ретраит сам, следующий независимый триггер
        решает, нужен ли новый клип."""
        try:
            resp = await self._request(
                "POST", "/clips", token=user_token,
                params=[("broadcaster_id", broadcaster_id)],
                retry=False,
            )
        except HelixError as exc:
            # 429 — Twitch отклонил запрос ДО создания клипа (рейт-лимит
            # проверяется раньше бизнес-логики) — исход точно известен.
            # 5xx и транспортные сбои (status_code=0) — исход неизвестен:
            # ошибка могла произойти и после того, как клип физически
            # поставлен в очередь на стороне Twitch (см. HelixError).
            outcome: Literal["failed", "unknown"] = "failed" if exc.status_code == 429 else "unknown"
            return ClipResult(
                broadcaster_id=broadcaster_id, success=False, error=str(exc), outcome=outcome
            )

        if resp.status_code == 202:
            data = resp.json().get("data") or [{}]
            row = data[0]
            return ClipResult(
                broadcaster_id=broadcaster_id,
                success=True,
                clip_id=row.get("id", ""),
                edit_url=row.get("edit_url", ""),
                outcome="created",
            )
        # Любой другой код, дошедший сюда без исключения — 4xx кроме 429,
        # _request возвращает resp напрямую без ретрая (см. условие
        # resp.status_code == 429 or resp.status_code >= 500 внутри
        # _request). Twitch синхронно ответил отказом, исход точно
        # известен, клип не создан.
        return ClipResult(
            broadcaster_id=broadcaster_id, success=False,
            error=f"{resp.status_code}: {resp.text[:300]}", outcome="failed",
        )
