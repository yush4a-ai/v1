"""Channel Registry: состав каналов и желаемое состояние модерации.

Реестр каналов один на монорепо (var/registry.db). Их было два — свой у
twitch-bots и зеркало у Cigilbot, которые синхронизировал POST /channels;
пока это были разные процессы, зеркало имело смысл. Оба движка теперь в
одном процессе, и две копии одной таблицы стали способом получить
расхождение внутри него, а не защитой от недоступности соседа.

POST /channels пережил схлопывание как вход для ВНЕШНЕГО вызова — если
реестром однажды станет управлять что-то за пределами репозитория. Изнутри
им никто не пользуется: панель пишет в реестр напрямую.

start/stop выставляют desired_state. Исполняет его бот: ModerationHub
внутри main.py сверяется с реестром и поднимает или гасит движок канала
(см. cigilbot/pipeline.py). Панель ничего не запускает — раньше этим
занимался supervisor в её же процессе, и её падение останавливало
restart-on-crash для консьюмеров.

Аутентификация НЕ через cookie-сессию panel/auth.py (это не человек за
браузером, а сервер-сервер вызов) — общий секрет INTERNAL_SYNC_TOKEN в
заголовке X-Internal-Token, читаемый из того же корневого .env, что
PANEL_TWITCH_CLIENT_ID/SECRET (см. panel/paths.py::ENV_FILE). Плюс
проверка, что запрос пришёл с localhost — второй слой защиты на случай,
если панель однажды станет доступна не только на 127.0.0.1 (см. риск, уже
описанный в docstring panel/moderation_api.py про X-Panel-Role).
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from cigilbot.integrations import bot_process_control
from cigilbot.storage.registry_store import ChannelRecord, RegistryStore
from panel.auth import require_authenticated
from paths import ENV_FILE, REGISTRY_DB

router = APIRouter(prefix="/api/registry")

# Иерархия ролей — тот же принцип, что moderation_api.py::_ROLE_RANK.
# Управление supervisor-процессами (start/stop/reset_crash) — операционное
# действие уровня инстанса, не модерация конкретного канала, поэтому
# требует общую роль сессии (require_authenticated), не role_for_profile.
_ROLE_RANK = {"VIEWER": 0, "MODERATOR": 1, "ADMIN": 2, "OWNER": 3}


def _require_role(role: str, minimum: str) -> None:
    if _ROLE_RANK[role] < _ROLE_RANK[minimum]:
        raise HTTPException(status_code=403, detail=f"Требуется роль {minimum}+ (у вас {role})")

_LOCALHOST_IPS = {"127.0.0.1", "::1"}


def _read_env(env_file: Path, key: str) -> str:
    if not env_file.exists():
        return ""
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}="):
            return stripped.split("=", 1)[1].strip()
    return ""


def _internal_sync_token() -> str:
    # ENV_FILE, а не ROOT/".env": .env переехал в корень монорепо, тогда как
    # ROOT здесь — каталог состояния модерации. До слияния это был
    # один и тот же каталог, и разница ничего не значила.
    return os.environ.get("INTERNAL_SYNC_TOKEN", "") or _read_env(ENV_FILE, "INTERNAL_SYNC_TOKEN")


def _require_internal_token(request: Request) -> None:
    client_host = request.client.host if request.client else None
    if client_host not in _LOCALHOST_IPS:
        raise HTTPException(status_code=403, detail="Только localhost может вызывать этот эндпоинт")

    expected = _internal_sync_token()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="INTERNAL_SYNC_TOKEN не настроен в .env — синхронизация Registry отключена",
        )

    provided = request.headers.get("X-Internal-Token", "")
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Неверный X-Internal-Token")


class ChannelSyncRequest(BaseModel):
    broadcaster_id: str
    login: str
    display_name: str | None = None


def _channel_to_dict(record: ChannelRecord) -> dict[str, object]:
    return {
        "broadcaster_id": record.broadcaster_id,
        "login": record.login,
        "display_name": record.display_name,
        "status": record.status,
        "registered_by": record.registered_by,
    }


@router.post("/channels")
async def sync_channel(
    payload: ChannelSyncRequest, request: Request, response: Response
) -> dict[str, object]:
    _require_internal_token(request)

    if not payload.broadcaster_id.strip() or not payload.login.strip():
        raise HTTPException(status_code=422, detail="broadcaster_id и login обязательны")

    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        existing = await registry.get_channel(payload.broadcaster_id)
        record = await registry.upsert_channel(
            broadcaster_id=payload.broadcaster_id,
            login=payload.login,
            display_name=payload.display_name,
            registered_by="sync",
        )
    finally:
        await registry.close()

    response.status_code = 200 if existing is not None else 201
    return {"status": "registered" if existing is None else "updated", **_channel_to_dict(record)}


def _channel_status_dict(record: ChannelRecord) -> dict[str, object]:
    return {
        **_channel_to_dict(record),
        "desired_state": record.desired_state,
        "process_status": record.process_status,
        "pid": record.pid,
        "last_heartbeat_at": record.last_heartbeat_at,
        "restart_count": record.restart_count,
    }


@router.get("/channels")
async def list_channels(
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        channels = await registry.list_channels(status=None)
    finally:
        await registry.close()
    return [_channel_status_dict(c) for c in channels]


async def _get_or_404(registry: RegistryStore, broadcaster_id: str) -> ChannelRecord:
    record = await registry.get_channel(broadcaster_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Канал {broadcaster_id!r} не найден в Registry")
    return record


@router.post("/channels/{broadcaster_id}/start")
async def start_channel(
    broadcaster_id: str, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    """Выставляет desired_state='running' — движок канала поднимется на
    следующем тике сверки в процессе бота (см.
    cigilbot/pipeline.py::ModerationHub), не синхронно из этого хендлера."""
    role, _ = session
    _require_role(role, "ADMIN")

    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        record = await _get_or_404(registry, broadcaster_id)
        await registry.set_desired_state(broadcaster_id, "running")
        record = await registry.get_channel(broadcaster_id)  # type: ignore[assignment]
    finally:
        await registry.close()
    return _channel_status_dict(record)


@router.post("/channels/{broadcaster_id}/stop")
async def stop_channel(
    broadcaster_id: str, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    role, _ = session
    _require_role(role, "ADMIN")

    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        record = await _get_or_404(registry, broadcaster_id)
        await registry.set_desired_state(broadcaster_id, "stopped")
        record = await registry.get_channel(broadcaster_id)  # type: ignore[assignment]
    finally:
        await registry.close()
    return _channel_status_dict(record)


@router.post("/channels/{broadcaster_id}/reset_crash")
async def reset_crash(
    broadcaster_id: str, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    """Ручной выход из process_status='crashed' после того как оператор
    поправил проблему — обнуляет restart_count, supervisor снова начнёт
    пытаться поднять процесс на следующем тике, если desired_state='running'."""
    role, _ = session
    _require_role(role, "ADMIN")

    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        await _get_or_404(registry, broadcaster_id)
        await registry.reset_crash(broadcaster_id)
        # Перечитываем через _get_or_404, а не сырым get_channel: тот отдаёт
        # ChannelRecord | None, и None ушёл бы в _channel_status_dict падением
        # на атрибуте вместо честного 404.
        record = await _get_or_404(registry, broadcaster_id)
    finally:
        await registry.close()
    return _channel_status_dict(record)


# ---------------------------------------------------------------------------
# Управление процессом main.py. Один процесс на все активные каналы
# (multi-channel), не per-channel — поэтому нет параметра broadcaster_id.
#
# При запуске через run.py панель живёт ВНУТРИ бота, и запускать его отсюда
# нечем: получился бы второй main.py со вторым движком модерации на те же
# mod.<id>.db и ту же очередь действий, то есть задвоенные вердикты и
# задвоенные баны. Поэтому в этом режиме start/stop честно отвечают 409, а
# не делают вид, что сработали. Флаг ставит run.py (см. app.state ниже);
# при отдельном запуске `python -m panel.server` его нет и всё работает
# по-старому.
# ---------------------------------------------------------------------------


def _in_bot_process(request: Request) -> bool:
    return bool(getattr(request.app.state, "in_bot_process", False))


@router.get("/bot/status")
async def bot_status(
    request: Request, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    if _in_bot_process(request):
        return {"running": True, "pid": os.getpid(), "in_process": True}
    return {"running": bot_process_control.is_running(), "pid": bot_process_control.get_pid()}


@router.post("/bot/start")
async def bot_start(
    request: Request, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    role, _ = session
    _require_role(role, "ADMIN")
    if _in_bot_process(request):
        raise HTTPException(
            status_code=409,
            detail="Бот уже запущен — панель работает внутри его процесса (run.py)",
        )
    try:
        pid = bot_process_control.start_bot()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"running": True, "pid": pid}


@router.post("/bot/stop")
async def bot_stop(
    request: Request, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    role, _ = session
    _require_role(role, "ADMIN")
    if _in_bot_process(request):
        raise HTTPException(
            status_code=409,
            detail="Панель работает внутри процесса бота (run.py) — остановите его целиком "
                   "в терминале, иначе она остановит сама себя",
        )
    bot_process_control.stop_bot()
    return {"running": False, "pid": None}
