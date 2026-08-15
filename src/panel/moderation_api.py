"""REST + WebSocket роутер экрана модерации (этап 8).

Подключается к приложению в panel/server.py — тому же, куда подключён
роутер экрана нейроботов (panel/bots_api.py). Раньше это были два
самостоятельных приложения на разных портах с раздельным входом; см.
докстринг panel/server.py про то, почему их свели обратно.

Панель — процесс, отдельный от бота, и Twitch-подключения не имеет. Кнопка
BAN ALL кладёт задание в mod_action_queue (в mod.<broadcaster_id>.db, собственной
БД Cigilbot) — исполняет его cigilbot/executor.py внутри процесса бота
(см. cigilbot/pipeline.py), который поллит очередь так же, как раньше это
делал main.py._poll_action_queue (см. docs/moderation-plan.md, раздел 7).
Здесь только пишем в очередь и читаем результат/аудит обратно.

Роли и проверка прав — здесь, в роутере, а не в JS на фронте (раздел 7
плана: "проверка прав в роутере, а не в UI"). Роль и логин берутся из
подписанной cookie-сессии, выставленной panel/auth.py ПОСЛЕ входа через
Twitch и проверки через Helix (сам канал -> OWNER, модераторы канала ->
MODERATOR, остальные вошедшие -> VIEWER, плюс ручной ADMIN-оверрайд из
mod_panel_users) — не из заголовка, который клиент мог заявить о себе сам.
Старая версия этого модуля читала роль из заголовка X-Panel-Role, которому
верила без проверки; это было осознанно задокументированным временным
ограничением на период "панель только на 127.0.0.1", а не забытой
проверкой — но раз панель теперь доступна кому угодно в локальной сети,
этого недостаточно, и вместо заголовка используется panel.auth.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from cigilbot.domain.types import ContentCategory
from cigilbot.orchestration.executor import parse_payload
from cigilbot.storage.registry_store import RegistryStore
from cigilbot.storage.store import ModerationStore, PatternInput
from panel.auth import require_authenticated, role_for_profile
from paths import MOD_VAR, REGISTRY_DB, REPO_ROOT, safe_segment

# Где лежат mod.<broadcaster_id>.db и registry.db. Раньше это был
# `Path(__file__).parent.parent` — панель жила внутри Cigilbot, корень
# пакета совпадал с корнем проекта, а состояние лежало там же, что и код.
# Теперь это разные каталоги (см. panel/paths.py). Имя ROOT сохранено: на
# него монкейпатчатся тесты (tests/panel/conftest.py::tmp_root).
#
# Блок sys.path, стоявший здесь же, переехал в panel/__init__.py — иначе
# каждый модуль пакета чинил бы пути заново.
ROOT = MOD_VAR

# Корень проекта — только ради config/moderation.yml, который экран
# Settings читает и пишет. Это конфиг, а не состояние: он под git.
SRC_ROOT = REPO_ROOT

router = APIRouter(prefix="/api/moderation")

# Иерархия ролей раздела 7 плана. Числа только для сравнения "достаточно ли
# прав", наружу (в JSON) не уходят — там всегда сама строка роли.
_ROLE_RANK = {"VIEWER": 0, "MODERATOR": 1, "ADMIN": 2, "OWNER": 3}


def require_role(role: str, minimum: str) -> None:
    if _ROLE_RANK[role] < _ROLE_RANK[minimum]:
        raise HTTPException(
            status_code=403, detail=f"Требуется роль {minimum}+ (у вас {role})"
        )


# ---------------------------------------------------------------------------
# Доступ к БД канала. Параметр `profile` во всех эндпоинтах ниже — исторические
# название с ранних этапов проекта (профиль бота); семантика поменялась при
# переходе на Channel Registry (см. docs/master-plan.html, направление
# 00) — теперь это broadcaster_id (стабильный Twitch ID), не имя .env-файла.
# Параметр не переименован в сигнатурах эндпоинтов ниже, чтобы не менять
# фронтенд (moderation.js) заодно — это чисто внутренняя точка доступа к БД.
# ---------------------------------------------------------------------------


def _db_path(broadcaster_id: str) -> Path:
    # mod.<broadcaster_id>.db — собственная БД Cigilbot, физически отдельная
    # от bot.db в twitch-bots. Один Twitch-бот-аккаунт обслуживает все
    # каналы сразу, поэтому идентификатор канала (не INSTANCE бота) — ключ
    # выбора файла; broadcaster_id стабилен к переименованию канала, в
    # отличие от login.
    #
    # broadcaster_id приходит сюда напрямую из query-параметра "profile"
    # (или из первого сообщения WebSocket) — safe_segment() (paths.py)
    # защищает от выхода за пределы var/cigilbot/ через разделители пути.
    # Проверка сознательно НЕ белый список формата (числовой Twitch ID) —
    # тесты этого файла используют произвольные строковые суррогаты
    # ("other", "second") как легитимный broadcaster_id, и в api_overview
    # значение приходит уже из Channel Registry (доверенный источник), не
    # только из запроса.
    try:
        return ROOT / f"mod.{safe_segment(broadcaster_id)}.db"
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"Некорректный profile/broadcaster_id: {broadcaster_id!r}"
        ) from exc


async def _open_store(broadcaster_id: str) -> ModerationStore:
    path = _db_path(broadcaster_id)
    if not path.exists():
        raise HTTPException(
            status_code=404, detail=f"БД канала {broadcaster_id!r} ещё не создана"
        )
    store = ModerationStore(str(path))
    await store.connect()
    return store


async def _open_or_create_store(broadcaster_id: str) -> ModerationStore:
    """Как _open_store, но создаёт mod.<broadcaster_id>.db, если файла ещё
    нет — только для настроек автоклипа (autoclip_settings ниже). В отличие
    от остальных эндпоинтов этого роутера, автоклип НЕ требует, чтобы на
    канале хоть раз стартовала модерация (MODERATION_ENABLED может быть
    выключен, автоклип — независимая фича, см. bot/autoclip.py); 404 здесь
    заставил бы включать модерацию только ради того, чтобы завести файл БД
    под настройку, к модерации не относящуюся. ModerationStore.connect()
    сам создаёт файл и прогоняет миграции с нуля (aiosqlite.connect на
    несуществующий путь создаёт файл — штатное поведение sqlite)."""
    store = ModerationStore(str(_db_path(broadcaster_id)))
    await store.connect()
    return store


# ---------------------------------------------------------------------------
# Профили — список каналов, известных Channel Registry (registry.db). Поле
# "profile" в ответе — теперь broadcaster_id (см. комментарий выше), не
# сохранён под старым именем ради совместимости фронтенда без переписывания.
# ---------------------------------------------------------------------------


@router.get("/profiles")
async def api_profiles(
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, str]]:
    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        channels = await registry.list_channels(status=None)
    finally:
        await registry.close()
    return [{"profile": c.broadcaster_id, "channel": c.login} for c in channels]


# ---------------------------------------------------------------------------
# Чтение: кластеры, лента вердиктов, аудит
# ---------------------------------------------------------------------------


@router.get("/overview")
async def api_overview(
    hours: float = 24.0,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    """Operator Home (направление 06 master-plan.html): KPI across всех
    каналов Registry, карточка на канал, лента последних алертов — одним
    запросом вместо N, как раньше делал loadChannels() в JS (attack_mode
    дёргался отдельно на каждый профиль).

    Алерт-лента строится из mod_clusters (created_at, статус active), не из
    отдельного лога — своей таблицы для истории алертов нет, а отправленные
    в Discord алерты (cigilbot/alerts.py::send_cluster_alert) триггерятся
    на то же событие "новый кластер"."""
    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        channels = await registry.list_channels(status=None)
    finally:
        await registry.close()

    since = time.time() - hours * 3600
    channel_cards: list[dict[str, object]] = []
    alerts: list[dict[str, object]] = []
    total_new_clusters = 0
    total_would_timeout = 0
    total_would_ban = 0
    total_messages = 0

    for c in channels:
        path = _db_path(c.broadcaster_id)
        if not path.exists():
            channel_cards.append(
                {
                    "profile": c.broadcaster_id,
                    "channel": c.login,
                    "status": "offline",
                    "active_clusters": 0,
                    "new_clusters": 0,
                    "would_timeout": 0,
                    "would_ban": 0,
                }
            )
            continue
        store = ModerationStore(str(path))
        await store.connect()
        try:
            digest = await store.get_digest_stats(since=since)
            active_clusters = await store.get_active_clusters(limit=5)
            attack = await store.get_active_attack_mode()
        finally:
            await store.close()

        total_new_clusters += digest.new_clusters
        total_would_timeout += digest.would_timeout
        total_would_ban += digest.would_ban
        total_messages += digest.total_messages

        status = "attack" if attack is not None else ("live" if active_clusters else "idle")
        channel_cards.append(
            {
                "profile": c.broadcaster_id,
                "channel": c.login,
                "status": status,
                "active_clusters": len(active_clusters),
                "new_clusters": digest.new_clusters,
                "would_timeout": digest.would_timeout,
                "would_ban": digest.would_ban,
            }
        )

        for cluster in active_clusters:
            alerts.append(
                {
                    "channel": c.login,
                    "profile": c.broadcaster_id,
                    "cluster_id": cluster["id"],
                    "created_at": cluster["created_at"],
                    "size": cluster["size"],
                    "risk_score": cluster["risk_score"],
                }
            )

    alerts.sort(key=lambda a: a["created_at"], reverse=True)  # type: ignore[arg-type,return-value]

    return {
        "kpi": {
            "channels_connected": len(channels),
            "new_clusters": total_new_clusters,
            "would_timeout": total_would_timeout,
            "would_ban": total_would_ban,
            "total_messages": total_messages,
            "hours": hours,
        },
        "channels": channel_cards,
        "alerts": alerts[:20],
    }


@router.get("/clusters")
async def api_clusters(
    request: Request,
    profile: str = "main",
    limit: int = 50,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    # MODERATOR, не VIEWER: ники подозреваемых в спаме и risk_score
    # конкретных людей — не публичная информация. Обычный зритель, вошедший
    # через Twitch без модераторских прав, не должен видеть чужие данные
    # только по факту входа (2026-08-15, решение по итогам UX-аудита панели —
    # см. тот же сдвиг VIEWER->MODERATOR на всех "личных данных" ручках ниже).
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.get_active_clusters(limit=limit)
    finally:
        await store.close()


@router.get("/verdicts")
async def api_verdicts(
    request: Request,
    profile: str = "main",
    min_risk: int = 30,
    limit: int = 100,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.get_recent_verdicts(min_risk_level=min_risk, limit=limit)
    finally:
        await store.close()


@router.get("/audit")
async def api_audit(
    request: Request,
    profile: str = "main",
    limit: int = 100,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.get_action_audit(limit=limit)
    finally:
        await store.close()


@router.get("/users")
async def api_list_users(
    request: Request,
    profile: str = "main",
    search: str = "",
    limit: int = 100,
    offset: int = 0,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.list_users(search=search, limit=limit, offset=offset)
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# Paste Wipe — ручная зачистка волны копипасты (пользователь 2026-08-13:
# сценарий "стример недоволен, что весь чат кидает одну и ту же пасту").
# Модератор вставляет образец текста, панель показывает превью найденных
# совпадений за окно поиска, дальше исполнение идёт через уже существующий
# /actions с action="TIMEOUT" и списком найденных user_id — отдельного
# execute-эндпоинта нет специально, чтобы не дублировать логику постановки
# в очередь/аудита, которая уже есть в api_enqueue_action.
# ---------------------------------------------------------------------------

PASTE_WAVE_WINDOW_SECONDS = 120.0


@router.get("/recent_messages")
async def api_list_recent_messages(
    request: Request,
    profile: str = "main",
    limit: int = 15,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    """Последние сообщения чата для клика "вставить как образец пасты"
    (см. store.list_recent_messages — избегает ручного копирования из
    внешнего чат-виджета, которое цепляло мусор вроде ника)."""
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.list_recent_messages(limit=limit)
    finally:
        await store.close()


@router.get("/paste_wave")
async def api_find_paste_wave(
    request: Request,
    sample_text: str,
    profile: str = "main",
    window_seconds: float = PASTE_WAVE_WINDOW_SECONDS,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    require_role(await role_for_profile(request, profile), "MODERATOR")
    if not sample_text.strip():
        raise HTTPException(status_code=400, detail="Введите текст пасты для поиска")
    store = await _open_store(profile)
    try:
        return await store.find_paste_wave(sample_text=sample_text, window_seconds=window_seconds)
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# Роли панели
# ---------------------------------------------------------------------------


class SetRoleRequest(BaseModel):
    profile: str = "main"
    login: str
    role: str


@router.get("/panel_users")
async def api_panel_users(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    # ADMIN, не VIEWER: список ADMIN/OWNER-логинов канала — разведочная
    # информация (см. security-аудит), нет причин показывать её ниже роли,
    # которая и так может им управлять.
    require_role(await role_for_profile(request, profile), "ADMIN")
    store = await _open_store(profile)
    try:
        return await store.list_panel_users()
    finally:
        await store.close()


@router.post("/panel_users")
async def api_set_panel_user(
    request: Request,
    payload: SetRoleRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    # Роль на КОНКРЕТНОМ канале payload.profile, не общая роль сессии —
    # раньше здесь читался caller_role из session (роль на канале самой
    # панели), что позволяло ADMIN одного канала назначать роли на любом
    # другом канале, лишь бы знать его broadcaster_id (см. security-аудит,
    # находка BFLA). Тот же паттерн, что везде в этом роутере ниже.
    caller_role = await role_for_profile(request, payload.profile)
    require_role(caller_role, "ADMIN")

    new_role = payload.role.upper()
    if new_role not in _ROLE_RANK:
        raise HTTPException(status_code=400, detail=f"Неизвестная роль: {payload.role!r}")
    # Только OWNER может выдавать роль OWNER — иначе ADMIN мог бы сам себя
    # повысить до высшей роли.
    if new_role == "OWNER":
        require_role(caller_role, "OWNER")

    store = await _open_store(payload.profile)
    try:
        await store.upsert_panel_user(payload.login, new_role)
    finally:
        await store.close()
    return {"login": payload.login.lower(), "role": new_role}


# ---------------------------------------------------------------------------
# Действия: ставят задание в очередь, которую поллит executor.py в
# процессе бота (см. докстринг модуля). Требуют роль MODERATOR+.
#
# BUG-001 аудита: раньше target_user_ids принимался от клиента как есть —
# браузер мог прислать любой список user_id под любым cluster_id, и
# executor.py банил ровно его, никогда не сверяя со фактическим составом
# mod_cluster_members. Это делало возможным как минимум баг ("модератор
# видел устаревший снимок кластера, забанил не тех"), так и потенциальную
# эксплуатацию (клиент диктует, кого банить, независимо от того, что решил
# детектор). Теперь для BAN/TIMEOUT с указанным cluster_id сервер САМ
# подставляет актуальный список участников из БД — то, что прислал клиент в
# target_user_ids для такого запроса, полностью игнорируется.
# ---------------------------------------------------------------------------

# SEC-002 аудита: без верхнего предела на размер ручного массового действия
# один запрос мог адресовать сколь угодно много пользователей — потенциальный
# DoS через executor (последовательные запросы к Helix) и просто риск огромной
# ошибки одним кликом. Значение с запасом больше типичного размера кластера
# (десятки), но не позволяет случайно/умышленно адресовать тысячи.
MAX_MANUAL_BULK_TARGETS = 200


class ActionRequestBody(BaseModel):
    profile: str = "main"
    action: str
    target_user_ids: list[str] = []
    message_ids: list[str] = []
    reason: str = ""
    duration_seconds: int | None = None
    cluster_id: int | None = None


@router.post("/actions")
async def api_enqueue_action(
    request: Request,
    payload: ActionRequestBody,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, actor = session
    role = await role_for_profile(request, payload.profile)
    require_role(role, "MODERATOR")

    store = await _open_store(payload.profile)
    try:
        target_user_ids = payload.target_user_ids
        if payload.cluster_id is not None and payload.action in ("BAN", "TIMEOUT"):
            # Источник правды — БД на момент исполнения, не то, что клиент
            # запомнил при рендере карточки кластера (тот снимок мог устареть
            # за то время, пока модератор читал модалку подтверждения).
            current_members = await store.get_cluster_member_ids(payload.cluster_id)
            if not current_members:
                raise HTTPException(
                    status_code=404,
                    detail=f"Кластер #{payload.cluster_id} не найден или пуст — "
                    "возможно, уже обработан или устарел",
                )
            target_user_ids = current_members

        if len(target_user_ids) > MAX_MANUAL_BULK_TARGETS:
            raise HTTPException(
                status_code=400,
                detail=f"Слишком много целей за одно действие: {len(target_user_ids)} "
                f"(максимум {MAX_MANUAL_BULK_TARGETS})",
            )

        raw = {
            "action": payload.action,
            "target_user_ids": target_user_ids,
            "message_ids": payload.message_ids,
            "reason": payload.reason,
            "duration_seconds": payload.duration_seconds,
            "cluster_id": payload.cluster_id,
        }
        try:
            parse_payload(raw)  # валидируем ДО записи в очередь — понятная ошибка сразу
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        queue_id = await store.enqueue_action(
            requested_by=actor, requested_role=role, payload=raw
        )
        if payload.cluster_id is not None:
            # BAN ALL/TIMEOUT ALL с этого кластера — он обработан, больше не
            # должен маячить на главном экране как "активный".
            await store.set_cluster_status(payload.cluster_id, "actioned")
    finally:
        await store.close()
    return {"queue_id": queue_id, "status": "pending", "target_count": len(target_user_ids)}


class ClusterDecisionRequest(BaseModel):
    profile: str = "main"


@router.post("/clusters/{cluster_id}/ignore")
async def api_ignore_cluster(
    request: Request,
    cluster_id: int,
    payload: ClusterDecisionRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")
    store = await _open_store(payload.profile)
    try:
        await store.set_cluster_status(cluster_id, "ignored")
    finally:
        await store.close()
    return {"cluster_id": cluster_id, "status": "ignored"}


@router.post("/clusters/{cluster_id}/mark_safe")
async def api_mark_safe_cluster(
    request: Request,
    cluster_id: int,
    payload: ClusterDecisionRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")
    store = await _open_store(payload.profile)
    try:
        await store.set_cluster_status(cluster_id, "marked_safe")
    finally:
        await store.close()
    return {"cluster_id": cluster_id, "status": "marked_safe"}


# ---------------------------------------------------------------------------
# Доверенные пользователи (этап 9a). Отдельно от clusters/{id}/mark_safe
# выше: та ручка помечает АРХИВНЫЙ статус конкретного кластера ("этот
# инцидент был безопасен"), эта — самого ПОЛЬЗОВАТЕЛЯ на будущее
# (UserState.marked_safe -> policy.is_protected, применяется ко всем его
# будущим сообщениям, не только к этому кластеру).
# ---------------------------------------------------------------------------


class MarkUserSafeRequest(BaseModel):
    profile: str = "main"
    reason: str = ""


@router.post("/users/{user_id}/mark_safe")
async def api_mark_user_safe(
    request: Request,
    user_id: str,
    payload: MarkUserSafeRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")
    store = await _open_store(payload.profile)
    try:
        await store.mark_trusted(user_id, added_by=login, reason=payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    finally:
        await store.close()
    return {"user_id": user_id, "trusted": True}


@router.post("/users/{user_id}/unmark_safe")
async def api_unmark_user_safe(
    request: Request,
    user_id: str,
    payload: MarkUserSafeRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")
    store = await _open_store(payload.profile)
    try:
        await store.unmark_trusted(user_id)
    finally:
        await store.close()
    return {"user_id": user_id, "trusted": False}


@router.get("/trusted")
async def api_list_trusted(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.list_trusted()
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# Bot Pattern Library (этап 9b). REST готов раньше отдельного экрана
# Patterns в панели (см. план) — им уже можно пользоваться через API или
# заполнить конфигом/скриптом, UI подключится позже.
# ---------------------------------------------------------------------------


class PatternRequest(BaseModel):
    profile: str = "main"
    name: str
    description: str = ""
    required_signal_names: list[str] = []
    min_families: int = 0
    min_risk_score: int = 0
    min_confidence: float = 0.0
    min_cluster_size: int = 0
    enabled: bool = True
    auto_enabled: bool = False
    weight: float = 1.0


@router.get("/patterns")
async def api_list_patterns(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    # MODERATOR: точные пороги (min_risk_score, required_signal_names) — это
    # инструкция "как не попасться" для того, кто читает список.
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        patterns = await store.list_patterns()
    finally:
        await store.close()
    return [
        {
            "id": p.id, "name": p.name, "description": p.description,
            "required_signal_names": list(p.required_signal_names),
            "min_families": p.min_families, "min_risk_score": p.min_risk_score,
            "min_confidence": p.min_confidence, "min_cluster_size": p.min_cluster_size,
            "enabled": p.enabled, "auto_enabled": p.auto_enabled, "weight": p.weight,
            "created_by": p.created_by, "created_at": p.created_at,
        }
        for p in patterns
    ]


@router.post("/patterns")
async def api_create_pattern(
    request: Request,
    payload: PatternRequest, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        pattern_id = await store.create_pattern(
            PatternInput(
                name=payload.name,
                description=payload.description,
                required_signal_names=tuple(payload.required_signal_names),
                min_families=payload.min_families,
                min_risk_score=payload.min_risk_score,
                min_confidence=payload.min_confidence,
                min_cluster_size=payload.min_cluster_size,
                enabled=payload.enabled,
                auto_enabled=payload.auto_enabled,
                weight=payload.weight,
                created_by=login,
            )
        )
    finally:
        await store.close()
    return {"id": pattern_id}


class SetPatternEnabledRequest(BaseModel):
    profile: str = "main"
    enabled: bool


@router.post("/patterns/{pattern_id}/enabled")
async def api_set_pattern_enabled(
    request: Request,
    pattern_id: int,
    payload: SetPatternEnabledRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.set_pattern_enabled(pattern_id, payload.enabled)
    finally:
        await store.close()
    return {"id": pattern_id, "enabled": payload.enabled}


class DeletePatternRequest(BaseModel):
    profile: str = "main"


@router.post("/patterns/{pattern_id}/delete")
async def api_delete_pattern(
    request: Request,
    pattern_id: int,
    payload: DeletePatternRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.delete_pattern(pattern_id)
    finally:
        await store.close()
    return {"id": pattern_id, "deleted": True}


# ---------------------------------------------------------------------------
# Content Rules — словарный детектор (Rule Engine, cigilbot/content/).
#
# РЕЖИМ НАБЛЮДАТЕЛЯ: content_moderation_enabled управляет только тем, что
# записывает content_policy.decide_content() в аудит (mod_content_events) —
# executor.py ничего из этого не читает и не исполняет ни при каком
# значении переключателя (см. ModerationEngine._check_content). Включение
# здесь не запускает реальные таймауты/баны сейчас; когда это изменится,
# понадобится отдельная явная фича, не флаг ниже.
#
# Синхронизация с движком, как у Pattern Library/Attack Mode — панель не
# имеет прямого доступа к запущенному движку (отдельный процесс), поэтому
# reload_content_rules()/sync_content_settings() вызывает поллер в
# cigilbot/pipeline.py, не этот роутер.
# ---------------------------------------------------------------------------


class ContentRuleRequest(BaseModel):
    profile: str = "main"
    category: str
    phrase: str


@router.get("/content_rules")
async def api_list_content_rules(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    # MODERATOR: список запрещённых слов/фраз тривиально обходится, если
    # знаешь список — не публичная информация.
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        rules = await store.list_content_rules()
    finally:
        await store.close()
    return [
        {"id": r.id, "category": r.category.value, "phrase": r.phrase, "enabled": r.enabled}
        for r in rules
    ]


@router.post("/content_rules")
async def api_add_content_rule(
    request: Request,
    payload: ContentRuleRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    try:
        category = ContentCategory(payload.category)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Неизвестная категория: {payload.category}") from exc

    store = await _open_store(payload.profile)
    try:
        try:
            rule = await store.add_content_rule(category=category, phrase=payload.phrase, created_by=login)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await store.close()
    return {"id": rule.id, "category": rule.category.value, "phrase": rule.phrase}


class SetContentRuleEnabledRequest(BaseModel):
    profile: str = "main"
    enabled: bool


@router.post("/content_rules/{rule_id}/enabled")
async def api_set_content_rule_enabled(
    request: Request,
    rule_id: int,
    payload: SetContentRuleEnabledRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.set_content_rule_enabled(rule_id, payload.enabled)
    finally:
        await store.close()
    return {"id": rule_id, "enabled": payload.enabled}


class DeleteContentRuleRequest(BaseModel):
    profile: str = "main"


@router.post("/content_rules/{rule_id}/delete")
async def api_delete_content_rule(
    request: Request,
    rule_id: int,
    payload: DeleteContentRuleRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.delete_content_rule(rule_id)
    finally:
        await store.close()
    return {"id": rule_id, "deleted": True}


class SetContentModerationEnabledRequest(BaseModel):
    profile: str = "main"
    enabled: bool


@router.get("/content_settings")
async def api_get_content_settings(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, profile), "VIEWER")
    store = await _open_store(profile)
    try:
        settings = await store.get_content_settings()
    finally:
        await store.close()
    return settings.to_dict()


@router.post("/content_settings")
async def api_set_content_moderation_enabled(
    request: Request,
    payload: SetContentModerationEnabledRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.set_content_moderation_enabled(payload.enabled, updated_by=login)
        settings = await store.get_content_settings()
    finally:
        await store.close()
    return settings.to_dict()


# ---------------------------------------------------------------------------
# Живой рубильник автоклипа (bot/autoclip.py) — тот же принцип, что
# Attack Mode/Content Settings: панель пишет в mod.<broadcaster_id>.db,
# AutoclipHub._reconcile перечитывает раз в RECONCILE_INTERVAL_SECONDS, без
# рестарта бота. Использует _open_or_create_store, не _open_store: автоклип
# не требует, чтобы модерация хоть раз стартовала на этом канале.
# ---------------------------------------------------------------------------


class SetAutoclipEnabledRequest(BaseModel):
    profile: str = "main"
    enabled: bool


@router.get("/autoclip_settings")
async def api_get_autoclip_settings(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    # VIEWER, а не только ADMIN/OWNER (у мутирующей ручки ниже) — но всё
    # равно обязательна: без неё чтение создавало mod.<broadcaster_id>.db
    # для ЛЮБОГО broadcaster_id, включая канал, где у вошедшего нет вообще
    # никакой роли (_open_or_create_store создаёт файл, если его не было).
    require_role(await role_for_profile(request, profile), "VIEWER")
    store = await _open_or_create_store(profile)
    try:
        settings = await store.get_autoclip_settings()
    finally:
        await store.close()
    return settings.to_dict()


@router.post("/autoclip_settings")
async def api_set_autoclip_enabled(
    request: Request,
    payload: SetAutoclipEnabledRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")
    store = await _open_or_create_store(payload.profile)
    try:
        await store.set_autoclip_enabled(payload.enabled, updated_by=login)
        settings = await store.get_autoclip_settings()
    finally:
        await store.close()
    return settings.to_dict()


class SetAutoclipThresholdsRequest(BaseModel):
    """Поля-None означают "не менять этот параметр — вернуться к значению
    из config/channels/<канал>.yml", тот же принцип, что AutoclipSettings.
    Пустая строка в списке фраз недопустима — тот же смысл, что и в
    ContentRuleRequest.phrase (пустая фраза совпала бы с чем угодно)."""

    profile: str = "main"
    burst_unique_authors_threshold: int | None = None
    burst_window_seconds: float | None = None
    keyword_phrases: list[str] | None = None
    voice_phrases: list[str] | None = None
    cooldown_seconds: float | None = None
    capture_delay_seconds: float | None = None


@router.post("/autoclip_settings/thresholds")
async def api_set_autoclip_thresholds(
    request: Request,
    payload: SetAutoclipThresholdsRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")

    if payload.burst_unique_authors_threshold is not None and payload.burst_unique_authors_threshold < 1:
        raise HTTPException(status_code=400, detail="burst_unique_authors_threshold должен быть не меньше 1")
    if payload.burst_window_seconds is not None and payload.burst_window_seconds <= 0:
        raise HTTPException(status_code=400, detail="burst_window_seconds должен быть больше 0")
    if payload.cooldown_seconds is not None and payload.cooldown_seconds < 0:
        raise HTTPException(status_code=400, detail="cooldown_seconds не может быть отрицательным")
    if payload.capture_delay_seconds is not None and payload.capture_delay_seconds < 0:
        raise HTTPException(status_code=400, detail="capture_delay_seconds не может быть отрицательным")
    for phrases in (payload.keyword_phrases, payload.voice_phrases):
        if phrases is not None and any(not p.strip() for p in phrases):
            raise HTTPException(status_code=400, detail="Пустая фраза в списке недопустима")

    store = await _open_or_create_store(payload.profile)
    try:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=payload.burst_unique_authors_threshold,
            burst_window_seconds=payload.burst_window_seconds,
            keyword_phrases=tuple(payload.keyword_phrases) if payload.keyword_phrases is not None else None,
            voice_phrases=tuple(payload.voice_phrases) if payload.voice_phrases is not None else None,
            cooldown_seconds=payload.cooldown_seconds,
            capture_delay_seconds=payload.capture_delay_seconds,
            updated_by=login,
        )
        settings = await store.get_autoclip_settings()
    finally:
        await store.close()
    return settings.to_dict()


class SetAutoclipAutoScaleRequest(BaseModel):
    """percent/minimum/maximum обязательны при enabled=True (формула без
    них не считается) — при enabled=False можно не передавать, тогда
    отправляются как есть (None), потому что порог перестаёт вычисляться."""

    profile: str = "main"
    enabled: bool
    percent: float | None = None
    minimum: int | None = None
    maximum: int | None = None


@router.post("/autoclip_settings/auto_scale")
async def api_set_autoclip_auto_scale(
    request: Request,
    payload: SetAutoclipAutoScaleRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")

    if payload.enabled:
        if payload.percent is None or not (0 < payload.percent <= 1):
            raise HTTPException(status_code=400, detail="percent должен быть в диапазоне (0, 1]")
        if payload.minimum is None or payload.minimum < 1:
            raise HTTPException(status_code=400, detail="minimum должен быть не меньше 1")
        if payload.maximum is None or payload.maximum < payload.minimum:
            raise HTTPException(status_code=400, detail="maximum должен быть не меньше minimum")

    store = await _open_or_create_store(payload.profile)
    try:
        await store.set_autoclip_auto_scale(
            enabled=payload.enabled, percent=payload.percent,
            minimum=payload.minimum, maximum=payload.maximum, updated_by=login,
        )
        settings = await store.get_autoclip_settings()
    finally:
        await store.close()
    return settings.to_dict()


@router.get("/content_events")
async def api_list_content_events(
    request: Request,
    profile: str = "main",
    limit: int = 50,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    """Лента срабатываний словарного детектора для панели — отдельно от
    /verdicts, т.к. content-события не имеют risk_score/confidence/signals
    (см. докстринг миграции 014)."""
    # MODERATOR: конкретные логины и категория нарушения (расизм/угрозы/
    # реклама) — личные данные, не публичная лента.
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.list_content_events(limit=limit)
    finally:
        await store.close()


class MarkContentEventManualActionRequest(BaseModel):
    profile: str = "main"
    action: str


@router.post("/content_events/{event_id}/manual_action")
async def api_mark_content_event_manual_action(
    request: Request,
    event_id: int,
    payload: MarkContentEventManualActionRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    """Пометить строку ленты Content разобранной вручную (пользователь
    2026-08-13: "можем как-то помечать сообщения... более тусклым делать").
    Не исполняет действие само — панель зовёт /actions отдельно, эта
    пометка чисто визуальная, поэтому роль та же, что у /actions (MODERATOR+),
    не строже: если модератору можно нажать TIMEOUT/BAN, ему можно и
    оставить об этом след в ленте."""
    _global_role, actor = session
    role = await role_for_profile(request, payload.profile)
    require_role(role, "MODERATOR")

    if payload.action not in ("TIMEOUT", "BAN", "DELETE_MESSAGES"):
        raise HTTPException(status_code=400, detail=f"Неизвестное действие: {payload.action!r}")

    store = await _open_store(payload.profile)
    try:
        await store.mark_content_event_manual_action(event_id, action=payload.action, actor=actor)
    finally:
        await store.close()
    return {"id": event_id, "manual_action": payload.action}


CONTENT_WS_POLL_INTERVAL_SECONDS = 2.0


@router.websocket("/content_ws")
async def ws_content_events(websocket: WebSocket) -> None:
    """Живая лента срабатываний Rule Engine — отдельный канал от /ws
    (пользователь 2026-08-13: "не хочу смешивать спам атаку и модерацию
    вместе"). Тот же poll-через-WebSocket паттерн, что /ws: клиент
    получает свежий снимок раз в CONTENT_WS_POLL_INTERVAL_SECONDS, а не
    push по событию — сервер не хранит подписчиков между запросами
    (см. ws_moderation), так что новый событийный broadcast не нужен."""
    import asyncio
    import json

    from panel.auth import SESSION_KEY

    if websocket.session.get(SESSION_KEY) is None:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    profile = "main"
    try:
        first = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        if first:
            profile = first.strip() or "main"
    except (TimeoutError, WebSocketDisconnect):
        pass

    # См. ws_moderation — та же дыра (BOLA) была здесь: profile из первого
    # сообщения без проверки роли на канал. MODERATOR, не VIEWER: лента
    # событий содержит конкретные логины и категорию нарушения — те же
    # личные данные, что закрыты на REST GET /content_events (2026-08-15).
    role = await role_for_profile(websocket, profile)
    if _ROLE_RANK[role] < _ROLE_RANK["MODERATOR"]:
        await websocket.close(code=4403)
        return

    try:
        while True:
            path = _db_path(profile)
            if not path.exists():
                await websocket.send_text(json.dumps({"events": []}))
                await asyncio.sleep(CONTENT_WS_POLL_INTERVAL_SECONDS)
                continue

            store = ModerationStore(str(path))
            await store.connect()
            try:
                events = await store.list_content_events(limit=50)
            finally:
                await store.close()

            await websocket.send_text(json.dumps({"events": events}))
            await asyncio.sleep(CONTENT_WS_POLL_INTERVAL_SECONDS)
    except WebSocketDisconnect:
        pass


# ---------------------------------------------------------------------------
# Attack Mode (этап 9c, раздел 11 ТЗ риск #16). Активация требует ADMIN+ —
# выше порог, чем обычные MODERATOR-действия, т.к. снижает пороги
# детекции для ВСЕГО канала, а не для одного кластера/пользователя.
# Движок (engine.py) не подхватывает изменение автоматически — вызывающий
# код (main.py) должен вызвать ModerationEngine.sync_attack_mode() после
# каждого activate/deactivate, аналогично reload_patterns() для Pattern
# Library. Сама панель не имеет прямого доступа к запущенному движку
# (отдельный процесс), поэтому синхронизация — забота main.py/бота,
# не этого роутера.
# ---------------------------------------------------------------------------

DEFAULT_ATTACK_MODE_DURATION_SECONDS = 30 * 60


class ActivateAttackModeRequest(BaseModel):
    profile: str = "main"
    duration_seconds: float = DEFAULT_ATTACK_MODE_DURATION_SECONDS


@router.post("/attack_mode/activate")
async def api_activate_attack_mode(
    request: Request,
    payload: ActivateAttackModeRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    if payload.duration_seconds <= 0:
        raise HTTPException(status_code=400, detail="duration_seconds должен быть положительным")

    store = await _open_store(payload.profile)
    try:
        status = await store.activate_attack_mode(
            activated_by=login, duration_seconds=payload.duration_seconds
        )
    finally:
        await store.close()
    return status.to_dict()


class DeactivateAttackModeRequest(BaseModel):
    profile: str = "main"


@router.post("/attack_mode/deactivate")
async def api_deactivate_attack_mode(
    request: Request,
    payload: DeactivateAttackModeRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.deactivate_attack_mode()
    finally:
        await store.close()
    return {"active": False}


@router.get("/attack_mode")
async def api_get_attack_mode(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, profile), "VIEWER")
    store = await _open_store(profile)
    try:
        status = await store.get_active_attack_mode()
    finally:
        await store.close()
    if status is None:
        return {"active": False}
    return {"active": True, **status.to_dict()}


# ---------------------------------------------------------------------------
# Giveaway Mode (FALSE-BAN-001 аудита). Противоположность Attack Mode —
# СНИЖАЕТ чувствительность детекции на время розыгрыша через
# ChannelContext.is_giveaway (confidence.py context_factor), потому что нет
# технического сигнала, отличающего "100 зрителей написали !giveaway" от
# координированной атаки — оба выглядят как синхронное появление одинакового
# короткого сообщения. Требует ADMIN+ по той же логике, что Attack Mode:
# меняет поведение детекции для всего канала, не для одного кластера.
# ---------------------------------------------------------------------------

DEFAULT_GIVEAWAY_MODE_DURATION_SECONDS = 15 * 60


class ActivateGiveawayModeRequest(BaseModel):
    profile: str = "main"
    duration_seconds: float = DEFAULT_GIVEAWAY_MODE_DURATION_SECONDS


@router.post("/giveaway_mode/activate")
async def api_activate_giveaway_mode(
    request: Request,
    payload: ActivateGiveawayModeRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    if payload.duration_seconds <= 0:
        raise HTTPException(status_code=400, detail="duration_seconds должен быть положительным")

    store = await _open_store(payload.profile)
    try:
        status = await store.activate_giveaway_mode(
            activated_by=login, duration_seconds=payload.duration_seconds
        )
    finally:
        await store.close()
    return status.to_dict()


class DeactivateGiveawayModeRequest(BaseModel):
    profile: str = "main"


@router.post("/giveaway_mode/deactivate")
async def api_deactivate_giveaway_mode(
    request: Request,
    payload: DeactivateGiveawayModeRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    store = await _open_store(payload.profile)
    try:
        await store.deactivate_giveaway_mode()
    finally:
        await store.close()
    return {"active": False}


@router.get("/giveaway_mode")
async def api_get_giveaway_mode(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, profile), "VIEWER")
    store = await _open_store(profile)
    try:
        status = await store.get_active_giveaway_mode()
    finally:
        await store.close()
    if status is None:
        return {"active": False}
    return {"active": True, **status.to_dict()}


# ---------------------------------------------------------------------------
# Discord-webhook (направление 01 master-plan.html). Меняет ADMIN+, той же
# логикой, что Attack/Giveaway Mode — влияет на весь канал, не на один
# кластер. GET маскирует url (как токены в Settings): читающий видит, что
# webhook настроен и на что похож, но не может скопировать его целиком из
# ответа API — сам адрес секрет ровно в том же смысле, что API-ключ.
# ---------------------------------------------------------------------------

_WEBHOOK_VISIBLE_SUFFIX = 6


def _mask_webhook_url(url: str) -> str:
    if len(url) <= _WEBHOOK_VISIBLE_SUFFIX:
        return "•" * len(url)
    return "•" * (len(url) - _WEBHOOK_VISIBLE_SUFFIX) + url[-_WEBHOOK_VISIBLE_SUFFIX:]


class SetDiscordWebhookRequest(BaseModel):
    profile: str = "main"
    url: str
    enabled: bool = True


@router.post("/discord_webhook")
async def api_set_discord_webhook(
    request: Request,
    payload: SetDiscordWebhookRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    if payload.enabled and not payload.url.startswith("https://discord.com/api/webhooks/"):
        raise HTTPException(
            status_code=400,
            detail="Неверный адрес — Discord-webhook начинается с https://discord.com/api/webhooks/",
        )

    store = await _open_store(payload.profile)
    try:
        config = await store.set_discord_webhook(
            url=payload.url, enabled=payload.enabled, updated_by=login
        )
    finally:
        await store.close()
    return {**config.to_dict(), "url": _mask_webhook_url(config.url)}


@router.get("/discord_webhook")
async def api_get_discord_webhook(
    request: Request,
    profile: str = "main",
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    require_role(await role_for_profile(request, profile), "VIEWER")
    store = await _open_store(profile)
    try:
        config = await store.get_discord_webhook()
    finally:
        await store.close()
    if config is None:
        return {"configured": False}
    return {"configured": True, **config.to_dict(), "url": _mask_webhook_url(config.url)}


class SetAlertThresholdRequest(BaseModel):
    profile: str = "main"
    threshold: float


@router.post("/discord_webhook/alert_threshold")
async def api_set_alert_threshold(
    request: Request,
    payload: SetAlertThresholdRequest,
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    """Порог confidence, выше которого новый кластер шлёт Discord-алерт —
    настраивается отдельно от самого webhook (адрес и чувствительность
    меняются независимо, см. store.set_alert_confidence_threshold)."""
    require_role(await role_for_profile(request, payload.profile), "ADMIN")
    if not 0.0 <= payload.threshold <= 1.0:
        raise HTTPException(status_code=400, detail="Порог должен быть от 0 до 1")

    store = await _open_store(payload.profile)
    try:
        try:
            await store.set_alert_confidence_threshold(threshold=payload.threshold)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        config = await store.get_discord_webhook()
    finally:
        await store.close()
    assert config is not None
    return {**config.to_dict(), "url": _mask_webhook_url(config.url)}


# ---------------------------------------------------------------------------
# Feedback loop / FP-статистика (этап 9d). Отдельно от clusters/{id}/mark_safe
# и clusters/{id}/ignore из этапа 8: те архивируют кластер, эта ручка учит
# систему — снижает confidence конкретного СИГНАЛА на будущее через
# mod_feedback -> engine.py: reload_fp_penalties() (см. main.py поллер).
# ---------------------------------------------------------------------------


class FeedbackRequest(BaseModel):
    profile: str = "main"
    signal_name: str
    decision: str
    verdict_id: int | None = None
    cluster_id: int | None = None
    user_id: str | None = None
    pattern_id: int | None = None


_VALID_FEEDBACK_DECISIONS = {"FALSE_POSITIVE", "CONFIRMED_BOT"}


@router.post("/feedback")
async def api_record_feedback(
    request: Request,
    payload: FeedbackRequest, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    _global_role, login = session
    require_role(await role_for_profile(request, payload.profile), "MODERATOR")
    if payload.decision not in _VALID_FEEDBACK_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"decision должен быть одним из {sorted(_VALID_FEEDBACK_DECISIONS)}",
        )

    store = await _open_store(payload.profile)
    try:
        feedback_id = await store.record_feedback(
            signal_name=payload.signal_name,
            moderator=login,
            decision=payload.decision,
            verdict_id=payload.verdict_id,
            cluster_id=payload.cluster_id,
            user_id=payload.user_id,
            pattern_id=payload.pattern_id,
        )
    finally:
        await store.close()
    return {"id": feedback_id}


@router.get("/feedback")
async def api_list_feedback(
    request: Request,
    profile: str = "main",
    limit: int = 100,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    # MODERATOR: запись фидбека содержит user_id конкретного зрителя.
    require_role(await role_for_profile(request, profile), "MODERATOR")
    store = await _open_store(profile)
    try:
        return await store.list_feedback(limit=limit)
    finally:
        await store.close()


@router.get("/stats/daily")
async def api_get_daily_stats(
    request: Request,
    profile: str = "main",
    days: int = 30,
    session: tuple[str, str] = Depends(require_authenticated),
) -> list[dict[str, object]]:
    # Единственная VIEWER-ручка в этом файле, которую стоит оставить открытой
    # намеренно (2026-08-15): агрегированная статистика по дням без личных
    # данных — кандидат на будущий публичный экран статистики для зрителей.
    require_role(await role_for_profile(request, profile), "VIEWER")
    store = await _open_store(profile)
    try:
        return await store.get_daily_stats(days=days)
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# Settings (экран Settings панели). config/moderation.yml — общий на все
# профили бота (не за каждый профиль отдельно, как БД), поэтому без
# параметра profile, в отличие от остальных эндпоинтов этого роутера.
# Конфиг движка читается ОДИН РАЗ при старте бота (main.py) — сохранение
# отсюда меняет файл на диске, но применится только после рестарта бота;
# hot-reload конфига сознательно не делается — отдельная, более рискованная
# фича (веса/пороги детекции меняются "на лету" под живым трафиком), не
# входит в объём "довести панель до готовности к тестированию".
# ---------------------------------------------------------------------------

from cigilbot.domain.config import ConfigError, load_config  # noqa: E402


def _config_path() -> Path:
    # SRC_ROOT, а не ROOT: moderation.yml — конфиг под git, он лежит с
    # исходниками, тогда как ROOT указывает на var/ с рабочим состоянием.
    # Пока панель жила внутри Cigilbot, это был один и тот же каталог.
    #
    # Вычисляется на каждый вызов (не константа при импорте модуля) — тесты
    # подменяют SRC_ROOT через monkeypatch.setattr(moderation_api, ...),
    # как и остальной модуль (см. _db_path выше).
    return SRC_ROOT / "config" / "moderation.yml"


class ConfigSaveRequest(BaseModel):
    yaml_text: str


@router.get("/config")
async def api_get_config(
    session: tuple[str, str] = Depends(require_authenticated),
) -> dict[str, object]:
    # MODERATOR+, не просто require_authenticated — в отличие от остальных
    # GET-ручек этого роутера (все проходят per-channel role_for_profile),
    # эта была защищена только фактом входа, без минимальной роли вовсе:
    # любой VIEWER на любом канале мог прочитать полные веса/пороги
    # детекторов (MIN_FAMILIES_FOR_BAN, confidence.minimum_for_ban и т.д.),
    # что при координированной атаке помогает подбирать поведение ниже
    # порогов срабатывания. Запись (api_save_config ниже) уже требует
    # ADMIN — асимметрия чтение/запись не была оправдана характером данных
    # (security-аудит 2026-08-15, MEDIUM #12).
    role, _login = session
    require_role(role, "MODERATOR")

    path = _config_path()
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{path} не найден")
    text = path.read_text(encoding="utf-8")
    try:
        cfg = load_config(path)
        parse_error = None
    except ConfigError as exc:
        cfg = None
        parse_error = str(exc)

    return {
        "yaml_text": text,
        "parse_error": parse_error,
        "mode": cfg.sensitivity.value if cfg else None,
        "risk_thresholds": (
            {"observe": cfg.risk.observe, "timeout": cfg.risk.timeout, "ban": cfg.risk.ban}
            if cfg
            else None
        ),
    }


@router.post("/config")
async def api_save_config(
    payload: ConfigSaveRequest, session: tuple[str, str] = Depends(require_authenticated)
) -> dict[str, object]:
    role, _login = session
    require_role(role, "ADMIN")

    path = _config_path()
    # Валидация ДО записи на диск — тот же принцип, что api_enqueue_action:
    # понятная ошибка сразу, а не побитый YAML, который уронит бота при
    # следующем перезапуске.
    tmp_path = path.with_suffix(".yml.tmp-validate")
    tmp_path.write_text(payload.yaml_text, encoding="utf-8")
    try:
        load_config(tmp_path)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=f"Конфиг некорректен: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    path.write_text(payload.yaml_text, encoding="utf-8")
    return {"ok": True, "restart_required": True}


# ---------------------------------------------------------------------------
# Live-обновления. При атаке важна задержка в секундах, не десятках секунд
# polling'а — поэтому WebSocket, а не GET раз в N секунд (раздел 7 плана).
# ---------------------------------------------------------------------------

WS_POLL_INTERVAL_SECONDS = 2.0


@router.websocket("/ws")
async def ws_moderation(websocket: WebSocket) -> None:
    import asyncio
    import json

    from panel.auth import SESSION_KEY

    if websocket.session.get(SESSION_KEY) is None:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    profile = "main"
    try:
        first = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        if first:
            profile = first.strip() or "main"
    except (TimeoutError, WebSocketDisconnect):
        pass

    # Раньше здесь проверялось только "залогинен ли вообще" (SESSION_KEY
    # выше) — profile из первого сообщения клиента открывал БД любого
    # канала без проверки, что у вошедшего есть на него хоть какая-то
    # роль (см. security-аудит, BOLA). role_for_profile принимает
    # HTTPConnection — WebSocket ей подходит так же, как Request.
    # MODERATOR, не VIEWER: clusters/verdicts — ники подозреваемых и
    # risk_score конкретных людей, те же личные данные, что закрыты на
    # REST GET /clusters, /verdicts (2026-08-15).
    role = await role_for_profile(websocket, profile)
    if _ROLE_RANK[role] < _ROLE_RANK["MODERATOR"]:
        await websocket.close(code=4403)
        return

    try:
        while True:
            path = _db_path(profile)
            if not path.exists():
                await websocket.send_text(json.dumps({"clusters": [], "verdicts": []}))
                await asyncio.sleep(WS_POLL_INTERVAL_SECONDS)
                continue

            store = ModerationStore(str(path))
            await store.connect()
            try:
                clusters = await store.get_active_clusters(limit=50)
                verdicts = await store.get_recent_verdicts(min_risk_level=30, limit=30)
            finally:
                await store.close()

            await websocket.send_text(json.dumps({"clusters": clusters, "verdicts": verdicts}))
            await asyncio.sleep(WS_POLL_INTERVAL_SECONDS)
    except WebSocketDisconnect:
        pass
