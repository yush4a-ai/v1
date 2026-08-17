"""Общие фикстуры для тестов роутера panel/moderation_api.py.

app_client — анонимный TestClient (без сессии, как только что открывший
страницу браузер). login_as(client, role, login) — единственный способ
получить аутентифицированный клиент: реальный Twitch OAuth в тестах не
проходим (нет сети), поэтому тестовое приложение поднимает отдельный
/test/set_session эндпоинт, который пишет request.session напрямую —
он существует ТОЛЬКО в тестовом app, panel/server.py его не подключает.
Это эквивалент результата panel/auth.py::auth_callback после успешного
входа, без похода на настоящий Twitch.

app_client собирается через panel.server.create_app(), а не вручную
(bug-аудит 2026-08-15, HIGH) — раньше тестовое приложение строилось здесь
отдельным, более коротким списком app.add_...() и молча разошлось с
продакшеном: без SlowAPIMiddleware, без ValueError-обработчика, без
реальных настроек сессии. Rate limiting (весь panel/rate_limit.py) и
12-часовой TTL сессии из-за этого не были защищены тестами вообще.
create_app(roots) собирает ТУ ЖЕ форму приложения, что и продакшен —
разница только в путях (roots указывает на tmp-папку).

ROOT подменён на временную папку: свой registry.db (один канал с
DEFAULT_TEST_CHANNEL/DEFAULT_TEST_BROADCASTER_ID) и своя mod.<broadcaster_id>.db
с применёнными миграциями, изолированные от настоящего проекта — источник
правды сменился с .env.<profile> на Channel Registry (см.
docs/master-plan.html, направление 00). bots_api.ROOT/VAR подменены тем же
приёмом — create_app() теперь подключает и bots_router, а не только
moderation_router, как раньше здесь вручную.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

import panel.bots_api as bots_api
import panel.moderation_api as moderation_api
import panel.registry_api as registry_api
from cigilbot.storage.registry_store import RegistryStore
from cigilbot.storage.store import ModerationStore
from panel.auth import SESSION_KEY, _list_profile_channels
from panel.server import create_app
from paths import PanelRoots

# Канал тестового профиля — нужен для по-канальных ролей (role_for_profile
# резолвит broadcaster_id -> channel через Registry, см. panel/auth.py).
# Значение произвольное, важно только что оно единообразно между
# tmp_root и login_as (см. DEFAULT_TEST_CHANNEL ниже).
#
# DEFAULT_TEST_BROADCASTER_ID = "main" (а не реалистичный числовой Twitch
# ID) — намеренно: подавляющее большинство тестов в test_moderation_api.py
# зовут эндпоинты БЕЗ явного параметра profile, полагаясь на дефолт
# `profile: str = "main"` в panel/moderation_api.py. Значение здесь должно
# совпасть с этим дефолтом, иначе пришлось бы явно передавать profile=...
# в ~90 мест теста ради значения, которое нигде за пределами тестов не
# должно быть валидным broadcaster_id (в проде broadcaster_id всегда
# числовая строка от Twitch, "main" там появиться не может).
DEFAULT_TEST_CHANNEL = "test_channel"
DEFAULT_TEST_BROADCASTER_ID = "main"


@pytest.fixture
async def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    registry = RegistryStore(str(tmp_path / "registry.db"))
    await registry.connect()
    await registry.upsert_channel(
        broadcaster_id=DEFAULT_TEST_BROADCASTER_ID, login=DEFAULT_TEST_CHANNEL, registered_by="manual"
    )
    await registry.close()
    # Разные корни, в проде все разные, в тесте все в одной tmp-папке:
    #   ROOT        — состояние модерации (mod.*.db), var/cigilbot
    #   SRC_ROOT    — исходники (config/moderation.yml), корень проекта
    #   REGISTRY_DB — единственный реестр каналов, var/registry.db
    #   bots_api.ROOT/VAR — исходники/состояние экрана "Боты" (create_app()
    #   теперь подключает и bots_router, не только moderation_router).
    monkeypatch.setattr(moderation_api, "ROOT", tmp_path)
    monkeypatch.setattr(moderation_api, "SRC_ROOT", tmp_path)
    monkeypatch.setattr(moderation_api, "REGISTRY_DB", tmp_path / "registry.db")
    monkeypatch.setattr(registry_api, "REGISTRY_DB", tmp_path / "registry.db")
    monkeypatch.setattr(bots_api, "ROOT", tmp_path)
    monkeypatch.setattr(bots_api, "VAR", tmp_path)
    return tmp_path


@pytest.fixture
async def db_path(tmp_root: Path) -> Path:
    path = tmp_root / f"mod.{DEFAULT_TEST_BROADCASTER_ID}.db"
    store = ModerationStore(str(path))
    await store.connect()
    await store.close()
    return path


@pytest.fixture
def app_client(db_path: Path, tmp_root: Path) -> TestClient:
    # create_app() — та же форма приложения, что и продакшен (server.py):
    # SlowAPIMiddleware, ValueError-обработчик, реальные настройки сессии,
    # все роутеры (bug-аудит 2026-08-15, HIGH — см. докстринг файла).
    #
    # all_at: в проде корни разные — исходники и .env в корне проекта,
    # registry.db в var/ — а здесь оба указывают в одну tmp-папку.
    app = create_app(PanelRoots.all_at(tmp_root))

    @app.post("/test/set_session")
    async def _set_session(request: Request, role: str, login: str = "test_user") -> dict[str, str]:
        # {"roles": {channel: role}} — формат, который реально пишет
        # panel/auth.py::auth_callback после входа через Twitch (роли
        # по-канальные, см. _resolve_roles_by_channel). "role" верхнего
        # уровня оставлен для обратной совместимости с local читателями
        # общей роли (auth_me и т.п.), не с проверками прав на действия.
        #
        # ADMIN/OWNER — глобальный оверрайд в реальном коде (admin_override
        # применяется к КАЖДОМУ каналу одинаково, см. _resolve_roles_by_channel),
        # не по-канальный статус — иначе тестовый login_as(..., "ADMIN")
        # проверял бы поведение, которого прод не имеет: настоящий ADMIN
        # властен на любом профиле, не только на "своём". MODERATOR/VIEWER,
        # наоборот, приходят из Twitch-статуса за конкретный канал, поэтому
        # остаются привязаны только к DEFAULT_TEST_CHANNEL.
        if role in ("ADMIN", "OWNER"):
            roles = dict.fromkeys(
                (await _list_profile_channels(PanelRoots.all_at(moderation_api.ROOT))).values(), role
            )
            roles.setdefault(DEFAULT_TEST_CHANNEL, role)
        else:
            roles = {DEFAULT_TEST_CHANNEL: role}
        request.session[SESSION_KEY] = {
            "login": login,
            "user_id": "1",
            "role": role,
            "roles": roles,
        }
        return {"ok": "true"}

    return TestClient(app)


def login_as(client: TestClient, role: str, login: str = "test_user") -> TestClient:
    resp = client.post("/test/set_session", params={"role": role, "login": login})
    assert resp.status_code == 200
    return client


@pytest.fixture
async def store(db_path: Path) -> ModerationStore:
    s = ModerationStore(str(db_path))
    await s.connect()
    return s
