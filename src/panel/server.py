"""Единственный процесс панели: экран модерации + экран нейроботов.

История этого файла — круг. Сначала /moderation была экраном внутри панели
нейроботов (порт 8765) с общей cookie-сессией. Потом её вынесли в отдельный
процесс на 8766, чтобы двумя продуктами можно было управлять независимо;
ценой стало то, что вход приходилось проходить дважды — порт входит в origin,
и cookie одного процесса не видна другому даже на localhost. Теперь экраны
снова в одном приложении, и вход снова один.

Панель осталась единственным процессом, который не слился ни с чем: движок
модерации переехал внутрь бота (cigilbot/pipeline.py), и в системе теперь
ровно два процесса — бот и эта панель. Панель не считает и не исполняет
ничего сама: пишет desired_state, паттерны и Attack Mode в БД, а читает их
оттуда бот. Это единственная причина, по которой она может падать и
подниматься независимо, не задевая модерацию.

Запуск: ..\\..\\.venv\\Scripts\\python -m panel.server
Откроется на http://localhost:8766/
"""

import hashlib
import os
import secrets
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from cigilbot.storage.store import ModerationStore
from panel.auth import load_panel_auth_config
from panel.auth import router as auth_router
from panel.bots_api import router as bots_router
from panel.moderation_api import router as moderation_router
from panel.registry_api import router as registry_router
from paths import ENV_FILE, MAIN_PROFILE, MOD_DB, MOD_VAR, PanelRoots

STATIC_DIR = Path(__file__).parent / "static"


def db_path(profile: str) -> Path:
    """mod_panel_users (ADMIN-оверрайды ролей) хранится в mod.db Cigilbot.

    Эта же БД теперь обслуживает и экран нейроботов: до слияния он держал
    свой список админов в panel_admins внутри bot.db, и выданный там ADMIN
    не действовал на экране модерации. Победила mod.db — bot.db принадлежит
    боту и пересоздаётся им на каждом старте через executescript без
    версионирования, тогда как здесь есть настоящие миграции."""
    return MOD_VAR / f"mod.{profile}.db" if profile != MAIN_PROFILE else MOD_DB


# lifespan с supervisor'ом отсюда убран. Панель держала фоновую задачу,
# которая поднимала и останавливала consumer-процессы по desired_state
# каналов. Движок модерации теперь живёт в процессе бота и сверяется с
# Registry сам (cigilbot/pipeline.py::ModerationHub), поэтому панели
# следить не за чем: она по-прежнему ПИШЕТ desired_state через
# /api/registry/channels/{id}/start|stop, но исполняет его бот.
#
# Побочный выигрыш: раньше падение панели останавливало restart-on-crash
# для консьюмеров. Теперь модерация не зависит от того, открыта ли панель.
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(moderation_router)
app.include_router(registry_router)
app.include_router(bots_router)


def _read_own_env(key: str) -> str:
    if not ENV_FILE.exists():
        return ""
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}="):
            return stripped.split("=", 1)[1]
    return ""


# Единственный .env на весь монорепо. Раньше их было два — по одному на
# проект, с разными значениями одних и тех же PANEL_TWITCH_* ключей, потому
# что двум процессам на разных портах нужны были разные redirect URI. Порт
# один — приложение Twitch одно — файл один (см. panel/paths.py).
_panel_auth_config = load_panel_auth_config(ENV_FILE.parent)

_session_secret = os.environ.get("PANEL_SESSION_SECRET", "") or _read_own_env("PANEL_SESSION_SECRET")
if not _session_secret:
    # Временный секрет, если вход ещё не настроен — auth_login всё равно
    # отдаст 503 без PANEL_TWITCH_* (см. PanelAuthConfig.configured),
    # роли/действия защищены require_role* независимо от секрета сессии.
    _session_secret = secrets.token_hex(32)

app.state.panel_auth_config = _panel_auth_config
app.state.panel_roots = PanelRoots.default()
app.state.moderation_store_factory = lambda: ModerationStore(str(db_path(MAIN_PROFILE)))
app.add_middleware(SessionMiddleware, secret_key=_session_secret, same_site="lax")
app.include_router(auth_router)


def _static_hash(filename: str) -> str:
    """Короткий хэш содержимого статического файла для cache-busting
    query-параметра (?v=<hash>). Правки в moderation.js/.css без этого
    зависали в HTTP-кэше браузера даже после жёсткой перезагрузки
    (Ctrl+Shift+R), потому что путь /static/moderation.js не менялся —
    браузер валидирует по ETag/Last-Modified, не всегда надёжно на
    localhost. Хэш меняется вместе с содержимым, так что URL меняется
    вместе с ним — старая закэшированная копия просто никогда не
    запрашивается повторно под новым URL."""
    return hashlib.sha256((STATIC_DIR / filename).read_bytes()).hexdigest()[:10]


_STATIC_VERSIONS = {name: _static_hash(name) for name in ("moderation.js",)}


@app.get("/")
@app.get("/moderation")
def moderation_page() -> HTMLResponse:
    html = (STATIC_DIR / "moderation.html").read_text(encoding="utf-8")
    for filename, version in _STATIC_VERSIONS.items():
        html = html.replace(f'src="/static/{filename}"', f'src="/static/{filename}?v={version}"')
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8766)
