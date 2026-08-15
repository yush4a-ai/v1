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

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.sessions import SessionMiddleware

from cigilbot.storage.store import ModerationStore
from panel.auth import load_panel_auth_config
from panel.auth import router as auth_router
from panel.bots_api import router as bots_router
from panel.moderation_api import router as moderation_router
from panel.rate_limit import limiter
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

# Лимитер по IP (panel/rate_limit.py) — до этого ничего не ограничивало
# частоту запросов к /auth/* (OAuth-callback'и, каждый из которых бьёт по
# Twitch API несколькими исходящими запросами) и к /api/chat_send (флуд
# чата от имени бота модератором). app.state.limiter — соглашение slowapi:
# SlowAPIMiddleware и _rate_limit_exceeded_handler читают лимитер отсюда,
# а @limiter.limit(...) в auth.py/bots_api.py декорирует эндпоинты тем же
# объектом напрямую (см. panel/rate_limit.py, см. security-аудит, находка
# Medium).
app.state.limiter = limiter


async def _handle_rate_limit_exceeded(request: Request, exc: Exception) -> Response:
    # Обёртка ради типа: add_exception_handler ждёт Callable[[Request,
    # Exception], ...], а slowapi._rate_limit_exceeded_handler типизирован
    # конкретно под RateLimitExceeded — mypy strict эту частную сигнатуру
    # не принимает без явного каста, хотя runtime-контракт (регистрация
    # обработчика ИМЕННО под RateLimitExceeded строкой ниже) гарантирует,
    # что exc всегда будет этим типом.
    assert isinstance(exc, RateLimitExceeded)
    return _rate_limit_exceeded_handler(request, exc)


app.add_exception_handler(RateLimitExceeded, _handle_rate_limit_exceeded)


async def _handle_bad_path_segment(request: Request, exc: Exception) -> Response:
    # safe_segment() (paths.py) поднимает ValueError, когда profile/name/
    # broadcaster_id из запроса пытается выйти за пределы каталога через
    # разделители пути ("../../secret") — единый обработчик вместо
    # try/except в каждом из ~20 роутов bots_api.py, которые принимают
    # profile напрямую как query/body-параметр (security-аудит 2026-08-15,
    # CRITICAL #1).
    assert isinstance(exc, ValueError)
    return JSONResponse({"error": str(exc)}, status_code=400)


app.add_exception_handler(ValueError, _handle_bad_path_segment)
app.add_middleware(SlowAPIMiddleware)

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

# https_only=True требует, чтобы панель реально была доступна по HTTPS
# (прямая раздача или через прокси/туннель) — иначе браузер отказывается
# ставить cookie вообще и вход ломается. По умолчанию выключено: панель
# эксплуатируется по HTTP на localhost/LAN (security-аудит 2026-08-15,
# HIGH #5) — включать явно через PANEL_SESSION_HTTPS_ONLY=true, когда
# перед панелью действительно стоит HTTPS.
_session_https_only = (
    os.environ.get("PANEL_SESSION_HTTPS_ONLY", "") or _read_own_env("PANEL_SESSION_HTTPS_ONLY")
).strip().lower() == "true"

# 12 часов, не дефолтные 14 дней Starlette — роль (OWNER/MODERATOR/VIEWER)
# пересчитывается только на новый /auth/callback, так что разжалованный на
# самом Twitch модератор оставался бы MODERATOR в панели до истечения
# cookie. Сессии нет server-side revocation (compromise = живёт до
# max_age), поэтому короче — тоже смягчение того же риска, не полное
# закрытие (security-аудит 2026-08-15, HIGH #5).
_SESSION_MAX_AGE_SECONDS = 12 * 3600

app.state.panel_auth_config = _panel_auth_config
app.state.panel_roots = PanelRoots.default()
app.state.moderation_store_factory = lambda: ModerationStore(str(db_path(MAIN_PROFILE)))
app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
    same_site="lax",
    https_only=_session_https_only,
    max_age=_SESSION_MAX_AGE_SECONDS,
)
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
