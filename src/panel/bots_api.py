"""Экран управления нейроботами — роутер объединённой панели.

Каждый бот — это отдельный "профиль": свой .env.<profile> файл (или корневой
.env для профиля "main"), свои процессы main.py/voice_main.py, своя БД, своя
очередь голоса, свой usage.json. Один физический бот-код (main.py, bot/*)
переиспользуется для всех профилей — их разводит переменная окружения
BOT_ENV_FILE и INSTANCE внутри .env (см. bot/config.py), в точности как
раньше при ручном запуске двух ботов на разные каналы.

Профильная модель здесь сохранена намеренно. Cigilbot отказался от неё в
Phase 1 в пользу Channel Registry, twitch-bots — нет, и слияние панелей эту
разницу не трогало: задача была свести вход и порт в один, а не переделать
то, как заводятся боты (см. CLAUDE.md, "Две сосуществующие модели каналов").

Раньше файл назывался panel/server.py и был самостоятельным приложением на
порту 8765 со своим SessionMiddleware, своим Twitch-приложением и своим
входом. Теперь это роутер внутри panel/server.py на 8766: приложение,
сессия и вход — общие, здесь остались только роуты и логика профилей.
"""

import asyncio
import contextlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

import httpx
import streamlink
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Импортируется здесь, а не в самом низу файла (как раньше), чтобы роуты
# ниже могли требовать сессию/роль через Depends() уже на момент объявления —
# SEC-001: раньше все эндпоинты этого файла (в отличие от panel/moderation_api.py)
# не имели вообще никакой проверки авторизации, потому что require_authenticated
# существовал только "после" них по тексту файла и никогда не подключался.
# panel.auth не импортирует этот модуль (проверено), цикла нет.
import paths
from bot.twitch_helix import HelixResolveError, HelixResolver
from cigilbot.storage.registry_store import RegistryStore
from panel.auth import require_role_min
from panel.rate_limit import limiter
from paths import (
    BOT_VAR,
    MAIN_PROFILE,
    PROMPTS_DIR,
    REGISTRY_DB,
    REPO_ROOT,
    VENV_PYTHON,
    safe_segment,
)

log = logging.getLogger("panel.bots")

# Та же иерархия, что panel/moderation_api.py::_ROLE_RANK и panel/auth.py —
# продублирована здесь намеренно (не импортирована оттуда), тем же приёмом,
# что и в остальных роутерах панели: избегает цикла server.py -> bots_api.py
# -> auth.py -> обратно в server.py.
_ROLE_RANK = {"VIEWER": 0, "MODERATOR": 1, "ADMIN": 2, "OWNER": 3}

# ROOT — корень проекта: .env.<profile>, prompts/, main.py.
# VAR — рабочее состояние бота: bot.db, usage.json, логи, pid.
#
# Раньше это был один `Path(__file__).parent.parent`, означавший сразу и
# корень проекта, и место .env, и место БД. Совпадение развалилось дважды —
# когда панель уехала в отдельный каталог, и когда состояние уехало в var/.
ROOT = REPO_ROOT
VAR = BOT_VAR

CHANNEL_HISTORY_FILE = VAR / "panel_state" / "channel_history.json"
MAX_CHANNEL_HISTORY = 8
PROMPT_HISTORY_DIR = VAR / "panel_state" / "prompt_history"
MAX_PROMPT_HISTORY = 15

# DeepSeek-chat, USD за 1M токенов — грубая оценка без учёта кэш-скидки
PRICE_PER_1M_INPUT_USD = 0.27
PRICE_PER_1M_OUTPUT_USD = 1.10

DEEPSEEK_BALANCE_URL = "https://api.deepseek.com/user/balance"
# Баланс не меняется на лету — кэшируем ответ, чтобы polling с фронта раз в
# 5 сек не долбил DeepSeek API запросами, которые всегда возвращают одно и то же.
BALANCE_CACHE_SECONDS = 60
_balance_cache: dict[str, tuple[float, dict]] = {}

# Бесплатный курс-API без ключа — для показа баланса ещё и в рублях (в
# скобках рядом с исходной валютой). Курсы валют меняются не поминутно,
# так что кэшируем на дольше, чем баланс.
EXCHANGE_RATE_URL = "https://api.exchangerate-api.com/v4/latest/{}"
EXCHANGE_RATE_CACHE_SECONDS = 3600
_rate_cache: dict[str, tuple[float, float | None]] = {}


async def fetch_rub_rate(currency: str) -> float | None:
    """Курс currency -> RUB, или None если не удалось получить."""
    cached = _rate_cache.get(currency)
    if cached and time.monotonic() - cached[0] < EXCHANGE_RATE_CACHE_SECONDS:
        return cached[1]

    rate = None
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(EXCHANGE_RATE_URL.format(currency))
        resp.raise_for_status()
        rate = resp.json().get("rates", {}).get("RUB")
    except (httpx.HTTPError, ValueError):
        pass

    _rate_cache[currency] = (time.monotonic(), rate)
    return rate


# Live/offline статус канала — тот же streamlink, что использует
# TwitchStreamSource в bot/audio_source.py для чтения звука. Запрос к Twitch
# не мгновенный (1-3 сек), поэтому кэшируем и выполняем в отдельном потоке,
# чтобы не блокировать event loop панели.
CHANNEL_STATUS_CACHE_SECONDS = 30
_channel_status_cache: dict[str, tuple[float, bool | None]] = {}


def _check_channel_live_sync(channel: str) -> bool | None:
    try:
        session = streamlink.Streamlink()
        session.set_option("twitch-disable-ads", True)
        streams = session.streams(f"https://twitch.tv/{channel}")
        return bool(streams)
    except Exception:
        return None


async def fetch_channel_live(channel: str) -> dict:
    if not channel:
        return {"channel": "", "live": None}

    cached = _channel_status_cache.get(channel)
    if cached and time.monotonic() - cached[0] < CHANNEL_STATUS_CACHE_SECONDS:
        return {"channel": channel, "live": cached[1]}

    loop = asyncio.get_event_loop()
    live = await loop.run_in_executor(None, _check_channel_live_sync, channel)
    _channel_status_cache[channel] = (time.monotonic(), live)
    return {"channel": channel, "live": live}


class StartStopRequest(BaseModel):
    profile: str = MAIN_PROFILE


class SwitchChannelRequest(BaseModel):
    profile: str
    channel: str


class SavePromptRequest(BaseModel):
    name: str
    personality: str


class ApplyPromptRequest(BaseModel):
    profile: str
    personality: str


class VoiceSettingsRequest(BaseModel):
    profile: str
    voice_silence_threshold: int
    voice_free_reply_cooldown: int
    voice_require_trigger: bool


class StreamerContextRequest(BaseModel):
    profile: str
    streamer_name: str
    streamer_context: str


class SetNoteRequest(BaseModel):
    profile: str
    username: str
    note: str


class SendChatMessageRequest(BaseModel):
    profile: str = MAIN_PROFILE
    channel_login: str
    text: str


class PromptPreviewRequest(BaseModel):
    profile: str
    personality: str
    message: str
    username: str = "тестовый_зритель"


router = APIRouter()


# ---------------------------------------------------------------------------
# Профили: список + путь к .env каждого профиля.
# ---------------------------------------------------------------------------

def _env_file_for(profile: str) -> Path:
    """Профиль "main" читается из КОРНЕВОГО .env монорепо, не из
    .env — после слияния панелей общий конфиг живёт в
    одном файле на весь репозиторий (см. panel/paths.py). Остальные
    профили остались рядом с main.py, как и были.

    safe_segment() — защита от path traversal через profile: без неё
    profile="../../secret" читал/писал произвольный файл на диске
    (в отличие от cigilbot-стороны, paths.mod_db(), эта защита здесь
    отсутствовала до находки в security-аудите 2026-08-15).

    Путь строится от ROOT (переменная модуля), а не от импортированной
    константы paths.ENV_FILE: ROOT — единственное, что подменяют тесты
    (tests/panel/conftest.py), и через ENV_FILE профиль "main" уходил мимо
    подмены в БОЕВОЙ .env разработчика — то есть тест, тронувший профиль
    main, читал (и при записи изменил бы) настоящие ключи. Найдено
    bug-аудитом 2026-08-17, когда временный тест напечатал реальный
    DEEPSEEK_API_KEY. Тот же приём и та же причина, что у
    moderation_api.py::_open_panel_users_store."""
    if profile == MAIN_PROFILE:
        return ROOT / ".env"
    return ROOT / f".env.{safe_segment(profile)}"


def list_profiles() -> list[str]:
    profiles = []
    # От ROOT, не от paths.ENV_FILE — см. _env_file_for(): иначе список
    # профилей в тестах включал бы "main" по факту существования боевого
    # .env, независимо от подменённого корня.
    if (ROOT / ".env").exists():
        profiles.append(MAIN_PROFILE)
    for p in sorted(ROOT.glob(".env.*")):
        # .env.example — шаблон, не профиль. .env.backup-* — ручные копии
        # .env (например перед рискованной правкой), не боты: были ошибочно
        # видны в сайдбаре как отдельный "бот" под именем backup-<дата>.
        if p.name == ".env.example" or p.name.startswith(".env.backup"):
            continue
        profiles.append(p.name.removeprefix(".env."))
    return profiles


def new_profile_from_template(profile: str, bot_token: str, bot_nick: str) -> None:
    """Создаёт .env.<profile> с минимальным набором полей, остальное можно
    донастроить через панель (канал, промт, голос).

    bot_token/bot_nick приходят из запроса и подставляются в построчный
    формат .env — перевод строки в них дописал бы в файл посторонние
    переменные (bug-аудит 2026-08-17, тот же вектор, что закрыт в
    paths.write_env_values; здесь файл пишется напрямую, минуя её, поэтому
    проверка продублирована)."""
    for name, value in (("bot_token", bot_token), ("bot_nick", bot_nick)):
        if "\n" in value or "\r" in value:
            raise ValueError(f"Значение {name} содержит перевод строки")
    env_file = _env_file_for(profile)
    if env_file.exists():
        raise FileExistsError(profile)
    content = (
        f"INSTANCE={profile}\n"
        f"TWITCH_BOT_TOKEN={bot_token}\n"
        f"TWITCH_BOT_NICK={bot_nick}\n"
        f"TWITCH_CHANNEL=\n"
        f"DEEPSEEK_API_KEY={read_env(MAIN_PROFILE).get('DEEPSEEK_API_KEY', '')}\n"
        f"BOT_TRIGGER={bot_nick}\n"
        f"VOICE_TRIGGER={bot_nick}\n"
        f"VOICE_REQUIRE_TRIGGER=false\n"
        f"VOICE_ENABLED=false\n"
        f"VOICE_SOURCE=twitch\n"
        f"VOICE_STREAM_CHANNEL=\n"
        f"VOICE_SILENCE_THRESHOLD=500\n"
        f"VOICE_FREE_REPLY_COOLDOWN=20\n"
        f"STREAMER_NAME=стример\n"
        f"STREAMER_CONTEXT=\n"
        f"BOT_PERSONALITY=Ты — дружелюбный чат-бот стримера. Отвечай коротко и с юмором.\n"
    )
    env_file.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# .env: чтение и точечная запись отдельных переменных без потери остального
# файла (комментарии, порядок строк) — правим построчно, как это делали
# вручную через Edit все прошлые разы.
# ---------------------------------------------------------------------------

def read_env(profile: str) -> dict[str, str]:
    env_file = _env_file_for(profile)
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


def write_env_values(profile: str, updates: dict[str, str]) -> None:
    # paths.write_env_values() — единая реализация вместо трёх независимых
    # копий (была тут, в panel/auth.py и cigilbot/integrations/mod_token.py),
    # которые могли гоняться друг с другом при параллельной записи одного
    # .env (bug-аудит 2026-08-15, HIGH #4).
    paths.write_env_values(_env_file_for(profile), updates)


# ---------------------------------------------------------------------------
# Управление процессами — PID-файлы теперь именованы по профилю, чтобы
# несколько ботов не конфликтовали (bot.<profile>.pid, voice.<profile>.pid).
# Профиль "main" по-прежнему использует голые bot.pid/voice.pid — так старые
# запущенные вручную процессы (до многоботовости) панель тоже подхватывает.
# ---------------------------------------------------------------------------

def _pid_file(profile: str, kind: str) -> Path:
    if profile == MAIN_PROFILE:
        return VAR / "run" / f"{kind}.pid"
    return VAR / "run" / f"{kind}.{safe_segment(profile)}.pid"


def _read_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (ValueError, OSError):
        return None


def _process_alive(pid: int) -> bool:
    # /FI IMAGENAME защищает от PID reuse false positive: если процесс
    # умер и ОС успела переиспользовать его PID для чего-то ещё до
    # следующей проверки, не считаем чужой процесс нашим ботом только
    # потому что число совпало.
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FI", "IMAGENAME eq python.exe", "/NH"],
        capture_output=True,
        text=True,
    )
    return str(pid) in result.stdout


def _is_running(path: Path) -> bool:
    pid = _read_pid(path)
    return bool(pid and _process_alive(pid))


def _stop_pid(path: Path) -> None:
    with _pid_lock(path):
        pid = _read_pid(path)
        if pid and _process_alive(pid):
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
        path.unlink(missing_ok=True)


# Атомарная секция "проверить процесс жив -> запустить новый" per pid-файл —
# без этого параллельный вызов start_profile() для одного и того же profile
# (двойной клик в UI, или запрос от двух вкладок) может дважды пройти
# _is_running()==False до того, как первый успеет записать pid-файл, и
# породить два живых main.py на один профиль/канал.
_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_STALE_SECONDS = 30.0


@contextlib.contextmanager
def _pid_lock(pid_file: Path):
    lock_path = pid_file.with_suffix(pid_file.suffix + ".lock")
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    fd = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                # time.time(), не time.monotonic() — st_mtime считается по
                # эпохе, monotonic() от произвольной точки отсчёта; их
                # разность не значит "секунд назад" и лок никогда не
                # считался устаревшим по этой проверке (тот же баг найден
                # и исправлен в cigilbot/integrations/bot_process_control.py
                # и paths.py::_env_file_lock, bug-аудит 2026-08-15, MEDIUM #13).
                if time.time() - lock_path.stat().st_mtime > _LOCK_STALE_SECONDS:
                    lock_path.unlink(missing_ok=True)
                    continue
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Не удалось получить lock на {pid_file.name} (занято другим запросом)"
                ) from None
            time.sleep(0.1)
    try:
        yield
    finally:
        os.close(fd)
        lock_path.unlink(missing_ok=True)


def _start(profile: str, script: str, pid_file: Path, log_out: Path, log_err: Path) -> int:
    """Обёрнуто в _pid_lock() — см. docstring там же. Проверка
    _is_running() внутри лока, а не только у вызывающей стороны
    (start_profile), закрывает гонку между двумя параллельными вызовами."""
    # До _pid_lock: lock-файл лежит рядом с pid-файлом в var/bot/run,
    # и без каталога os.open(O_CREAT) упадёт раньше запуска. На чистом клоне
    # var/ не существует — он целиком в .gitignore.
    paths.ensure_dirs()

    with _pid_lock(pid_file):
        if _is_running(pid_file):
            existing = _read_pid(pid_file)
            if existing is not None:
                return existing

        env_file = _env_file_for(profile)
        env = None
        if profile != MAIN_PROFILE:
            env = os.environ.copy()
            env["BOT_ENV_FILE"] = str(env_file)

        # Дескрипторы закрываются в родителе сразу после Popen — Popen уже
        # задублировал их дочернему процессу через dup(), держать их
        # открытыми в панели дальше — утечка FD при частых рестартах.
        with open(log_out, "a", encoding="utf-8") as out_f, open(log_err, "a", encoding="utf-8") as err_f:
            proc = subprocess.Popen(
                [str(VENV_PYTHON), script],
                cwd=str(ROOT),
                stdout=out_f,
                stderr=err_f,
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=env,
            )
        pid_file.write_text(str(proc.pid), encoding="ascii")
        return proc.pid


def _instance_path(profile: str, name: str, ext: str) -> Path:
    """Тот же алгоритм имени файла, что и Config._path в bot/config.py —
    панель должна читать ФАЙЛЫ ТОГО ЖЕ инстанса, что сейчас запущен.

    read_env(profile) уже проходит через _env_file_for(), которая
    валидирует profile через safe_segment() — вторая проверка здесь не
    нужна, но сам INSTANCE (из содержимого .env, не из запроса) тоже
    подставляется в путь: он пишется только через new_profile_from_template
    (INSTANCE=profile, тот же уже провалидированный profile) или вручную
    оператором с доступом к файлам на диске, поэтому отдельно не
    проверяется."""
    instance = read_env(profile).get("INSTANCE", "").strip()
    filename = f"{name}.{instance}.{ext}" if instance else f"{name}.{ext}"
    return VAR / filename


def db_path(profile: str) -> Path:
    return _instance_path(profile, "bot", "db")


# ---------------------------------------------------------------------------
# Авторизация панели (SEC-001). Раньше здесь стоял целый блок настройки —
# чтение PANEL_SESSION_SECRET, SessionMiddleware, app.state, подключение
# auth_router — и стоял он именно тут, выше первого роута, чтобы
# require_role_min существовал к моменту вычисления декораторов. Всё это
# переехало в panel/server.py, который собирает единственное приложение;
# здесь остался только импорт зависимости (см. импорты в шапке файла).
#
# app.state.panel_db_factory отсюда исчез вместе с ним: ADMIN-оверрайды
# ролей больше не живут в panel_admins внутри bot.db, оба экрана теперь
# читают один список из mod_panel_users (см. panel/auth.py и разовый
# scripts/merge_panel_admins.py, переносящий старые записи).
# ---------------------------------------------------------------------------


def usage_path(profile: str) -> Path:
    return _instance_path(profile, "usage", "json")


def log_path(profile: str) -> Path:
    return VAR / "logs" / _instance_path(profile, "bot", "log").name


def get_usage(profile: str) -> dict:
    path = usage_path(profile)
    if not path.exists():
        return {"requests": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"requests": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
    cost = (
        data.get("input_tokens", 0) / 1_000_000 * PRICE_PER_1M_INPUT_USD
        + data.get("output_tokens", 0) / 1_000_000 * PRICE_PER_1M_OUTPUT_USD
    )
    return {**data, "cost_usd": round(cost, 4)}


async def fetch_deepseek_balance(api_key: str) -> dict:
    """Реальный остаток на счёте DeepSeek — в отличие от usage.json (наша
    оценка расхода по токенам), это официальная цифра от самого DeepSeek."""
    if not api_key:
        return {"error": "нет ключа"}

    cached = _balance_cache.get(api_key)
    if cached and time.monotonic() - cached[0] < BALANCE_CACHE_SECONDS:
        return cached[1]

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                DEEPSEEK_BALANCE_URL, headers={"Authorization": f"Bearer {api_key}"}
            )
        resp.raise_for_status()
        data = resp.json()
        infos = data.get("balance_infos", [])
        balances = []
        for b in infos:
            currency = b.get("currency")
            total = b.get("total_balance")
            rub = None
            try:
                rate = await fetch_rub_rate(currency)
                if rate is not None:
                    rub = round(float(total) * rate, 2)
            except (TypeError, ValueError):
                pass
            balances.append({"currency": currency, "total_balance": total, "rub": rub})
        result = {"is_available": data.get("is_available", False), "balances": balances}
    except (httpx.HTTPError, ValueError) as e:
        result = {"error": str(e)}

    _balance_cache[api_key] = (time.monotonic(), result)
    return result


def get_profile_status(profile: str) -> dict:
    env = read_env(profile)
    return {
        "profile": profile,
        "bot_nick": env.get("TWITCH_BOT_NICK", ""),
        "bot_running": _is_running(_pid_file(profile, "bot")),
        "voice_running": _is_running(_pid_file(profile, "voice")),
        "channel": env.get("TWITCH_CHANNEL", ""),
        "voice_enabled": env.get("VOICE_ENABLED", "false").lower() == "true",
        "voice_source": env.get("VOICE_SOURCE", "mic"),
        "voice_silence_threshold": int(env.get("VOICE_SILENCE_THRESHOLD", "500") or 500),
        "voice_free_reply_cooldown": int(env.get("VOICE_FREE_REPLY_COOLDOWN", "20") or 20),
        "voice_require_trigger": env.get("VOICE_REQUIRE_TRIGGER", "false").lower() == "true",
        "streamer_name": env.get("STREAMER_NAME", ""),
        "streamer_context": env.get("STREAMER_CONTEXT", ""),
        "usage": get_usage(profile),
        # Чисто модерационный профиль (см. .env.cigilbot) — без DEEPSEEK_API_KEY
        # main.py не создаёт Brain и ничего не отвечает в чате, только
        # наблюдает и модерирует через Cigilbot. Такие профили не показываются
        # в списке "Боты" панели (см. api_profiles) — управляются через
        # раздел "Модерация", у них нет Chat/Brain/Prompt.
        "is_moderation_only": not env.get("DEEPSEEK_API_KEY", "").strip(),
        # Основной бот (профиль MAIN_PROFILE, живёт в корневом .env) — у него
        # модерация (Cigilbot) и свой чат-LLM одновременно, поэтому
        # is_moderation_only ниже не годится как признак "это тот самый
        # флагманский бот": DEEPSEEK_API_KEY у него заполнен. is_flagship —
        # отдельный признак чисто для сайдбара (2026-08-15, пользователь:
        # "хочу запустить множество LLM-ботов, а cigilbot — основной, не
        # хочу чтобы он был в одной категории с ними"). Остальные профили
        # (.env.<profile>) — простые чат-компаньоны без модерации.
        "is_flagship": profile == MAIN_PROFILE,
    }


def start_profile(profile: str, voice: bool = True) -> dict:
    logs_dir = VAR / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    started = {}
    if voice and read_env(profile).get("VOICE_ENABLED", "false").lower() == "true":
        voice_pid_file = _pid_file(profile, "voice")
        if not _is_running(voice_pid_file):
            suffix = f".{profile}" if profile != MAIN_PROFILE else ""
            started["voice_pid"] = _start(
                profile, "voice_main.py", voice_pid_file,
                logs_dir / f"voice_stdout{suffix}.log", logs_dir / f"voice_stderr{suffix}.log",
            )
    bot_pid_file = _pid_file(profile, "bot")
    if not _is_running(bot_pid_file):
        suffix = f".{profile}" if profile != MAIN_PROFILE else ""
        started["bot_pid"] = _start(
            profile, "main.py", bot_pid_file,
            logs_dir / f"stdout{suffix}.log", logs_dir / f"stderr{suffix}.log",
        )
    return started


def stop_profile(profile: str) -> None:
    _stop_pid(_pid_file(profile, "bot"))
    _stop_pid(_pid_file(profile, "voice"))


# ---------------------------------------------------------------------------
# HTTP-эндпоинты
# ---------------------------------------------------------------------------

@router.get("/bots")
def index():
    # Путь сменился с "/" на "/bots": в объединённой панели корень занят
    # экраном модерации (panel/server.py), а два экрана не могут делить
    # один URL. Ссылка между экранами теперь внутренняя, а не на другой
    # порт — раньше в index.html стояла ссылка на localhost:8766, и она
    # вела в процесс с ОТДЕЛЬНОЙ сессией, где надо было логиниться заново.
    #
    # FileResponse по умолчанию не запрещает кэш — index.html (в отличие
    # от статики с ?v=hash в самом файле) браузер иначе кэширует надолго и
    # правки (например, ссылка на панель модерации, испр. 09.08) не
    # подхватываются даже после обычного обновления страницы. no-store —
    # эта страница маленькая и меняется редко, цена перезапроса ничтожна
    # по сравнению с ценой невидимого устаревшего UI.
    response = FileResponse(Path(__file__).parent / "static" / "index.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/api/profiles")
def api_profiles(session: tuple[str, str] = require_role_min("OWNER")):
    # Модерационные профили (is_moderation_only) не показываются в списке
    # "Боты" — они управляются через раздел "Модерация" (панель на 8766),
    # у них нет LLM-функций (Chat/Brain/Prompt), которые эта карточка
    # отображает. См. get_profile_status.
    statuses = [get_profile_status(p) for p in list_profiles()]
    return JSONResponse([s for s in statuses if not s["is_moderation_only"]])


@router.get("/api/deepseek_balance")
async def api_deepseek_balance(
    profile: str = MAIN_PROFILE, session: tuple[str, str] = require_role_min("OWNER")
):
    api_key = read_env(profile).get("DEEPSEEK_API_KEY", "")
    balance = await fetch_deepseek_balance(api_key)
    return JSONResponse(balance)


@router.get("/api/channel_status")
async def api_channel_status(
    profile: str = MAIN_PROFILE, session: tuple[str, str] = require_role_min("OWNER")
):
    channel = read_env(profile).get("TWITCH_CHANNEL", "").strip()
    status = await fetch_channel_live(channel)
    return JSONResponse(status)


@router.post("/api/prompt/preview")
async def api_prompt_preview(
    payload: PromptPreviewRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    """Тестовый прогон промта: реальный вызов DeepSeek с текстом из
    редактора, БЕЗ публикации в Twitch-чат и без записи в БД бота. Позволяет
    проверить эффект правки промта мгновенно, не дожидаясь живого зрителя."""
    from bot.brain import Brain

    personality = payload.personality.strip()
    if not personality:
        return JSONResponse({"error": "personality пуст"}, status_code=400)

    env = read_env(payload.profile)
    api_key = env.get("DEEPSEEK_API_KEY", "")
    channel = env.get("TWITCH_CHANNEL", "preview")
    if not api_key:
        return JSONResponse({"error": "нет DEEPSEEK_API_KEY"}, status_code=400)

    brain = Brain(api_key, personality, channel)
    try:
        reply = await brain.reply(payload.username, payload.message, [], None)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)

    return JSONResponse({"reply": reply})


@router.post("/api/profiles/new")
async def api_new_profile(
    payload: dict, session: tuple[str, str] = require_role_min("OWNER")
):
    """Создаёт новый профиль бота (новый .env.<profile>) с отдельным
    Twitch-аккаунтом. Дальше канал/промт/голос донастраиваются как обычно.

    Требует OWNER: принимает произвольный Twitch-токен от клиента и
    регистрирует его как токен нового бота — самое высокое доверие среди
    мутирующих эндпоинтов этого файла (SEC-001)."""
    profile = re.sub(r"[^a-z0-9_]", "", payload.get("profile", "").lower())
    bot_token = payload.get("bot_token", "").strip()
    bot_nick = payload.get("bot_nick", "").strip()
    if not profile or not bot_token or not bot_nick:
        return JSONResponse({"error": "нужны profile, bot_token, bot_nick"}, status_code=400)
    if not bot_token.startswith("oauth:"):
        bot_token = f"oauth:{bot_token}"
    try:
        new_profile_from_template(profile, bot_token, bot_nick)
    except FileExistsError:
        return JSONResponse({"error": "профиль с таким именем уже есть"}, status_code=400)
    return JSONResponse({"created": profile})


@router.post("/api/channels")
async def api_add_channel(payload: dict, session: tuple[str, str] = require_role_min("OWNER")):
    """Добавляет канал в Channel Registry (registry.db) — один Twitch-бот-
    аккаунт обслуживает все каналы (см. docs/master-plan.html,
    направление 00), поэтому в отличие от /api/profiles/new здесь НЕ
    создаётся новый .env.<profile>/новый бот-аккаунт, только запись канала.
    Оператор перезапускает main.py вручную через панель 8766, когда сочтёт
    момент подходящим (см. bot/registry.py — авто-restart здесь намеренно
    не делается, задел на будущее убран как мёртвый код).

    Резолвит login -> broadcaster_id через Helix (стабильный ID переживает
    переименование канала), затем зеркалирует канал в Cigilbot registry.db
    (см. panel/registry_api.py) — если Cigilbot недоступен в этот момент,
    канал всё равно остаётся созданным здесь (cigilbot_synced=false в
    ответе), чтобы недоступность соседнего процесса не блокировала
    основную операцию."""
    login = re.sub(r"[^a-z0-9_]", "", payload.get("login", "").strip().lower())
    if not login:
        return JSONResponse({"error": "нужен login"}, status_code=400)

    client_id = read_env(MAIN_PROFILE).get("PANEL_TWITCH_CLIENT_ID", "")
    client_secret = read_env(MAIN_PROFILE).get("PANEL_TWITCH_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return JSONResponse(
            {"error": "PANEL_TWITCH_CLIENT_ID/SECRET не настроены в .env"}, status_code=503
        )

    resolver = HelixResolver(client_id, client_secret)
    try:
        try:
            users = await resolver.resolve_logins([login])
        except HelixResolveError as exc:
            return JSONResponse({"error": f"Helix: {exc}"}, status_code=502)
    finally:
        await resolver.close()

    if not users:
        return JSONResponse({"error": f"канал {login!r} не найден на Twitch"}, status_code=404)
    user = users[0]

    # Одна запись в один Registry. Раньше здесь было две: своя БД плюс
    # зеркало на стороне Cigilbot, куда сначала уходил HTTP-запрос с общим
    # секретом INTERNAL_SYNC_TOKEN, а после слияния панелей — прямая запись
    # во второй файл. Реестр стал один на монорепо (см. panel/paths.py::
    # REGISTRY_DB), поэтому зеркалить некуда и нечего: вместе с зеркалом
    # исчез и класс отказа "копии разошлись".
    registry = RegistryStore(str(REGISTRY_DB))
    await registry.connect()
    try:
        record = await registry.upsert_channel(
            broadcaster_id=user.id, login=user.login, display_name=user.display_name,
            registered_by="panel",
        )
    finally:
        await registry.close()

    return JSONResponse({"broadcaster_id": record.broadcaster_id, "login": record.login})


@router.post("/api/start")
def api_start(
    payload: StartStopRequest = StartStopRequest(),
    session: tuple[str, str] = require_role_min("OWNER"),
):
    # Тело запроса (Pydantic), не query-параметр функции — FastAPI резолвит
    # голый `profile: str` как query-параметр на POST, и такой запрос можно
    # отправить обычной HTML-формой без JS (Content-Type: application/
    # x-www-form-urlencoded, не application/json), т.е. cross-site без
    # чтения ответа. SameSite=Lax сейчас блокирует это на практике, но это
    # была единственная линия защиты, без CSRF-токена (security-аудит
    # 2026-08-15, MEDIUM #14). JSON-body такой форме недоступен.
    started = start_profile(payload.profile)
    return JSONResponse({"started": started, "status": get_profile_status(payload.profile)})


@router.post("/api/stop")
def api_stop(
    payload: StartStopRequest = StartStopRequest(),
    session: tuple[str, str] = require_role_min("OWNER"),
):
    stop_profile(payload.profile)
    return JSONResponse({"status": get_profile_status(payload.profile)})


def _load_channel_history() -> list[str]:
    if not CHANNEL_HISTORY_FILE.exists():
        return []
    try:
        return json.loads(CHANNEL_HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _remember_channel(channel: str) -> None:
    history = [c for c in _load_channel_history() if c != channel]
    history.insert(0, channel)
    history = history[:MAX_CHANNEL_HISTORY]
    CHANNEL_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    CHANNEL_HISTORY_FILE.write_text(json.dumps(history, ensure_ascii=False), encoding="utf-8")


def _prompt_history_file(profile: str) -> Path:
    return PROMPT_HISTORY_DIR / f"{safe_segment(profile)}.json"


def _load_prompt_history(profile: str) -> list[dict]:
    path = _prompt_history_file(profile)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _push_prompt_history(profile: str, personality: str) -> None:
    """Сохраняет ТЕКУЩИЙ (ещё не заменённый) промт перед тем, как его
    перепишут — чтобы "Применить" всегда можно было откатить назад."""
    if not personality.strip():
        return
    history = _load_prompt_history(profile)
    if history and history[0]["personality"] == personality:
        return  # не плодим дубли, если применяют то же самое повторно
    history.insert(0, {"personality": personality, "saved_at": time.time()})
    history = history[:MAX_PROMPT_HISTORY]
    PROMPT_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    _prompt_history_file(profile).write_text(
        json.dumps(history, ensure_ascii=False), encoding="utf-8"
    )


@router.get("/api/prompt/history")
def api_prompt_history(
    profile: str = MAIN_PROFILE, session: tuple[str, str] = require_role_min("OWNER")
):
    return JSONResponse(_load_prompt_history(profile))


@router.get("/api/channel_history")
def api_channel_history(session: tuple[str, str] = require_role_min("OWNER")):
    return JSONResponse(_load_channel_history())


@router.post("/api/switch_channel")
def api_switch_channel(
    payload: SwitchChannelRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    # JSON body, не query-параметры — см. комментарий у api_start (security-
    # аудит 2026-08-15, MEDIUM #14).
    profile = payload.profile
    channel = payload.channel.strip().lstrip("#").lower()
    if not re.fullmatch(r"[a-z0-9_]{1,25}", channel):
        return JSONResponse({"error": "Некорректное имя канала"}, status_code=400)

    was_running = _is_running(_pid_file(profile, "bot"))
    stop_profile(profile)

    write_env_values(profile, {"TWITCH_CHANNEL": channel, "VOICE_STREAM_CHANNEL": channel})
    _remember_channel(channel)

    if was_running:
        started = start_profile(profile)
        return JSONResponse({"started": started, "status": get_profile_status(profile)})
    return JSONResponse({"status": get_profile_status(profile)})


@router.get("/api/prompts")
def api_list_prompts(session: tuple[str, str] = require_role_min("OWNER")):
    if not PROMPTS_DIR.exists():
        return JSONResponse([])
    names = sorted(p.stem for p in PROMPTS_DIR.glob("*.txt"))
    return JSONResponse(names)


@router.get("/api/prompt/current")
def api_get_current_prompt(
    profile: str = MAIN_PROFILE, session: tuple[str, str] = require_role_min("OWNER")
):
    return JSONResponse({"personality": read_env(profile).get("BOT_PERSONALITY", "")})


@router.get("/api/prompt/{name}")
def api_get_prompt(name: str, session: tuple[str, str] = require_role_min("OWNER")):
    # FastAPI/Starlette запрещает только литеральный "/" в сегменте пути —
    # "\" (разделитель пути на Windows) проходит нетронутым, поэтому
    # traversal через name="..\\..\\Windows\\win.ini" без этой проверки
    # отдавал содержимое произвольного .txt-файла на диске (security-аудит
    # 2026-08-15, CRITICAL #1).
    path = PROMPTS_DIR / f"{safe_segment(name)}.txt"
    if not path.exists():
        return JSONResponse({"error": "не найдено"}, status_code=404)
    return JSONResponse({"personality": path.read_text(encoding="utf-8").strip()})


@router.post("/api/prompt/save")
async def api_save_prompt(
    payload: SavePromptRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    """Сохраняет текст как именованный промт в prompts/ (не применяет его)."""
    name = re.sub(r"[^a-z0-9\-]", "", payload.name.lower().replace(" ", "-"))
    text = payload.personality.strip()
    if not name or not text:
        return JSONResponse({"error": "нужны name и personality"}, status_code=400)
    PROMPTS_DIR.mkdir(exist_ok=True)
    (PROMPTS_DIR / f"{name}.txt").write_text(text + "\n", encoding="utf-8")
    return JSONResponse({"saved": name})


@router.post("/api/prompt/apply")
async def api_apply_prompt(
    payload: ApplyPromptRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    """Применяет текст как текущий BOT_PERSONALITY и перезапускает чат-бота,
    если он был запущен — иначе новый характер не подхватится (личность
    читается один раз при старте процесса)."""
    text = payload.personality.strip()
    if not text:
        return JSONResponse({"error": "personality пуст"}, status_code=400)

    one_line = " ".join(text.split("\n")).strip()

    def _apply_and_restart() -> bool:
        """Всё блокирующее — одним куском в отдельном потоке.

        Хендлер async, а внутри subprocess.run(taskkill/tasklist), запуск
        нового процесса и файловый лок с time.sleep(0.1) в цикле ожидания:
        прямой вызов из корутины останавливает event loop панели целиком на
        всё время перезапуска бота — вместе с WebSocket-лентами модерации,
        которые обслуживает то же приложение. Тот же класс находки, что уже
        закрыт в registry_api.py (bug-аудит 2026-08-15, HIGH), сюда фикс
        тогда не дошёл (bug-аудит 2026-08-17)."""
        current = read_env(payload.profile).get("BOT_PERSONALITY", "")
        if current and current != one_line:
            _push_prompt_history(payload.profile, current)

        write_env_values(payload.profile, {"BOT_PERSONALITY": one_line})

        bot_pid_file = _pid_file(payload.profile, "bot")
        running = _is_running(bot_pid_file)
        if running:
            _stop_pid(bot_pid_file)
            logs_dir = VAR / "logs"
            suffix = f".{payload.profile}" if payload.profile != MAIN_PROFILE else ""
            _start(payload.profile, "main.py", bot_pid_file,
                   logs_dir / f"stdout{suffix}.log", logs_dir / f"stderr{suffix}.log")
        return running

    was_running = await asyncio.to_thread(_apply_and_restart)
    return JSONResponse({"applied": True, "restarted": was_running})


# ---------------------------------------------------------------------------
# Настройки голоса — правят .env напрямую, перезапускают оба процесса, если
# они были запущены (пороги читаются один раз при старте voice_main.py).
# ---------------------------------------------------------------------------

@router.post("/api/voice_settings")
def api_voice_settings(
    payload: VoiceSettingsRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    write_env_values(payload.profile, {
        "VOICE_SILENCE_THRESHOLD": str(payload.voice_silence_threshold),
        "VOICE_FREE_REPLY_COOLDOWN": str(payload.voice_free_reply_cooldown),
        "VOICE_REQUIRE_TRIGGER": "true" if payload.voice_require_trigger else "false",
    })

    was_running = _is_running(_pid_file(payload.profile, "bot"))
    if was_running:
        stop_profile(payload.profile)
        start_profile(payload.profile)
        return JSONResponse({"applied": True, "restarted": True, "status": get_profile_status(payload.profile)})
    return JSONResponse({"applied": True, "restarted": False, "status": get_profile_status(payload.profile)})


# ---------------------------------------------------------------------------
# Вводные о стримере канала (имя/пол/город/тематика) — короткий фон, который
# бот учитывает в разговоре, но не пересказывает чату. Отдельно от
# BOT_PERSONALITY, потому что это факт про площадку, а не про характер бота,
# и должно меняться при каждом переключении канала.
# ---------------------------------------------------------------------------

@router.post("/api/streamer_context")
def api_streamer_context(
    payload: StreamerContextRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    write_env_values(payload.profile, {
        "STREAMER_NAME": payload.streamer_name.strip() or "стример",
        "STREAMER_CONTEXT": payload.streamer_context.strip(),
    })

    was_running = _is_running(_pid_file(payload.profile, "bot"))
    if was_running:
        stop_profile(payload.profile)
        start_profile(payload.profile)
        return JSONResponse({"applied": True, "restarted": True, "status": get_profile_status(payload.profile)})
    return JSONResponse({"applied": True, "restarted": False, "status": get_profile_status(payload.profile)})


# ---------------------------------------------------------------------------
# Зрители — читает таблицу viewers из bot.db (той же БД, что использует
# запущенный бот прямо сейчас, с учётом INSTANCE).
# ---------------------------------------------------------------------------

@router.get("/api/viewers")
def api_viewers(
    profile: str = MAIN_PROFILE, session: tuple[str, str] = require_role_min("OWNER")
):
    path = db_path(profile)
    if not path.exists():
        return JSONResponse([])
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT username, first_seen, last_seen, message_count, note "
            "FROM viewers ORDER BY last_seen DESC LIMIT 100"
        ).fetchall()
    finally:
        conn.close()
    return JSONResponse([dict(r) for r in rows])


def _all_bot_nicks() -> set[str]:
    """Никнеймы ВСЕХ ботов-профилей (не только текущего) — чтобы в ленте
    любой из них подсвечивался как бот, а не только хозяин этой вкладки."""
    return {
        read_env(p).get("TWITCH_BOT_NICK", "").lower()
        for p in list_profiles()
        if read_env(p).get("TWITCH_BOT_NICK")
    }


@router.get("/api/chat_feed")
def api_chat_feed(
    profile: str = MAIN_PROFILE, session: tuple[str, str] = require_role_min("OWNER")
):
    """Живая лента: кто что написал/сказал — читаем из recent_messages,
    а не из логов, там уже готовая структура автор/текст."""
    path = db_path(profile)
    if not path.exists():
        return JSONResponse([])
    env = read_env(profile)
    streamer_name = env.get("STREAMER_NAME", "стример").lower()
    bot_nicks = _all_bot_nicks()

    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT username, content, created_at FROM recent_messages "
            "ORDER BY id DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    feed = [
        {
            "username": r["username"],
            "content": r["content"],
            "created_at": r["created_at"],
            "is_bot": r["username"].lower() in bot_nicks,
            "is_streamer_voice": r["username"].lower() == streamer_name,
        }
        for r in reversed(rows)
    ]
    return JSONResponse(feed)


@router.post("/api/viewers/note")
def api_set_viewer_note(
    payload: SetNoteRequest, session: tuple[str, str] = require_role_min("OWNER")
):
    path = db_path(payload.profile)
    if not path.exists():
        return JSONResponse({"error": "База данных ещё не создана"}, status_code=404)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "UPDATE viewers SET note = ? WHERE username = ?",
            (payload.note, payload.username.lower()),
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"saved": True})


@router.post("/api/chat_send")
@limiter.limit("30/minute")
def api_send_chat_message(
    request: Request,
    payload: SendChatMessageRequest,
    session: tuple[str, str] = require_role_min("OWNER"),
):
    """Ставит сообщение в очередь panel_outbox (bot.db) — сам процесс бота
    вычитывает её раз в секунду (main.py::_poll_panel_outbox) и отправляет
    от своего имени в указанный канал через MessageQueue. Панель ничего не
    исполняет сама (см. CLAUDE.md), только пишет намерение в БД, которую
    читает бот — тот же принцип, что у desired_state/Attack Mode.

    30/minute — ограничение введено, чтобы скомпрометированная или
    недобросовестная MODERATOR-сессия не могла флудить чат через панель:
    раньше единственным лимитом была проверка длины сообщения (≤500
    символов), без ограничения частоты (см. security-аудит, находка
    Medium). request — первым позиционным параметром: slowapi ищет его по
    имени/позиции в сигнатуре декорированной функции."""
    text = payload.text.strip()
    if not text:
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    if len(text) > 500:
        return JSONResponse({"error": "Слишком длинное сообщение"}, status_code=400)
    channel_login = payload.channel_login.strip().lower()
    if not channel_login:
        return JSONResponse({"error": "Не выбран канал"}, status_code=400)
    path = db_path(payload.profile)
    if not path.exists():
        return JSONResponse({"error": "База данных ещё не создана"}, status_code=404)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            "INSERT INTO panel_outbox (channel_login, text, created_at) VALUES (?, ?, ?)",
            (channel_login, text, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse({"queued": True})


# ---------------------------------------------------------------------------
# Живые логи — WebSocket, читает хвост bot.<profile>.log и досылает новые
# строки. Профиль передаётся первым сообщением клиента после подключения.
# ---------------------------------------------------------------------------


@router.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket):
    from panel.auth import SESSION_KEY

    # Раньше здесь проверялось только "залогинен ли вообще" — любой VIEWER
    # (роль выдаётся автоматически всем, кто прошёл /auth/login) мог
    # стримить в реальном времени чужие логи бота: чат, ники, ответы
    # DeepSeek (bug-аудит 2026-08-15, HIGH). Весь этот роутер теперь
    # OWNER-only (см. require_role_min("OWNER") на остальных роутах файла) —
    # экран ботов не предназначен для модераторов, это разовая настройка
    # оператора, — так что здесь тот же порог, а не по-канальный
    # role_for_profile.
    user = websocket.session.get(SESSION_KEY)
    if user is None:
        await websocket.close(code=4401)
        return
    role = str(user.get("role", "VIEWER"))
    if _ROLE_RANK[role] < _ROLE_RANK["OWNER"]:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    try:
        profile = await websocket.receive_text()
        if not re.fullmatch(r"[a-z0-9_]+", profile):
            profile = MAIN_PROFILE
        log_file = log_path(profile)

        pos = 0
        if log_file.exists():
            size = log_file.stat().st_size
            pos = max(0, size - 8000)  # последние ~8KB при подключении

        while True:
            if log_file.exists():
                with open(log_file, encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                if chunk:
                    await websocket.send_text(chunk)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
