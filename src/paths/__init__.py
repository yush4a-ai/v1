"""Все пути проекта в одном месте: где исходники, где состояние, где .env.

Модулей было три — bot/paths.py, cigilbot/paths.py и panel/paths.py — с
продублированными определениями REPO_ROOT, VAR и REGISTRY_DB, которые
"обязаны совпадать", и с тестом, стерегущим это совпадение. Дублирование
было вынужденным: пакеты лежали в трёх отдельных каталогах под apps/, и
импортировать общий модуль было неоткуда, пока не отработает
sys.path-бутстрап, который сам этот модуль и импортировал.

Каталог теперь один, и вместе с ним исчезли: бутстрап в panel/__init__.py,
вставка соседнего проекта в sys.path из main.py, mypy_path через ../, и
необходимость проверять тестом, что три копии констант не разъехались.

Этот модуль сам переехал под src/ вместе с bot/, cigilbot/, panel/ — но
остаётся вне всех трёх пакетов, а не внутри одного из них: его равноправно
импортируют run.py, main.py, voice_main.py, scripts/*, и все три пакета.

Пакет (src/paths/__init__.py), не одиночный файл (src/paths.py) — hatchling
делает честный editable-редирект только для пакетов в [tool.hatch.build.
targets.wheel] packages. Одиночный force-include файл копируется в
site-packages при установке, и Path(__file__) в нём после этого указывает
на .venv, не на src/. REPO_ROOT поэтому — parents[2], на два уровня выше
src/paths/, не parent.

Разделение, которое ОСТАЁТСЯ осмысленным
----------------------------------------
Исходники (здесь, под git) и рабочее состояние (var/, вне git) — разные
вещи, и путать их дорого. Когда-то они совпадали: БД лежали рядом с кодом,
и "корень проекта" незаметно означал сразу и место кода, и место конфига,
и место БД. Разъехалось это только при переезде панели — и стоило бага, в
котором панель писала бы токен модератора не туда, откуда его читают.

Внутри var/ состояние разложено по владельцу: var/bot — то, что пишет
чат-бот, var/cigilbot — то, что пишет движок модерации. Реестр каналов
лежит прямо в var/, потому что не принадлежит ни тому, ни другому: им
пользуются оба и панель.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# -- исходники и конфиг ------------------------------------------------------

# Единственный .env монорепо. Сюда panel/auth.py::_write_env_values пишет
# TWITCH_MOD_* после входа под аккаунтом бота, и ровно отсюда их читает
# движок модерации. Если эти два пути разойдутся, панель отрапортует об
# успешно полученном токене, а все баны начнут падать с 401.
ENV_FILE = REPO_ROOT / ".env"

PROMPTS_DIR = REPO_ROOT / "prompts"
CONFIG_DIR = REPO_ROOT / "config"

VENV_PYTHON = REPO_ROOT / ".venv" / "Scripts" / "python.exe"

# Профиль бота по умолчанию: живёт в корневом .env, а не в .env.<profile>.
MAIN_PROFILE = "main"

# -- рабочее состояние (var/, целиком в .gitignore) --------------------------

VAR = REPO_ROOT / "var"

# Channel Registry — один на весь проект. Реестров было два (свой у бота,
# зеркало у модерации), и панель их синхронизировала; это имело смысл, пока
# они жили в разных процессах. Движок модерации переехал в процесс бота, и
# две копии одной таблицы стали способом получить расхождение внутри одного
# процесса, а не защитой от недоступности соседа.
REGISTRY_DB = VAR / "registry.db"

# Cross-Channel Bot Fingerprint (направление 03 master-plan.html) — известные
# боты, забаненные хотя бы на одном канале оператора. Общий на все каналы,
# как registry.db, но другой владелец данных: не "какие каналы существуют",
# а "кто на них забанен" (см. cigilbot/fingerprints_migrations.py).
FINGERPRINTS_DB = VAR / "fingerprints.db"

BOT_VAR = VAR / "bot"
BOT_LOGS = BOT_VAR / "logs"
# pid- и lock-файлы: самое эфемерное состояние, единственное, что можно
# снести целиком на остановленной системе без последствий.
BOT_RUN = BOT_VAR / "run"
# Рабочие файлы экрана ботов в панели (история каналов и промтов) — рядом с
# состоянием бота, потому что описывают именно его профили.
BOT_PANEL_STATE = BOT_VAR / "panel_state"

MOD_VAR = VAR / "cigilbot"
MOD_LOGS = MOD_VAR / "logs"
MOD_RUN = MOD_VAR / "run"

# Роли панели (mod_panel_users) — единственная таблица этой БД. Один список
# ADMIN на оба экрана панели (см. panel/auth.py).
MOD_DB = MOD_VAR / "mod.db"


def safe_segment(value: str) -> str:
    """Проверяет, что value можно безопасно подставить как ОДИН сегмент
    имени файла (не подкаталог, без выхода за пределы родительской
    директории) — общий guard для всех мест, где значение снаружи
    (broadcaster_id, profile, prompt name...) становится частью пути на
    диске. До первого применения (mod_db) "../../secret" выходил за
    пределы var/cigilbot/ и открывал произвольные файлы на диске,
    доступные процессу; тот же класс бага повторялся отдельно в каждом
    месте, где путь строился вручную (panel/bots_api.py — profile в имени
    .env-файла, БД инстанса, истории промтов; GET /api/prompt/{name}).
    Один guard вместо N копий, чтобы фикс одной дыры не пропускал
    остальные.

    НЕ проверяет формат (например, что broadcaster_id — число) — только
    что значение не может вырваться за пределы каталога, в который его
    подставляют. Более строгий whitelist ломал бы легитимные
    нечисловые surrogate-имена (тестовые "other", "second", profile-имена
    вроде "main")."""
    if (
        os.sep in value
        or (os.altsep and os.altsep in value)
        or value in ("", ".", "..")
    ):
        raise ValueError(f"Некорректное значение пути: {value!r}")
    return value


def mod_db(broadcaster_id: str) -> Path:
    """mod.<broadcaster_id>.db — всё состояние модерации канала.

    Файл на канал, потому что движок стейтфул и смешивать состояние разных
    каналов незачем. Ключ — broadcaster_id, стабильный к переименованию
    канала, в отличие от login.

    safe_segment() ниже — единственная точка, где broadcaster_id
    превращается в путь к файлу, и защищает только от выхода за пределы
    MOD_VAR через разделители пути. Значение приходит и из доверенных
    мест (auth.py, уже сверенное с Channel Registry) и из недоверенных
    (panel/moderation_api.py и auth.py::auth_clip_status — сырой
    query-параметр/WebSocket-сообщение от клиента), поэтому проверка
    нужна тут, а не только в вызывающем коде."""
    return MOD_VAR / f"mod.{safe_segment(broadcaster_id)}.db"


def bot_db(instance: str = "") -> Path:
    """bot.db — зрители, история чата. INSTANCE разводит несколько ботов по
    разным файлам (bot.<instance>.db); панель повторяет тот же алгоритм в
    panel/bots_api.py::_instance_path, чтобы читать файлы того инстанса,
    который сейчас запущен."""
    return BOT_VAR / (f"bot.{instance}.db" if instance else "bot.db")


def ensure_dirs() -> None:
    """Создаёт каталоги состояния. Зовётся при старте процессов и перед
    записью — на чистом клоне var/ не существует вовсе.

    Важно звать ДО взятия pid-lock, а не внутри: сам lock-файл лежит в
    var/*/run, и без каталога os.open(O_CREAT) упадёт раньше, чем что-либо
    запустится."""
    for path in (BOT_VAR, BOT_LOGS, BOT_RUN, BOT_PANEL_STATE, MOD_VAR, MOD_LOGS, MOD_RUN):
        path.mkdir(parents=True, exist_ok=True)


_ENV_LOCK_TIMEOUT_SECONDS = 5.0
_ENV_LOCK_STALE_SECONDS = 10.0


@contextlib.contextmanager
def _env_file_lock(env_file: Path) -> Iterator[None]:
    """Файловый лок вокруг read-modify-write .env — тот же O_CREAT|O_EXCL
    приём, что уже применён в panel/bots_api.py::_pid_lock. Без него три
    независимых читателя/писателя одного .env (ModTokenManager в процессе
    бота — лениво, при истечении токена модератора; panel/auth.py — при
    прохождении OAuth-логина оператором; panel/bots_api.py — при смене
    промта/настроек) могли гонять друг друга: кто записал последним, тот и
    победил, а обновление конкурента откатывалось назад целиком (bug-аудит
    2026-08-15, HIGH #4) — включая уже отозванный Twitch-ом refresh_token,
    из-за чего executor начинал получать 401 при следующем использовании."""
    lock_path = env_file.with_suffix(env_file.suffix + ".lock")
    deadline = time.monotonic() + _ENV_LOCK_TIMEOUT_SECONDS
    fd = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                # time.time(), не time.monotonic() — st_mtime считается по
                # эпохе (как time.time()), monotonic() от произвольной точки
                # отсчёта, не связанной с эпохой: их разность не означает
                # "секунд назад" и почти всегда даёт огромное отрицательное
                # число, из-за чего протухший лок никогда не считался бы
                # устаревшим по этой проверке (найдено тестом на копии этого
                # же кода в bot_process_control.py, bug-аудит 2026-08-15,
                # MEDIUM #13 — здесь исправлено сразу, до того как баг успел
                # воспроизвестись в проде).
                if time.time() - lock_path.stat().st_mtime > _ENV_LOCK_STALE_SECONDS:
                    lock_path.unlink(missing_ok=True)
                    continue
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Не удалось получить lock на {env_file.name} (занято другим процессом)"
                ) from None
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(fd)
        lock_path.unlink(missing_ok=True)


def write_env_values(env_file: Path, updates: dict[str, str]) -> None:
    """Точечная запись переменных в .env без потери остального файла
    (комментарии, порядок строк) — единая реализация вместо трёх
    независимых копий (panel/auth.py, panel/bots_api.py,
    cigilbot/integrations/mod_token.py), которые расходились и гонялись
    друг с другом при параллельной записи одного файла (см.
    _env_file_lock). Общая точка в paths.py, а не в panel/ или cigilbot/,
    потому что обе стороны (bot-процесс и панель) её вызывают, а
    bot/ не должен импортировать panel.* (см. mod_token.py).

    Перевод строки в ЗНАЧЕНИИ запрещён (bug-аудит 2026-08-17): формат .env
    построчный, "KEY=value\\nOTHER=x" — это уже две переменные, а не одна с
    переносом. Значения сюда приходят из панели (ник бота, STREAMER_CONTEXT,
    промпт), то есть от человека, и без этой проверки один \\n позволял
    дописать в файл ЛЮБУЮ другую переменную — включая BOT_ENV_FILE
    (перенаправляет бота на чужой конфиг) и DEEPSEEK_API_KEY. Воспроизведено
    тестом: значение "ник\\nBOT_ENV_FILE=/etc/passwd" честно создавало
    BOT_ENV_FILE. Экранировать нечем — формат не поддерживает продолжение
    строки, поэтому единственный корректный ответ это отказ."""
    for key, value in updates.items():
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"Значение {key} содержит перевод строки — формат .env построчный, "
                "такое значение дописало бы в файл посторонние переменные"
            )
    with _env_file_lock(env_file):
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


@dataclass(frozen=True, slots=True)
class PanelRoots:
    """Корни, которые панель кладёт в app.state.

    Осталось два поля из шести: пока пакеты лежали в трёх отдельных
    каталогах под apps/, панели приходилось помнить каждый отдельно
    (исходники бота, исходники модерации, состояние того и другого).
    Каталог теперь один, и все "где исходники" схлопнулись в repo.

    Существует ради тестов: они подменяют корни на tmp-папку, а константы
    модуля для этого не годятся.
    """

    repo: Path
    """Корень проекта: .env, .env.<profile>, config/, prompts/, main.py."""

    var: Path
    """Рабочее состояние. В проде var/, в тестах — та же tmp-папка."""

    @property
    def registry_db(self) -> Path:
        return self.var / "registry.db"

    @classmethod
    def default(cls) -> PanelRoots:
        return cls(repo=REPO_ROOT, var=VAR)

    @classmethod
    def all_at(cls, path: Path) -> PanelRoots:
        """Все корни в одной папке — для тестов."""
        return cls(repo=path, var=path)
