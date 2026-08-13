"""Управление процессом main.py (чат-бот twitch-bots) напрямую из Cigilbot.

Экран Registry в панели (panel/registry_api.py) запускает main.py как
subprocess сам, тем же проверенным приёмом (subprocess.Popen + pid-файл +
tasklist), что уже работает в cigilbot/process_control.py для consumer-
процессов и в panel/bots_api.py для профилей ботов.

Отдельно от panel/bots_api.py, хотя оба умеют запускать main.py, и это
не дублирование: там процесс запускается ПО ПРОФИЛЮ (свой .env.<profile>,
свой INSTANCE, своя БД), здесь — ровно один мульти-канальный бот
модерации с фиксированным .env.cigilbot. Пути пересекаются только в
приёме управления процессом, но не в том, чем управляют.

main.py при запуске с BOT_ENV_FILE=.env.cigilbot сам читает список
активных каналов из своего registry.db (см. twitch-bots/main.py::
_load_initial_channels) — здесь ничего про конкретные каналы знать не
нужно, только держать сам процесс живым.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import paths

# Откуда запускается main.py. Раньше это был корень соседнего проекта, и
# BOT_PROJECT_ROOT существовал затем, чтобы указать на twitch-bots, лежащий
# не рядом. Проект теперь один, каталог у него один — переменная осталась
# только как аварийный оверрайд.
BOT_PROJECT_ROOT = Path(os.environ.get("BOT_PROJECT_ROOT", str(paths.REPO_ROOT)))

BOT_VENV_PYTHON = paths.VENV_PYTHON

# Профиль бота, читающий каналы из Registry (см. .env.cigilbot в корне —
# единственный профиль без DEEPSEEK_API_KEY, чисто модерационный). Не
# настраивается снаружи: этот модуль управляет ровно
# одним конкретным ботом-процессом, а не произвольным профилем.
BOT_ENV_FILE_NAME = ".env.cigilbot"

PID_FILE = paths.MOD_RUN / "chatbot.pid"
LOCK_FILE = paths.MOD_RUN / "chatbot.lock"
LOG_OUT = paths.MOD_LOGS / "chatbot.out.log"
LOG_ERR = paths.MOD_LOGS / "chatbot.err.log"

# Между двумя параллельными вызовами start_bot() (например, двойной клик в
# панели, или ручной start во время автоматического) нужна атомарная секция
# "проверить pid жив -> записать новый pid", иначе оба вызова могут пройти
# проверку is_running()==False до того, как первый запишет PID_FILE, и
# породить два живых main.py. Lock-файл через O_CREAT|O_EXCL — атомарен на
# Windows и не требует msvcrt.locking.
_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_STALE_SECONDS = 30.0  # защита от вечного зависания, если процесс упал с открытым lock-файлом


@contextlib.contextmanager
def _pid_lock() -> Iterator[None]:
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    fd = None
    while True:
        try:
            fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.monotonic() - LOCK_FILE.stat().st_mtime > _LOCK_STALE_SECONDS:
                    LOCK_FILE.unlink(missing_ok=True)
                    continue
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Не удалось получить lock на управление chatbot-процессом (занято другим запросом)"
                ) from None
            time.sleep(0.1)
    try:
        yield
    finally:
        os.close(fd)
        LOCK_FILE.unlink(missing_ok=True)


def _read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text(encoding="ascii").strip())
    except (ValueError, OSError):
        return None


def _process_alive(pid: int) -> bool:
    # /V + сверка имени образа защищает от PID reuse: если исходный
    # main.py умер и ОС успела отдать его PID другому процессу до того,
    # как мы это заметили, "python.exe" в выводе всё ещё может случайно
    # совпасть — но это уже конкретный, а не любой процесс с этим PID.
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FI", "IMAGENAME eq python.exe", "/NH"],
        capture_output=True,
        text=True,
    )
    return str(pid) in result.stdout


def is_running() -> bool:
    pid = _read_pid()
    return bool(pid and _process_alive(pid))


def get_pid() -> int | None:
    pid = _read_pid()
    return pid if pid and _process_alive(pid) else None


def stop_bot() -> None:
    with _pid_lock():
        pid = _read_pid()
        if pid and _process_alive(pid):
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
        PID_FILE.unlink(missing_ok=True)


def start_bot() -> int:
    """Не запускает второй раз, если процесс уже жив — возвращает
    существующий pid (идемпотентно, как cigilbot/process_control.py).
    Обёрнуто в _pid_lock(), чтобы параллельный вызов (двойной клик,
    supervisor + ручной start) не мог породить два живых main.py."""
    # До _pid_lock: сам lock-файл лежит в var/cigilbot/run, и без каталога
    # os.open(O_CREAT) упадёт раньше, чем что-либо запустится.
    paths.ensure_dirs()

    with _pid_lock():
        existing = get_pid()
        if existing is not None:
            return existing

        if not BOT_VENV_PYTHON.exists():
            raise RuntimeError(
                f"Не найден общий venv монорепо: {BOT_VENV_PYTHON} — "
                f"создайте его в корне: python -m venv .venv && "
                f".\\.venv\\Scripts\\pip install -r requirements.txt"
            )

        env = os.environ.copy()
        env["BOT_ENV_FILE"] = str(BOT_PROJECT_ROOT / BOT_ENV_FILE_NAME)

        # Файлы логов открываются на время Popen(...) и сразу закрываются
        # в родителе: Popen дублирует дескриптор дочернему процессу через
        # dup(), исходный объект в родителе нужен только на момент спавна.
        # Без явного close() объект держится живым до GC — при частых
        # рестартах (supervisor) это утечка FD в долгоживущем процессе панели.
        with open(LOG_OUT, "a", encoding="utf-8") as out_f, open(LOG_ERR, "a", encoding="utf-8") as err_f:
            proc = subprocess.Popen(
                [str(BOT_VENV_PYTHON), "main.py"],
                cwd=str(BOT_PROJECT_ROOT),
                stdout=out_f,
                stderr=err_f,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                env={**env, "PYTHONIOENCODING": "utf-8"},
            )
        PID_FILE.write_text(str(proc.pid), encoding="ascii")
        return proc.pid
