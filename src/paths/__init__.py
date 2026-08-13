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


def mod_db(broadcaster_id: str) -> Path:
    """mod.<broadcaster_id>.db — всё состояние модерации канала.

    Файл на канал, потому что движок стейтфул и смешивать состояние разных
    каналов незачем. Ключ — broadcaster_id, стабильный к переименованию
    канала, в отличие от login."""
    return MOD_VAR / f"mod.{broadcaster_id}.db"


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
