"""Тесты на то, что появилось именно при слиянии двух панелей в одну.

Остальное покрытие панели лежит в test_auth.py и test_moderation_api.py и
слияния не касается. Здесь — три вещи, которых до него не существовало:

  * _list_env_profile_channels — чтение каналов из .env/.env.<profile>.
    Раньше эта логика жила в копии auth.py на стороне twitch-bots и
    исчезала, когда обе копии сводили в одну; теперь это половина
    объединённого источника каналов.
  * _list_profile_channels — объединение двух моделей каналов (Registry +
    профили). До слияния каждая копия знала ровно одну модель.
  * _safe_next — возврат на исходный экран после входа. Экранов стало два
    на одном порту, и жёсткий редирект на /moderation выкидывал бы с
    экрана ботов того, кто входил именно туда.

Тут же и регрессия на файл tests/__init__.py: без него pytest импортирует
каталог tests/panel как топ-левел пакет `panel` и затеняет настоящий пакет
панели — тесты падают на ModuleNotFoundError ещё на сборе.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import paths
from cigilbot.storage.registry_store import RegistryStore
from panel.auth import (
    DEFAULT_AFTER_LOGIN,
    _list_env_profile_channels,
    _list_profile_channels,
    _safe_next,
)
from paths import PanelRoots


class TestEnvProfileChannels:
    def test_main_profile_read_from_repo_root_env(self, tmp_path: Path) -> None:
        # Профиль "main" живёт в КОРНЕВОМ .env монорепо, а не в
        # .env — общий конфиг после слияния один на репо.
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".env").write_text("TWITCH_CHANNEL=streamer\n", encoding="utf-8")

        roots = PanelRoots(repo=repo, var=tmp_path)
        assert _list_env_profile_channels(roots) == {"main": "streamer"}

    def test_named_profiles_read_from_bot_root(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".env").write_text("TWITCH_CHANNEL=main_channel\n", encoding="utf-8")
        (repo / ".env.second").write_text("TWITCH_CHANNEL=#SecondChannel\n", encoding="utf-8")

        roots = PanelRoots(repo=repo, var=tmp_path)
        # Канал нормализуется (без #, нижний регистр) — как и везде в auth.py.
        assert _list_env_profile_channels(roots) == {
            "main": "main_channel",
            "second": "secondchannel",
        }

    def test_example_file_and_channelless_profiles_skipped(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".env").write_text("TWITCH_CHANNEL=main_channel\n", encoding="utf-8")
        # Шаблон — не профиль.
        (repo / ".env.example").write_text("TWITCH_CHANNEL=твой_канал\n", encoding="utf-8")
        # Профиль с пустым каналом: заведён, но канал ещё не выбран —
        # роль по нему считать не по чему.
        (repo / ".env.blank").write_text("TWITCH_CHANNEL=\n", encoding="utf-8")

        roots = PanelRoots(repo=repo, var=tmp_path)
        assert _list_env_profile_channels(roots) == {"main": "main_channel"}

    def test_missing_env_files_are_not_an_error(self, tmp_path: Path) -> None:
        # Свежий клон без .env вообще: панель должна подниматься, а не падать.
        roots = PanelRoots.all_at(tmp_path)
        assert _list_env_profile_channels(roots) == {}


class TestProfileChannelsUnion:
    async def test_union_of_registry_and_env_profiles(self, tmp_path: Path) -> None:
        """Объединение, а не выбор одной модели: role_for_profile получает
        ключ и от moderation_api (broadcaster_id), и от экрана ботов (имя
        профиля). До слияния каждая копия auth.py знала ровно одну модель."""
        (tmp_path / ".env").write_text("TWITCH_CHANNEL=env_channel\n", encoding="utf-8")

        registry = RegistryStore(str(tmp_path / "registry.db"))
        await registry.connect()
        await registry.upsert_channel(
            broadcaster_id="12345", login="registry_channel", registered_by="manual"
        )
        await registry.close()

        roots = PanelRoots.all_at(tmp_path)
        assert await _list_profile_channels(roots) == {
            "main": "env_channel",
            "12345": "registry_channel",
        }

    async def test_registry_wins_on_key_collision(self, tmp_path: Path) -> None:
        """Если имя профиля совпало с broadcaster_id, права определяет
        модель модерации — не .env-файл, который правится руками."""
        (tmp_path / ".env.12345").write_text("TWITCH_CHANNEL=from_env\n", encoding="utf-8")

        registry = RegistryStore(str(tmp_path / "registry.db"))
        await registry.connect()
        await registry.upsert_channel(
            broadcaster_id="12345", login="from_registry", registered_by="manual"
        )
        await registry.close()

        roots = PanelRoots.all_at(tmp_path)
        assert (await _list_profile_channels(roots))["12345"] == "from_registry"


class TestSafeNext:
    @pytest.mark.parametrize("path", ["/bots", "/moderation", "/"])
    def test_internal_paths_allowed(self, path: str) -> None:
        assert _safe_next(path) == path

    @pytest.mark.parametrize(
        "hostile",
        [
            "//evil.com",  # protocol-relative — браузер уведёт на чужой хост
            "https://evil.com",
            "http://evil.com/bots",
            "javascript:alert(1)",
            "",
        ],
    )
    def test_external_targets_fall_back_to_default(self, hostile: str) -> None:
        assert _safe_next(hostile) == DEFAULT_AFTER_LOGIN


class TestPaths:
    def test_state_lives_outside_the_sources(self) -> None:
        """Ровно то, ради чего заведён var/: рабочее состояние не внутри
        дерева с исходниками. Если кто-то вернёт БД обратно к коду,
        сломается это утверждение, а не только вкус."""
        assert paths.VAR == paths.REPO_ROOT / "var"
        assert paths.BOT_VAR.is_relative_to(paths.VAR)
        assert paths.MOD_VAR.is_relative_to(paths.VAR)
        for source_dir in ("bot", "cigilbot", "panel", "tests", "config"):
            assert not paths.VAR.is_relative_to(paths.REPO_ROOT / source_dir)

    def test_registry_is_one_database_outside_both_owners(self) -> None:
        """Реестров было два — свой у бота и зеркало у модерации, которые
        синхронизировала панель. Пока это были разные процессы, зеркало
        имело смысл; в одном процессе расхождение копий стало бы багом
        внутри него. Реестр лежит прямо в var/, а не внутри var/bot или
        var/cigilbot, потому что не принадлежит ни тому, ни другому."""
        assert paths.REGISTRY_DB == paths.VAR / "registry.db"
        assert not paths.REGISTRY_DB.is_relative_to(paths.BOT_VAR)
        assert not paths.REGISTRY_DB.is_relative_to(paths.MOD_VAR)

    def test_repo_root_is_the_project_root(self) -> None:
        """Единственный paths.py лежит в корне, и REPO_ROOT считается от
        него. Раньше таких модулей было три, каждый считал корень своим
        числом .parent, и совпадение приходилось проверять тестом."""
        assert (paths.REPO_ROOT / "main.py").exists()
        assert (paths.REPO_ROOT / "pyproject.toml").exists()
        assert paths.ENV_FILE == paths.REPO_ROOT / ".env"

    def test_panel_roots_default_matches_module_constants(self) -> None:
        """PanelRoots существует ради подмены корней в тестах — значения по
        умолчанию обязаны совпадать с константами модуля."""
        roots = PanelRoots.default()
        assert roots.repo == paths.REPO_ROOT
        assert roots.var == paths.VAR
        assert roots.registry_db == paths.REGISTRY_DB

    def test_panel_roots_all_at_redirects_everything(self) -> None:
        roots = PanelRoots.all_at(Path("/tmp/x"))
        assert roots.repo == roots.var == Path("/tmp/x")
        assert roots.registry_db == Path("/tmp/x") / "registry.db"
