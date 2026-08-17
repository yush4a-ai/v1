"""Тесты paths.write_env_values — единой точки записи в .env.

Через неё проходят все три писателя (panel/auth.py после OAuth,
panel/bots_api.py при настройке профиля, cigilbot/integrations/mod_token.py
при автообновлении токена), то есть в этот файл попадают и секреты, и
значения, введённые человеком в панели. Своего файла тестов у неё не было
до bug-аудита 2026-08-17, хотя расхождение трёх копий уже было отдельной
HIGH-находкой цикла 1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import paths


def _parse(env_file: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value
    return values


class TestWriteEnvValues:
    def test_updates_existing_key_in_place(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("A=1\nB=2\nC=3\n", encoding="utf-8")

        paths.write_env_values(env, {"B": "new"})

        assert _parse(env) == {"A": "1", "B": "new", "C": "3"}

    def test_appends_missing_key(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("A=1\n", encoding="utf-8")

        paths.write_env_values(env, {"B": "2"})

        assert _parse(env) == {"A": "1", "B": "2"}

    def test_preserves_comments_and_blank_lines(self, tmp_path: Path) -> None:
        """Точечная запись, а не перегенерация файла: .env редактируют и
        руками, комментарии в нём — документация ключей."""
        env = tmp_path / ".env"
        env.write_text("# заголовок\nA=1\n\n# про B\nB=2\n", encoding="utf-8")

        paths.write_env_values(env, {"A": "changed"})

        text = env.read_text(encoding="utf-8")
        assert "# заголовок" in text
        assert "# про B" in text
        assert "A=changed" in text

    def test_creates_file_when_missing(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"

        paths.write_env_values(env, {"A": "1"})

        assert _parse(env) == {"A": "1"}


class TestNewlineInjectionRejected:
    """bug-аудит 2026-08-17: формат .env построчный, поэтому "\\n" внутри
    значения — это не экранируемый символ, а конец записи. Значения сюда
    приходят из панели (ник бота, STREAMER_CONTEXT, промпт), и без проверки
    один перевод строки позволял дописать в файл ЛЮБУЮ другую переменную:
    BOT_ENV_FILE (перенаправляет бота на чужой конфиг), DEEPSEEK_API_KEY,
    TWITCH_BOT_TOKEN. Воспроизведено до фикса — значение
    "ник\\nBOT_ENV_FILE=/etc/passwd" честно создавало BOT_ENV_FILE."""

    def test_newline_in_value_raises(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("DEEPSEEK_API_KEY=real\n", encoding="utf-8")

        with pytest.raises(ValueError, match="перевод строки"):
            paths.write_env_values(env, {"STREAMER_NAME": "боб\nDEEPSEEK_API_KEY=stolen"})

    def test_carriage_return_in_value_raises(self, tmp_path: Path) -> None:
        """\\r отдельно от \\n: Windows-перенос, splitlines() режет и по нему."""
        env = tmp_path / ".env"
        env.write_text("A=1\n", encoding="utf-8")

        with pytest.raises(ValueError, match="перевод строки"):
            paths.write_env_values(env, {"A": "x\rB=2"})

    def test_file_untouched_when_rejected(self, tmp_path: Path) -> None:
        """Проверка ДО открытия файла — отказ не должен оставить .env
        наполовину переписанным."""
        env = tmp_path / ".env"
        env.write_text("DEEPSEEK_API_KEY=real\nA=1\n", encoding="utf-8")
        before = env.read_text(encoding="utf-8")

        with pytest.raises(ValueError):
            paths.write_env_values(env, {"A": "ok", "B": "bad\nC=injected"})

        assert env.read_text(encoding="utf-8") == before
        assert "C" not in _parse(env)

    def test_multiline_value_rejected_even_alone(self, tmp_path: Path) -> None:
        """Даже без похожего на "KEY=" хвоста — значение всё равно потеряло
        бы вторую строку при чтении, то есть тихо исказилось."""
        env = tmp_path / ".env"
        env.write_text("A=1\n", encoding="utf-8")

        with pytest.raises(ValueError):
            paths.write_env_values(env, {"BOT_PERSONALITY": "первая строка\nвторая строка"})
