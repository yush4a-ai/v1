"""Тесты load_autoclip_channel_config — тот же стиль, что test_config.py::
TestChannelProfile, читает ту же секцию channel.yml, но независимо
(bot/autoclip_config.py дублирует _check_keys, не импортирует его)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bot.autoclip_config import (
    AutoclipConfigError,
    load_autoclip_channel_config,
)


class TestLoadAutoclipChannelConfig:
    def test_missing_channel_file_returns_disabled_defaults(self, tmp_path: Path) -> None:
        config = load_autoclip_channel_config("nosuchchannel", channels_dir=tmp_path)
        assert config.enabled is False
        assert config.burst.unique_authors_threshold == 12

    def test_missing_autoclip_section_returns_disabled_defaults(self, tmp_path: Path) -> None:
        chan = tmp_path / "mychan.yml"
        chan.write_text("channel_profile:\n  primary_language: ru\n", encoding="utf-8")
        config = load_autoclip_channel_config("mychan", channels_dir=tmp_path)
        assert config.enabled is False

    def test_loads_example_profile(self) -> None:
        config = load_autoclip_channel_config("example")
        assert config.enabled is False
        assert config.cooldown_seconds == 300
        assert "клип это" in config.keyword.phrases
        assert "заклипай" in config.voice.phrases

    def test_parses_full_override(self, tmp_path: Path) -> None:
        chan = tmp_path / "mychan.yml"
        chan.write_text(
            """
autoclip:
  enabled: true
  cooldown_seconds: 60
  burst:
    enabled: true
    window_seconds: 5
    unique_authors_threshold: 3
  keyword:
    enabled: true
    phrases: ["клип"]
  voice:
    enabled: false
    phrases: []
""",
            encoding="utf-8",
        )
        config = load_autoclip_channel_config("mychan", channels_dir=tmp_path)
        assert config.enabled is True
        assert config.cooldown_seconds == 60
        assert config.burst.window_seconds == 5
        assert config.burst.unique_authors_threshold == 3
        assert config.keyword.phrases == ("клип",)
        assert config.voice.enabled is False

    def test_unknown_top_level_autoclip_key_rejected(self, tmp_path: Path) -> None:
        chan = tmp_path / "mychan.yml"
        chan.write_text("autoclip:\n  enabled: true\n  typo_key: 1\n", encoding="utf-8")
        with pytest.raises(AutoclipConfigError):
            load_autoclip_channel_config("mychan", channels_dir=tmp_path)

    def test_unknown_burst_key_rejected(self, tmp_path: Path) -> None:
        chan = tmp_path / "mychan.yml"
        chan.write_text(
            "autoclip:\n  enabled: true\n  burst:\n    typo_key: 1\n", encoding="utf-8"
        )
        with pytest.raises(AutoclipConfigError):
            load_autoclip_channel_config("mychan", channels_dir=tmp_path)

    def test_channel_profile_section_alongside_autoclip_is_ignored(self, tmp_path: Path) -> None:
        chan = tmp_path / "mychan.yml"
        chan.write_text(
            """
channel_profile:
  primary_language: ru

autoclip:
  enabled: true
""",
            encoding="utf-8",
        )
        config = load_autoclip_channel_config("mychan", channels_dir=tmp_path)
        assert config.enabled is True
