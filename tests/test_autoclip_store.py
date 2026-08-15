"""Тесты store-методов живого рубильника автоклипа: mod_autoclip_settings
(миграция 017). Та же структура, что TestContentSettings в test_content_store.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "test.db"))
    await s.connect()
    return s


class TestAutoclipSettings:
    async def test_default_is_none_not_false(self, store: ModerationStore) -> None:
        """None, а не False — панель ещё не трогала канал, живой рубильник
        не должен молчаливо подменять дефолт из YAML (см. AutoclipSettings)."""
        settings = await store.get_autoclip_settings()
        assert settings.enabled is None

    async def test_enable_persists(self, store: ModerationStore) -> None:
        await store.set_autoclip_enabled(True, updated_by="admin")
        settings = await store.get_autoclip_settings()
        assert settings.enabled is True
        assert settings.updated_by == "admin"

    async def test_can_disable_again(self, store: ModerationStore) -> None:
        await store.set_autoclip_enabled(True, updated_by="admin")
        await store.set_autoclip_enabled(False, updated_by="mod1")
        settings = await store.get_autoclip_settings()
        assert settings.enabled is False
        assert settings.updated_by == "mod1"

    async def test_to_dict_shape(self, store: ModerationStore) -> None:
        await store.set_autoclip_enabled(True, updated_by="admin")
        settings = await store.get_autoclip_settings()
        data = settings.to_dict()
        assert data["enabled"] is True
        assert data["updated_by"] == "admin"
        assert "updated_at" in data


class TestAutoclipThresholds:
    async def test_default_thresholds_are_none(self, store: ModerationStore) -> None:
        settings = await store.get_autoclip_settings()
        assert settings.burst_unique_authors_threshold is None
        assert settings.burst_window_seconds is None
        assert settings.keyword_phrases is None
        assert settings.voice_phrases is None
        assert settings.cooldown_seconds is None

    async def test_thresholds_persist(self, store: ModerationStore) -> None:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=8,
            burst_window_seconds=15.0,
            keyword_phrases=("клип", "clip it"),
            voice_phrases=("заклипай",),
            cooldown_seconds=120.0,
            updated_by="mod1",
        )
        settings = await store.get_autoclip_settings()
        assert settings.burst_unique_authors_threshold == 8
        assert settings.burst_window_seconds == 15.0
        assert settings.keyword_phrases == ("клип", "clip it")
        assert settings.voice_phrases == ("заклипай",)
        assert settings.cooldown_seconds == 120.0
        assert settings.updated_by == "mod1"

    async def test_setting_thresholds_does_not_touch_enabled(self, store: ModerationStore) -> None:
        await store.set_autoclip_enabled(True, updated_by="streamer")
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=8, burst_window_seconds=15.0,
            keyword_phrases=("клип",), voice_phrases=None, cooldown_seconds=None,
            updated_by="mod1",
        )
        settings = await store.get_autoclip_settings()
        assert settings.enabled is True

    async def test_setting_enabled_does_not_touch_thresholds(self, store: ModerationStore) -> None:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=8, burst_window_seconds=15.0,
            keyword_phrases=("клип",), voice_phrases=None, cooldown_seconds=None,
            updated_by="mod1",
        )
        await store.set_autoclip_enabled(False, updated_by="mod2")
        settings = await store.get_autoclip_settings()
        assert settings.burst_unique_authors_threshold == 8
        assert settings.keyword_phrases == ("клип",)

    async def test_thresholds_do_not_set_enabled_on_fresh_row(
        self, store: ModerationStore
    ) -> None:
        """Настройка порогов раньше вкл/выкл — enabled остаётся None
        (не False, не True): сама по себе настройка порогов не должна ни
        включать, ни выключать канал (см. set_autoclip_thresholds)."""
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=5, burst_window_seconds=10.0,
            keyword_phrases=("клип",), voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        settings = await store.get_autoclip_settings()
        assert settings.enabled is None

    async def test_thresholds_do_not_touch_enabled_when_row_exists(
        self, store: ModerationStore
    ) -> None:
        """set_autoclip_thresholds на уже существующей строке (например,
        после set_autoclip_enabled) не должен затирать enabled ни в какую
        сторону — ON CONFLICT не упоминает эту колонку."""
        await store.set_autoclip_enabled(True, updated_by="streamer")
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=5, burst_window_seconds=None,
            keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        settings = await store.get_autoclip_settings()
        assert settings.enabled is True

    async def test_partial_thresholds_leave_others_none(self, store: ModerationStore) -> None:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=5, burst_window_seconds=None,
            keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        settings = await store.get_autoclip_settings()
        assert settings.burst_unique_authors_threshold == 5
        assert settings.burst_window_seconds is None
        assert settings.keyword_phrases is None

    async def test_to_dict_serializes_phrase_lists(self, store: ModerationStore) -> None:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=None, burst_window_seconds=None,
            keyword_phrases=("клип", "clip it"), voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        settings = await store.get_autoclip_settings()
        data = settings.to_dict()
        assert data["keyword_phrases"] == ["клип", "clip it"]
        assert data["voice_phrases"] is None


class TestAutoclipAutoScale:
    async def test_default_is_none(self, store: ModerationStore) -> None:
        settings = await store.get_autoclip_settings()
        assert settings.burst_auto_scale_enabled is None
        assert settings.burst_auto_scale_percent is None
        assert settings.burst_auto_scale_min is None
        assert settings.burst_auto_scale_max is None

    async def test_auto_scale_persists(self, store: ModerationStore) -> None:
        await store.set_autoclip_auto_scale(
            enabled=True, percent=0.05, minimum=5, maximum=100, updated_by="mod1"
        )
        settings = await store.get_autoclip_settings()
        assert settings.burst_auto_scale_enabled is True
        assert settings.burst_auto_scale_percent == 0.05
        assert settings.burst_auto_scale_min == 5
        assert settings.burst_auto_scale_max == 100
        assert settings.updated_by == "mod1"

    async def test_can_disable_again(self, store: ModerationStore) -> None:
        await store.set_autoclip_auto_scale(
            enabled=True, percent=0.05, minimum=5, maximum=100, updated_by="mod1"
        )
        await store.set_autoclip_auto_scale(
            enabled=False, percent=None, minimum=None, maximum=None, updated_by="mod2"
        )
        settings = await store.get_autoclip_settings()
        assert settings.burst_auto_scale_enabled is False

    async def test_auto_scale_does_not_touch_manual_thresholds(self, store: ModerationStore) -> None:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=8, burst_window_seconds=None,
            keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        await store.set_autoclip_auto_scale(
            enabled=True, percent=0.05, minimum=5, maximum=100, updated_by="mod1"
        )
        settings = await store.get_autoclip_settings()
        assert settings.burst_unique_authors_threshold == 8

    async def test_thresholds_do_not_touch_auto_scale(self, store: ModerationStore) -> None:
        await store.set_autoclip_auto_scale(
            enabled=True, percent=0.05, minimum=5, maximum=100, updated_by="mod1"
        )
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=8, burst_window_seconds=None,
            keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        settings = await store.get_autoclip_settings()
        assert settings.burst_auto_scale_enabled is True
        assert settings.burst_auto_scale_percent == 0.05


class TestAutoclipViewerCountCache:
    async def test_default_is_none(self, store: ModerationStore) -> None:
        settings = await store.get_autoclip_settings()
        assert settings.last_viewer_count is None

    async def test_update_on_empty_row_is_noop(self, store: ModerationStore) -> None:
        """Канал ни разу не настраивали через панель — нет смысла заводить
        строку только ради кэша viewer count."""
        await store.update_autoclip_viewer_count(500)
        settings = await store.get_autoclip_settings()
        assert settings.last_viewer_count is None

    async def test_update_persists_when_row_exists(self, store: ModerationStore) -> None:
        await store.set_autoclip_enabled(True, updated_by="streamer")
        await store.update_autoclip_viewer_count(842)
        settings = await store.get_autoclip_settings()
        assert settings.last_viewer_count == 842
        assert settings.last_viewer_count_at is not None and settings.last_viewer_count_at > 0

    async def test_update_does_not_touch_other_fields(self, store: ModerationStore) -> None:
        await store.set_autoclip_thresholds(
            burst_unique_authors_threshold=8, burst_window_seconds=None,
            keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
            updated_by="admin",
        )
        await store.update_autoclip_viewer_count(100)
        settings = await store.get_autoclip_settings()
        assert settings.burst_unique_authors_threshold == 8
        assert settings.last_viewer_count == 100
