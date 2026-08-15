"""Тесты ChannelAutoclip/AutoclipHub — end-to-end на моках HelixClient
(httpx.MockTransport, как test_twitch_api.py) и реальном RegistryStore
(как test_pipeline.py::_registry_with) для сверки состава каналов.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import paths
from bot.autoclip import (
    AutoclipHub,
    ChannelAutoclip,
    _apply_auto_scale,
    _merge_config,
    _scaled_burst_threshold,
)
from bot.autoclip_config import (
    AutoclipChannelConfig,
    BurstTriggerConfig,
    KeywordTriggerConfig,
    VoiceTriggerConfig,
)
from cigilbot.integrations.clip_token import ClipTokenManager
from cigilbot.integrations.twitch_api import HelixClient
from cigilbot.storage.registry_store import RegistryStore
from cigilbot.storage.store import AutoclipSettings, ModerationStore


def make_config(
    *,
    enabled: bool = True,
    cooldown_seconds: float = 300.0,
    burst_threshold: int = 3,
    burst_window: float = 10.0,
    keyword_phrases: tuple[str, ...] = ("клип это",),
    voice_phrases: tuple[str, ...] = ("клип это",),
    auto_scale_enabled: bool = False,
    auto_scale_percent: float = 0.04,
    auto_scale_min: int = 4,
    auto_scale_max: int = 200,
) -> AutoclipChannelConfig:
    return AutoclipChannelConfig(
        enabled=enabled,
        cooldown_seconds=cooldown_seconds,
        burst=BurstTriggerConfig(
            window_seconds=burst_window, unique_authors_threshold=burst_threshold,
            auto_scale_enabled=auto_scale_enabled, auto_scale_percent=auto_scale_percent,
            auto_scale_min=auto_scale_min, auto_scale_max=auto_scale_max,
        ),
        keyword=KeywordTriggerConfig(phrases=keyword_phrases),
        voice=VoiceTriggerConfig(phrases=voice_phrases),
    )


def make_helix(handler) -> HelixClient:  # type: ignore[no-untyped-def]
    return HelixClient(
        "cid", "csecret", transport=httpx.MockTransport(handler),
        max_requests_per_second=1000.0, backoff_base_seconds=0.0,
    )


def make_clip_token_manager(tmp_path: Path) -> ClipTokenManager:
    # ClipTokenManager всегда считает свежепереданный в конструктор токен
    # "требующим проверки сейчас" (_expires_at=0.0, см. clip_token.py) —
    # значит первый же get_valid_access_token() обновит его, и transport
    # должен уметь ответить на этот refresh-запрос. db_path здесь не
    # обязан существовать заранее — используется только при _refresh().
    from cigilbot.integrations.clip_token import ClipTokenState

    state = ClipTokenState(access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99")

    def refresh_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 14400},
        )

    return ClipTokenManager(
        client_id="cid", client_secret="csecret", db_path=str(tmp_path / "mod.1.db"), state=state,
        transport=httpx.MockTransport(refresh_handler),
    )


async def _drain(autoclip: ChannelAutoclip) -> None:
    await autoclip._queue.join()


class TestChannelAutoclipBurst:
    async def test_burst_fires_at_threshold(self, tmp_path: Path) -> None:
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(burst_threshold=3),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="hi", timestamp=0.0)
            autoclip.submit_chat_message(author_id="b", text="hi", timestamp=0.5)
            assert clip_calls == []
            autoclip.submit_chat_message(author_id="c", text="hi", timestamp=1.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert len(clip_calls) == 1

    async def test_single_author_flooding_does_not_trigger_burst(self, tmp_path: Path) -> None:
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(burst_threshold=3),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            for i in range(10):
                autoclip.submit_chat_message(author_id="flooder", text="hi", timestamp=float(i) * 0.1)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert clip_calls == []


class TestChannelAutoclipKeyword:
    async def test_keyword_matches_normalized_variant(self, tmp_path: Path) -> None:
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип это",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="КЛИП ЭТО!!!", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert len(clip_calls) == 1

    async def test_no_match_does_not_fire(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("не должно быть вызова Helix без совпадения")

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип это",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="привет как дела", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()


class TestChannelAutoclipCooldown:
    async def test_second_chat_trigger_within_cooldown_is_blocked(self, tmp_path: Path) -> None:
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип",), cooldown_seconds=300.0),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
            autoclip.submit_chat_message(author_id="b", text="клип", timestamp=10.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert len(clip_calls) == 1

    async def test_voice_command_bypasses_cooldown(self, tmp_path: Path) -> None:
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип",), voice_phrases=("клип это",), cooldown_seconds=300.0),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
            assert len(clip_calls) == 1

            # тот же канал, кулдаун ещё активен — но голос его не проверяет
            autoclip.submit_voice_command(text="клип это", timestamp=10.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert len(clip_calls) == 2

    async def test_helix_call_uses_correct_broadcaster_id(self, tmp_path: Path) -> None:
        seen_broadcaster_ids: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_broadcaster_ids.append(request.url.params["broadcaster_id"])
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="42",
            config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert seen_broadcaster_ids == ["42"]


class TestChannelAutoclipDisabled:
    async def test_disabled_config_never_triggers(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("выключенный автоклип не должен вызывать Helix")

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(enabled=False, keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()


async def _registry_with(tmp_path: Path, channels: list[tuple[str, str, str]]) -> Path:
    """channels: [(broadcaster_id, login, desired_state)] — тот же приём,
    что test_pipeline.py::_registry_with."""
    db = tmp_path / "registry.db"
    store = RegistryStore(str(db))
    await store.connect()
    for broadcaster_id, login, desired in channels:
        await store.upsert_channel(broadcaster_id=broadcaster_id, login=login, registered_by="test")
        await store.set_desired_state(broadcaster_id, desired)
    await store.close()
    return db


class TestAutoclipHubDisabled:
    async def test_disabled_hub_starts_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=False)
        await hub.start()
        try:
            assert hub.active_channels == []
        finally:
            await hub.stop()

    async def test_missing_credentials_does_not_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PANEL_TWITCH_CLIENT_ID", raising=False)
        monkeypatch.delenv("PANEL_TWITCH_CLIENT_SECRET", raising=False)
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True)
        await hub.start()
        try:
            assert hub.active_channels == []
        finally:
            await hub.stop()

    async def test_missing_clip_token_does_not_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Канал без токена клиппинга (mod_clip_token пуст) не запускает
        автоклип на СЕБЕ, но не мешает Hub'у стартовать вообще — другое
        поведение по сравнению со старым "один общий токен на процесс",
        см. AutoclipHub._start_channel."""
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True)
        await hub.start()
        try:
            assert hub.active_channels == []
        finally:
            await hub.stop()


async def _write_clip_token(broadcaster_id: str = "1") -> None:
    """Токен клиппинга per-channel (mod_clip_token, mod.<broadcaster_id>.db)
    — записывается через ту же ModerationStore, что использует
    AutoclipHub._start_channel (paths.mod_db(broadcaster_id), см.
    load_clip_token_manager). Требует, чтобы paths.MOD_VAR уже был
    monkeypatch-нут на tmp_path перед вызовом."""
    store = ModerationStore(str(paths.mod_db(broadcaster_id)))
    await store.connect()
    await store.set_clip_token(
        access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99"
    )
    await store.close()


class TestAutoclipHubEnabledOverride:
    """Живой рубильник из панели (mod_autoclip_settings) поверх
    autoclip.enabled из YAML — см. AutoclipHub._sync_enabled_overrides /
    _read_enabled_override / _start_channel."""

    async def test_panel_can_enable_channel_yaml_disables(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """YAML говорит enabled=false (или файла нет вовсе), но панель explicitly
        включила канал через mod_autoclip_settings — канал должен запуститься."""
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        mod_store = ModerationStore(str(paths.mod_db("1")))
        await mod_store.connect()
        await mod_store.set_autoclip_enabled(True, updated_by="admin1")
        await mod_store.close()

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True)
        await hub.start()
        try:
            assert hub.active_channels == ["alpha"]
        finally:
            await hub.stop()

    async def test_panel_can_disable_already_running_channel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Канал уже поднят (YAML enabled=true), панель выключает его через
        mod_autoclip_settings — _sync_enabled_overrides должен переключить
        существующий ChannelAutoclip.enabled на месте, без пересоздания."""
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text("autoclip:\n  enabled: true\n", encoding="utf-8")
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            assert hub.active_channels == ["alpha"]
            autoclip = hub._channels["1"]
            enabled_before: bool = autoclip.enabled
            assert enabled_before is True

            mod_store = ModerationStore(str(paths.mod_db("1")))
            await mod_store.connect()
            await mod_store.set_autoclip_enabled(False, updated_by="mod1")
            await mod_store.close()

            await hub._reconcile()

            enabled_after: bool = autoclip.enabled
            assert enabled_after is False
            # Тот же объект, не пересозданный — состояние (BurstWindow,
            # кулдаун) не потеряно при выключении из панели.
            assert hub._channels["1"] is autoclip
        finally:
            await hub.stop()

    async def test_disabled_channel_ignores_triggers_after_panel_toggle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """После выключения из панели submit_chat_message перестаёт
        триггерить клипы — сквозной эффект живого рубильника, не только
        внутреннее поле enabled."""
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text(
            "autoclip:\n  enabled: true\n  keyword:\n    phrases: [\"клип\"]\n", encoding="utf-8"
        )
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            mod_store = ModerationStore(str(paths.mod_db("1")))
            await mod_store.connect()
            await mod_store.set_autoclip_enabled(False, updated_by="mod1")
            await mod_store.close()
            await hub._reconcile()

            hub.submit_chat_message(channel="alpha", author_id="a", text="клип", timestamp=0.0)
            autoclip = hub._channels["1"]
            assert autoclip._queue.qsize() == 0
        finally:
            await hub.stop()


def _empty_settings(**overrides: object) -> AutoclipSettings:
    base: dict[str, object] = {
        "enabled": None, "updated_by": "", "updated_at": 0.0,
        "burst_unique_authors_threshold": None, "burst_window_seconds": None,
        "keyword_phrases": None, "voice_phrases": None, "cooldown_seconds": None,
    }
    base.update(overrides)
    return AutoclipSettings(**base)  # type: ignore[arg-type]


class TestMergeConfig:
    """_merge_config — чистая функция, юнит-тесты без AutoclipHub/БД."""

    def test_no_overrides_returns_yaml_values(self) -> None:
        yaml_config = make_config(burst_threshold=12, cooldown_seconds=300.0)
        merged = _merge_config(yaml_config, _empty_settings(), enabled=True)
        assert merged.burst.unique_authors_threshold == 12
        assert merged.cooldown_seconds == 300.0
        assert merged.keyword.phrases == yaml_config.keyword.phrases

    def test_burst_threshold_override_wins(self) -> None:
        yaml_config = make_config(burst_threshold=12)
        settings = _empty_settings(burst_unique_authors_threshold=5)
        merged = _merge_config(yaml_config, settings, enabled=True)
        assert merged.burst.unique_authors_threshold == 5

    def test_burst_window_override_wins(self) -> None:
        yaml_config = make_config(burst_window=20.0)
        settings = _empty_settings(burst_window_seconds=8.0)
        merged = _merge_config(yaml_config, settings, enabled=True)
        assert merged.burst.window_seconds == 8.0

    def test_keyword_phrases_override_wins(self) -> None:
        yaml_config = make_config(keyword_phrases=("клип это",))
        settings = _empty_settings(keyword_phrases=("клип", "clip it"))
        merged = _merge_config(yaml_config, settings, enabled=True)
        assert merged.keyword.phrases == ("клип", "clip it")

    def test_voice_phrases_override_wins(self) -> None:
        yaml_config = make_config(voice_phrases=("клип это",))
        settings = _empty_settings(voice_phrases=("заклипай",))
        merged = _merge_config(yaml_config, settings, enabled=True)
        assert merged.voice.phrases == ("заклипай",)

    def test_cooldown_override_wins(self) -> None:
        yaml_config = make_config(cooldown_seconds=300.0)
        settings = _empty_settings(cooldown_seconds=60.0)
        merged = _merge_config(yaml_config, settings, enabled=True)
        assert merged.cooldown_seconds == 60.0

    def test_partial_override_leaves_other_fields_from_yaml(self) -> None:
        yaml_config = make_config(burst_threshold=12, cooldown_seconds=300.0, keyword_phrases=("клип",))
        settings = _empty_settings(burst_unique_authors_threshold=5)
        merged = _merge_config(yaml_config, settings, enabled=True)
        assert merged.burst.unique_authors_threshold == 5
        assert merged.cooldown_seconds == 300.0
        assert merged.keyword.phrases == ("клип",)

    def test_enabled_comes_from_explicit_parameter_not_yaml_or_settings(self) -> None:
        yaml_config = make_config(enabled=True)
        merged = _merge_config(yaml_config, _empty_settings(enabled=True), enabled=False)
        assert merged.enabled is False


class TestAutoclipHubThresholdOverride:
    """Живые пороги из панели (mod_autoclip_settings) применяются к уже
    работающему ChannelAutoclip без пересоздания объекта."""

    async def test_panel_can_change_burst_threshold_on_running_channel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text(
            "autoclip:\n  enabled: true\n  burst:\n    unique_authors_threshold: 12\n",
            encoding="utf-8",
        )
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            autoclip = hub._channels["1"]
            assert autoclip.config.burst.unique_authors_threshold == 12

            mod_store = ModerationStore(str(paths.mod_db("1")))
            await mod_store.connect()
            await mod_store.set_autoclip_thresholds(
                burst_unique_authors_threshold=3, burst_window_seconds=None,
                keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
                updated_by="mod1",
            )
            await mod_store.close()

            await hub._reconcile()

            # Тот же объект — состояние не потеряно при обновлении порогов.
            assert hub._channels["1"] is autoclip
            assert autoclip.config.burst.unique_authors_threshold == 3
        finally:
            await hub.stop()

    async def test_lowered_burst_threshold_takes_effect_on_next_trigger(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Сквозной эффект: после снижения порога через панель меньшее
        число уникальных авторов уже достаточно для клипа."""
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text(
            "autoclip:\n  enabled: true\n  burst:\n    unique_authors_threshold: 12\n"
            "    window_seconds: 20\n",
            encoding="utf-8",
        )
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            # Порог 12 — двух авторов недостаточно.
            hub.submit_chat_message(channel="alpha", author_id="a", text="hi", timestamp=0.0)
            hub.submit_chat_message(channel="alpha", author_id="b", text="hi", timestamp=0.5)
            autoclip = hub._channels["1"]
            assert autoclip._queue.qsize() == 0

            mod_store = ModerationStore(str(paths.mod_db("1")))
            await mod_store.connect()
            await mod_store.set_autoclip_thresholds(
                burst_unique_authors_threshold=2, burst_window_seconds=None,
                keyword_phrases=None, voice_phrases=None, cooldown_seconds=None,
                updated_by="mod1",
            )
            await mod_store.close()
            await hub._reconcile()

            # Новый BurstWindow пуст после apply_config? Нет — тот же
            # объект, накопленные записи "a"/"b" всё ещё в окне (20 сек),
            # третий автор с уже сниженным порогом 2 должен добрать до триггера
            # даже без них, но проверим именно эффект нового порога напрямую.
            hub.submit_chat_message(channel="alpha", author_id="c", text="hi", timestamp=1.0)
            assert autoclip._queue.qsize() >= 1
        finally:
            await hub.stop()


class TestScaledBurstThreshold:
    """_scaled_burst_threshold — чистая формула, юнит-тесты без AutoclipHub."""

    def test_percent_of_viewer_count(self) -> None:
        burst = BurstTriggerConfig(auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200)
        assert _scaled_burst_threshold(viewer_count=1000, burst=burst) == 40

    def test_rounds_to_nearest_not_truncates(self) -> None:
        burst = BurstTriggerConfig(auto_scale_percent=0.04, auto_scale_min=1, auto_scale_max=200)
        # 12.5 -> round-half-to-even даёт 12 в Python; главное — не int()-усечение до 12 по совпадению,
        # проверяем реальным неровным числом.
        assert _scaled_burst_threshold(viewer_count=313, burst=burst) == round(313 * 0.04)

    def test_clamped_to_minimum_on_tiny_channel(self) -> None:
        burst = BurstTriggerConfig(auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200)
        assert _scaled_burst_threshold(viewer_count=10, burst=burst) == 4

    def test_clamped_to_maximum_on_huge_channel(self) -> None:
        burst = BurstTriggerConfig(auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200)
        assert _scaled_burst_threshold(viewer_count=100_000, burst=burst) == 200

    def test_zero_viewers_clamped_to_minimum(self) -> None:
        burst = BurstTriggerConfig(auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200)
        assert _scaled_burst_threshold(viewer_count=0, burst=burst) == 4


class TestApplyAutoScale:
    """_apply_auto_scale — чистая функция, применяет формулу поверх готового
    AutoclipChannelConfig (после _merge_config)."""

    def test_disabled_auto_scale_leaves_config_unchanged(self) -> None:
        config = make_config(burst_threshold=12, auto_scale_enabled=False)
        result = _apply_auto_scale(config, viewer_count=1000)
        assert result is config

    def test_enabled_but_no_viewer_count_leaves_config_unchanged(self) -> None:
        """Стрим оффлайн или Twitch ещё не опрошен — последнее известное
        значение порога остаётся в силе, не сбрасывается."""
        config = make_config(burst_threshold=12, auto_scale_enabled=True)
        result = _apply_auto_scale(config, viewer_count=None)
        assert result is config

    def test_enabled_with_viewer_count_recomputes_threshold(self) -> None:
        config = make_config(
            burst_threshold=12, auto_scale_enabled=True,
            auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200,
        )
        result = _apply_auto_scale(config, viewer_count=1000)
        assert result.burst.unique_authors_threshold == 40

    def test_same_computed_value_returns_same_object(self) -> None:
        """Если формула даёт то же значение, что уже стоит — не создаём
        новый объект (важно для сравнения != в AutoclipHub._sync_overrides,
        которое решает, вызывать ли apply_config)."""
        config = make_config(
            burst_threshold=40, auto_scale_enabled=True,
            auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200,
        )
        result = _apply_auto_scale(config, viewer_count=1000)
        assert result is config

    def test_other_fields_untouched(self) -> None:
        config = make_config(
            burst_threshold=12, cooldown_seconds=123.0, keyword_phrases=("клип",),
            auto_scale_enabled=True, auto_scale_percent=0.04, auto_scale_min=4, auto_scale_max=200,
        )
        result = _apply_auto_scale(config, viewer_count=1000)
        assert result.cooldown_seconds == 123.0
        assert result.keyword.phrases == ("клип",)
        assert result.burst.window_seconds == config.burst.window_seconds


def make_helix_with_streams(streams_by_id: dict[str, int]) -> HelixClient:
    """streams_by_id: {broadcaster_id: viewer_count} — отсутствие ключа
    значит канал оффлайн (get_streams вернёт is_live=False для него)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "oauth2/token" in str(request.url):
            return httpx.Response(200, json={"access_token": "app-tok", "expires_in": 3600})
        requested = request.url.params.get_list("user_id")
        data = [
            {"user_id": uid, "viewer_count": streams_by_id[uid]}
            for uid in requested
            if uid in streams_by_id
        ]
        return httpx.Response(200, json={"data": data})

    return HelixClient(
        "cid", "csecret", transport=httpx.MockTransport(handler),
        max_requests_per_second=1000.0, backoff_base_seconds=0.0,
    )


class TestAutoclipHubViewerCountPolling:
    """AutoclipHub._poll_viewer_counts — опрос Twitch и применение формулы
    через тот же путь, что живой рубильник/пороги (_sync_overrides)."""

    async def test_poll_updates_threshold_for_auto_scale_channel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text(
            "autoclip:\n"
            "  enabled: true\n"
            "  burst:\n"
            "    unique_authors_threshold: 12\n"
            "    auto_scale_enabled: true\n"
            "    auto_scale_percent: 0.04\n"
            "    auto_scale_min: 4\n"
            "    auto_scale_max: 200\n",
            encoding="utf-8",
        )
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            hub._helix_client = make_helix_with_streams({"1": 1000})
            await hub._poll_viewer_counts()

            autoclip = hub._channels["1"]
            assert autoclip.config.burst.unique_authors_threshold == 12  # ещё не подхвачено

            await hub._reconcile()
            assert autoclip.config.burst.unique_authors_threshold == 40
        finally:
            await hub.stop()

    async def test_offline_channel_keeps_last_known_threshold(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text(
            "autoclip:\n"
            "  enabled: true\n"
            "  burst:\n"
            "    unique_authors_threshold: 12\n"
            "    auto_scale_enabled: true\n"
            "    auto_scale_percent: 0.04\n"
            "    auto_scale_min: 4\n"
            "    auto_scale_max: 200\n",
            encoding="utf-8",
        )
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            hub._helix_client = make_helix_with_streams({"1": 1000})
            await hub._poll_viewer_counts()
            await hub._reconcile()
            autoclip = hub._channels["1"]
            assert autoclip.config.burst.unique_authors_threshold == 40

            # Канал ушёл в оффлайн — get_streams вернёт is_live=False.
            hub._helix_client = make_helix_with_streams({})
            await hub._poll_viewer_counts()
            await hub._reconcile()

            assert autoclip.config.burst.unique_authors_threshold == 40
        finally:
            await hub.stop()

    async def test_does_not_poll_channels_without_auto_scale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(paths, "MOD_VAR", tmp_path)
        await _write_clip_token()

        channels_dir = tmp_path / "channels"
        channels_dir.mkdir()
        (channels_dir / "alpha.yml").write_text("autoclip:\n  enabled: true\n", encoding="utf-8")
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])

        hub = AutoclipHub(registry_db_path=db, autoclip_enabled=True, channels_dir=channels_dir)
        await hub.start()
        try:
            def handler(request: httpx.Request) -> httpx.Response:
                raise AssertionError("не должно быть вызова /streams без auto_scale-каналов")

            hub._helix_client = make_helix(handler)
            await hub._poll_viewer_counts()
        finally:
            await hub.stop()
