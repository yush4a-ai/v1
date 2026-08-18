"""Тесты ChannelAutoclip/AutoclipHub — end-to-end на моках HelixClient
(httpx.MockTransport, как test_twitch_api.py) и реальном RegistryStore
(как test_pipeline.py::_registry_with) для сверки состава каналов.
"""

from __future__ import annotations

import asyncio
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


async def make_store(tmp_path: Path, *, name: str = "mod.1.db") -> ModerationStore:
    """Персистентность результата клипа (bug-аудит 2026-08-18) — тесты
    ChannelAutoclip передают реальный (не мок) ModerationStore, чтобы
    проверять фактические записи в mod_clips через store._db.execute
    напрямую, тем же приёмом, что test_store.py/test_executor.py."""
    store = ModerationStore(str(tmp_path / name))
    await store.connect()
    return store


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
            store=await make_store(tmp_path),
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
            store=await make_store(tmp_path),
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
            store=await make_store(tmp_path),
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
            store=await make_store(tmp_path),
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
            store=await make_store(tmp_path),
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

    async def test_failed_clip_does_not_set_cooldown(self, tmp_path: Path) -> None:
        """Регрессия на bug-аудит 2026-08-15 (CRITICAL #2, исправлено в
        цикле 1): _create_clip раньше выставлял кулдаун даже когда Helix
        вернул неудачу (стрим офлайн, истёкший scope, транзиентная ошибка)
        — следующий genuine-триггер молча терялся на весь cooldown_seconds
        без единого сигнала оператору. Фикс уже в проде (bot/autoclip.py::
        _create_clip, ветка else), но не был защищён тестом от регрессии —
        см. handoff.md, пункт 7 плана. Первый триггер получает 400 от
        Helix (success=False) -> второй триггер должен всё равно вызвать
        Helix, а не быть молча отброшен _in_cooldown()."""
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            # 400, не 500/429 — HelixClient._request ретраит 5xx/429
            # внутри ОДНОГО create_clip() (см. twitch_api.py, MAX_RETRIES),
            # с 500 первый же триггер тихо "самоисцелился" бы повтором и
            # get success=True, не проверив то, что нужно этому тесту:
            # 400 не ретраится — create_clip() возвращает success=False
            # сразу, ровно как настоящий "истёкший scope"/невалидный запрос.
            if len(clip_calls) == 1:
                return httpx.Response(400, text="bad request")
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип",), cooldown_seconds=300.0),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=await make_store(tmp_path),
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
            autoclip.submit_chat_message(author_id="b", text="клип", timestamp=10.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        # Оба сообщения дошли до Helix — кулдаун не выставился после
        # неудачи первого, второй триггер не был отброшен _in_cooldown().
        assert len(clip_calls) == 2

    async def test_voice_command_bypasses_cooldown(self, tmp_path: Path) -> None:
        clip_calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            clip_calls.append(str(request.url))
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип",), voice_phrases=("клип это",), cooldown_seconds=300.0),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=await make_store(tmp_path),
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
            store=await make_store(tmp_path),
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
            store=await make_store(tmp_path),
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


class TestClipEngineStateMachine:
    """Adversarial-проверка Clip Engine (bug-аудит 2026-08-18): не просто
    "тесты зелёные", а по каждому переходу state machine —
    pending -> {created, failed, lost_after_success, unknown} — прямая
    проверка строки в mod_clips, а где возможно — искусственное
    воспроизведение падения процесса ПОСЛЕ POST к Twitch, но ДО того, как
    живой процесс успел записать исход. Раздельный класс от
    TestChannelAutoclipBurst/Keyword/Cooldown, которые проверяют триггеры,
    не персистентность."""

    async def _clip_row(self, store: ModerationStore) -> tuple[object, ...]:
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, clip_id, edit_url, error FROM mod_clips ORDER BY id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        assert row is not None
        return tuple(row)

    async def test_pending_row_exists_before_helix_is_even_called(self, tmp_path: Path) -> None:
        """Запись создаётся ДО обращения к Helix — если процесс падает
        прямо здесь (симулируем зависшим handler'ом, который никогда не
        отвечает), pending-запись уже лежит в БД, а не только в памяти."""
        store = await make_store(tmp_path)

        never_responds = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            # Пробуждается только в finally, когда проверка уже сделана —
            # возвращаем обычный ответ, а не бросаем исключение: assert
            # внутри httpx-транспортного потока не долетит до pytest и
            # только оставит грязный traceback после закрытия event loop.
            await never_responds.wait()
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path),
            helix_client=HelixClient(
                "cid", "csecret", transport=httpx.MockTransport(handler),
                max_requests_per_second=1000.0, backoff_base_seconds=0.0,
            ),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            # Не ждём _drain — намеренно: consumer завис внутри "POST", как
            # процесс, зависший в момент реального сетевого вызова.
            for _ in range(50):
                cursor = await store._db.execute(  # noqa: SLF001
                    "SELECT status FROM mod_clips"
                )
                row = await cursor.fetchone()
                if row is not None:
                    break
                await asyncio.sleep(0.01)
            assert row is not None
            assert row[0] == "pending"
        finally:
            never_responds.set()
            await _drain(autoclip)
            await autoclip.stop()

    async def test_202_transitions_pending_to_created_with_ids(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        status, clip_id, edit_url, error = await self._clip_row(store)
        assert status == "created"
        assert clip_id == "c1"
        assert edit_url == "http://x/c1"
        assert error is None

    async def test_429_transitions_pending_to_failed_not_unknown(self, tmp_path: Path) -> None:
        """429 — точно известно, что Twitch не создал клип (rate limit
        отклонён синхронно), поэтому failed, а не unknown, несмотря на то
        что 429 в остальных Helix-вызовах ретраится."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"message": "rate limited"})

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        status, clip_id, edit_url, error = await self._clip_row(store)
        assert status == "failed"
        assert clip_id is None

    async def test_400_transitions_pending_to_failed(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="invalid request")

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        status, clip_id, edit_url, error = await self._clip_row(store)
        assert status == "failed"
        assert clip_id is None

    async def test_5xx_transitions_pending_to_unknown_not_failed(self, tmp_path: Path) -> None:
        """503 — исход неопределён с точки зрения клиента (запрос мог дойти
        и обработаться на стороне Twitch уже после ответа с ошибкой) —
        значит unknown, не failed, чтобы не потерять данные молча и не
        считать твёрдо установленным то, что не установлено."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="internal error")

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        status, clip_id, edit_url, error = await self._clip_row(store)
        assert status == "unknown"
        assert clip_id is None

    async def test_transport_error_transitions_pending_to_unknown(self, tmp_path: Path) -> None:
        """Соединение оборвалось (ConnectError/ReadTimeout — httpx не
        различает "запрос не ушёл" от "запрос ушёл, ответ не пришёл" одним
        except TransportError) — то же самое: неопределённость, не failed."""
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        status, clip_id, edit_url, error = await self._clip_row(store)
        assert status == "unknown"
        assert clip_id is None

    async def test_create_clip_is_not_retried_after_5xx(self, tmp_path: Path) -> None:
        """retry=False специфично для create_clip (в отличие от остальных
        Helix-методов) — POST create_clip не идемпотентен, повторный вызов
        внутри одной попытки рисковал бы создать второй клип на реальный
        503, который на самом деле мог успеть обработаться."""
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(503, text="internal error")

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert calls == 1

    async def test_db_failure_after_confirmed_202_lands_lost_after_success_not_silent_loss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Симулируем падение процесса МЕЖДУ подтверждённым 202 от Twitch и
        успешной записью mark_clip_created (например БД временно
        заблокирована другим writer'ом) — clip_id/edit_url уже известны
        живому процессу, это не 'unknown', а mark_clip_lost_after_success:
        данные не теряются, попытка помечается как потребовавшая подстраховки."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(202, json={"data": [{"id": "c1", "edit_url": "http://x/c1"}]})

        store = await make_store(tmp_path)

        original_mark_created = store.mark_clip_created

        async def failing_mark_created(*args: object, **kwargs: object) -> None:
            raise RuntimeError("БД заблокирована другим writer'ом (симуляция)")

        monkeypatch.setattr(store, "mark_clip_created", failing_mark_created)

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        # Восстанавливаем реальный метод, чтобы прочитать результат напрямую.
        monkeypatch.setattr(store, "mark_clip_created", original_mark_created)
        status, clip_id, edit_url, error = await self._clip_row(store)
        assert status == "lost_after_success"
        assert clip_id == "c1"
        assert edit_url == "http://x/c1"
        assert error is not None

    async def test_cold_restart_after_crash_during_post_marks_pending_as_unknown(
        self, tmp_path: Path
    ) -> None:
        """Полная симуляция сценария из аудита: процесс падает МЕЖДУ
        create_clip_attempt (pending уже в БД) и получением ответа Twitch —
        новый процесс на канале не видит эту попытку в памяти вовсе (свежий
        ChannelAutoclip, свежая очередь), но старая pending-запись всё ещё
        в БД. Стартовая уборка _consume() должна перевести её в unknown ДО
        обработки первого нового события, не позже и не через retry."""
        store = await make_store(tmp_path)

        # "Упавший" процесс: успел создать pending-запись, но так и не
        # дошёл до ответа Twitch (эквивалент kill -9 посреди HTTP-запроса).
        stale_attempt_id = await store.create_clip_attempt(
            created_at=1000.0, trigger_reason="burst", trigger_text="pog x5"
        )
        status_before, *_rest = await self._clip_row_by_id(store, stale_attempt_id)
        assert status_before == "pending"

        # "Новый" процесс поднимает канал заново — ничего не знает о
        # предыдущей попытке кроме того, что лежит в БД.
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("новый триггер в этом тесте не подаётся")

        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1", config=make_config(keyword_phrases=("клип",)),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            for _ in range(50):
                status, *_rest = await self._clip_row_by_id(store, stale_attempt_id)
                if status != "pending":
                    break
                await asyncio.sleep(0.01)
        finally:
            await autoclip.stop()

        status_after, clip_id, edit_url, error = await self._clip_row_by_id(store, stale_attempt_id)
        assert status_after == "unknown"
        assert clip_id is None
        assert error is None  # стартовая уборка не знает причины, в отличие от mark_clip_unknown

    async def test_unknown_outcome_is_not_automatically_retried(self, tmp_path: Path) -> None:
        """Явное требование аудита: устойчивость к неопределённости, не
        идемпотентность через авто-retry. unknown-попытка остаётся ровно
        одной строкой — следующий genuine-триггер создаёт НЕЗАВИСИМУЮ новую
        попытку (новый id), а не трогает старую."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(503, text="internal error")

        store = await make_store(tmp_path)
        autoclip = ChannelAutoclip(
            channel="chan", broadcaster_id="1",
            config=make_config(keyword_phrases=("клип",), cooldown_seconds=0.0),
            clip_token_manager=make_clip_token_manager(tmp_path), helix_client=make_helix(handler),
            store=store,
        )
        autoclip.start()
        try:
            autoclip.submit_chat_message(author_id="a", text="клип", timestamp=0.0)
            await _drain(autoclip)
        finally:
            await autoclip.stop()

        assert call_count == 1
        cursor = await store._db.execute("SELECT COUNT(*) FROM mod_clips")  # noqa: SLF001
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1

    async def test_lost_after_success_row_is_not_touched_by_stale_cleanup(
        self, tmp_path: Path
    ) -> None:
        """Стартовая уборка (mark_stale_pending_clips_unknown) трогает
        только status='pending' — lost_after_success уже несёт
        подтверждённый clip_id, переписывать его в unknown значило бы
        деградировать точную информацию до неопределённости."""
        store = await make_store(tmp_path)
        attempt_id = await store.create_clip_attempt(
            created_at=1000.0, trigger_reason="burst", trigger_text="pog"
        )
        await store.mark_clip_lost_after_success(
            attempt_id, clip_id="c1", edit_url="http://x/c1", error="запись не удалась"
        )

        reclaimed = await store.mark_stale_pending_clips_unknown()

        assert reclaimed == 0
        status, clip_id, edit_url, error = await self._clip_row_by_id(store, attempt_id)
        assert status == "lost_after_success"
        assert clip_id == "c1"

    async def _clip_row_by_id(self, store: ModerationStore, clip_attempt_id: int) -> tuple[object, ...]:
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, clip_id, edit_url, error FROM mod_clips WHERE id = ?",
            (clip_attempt_id,),
        )
        row = await cursor.fetchone()
        assert row is not None
        return tuple(row)
