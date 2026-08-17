"""Тесты движка модерации, работающего внутри процесса бота.

Слой, который этот модуль заменил (inbox.py + consumer.py + supervisor.py +
process_control.py), не был покрыт ни одним тестом — при том что именно
через него проходило каждое сообщение чата. Повторять это не стоит, тем
более что цена ошибки выросла: раньше сломанный consumer падал сам по
себе, теперь тот же код живёт в процессе, который читает чат.

Проверяется поведение, а не реализация: куда попадает событие, что
происходит при переполнении очереди, как состав каналов следует за
Registry и что сбой одного канала делает с остальными.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from cigilbot.domain.types import RiskLevel
from cigilbot.integrations.twitch_api import HelixClient
from cigilbot.orchestration import pipeline as pipeline_mod
from cigilbot.orchestration.pipeline import ChannelPipeline, ModerationHub
from cigilbot.storage.fingerprints_store import FingerprintStore
from cigilbot.storage.registry_store import RegistryStore


class StubEngine:
    """Движок с записью вызовов. Настоящий ModerationEngine тестируется в
    test_engine.py — здесь важно только то, что пайплайн его зовёт."""

    def __init__(self) -> None:
        self.seen: list[str] = []
        self.raids = 0
        self.fail_on: set[str] = set()
        self.known_bad_actor_syncs: list[frozenset[str]] = []

    async def observe(self, event):  # type: ignore[no-untyped-def]
        if event.text in self.fail_on:
            raise RuntimeError("движок сломался на этом сообщении")
        self.seen.append(event.text)
        return _verdict()

    def mark_raid_started(self) -> None:
        self.raids += 1

    def sync_known_bad_actors(self, user_ids: frozenset[str]) -> None:
        self.known_bad_actor_syncs.append(user_ids)


def _verdict(*, provisional: bool = False):  # type: ignore[no-untyped-def]
    class _V:
        is_provisional = provisional
        risk_level = RiskLevel.LOW
    return _V()


def _chat(text: str, *, channel: str = "streamer", user_id: str = "1") -> dict[str, object]:
    return {
        "kind": "chat_message",
        "user_id": user_id,
        "login": "viewer",
        "text": text,
        "timestamp": 0.0,
        "channel": channel,
    }


def _make_pipeline(tmp_path: Path, *, channel: str = "streamer") -> ChannelPipeline:
    """Пайплайн без start(): движок подменён, БД и Helix не нужны."""
    p = ChannelPipeline(
        broadcaster_id="1",
        channel=channel,
        mod_db_path=tmp_path / "mod.1.db",
        fingerprints_db_path=tmp_path / "fingerprints.db",
    )
    p.engine = StubEngine()  # type: ignore[assignment]
    return p


class TestSubmitDoesNotBlock:
    async def test_submit_is_not_a_coroutine(self, tmp_path: Path) -> None:
        """Главное свойство всей конструкции: обработчик сообщения чата не
        ждёт модерацию. Если submit когда-нибудь станет async, каждое
        сообщение начнёт оплачивать запись в SQLite и поход в Helix."""
        p = _make_pipeline(tmp_path)
        result = p.submit(_chat("привет"))
        assert result is True
        assert not asyncio.iscoroutine(result)

    async def test_events_are_processed_in_order(self, tmp_path: Path) -> None:
        """Движок стейтфул (скользящее окно, кластеры) — обработка не по
        порядку исказила бы кластеризацию."""
        p = _make_pipeline(tmp_path)
        for i in range(20):
            p.submit(_chat(f"msg-{i}"))

        task = asyncio.create_task(p._consume_queue())
        await p._queue.join()
        task.cancel()

        assert p.engine.seen == [f"msg-{i}" for i in range(20)]  # type: ignore[union-attr]

    async def test_engine_failure_does_not_stop_the_queue(self, tmp_path: Path) -> None:
        """Сбой на одном сообщении не должен останавливать разбор
        остальных: модерация наблюдает, она не вправе вставать колом."""
        p = _make_pipeline(tmp_path)
        p.engine.fail_on = {"плохое"}  # type: ignore[union-attr]
        for text in ("первое", "плохое", "третье"):
            p.submit(_chat(text))

        task = asyncio.create_task(p._consume_queue())
        await p._queue.join()
        task.cancel()

        assert p.engine.seen == ["первое", "третье"]  # type: ignore[union-attr]

    async def test_raid_event_reaches_engine(self, tmp_path: Path) -> None:
        # FALSE-BAN-001: рейд снижает чувствительность движка.
        p = _make_pipeline(tmp_path)
        p.submit({"kind": "raid_started", "channel": "streamer"})

        task = asyncio.create_task(p._consume_queue())
        await p._queue.join()
        task.cancel()

        assert p.engine.raids == 1  # type: ignore[union-attr]


class TestQueueOverflow:
    async def test_overflow_drops_and_counts_instead_of_blocking(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Осознанная цена переезда в память: mod_inbox лежала на диске и
        копилась без предела, очередь в памяти ограничена. Ждать здесь
        нельзя — ожидание дошло бы до чтения IRC, ровно того, чего вся
        конструкция избегает. Поэтому переполнение = потеря, и она должна
        быть посчитана, а не проглочена молча."""
        monkeypatch.setattr(pipeline_mod, "QUEUE_MAXSIZE", 3)
        p = _make_pipeline(tmp_path)

        accepted = [p.submit(_chat(f"m{i}")) for i in range(5)]

        assert accepted == [True, True, True, False, False]
        assert p.dropped == 2

    async def test_queue_accepts_again_after_drain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Переполнение — не терминальное состояние: как только движок
        разобрал накопленное, приём возобновляется."""
        monkeypatch.setattr(pipeline_mod, "QUEUE_MAXSIZE", 2)
        p = _make_pipeline(tmp_path)
        p.submit(_chat("a"))
        p.submit(_chat("b"))
        assert p.submit(_chat("c")) is False

        task = asyncio.create_task(p._consume_queue())
        await p._queue.join()
        task.cancel()

        assert p.submit(_chat("d")) is True


class _FakePipeline:
    """Подменяет ChannelPipeline в тестах хаба: настоящий тянет конфиг,
    миграции БД и Helix-клиентов, а проверяется здесь только состав
    каналов и маршрутизация."""

    instances: list[_FakePipeline] = []
    fail_start_for: set[str] = set()

    def __init__(
        self,
        *,
        broadcaster_id: str,
        channel: str,
        mod_db_path: Path,
        fingerprints_db_path: Path,
        mod_token_manager: object | None = None,
    ) -> None:
        self.broadcaster_id = broadcaster_id
        self.channel = channel
        self.mod_db_path = mod_db_path
        self.fingerprints_db_path = fingerprints_db_path
        self.mod_token_manager = mod_token_manager
        self.started = False
        self.stopped = False
        self.submitted: list[dict[str, object]] = []
        # Настоящий ChannelPipeline создаёт engine в start() — фейк не
        # поднимает реальный движок, ModerationHub._sync_fingerprints()
        # должен пропускать пайплайны без него, не падать. Аннотация
        # StubEngine | None (не None) — тесты присваивают StubEngine после
        # создания (см. TestHubFingerprintSync), и mypy должен это принимать.
        self.engine: StubEngine | None = None
        _FakePipeline.instances.append(self)

    async def start(self) -> None:
        if self.broadcaster_id in _FakePipeline.fail_start_for:
            raise RuntimeError("не удалось поднять движок канала")
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def submit(self, payload: dict[str, object]) -> bool:
        self.submitted.append(payload)
        return True


@pytest.fixture(autouse=True)
def _reset_fake_pipeline() -> None:
    _FakePipeline.instances = []
    _FakePipeline.fail_start_for = set()


@pytest.fixture
def fake_pipeline(monkeypatch: pytest.MonkeyPatch) -> type[_FakePipeline]:
    monkeypatch.setattr(pipeline_mod, "ChannelPipeline", _FakePipeline)
    return _FakePipeline


async def _registry_with(tmp_path: Path, channels: list[tuple[str, str, str]]) -> Path:
    """channels: [(broadcaster_id, login, desired_state)]"""
    db = tmp_path / "registry.db"
    store = RegistryStore(str(db))
    await store.connect()
    for broadcaster_id, login, desired in channels:
        await store.upsert_channel(
            broadcaster_id=broadcaster_id, login=login, registered_by="test"
        )
        await store.set_desired_state(broadcaster_id, desired)
    await store.close()
    return db


class TestHubRouting:
    async def test_event_goes_to_the_pipeline_of_its_channel(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        """Состояние каналов не смешивается — движок стейтфул, и сообщение
        одного канала не должно попасть в окно другого."""
        db = await _registry_with(
            tmp_path, [("1", "alpha", "running"), ("2", "beta", "running")]
        )
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            hub.submit(_chat("для alpha", channel="alpha"))
            hub.submit(_chat("для beta", channel="beta"))

            by_channel = {p.channel: p for p in fake_pipeline.instances}
            assert [e["text"] for e in by_channel["alpha"].submitted] == ["для alpha"]
            assert [e["text"] for e in by_channel["beta"].submitted] == ["для beta"]
        finally:
            await hub.stop()

    async def test_channel_name_is_normalised(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        # twitchio отдаёт имя канала как есть; в Registry оно нормализовано.
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            assert hub.submit(_chat("x", channel="#Alpha")) is True
        finally:
            await hub.stop()

    async def test_unknown_channel_is_counted_not_raised(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        """Бот может сидеть в канале, чья модерация выключена через панель.
        Это не ошибка — но и не повод молчать: счётчик отличает такой
        случай от «движок работает»."""
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            assert hub.submit(_chat("x", channel="unknown")) is False
            assert hub.dropped_unknown_channel == 1
        finally:
            await hub.stop()

    async def test_disabled_hub_accepts_nothing_and_starts_nothing(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        # MODERATION_ENABLED=false: бот работает, движок не поднимается.
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db, moderation_enabled=False)
        await hub.start()
        try:
            assert fake_pipeline.instances == []
            assert hub.submit(_chat("x", channel="alpha")) is False
        finally:
            await hub.stop()


class TestHubSharesOneModTokenManager:
    """bug-аудит 2026-08-17, HIGH: раньше каждый ChannelPipeline создавал
    свой ModTokenManager из общего .env — Twitch ротирует refresh_token при
    каждом обмене, второй канал получал invalid_grant (см. test_mod_token.py
    ::TestConcurrentManagersOnSharedEnv для гонки на уровне менеджера).
    Здесь проверяется структурная сторона фикса: ModerationHub создаёт
    ОДИН ModTokenManager и передаёт один и тот же объект каждому каналу."""

    async def test_all_pipelines_receive_the_same_manager_instance(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _SentinelManager:
            closed = False

            async def close(self) -> None:
                self.closed = True

        sentinel = _SentinelManager()
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_ID", "cid")
        monkeypatch.setenv("PANEL_TWITCH_CLIENT_SECRET", "csecret")
        monkeypatch.setattr(pipeline_mod, "load_mod_token_manager", lambda **kwargs: sentinel)

        db = await _registry_with(
            tmp_path, [("1", "alpha", "running"), ("2", "beta", "running")]
        )
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            assert len(fake_pipeline.instances) == 2
            managers = {id(p.mod_token_manager) for p in fake_pipeline.instances}
            assert managers == {id(sentinel)}, "оба канала должны получить один и тот же инстанс"
        finally:
            await hub.stop()

        assert sentinel.closed is True

    async def test_no_client_credentials_means_no_manager(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PANEL_TWITCH_CLIENT_ID", raising=False)
        monkeypatch.delenv("PANEL_TWITCH_CLIENT_SECRET", raising=False)

        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            assert fake_pipeline.instances[0].mod_token_manager is None
        finally:
            await hub.stop()


class TestHubReconcile:
    async def test_only_channels_wanted_running_are_started(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        db = await _registry_with(
            tmp_path, [("1", "alpha", "running"), ("2", "beta", "stopped")]
        )
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            assert hub.active_channels == ["alpha"]
        finally:
            await hub.stop()

    async def test_stop_request_shuts_the_channel_down(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        """Панель выставляет desired_state и больше ничего не делает —
        раньше исполнением занимался supervisor в её процессе, теперь бот
        сам сверяется с реестром."""
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            store = RegistryStore(str(db))
            await store.connect()
            await store.set_desired_state("1", "stopped")
            await store.close()

            await hub._reconcile()

            assert hub.active_channels == []
            assert fake_pipeline.instances[0].stopped is True
            assert hub.submit(_chat("x", channel="alpha")) is False
        finally:
            await hub.stop()

    async def test_renamed_channel_is_rerouted(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        """Каналы ключуются по broadcaster_id именно потому, что login
        меняется при переименовании. Маршрутизация же идёт по login —
        twitchio знает только его."""
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            store = RegistryStore(str(db))
            await store.connect()
            await store.upsert_channel(broadcaster_id="1", login="alpha_new")
            await store.close()

            await hub._reconcile()

            assert hub.submit(_chat("x", channel="alpha_new")) is True
            assert hub.submit(_chat("x", channel="alpha")) is False
            # Пайплайн тот же самый — канал не перезапускался, состояние
            # движка (окно, кластеры) переименование пережило.
            assert len(fake_pipeline.instances) == 1
        finally:
            await hub.stop()

    async def test_failed_channel_does_not_take_down_the_others(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        """Главная потеря переезда в один процесс — изоляция падений, и
        именно поэтому сбой запуска одного канала обязан быть локальным.
        Чат важнее модерации одного канала."""
        fake_pipeline.fail_start_for = {"1"}
        db = await _registry_with(
            tmp_path, [("1", "alpha", "running"), ("2", "beta", "running")]
        )
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            assert hub.active_channels == ["beta"]
            assert hub.submit(_chat("x", channel="beta")) is True
        finally:
            await hub.stop()

    async def test_failed_channel_is_marked_crashed_for_the_panel(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        fake_pipeline.fail_start_for = {"1"}
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            store = RegistryStore(str(db))
            await store.connect()
            record = await store.get_channel("1")
            await store.close()
            assert record is not None
            assert record.process_status == "crashed"
        finally:
            await hub.stop()

    async def test_new_channel_is_picked_up_on_next_tick(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        try:
            store = RegistryStore(str(db))
            await store.connect()
            await store.upsert_channel(broadcaster_id="2", login="beta")
            await store.set_desired_state("2", "running")
            await store.close()

            await hub._reconcile()

            assert hub.active_channels == ["alpha", "beta"]
        finally:
            await hub.stop()

    async def test_stop_shuts_every_channel_down(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        db = await _registry_with(
            tmp_path, [("1", "alpha", "running"), ("2", "beta", "running")]
        )
        hub = ModerationHub(registry_db_path=db)
        await hub.start()
        await hub.stop()

        assert all(p.stopped for p in fake_pipeline.instances)
        assert hub.active_channels == []


class TestPollActionQueueUsesOwnBroadcasterId:
    """BUG-005 аудита: токен модератора один на процесс (User Access Token
    аккаунта бота, годен для любого канала, где бот реально модератор), но
    ModTokenState.broadcaster_id — значение, записанное в .env один раз для
    ОДНОГО канала, выбранного при получении токена. При двух и более
    каналах под одной панелью second-канал исполнял бы задания с
    broadcaster_id ПЕРВОГО, если бы ActionExecutor строился по
    state.broadcaster_id, а не по self.broadcaster_id самого пайплайна —
    реальный инцидент 2026-08-13: таймаут для paverpapa исполнился на
    dobriy_yura."""

    async def test_executor_receives_pipeline_broadcaster_id_not_token_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cigilbot.integrations.mod_token import ModTokenManager
        from cigilbot.orchestration.executor import ActionExecutor

        pipeline = ChannelPipeline(
            broadcaster_id="second_channel",
            channel="beta",
            mod_db_path=tmp_path / "mod.2.db",
            fingerprints_db_path=tmp_path / "fingerprints.db",
        )

        fake_manager = object.__new__(ModTokenManager)
        # Токен получен на "первый_канал" — ровно сценарий бага: один общий
        # .env, TWITCH_MOD_BROADCASTER_ID записан для другого канала.
        fake_manager._access_token = "tok"  # noqa: SLF001
        fake_manager._refresh_token = "refresh"  # noqa: SLF001
        fake_manager._bot_user_id = "bot_user"  # noqa: SLF001
        fake_manager._broadcaster_id = "first_channel"  # noqa: SLF001
        fake_manager._expires_at = time.time() + 3600  # noqa: SLF001
        pipeline.mod_token_manager = fake_manager
        pipeline.helix_client = object.__new__(HelixClient)

        captured: dict[str, str] = {}

        class _StopLoop(Exception):
            pass

        async def fake_process_pending(executor: ActionExecutor, store: object) -> int:
            captured["broadcaster_id"] = executor._broadcaster_id  # noqa: SLF001
            return 0

        async def fake_sleep(seconds: float) -> None:
            # _poll_action_queue ловит все исключения из process_pending
            # (см. except Exception в самой функции) и продолжает цикл —
            # единственная точка, откуда можно остановить while True, не
            # изменяя саму функцию, это asyncio.sleep ПОСЛЕ первой итерации.
            raise _StopLoop

        monkeypatch.setattr(pipeline_mod, "process_pending", fake_process_pending)
        monkeypatch.setattr(asyncio, "sleep", fake_sleep)

        with pytest.raises(_StopLoop):
            await pipeline._poll_action_queue()

        assert captured["broadcaster_id"] == "second_channel"
        assert captured["broadcaster_id"] != "first_channel"


class TestHubFingerprintSync:
    """Cross-Channel Bot Fingerprint (направление 03 master-plan.html):
    ModerationHub читает fingerprints.db и раздаёт снимок каждому движку."""

    async def test_known_actors_reach_every_channel_engine(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        db = await _registry_with(
            tmp_path, [("1", "alpha", "running"), ("2", "beta", "running")]
        )
        fingerprints_path = tmp_path / "fingerprints.db"
        fp_store = FingerprintStore(str(fingerprints_path))
        await fp_store.connect()
        await fp_store.record_ban(
            user_id="bot1", login="bot1", banned_on_broadcaster_id="1", banned_on_login="alpha"
        )
        await fp_store.close()

        hub = ModerationHub(registry_db_path=db, fingerprints_db_path=fingerprints_path)
        await hub.start()
        try:
            for p in fake_pipeline.instances:
                p.engine = StubEngine()
            await hub._sync_fingerprints()  # noqa: SLF001

            for p in fake_pipeline.instances:
                assert p.engine is not None
                assert p.engine.known_bad_actor_syncs[-1] == frozenset({"bot1"})
        finally:
            await hub.stop()

    async def test_pipeline_without_engine_is_skipped(
        self, tmp_path: Path, fake_pipeline: type[_FakePipeline]
    ) -> None:
        # Пайплайн ещё не успел поднять движок (start() в процессе) — синк
        # не должен падать, engine остаётся None у фейка по умолчанию.
        db = await _registry_with(tmp_path, [("1", "alpha", "running")])
        hub = ModerationHub(registry_db_path=db, fingerprints_db_path=tmp_path / "fingerprints.db")
        await hub.start()
        try:
            await hub._sync_fingerprints()  # noqa: SLF001
        finally:
            await hub.stop()
