"""Тесты RegistryStore — bug-аудит 2026-08-15, HIGH #10: registry.db
единственный писатель состояния процессов (структурное правило CLAUDE.md
— "process_status пишет только supervisor.py/ModerationHub, панель никогда
напрямую"), и до этого файла у него не было ни одного прямого теста.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.storage.registry_store import RegistryStore


@pytest.fixture
async def store(tmp_path: Path) -> RegistryStore:
    s = RegistryStore(str(tmp_path / "registry.db"))
    await s.connect()
    return s


class TestUpsertChannel:
    async def test_creates_new_channel_with_defaults(self, store: RegistryStore) -> None:
        record = await store.upsert_channel(broadcaster_id="1", login="alpha")

        assert record.broadcaster_id == "1"
        assert record.login == "alpha"
        assert record.status == "active"
        assert record.desired_state == "stopped"
        assert record.process_status == "stopped"
        assert record.pid is None
        assert record.restart_count == 0
        assert record.registered_by == "sync"

    async def test_registered_by_is_recorded(self, store: RegistryStore) -> None:
        record = await store.upsert_channel(broadcaster_id="1", login="alpha", registered_by="manual")
        assert record.registered_by == "manual"

    async def test_idempotent_on_broadcaster_id(self, store: RegistryStore) -> None:
        """Идемпотентно по broadcaster_id — безопасно вызывать повторно
        (нужно для ретраев POST /api/registry/channels)."""
        first = await store.upsert_channel(broadcaster_id="1", login="alpha")
        second = await store.upsert_channel(broadcaster_id="1", login="alpha")
        assert first.id == second.id

        channels = await store.list_channels(status=None)
        assert len(channels) == 1

    async def test_updates_login_on_rename(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="old_name")
        updated = await store.upsert_channel(broadcaster_id="1", login="new_name")
        assert updated.login == "new_name"

    async def test_does_not_reset_desired_state_on_repeat_upsert(self, store: RegistryStore) -> None:
        """Синхронизация состава каналов не должна случайно перезапускать/
        останавливать уже управляемый процесс — upsert на существующий
        канал не трогает desired_state/process_status."""
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.set_desired_state("1", "running")
        await store.update_process_state("1", process_status="running", pid=1234)

        updated = await store.upsert_channel(broadcaster_id="1", login="alpha_renamed")
        assert updated.desired_state == "running"
        assert updated.process_status == "running"
        assert updated.pid == 1234


class TestGetChannel:
    async def test_returns_none_for_unknown_broadcaster_id(self, store: RegistryStore) -> None:
        assert await store.get_channel("nonexistent") is None

    async def test_returns_record_for_known_channel(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        record = await store.get_channel("1")
        assert record is not None
        assert record.login == "alpha"


class TestListChannels:
    async def test_default_filters_to_active_status(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.upsert_channel(broadcaster_id="2", login="beta")

        channels = await store.list_channels()
        assert {c.broadcaster_id for c in channels} == {"1", "2"}

    async def test_status_none_returns_all(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        channels = await store.list_channels(status=None)
        assert len(channels) == 1

    async def test_ordered_by_login(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="2", login="zebra")
        await store.upsert_channel(broadcaster_id="1", login="alpha")

        channels = await store.list_channels(status=None)
        assert [c.login for c in channels] == ["alpha", "zebra"]

    async def test_empty_registry_returns_empty_list(self, store: RegistryStore) -> None:
        assert await store.list_channels() == []


class TestSetDesiredState:
    async def test_updates_desired_state(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.set_desired_state("1", "running")

        record = await store.get_channel("1")
        assert record is not None
        assert record.desired_state == "running"

    async def test_does_not_touch_process_status(self, store: RegistryStore) -> None:
        """desired_state ("что должно быть") и process_status ("что есть
        по факту") — независимые поля, см. докстринг update_process_state."""
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.set_desired_state("1", "running")

        record = await store.get_channel("1")
        assert record is not None
        assert record.process_status == "stopped"


class TestUpdateProcessState:
    async def test_writes_status_pid_and_heartbeat(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.update_process_state("1", process_status="running", pid=4242)

        record = await store.get_channel("1")
        assert record is not None
        assert record.process_status == "running"
        assert record.pid == 4242
        assert record.last_heartbeat_at is not None

    async def test_records_exit_code(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.update_process_state("1", process_status="crashed", last_exit_code=1)

        record = await store.get_channel("1")
        assert record is not None
        assert record.last_exit_code == 1

    async def test_increment_restart_count(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.update_process_state("1", process_status="running", increment_restart_count=True)
        await store.update_process_state("1", process_status="running", increment_restart_count=True)

        record = await store.get_channel("1")
        assert record is not None
        assert record.restart_count == 2

    async def test_without_increment_flag_restart_count_unchanged(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.update_process_state("1", process_status="running", increment_restart_count=True)
        await store.update_process_state("1", process_status="running")

        record = await store.get_channel("1")
        assert record is not None
        assert record.restart_count == 1

    async def test_clearing_pid_on_stop(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.update_process_state("1", process_status="running", pid=4242)
        await store.update_process_state("1", process_status="stopped", pid=None)

        record = await store.get_channel("1")
        assert record is not None
        assert record.pid is None


class TestResetCrash:
    async def test_resets_restart_count_and_status(self, store: RegistryStore) -> None:
        await store.upsert_channel(broadcaster_id="1", login="alpha")
        await store.update_process_state("1", process_status="crashed", increment_restart_count=True)
        await store.update_process_state("1", process_status="crashed", increment_restart_count=True)

        await store.reset_crash("1")

        record = await store.get_channel("1")
        assert record is not None
        assert record.restart_count == 0
        assert record.process_status == "stopped"

    async def test_unknown_broadcaster_id_is_a_noop(self, store: RegistryStore) -> None:
        # UPDATE на несуществующий broadcaster_id не создаёт строку и не
        # падает — тот же принцип, что set_desired_state/update_process_state.
        await store.reset_crash("nonexistent")
        assert await store.get_channel("nonexistent") is None


class TestConnectionLifecycle:
    async def test_using_store_before_connect_raises(self, tmp_path: Path) -> None:
        store = RegistryStore(str(tmp_path / "unconnected.db"))
        with pytest.raises(RuntimeError, match="connect"):
            await store.list_channels()

    async def test_close_before_connect_is_a_noop(self, tmp_path: Path) -> None:
        store = RegistryStore(str(tmp_path / "unconnected.db"))
        await store.close()
