"""Тесты executor.py: разбор payload, исполнение, прогресс, аудит.

Всё на моках Helix через httpx.MockTransport — ни одного реального
запроса к Twitch (см. докстринг twitch_api.py).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

from cigilbot.integrations.twitch_api import HelixClient
from cigilbot.orchestration.executor import (
    DEFAULT_TIMEOUT_DURATION_SECONDS,
    MAX_TIMEOUT_DURATION_SECONDS,
    ActionExecutor,
    QueueAction,
    parse_payload,
    process_pending,
)
from cigilbot.storage.fingerprints_store import FingerprintStore
from cigilbot.storage.store import ModerationStore
from tests.conftest import EventFactory


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "executor_test.db"))
    await s.connect()
    return s


@pytest.fixture
async def fingerprint_store(tmp_path: Path) -> FingerprintStore:
    s = FingerprintStore(str(tmp_path / "fingerprints_test.db"))
    await s.connect()
    return s


def make_helix(handler) -> HelixClient:  # type: ignore[no-untyped-def]
    return HelixClient(
        "cid",
        "csecret",
        transport=httpx.MockTransport(handler),
        backoff_base_seconds=0.0,
        max_requests_per_second=1000.0,
    )


def ban_ok_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(200, json={"data": [{"user_id": body["data"]["user_id"]}]})


class TestParsePayload:
    def test_valid_ban_payload(self) -> None:
        req = parse_payload({"action": "BAN", "target_user_ids": ["1", "2"], "reason": "spam"})
        assert req.action == QueueAction.BAN
        assert req.target_user_ids == ("1", "2")
        assert req.reason == "spam"

    def test_valid_timeout_payload_with_duration(self) -> None:
        req = parse_payload(
            {"action": "TIMEOUT", "target_user_ids": ["1"], "duration_seconds": 300, "reason": "x"}
        )
        assert req.duration_seconds == 300

    def test_timeout_without_duration_stays_none(self) -> None:
        # None (не 600) — сигнал execute() посчитать прогрессивную
        # длительность по prior_timeouts (см. executor.py::_timeout_one),
        # дефолт больше не подставляется на уровне парсинга payload'а.
        req = parse_payload({"action": "TIMEOUT", "target_user_ids": ["1"], "reason": "x"})
        assert req.duration_seconds is None

    def test_valid_delete_messages_payload(self) -> None:
        req = parse_payload({"action": "DELETE_MESSAGES", "message_ids": ["m1", "m2"]})
        assert req.message_ids == ("m1", "m2")

    def test_missing_action_rejected(self) -> None:
        with pytest.raises(ValueError, match="action"):
            parse_payload({"target_user_ids": ["1"]})

    def test_unknown_action_rejected(self) -> None:
        with pytest.raises(ValueError, match="действие"):
            parse_payload({"action": "NUKE_EVERYTHING"})

    def test_ban_without_targets_rejected(self) -> None:
        with pytest.raises(ValueError, match="target_user_ids"):
            parse_payload({"action": "BAN", "target_user_ids": []})

    def test_delete_without_message_ids_rejected(self) -> None:
        with pytest.raises(ValueError, match="message_ids"):
            parse_payload({"action": "DELETE_MESSAGES", "message_ids": []})

    def test_non_string_list_rejected(self) -> None:
        with pytest.raises(ValueError, match="строк"):
            parse_payload({"action": "BAN", "target_user_ids": [1, 2, 3]})

    def test_non_int_duration_rejected(self) -> None:
        with pytest.raises(ValueError, match="duration_seconds"):
            parse_payload(
                {"action": "TIMEOUT", "target_user_ids": ["1"], "duration_seconds": "long"}
            )

    def test_cluster_id_propagated(self) -> None:
        req = parse_payload({"action": "BAN", "target_user_ids": ["1"], "cluster_id": 42})
        assert req.cluster_id == 42


class TestActionExecutorBan:
    async def test_all_succeed(self, store: ModerationStore) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload(
            {"action": "BAN", "target_user_ids": ["1", "2", "3"], "reason": "spam", "cluster_id": 7}
        )

        outcome = await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert outcome.succeeded == ("1", "2", "3")
        assert outcome.failed == ()
        assert outcome.summary == "3/3 выполнено"
        await helix.close()

    async def test_partial_failure(self, store: ModerationStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            uid = body["data"]["user_id"]
            if uid == "2":
                return httpx.Response(400, text="cannot ban broadcaster")
            return httpx.Response(200, json={"data": [{"user_id": uid}]})

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "BAN", "target_user_ids": ["1", "2", "3"], "reason": "spam"})

        outcome = await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert outcome.succeeded == ("1", "3")
        assert len(outcome.failed) == 1
        assert outcome.failed[0][0] == "2"
        assert "400" in outcome.summary or "с ошибкой" in outcome.summary
        await helix.close()

    async def test_writes_audit_record(self, store: ModerationStore) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload(
            {"action": "BAN", "target_user_ids": ["1", "2"], "reason": "known bot pattern", "cluster_id": 42}
        )

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT actor, actor_role, action, scope, cluster_id, succeeded, failed FROM mod_actions"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert tuple(row) == ("mod1", "MODERATOR", "BAN", "cluster", 42, 2, 0)
        await helix.close()

    async def test_scope_is_user_without_cluster_id(self, store: ModerationStore) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "BAN", "target_user_ids": ["1"], "reason": "x"})

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        cursor = await store._db.execute("SELECT scope FROM mod_actions")  # noqa: SLF001
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "user"
        await helix.close()


class TestActionExecutorBanFingerprint:
    """Cross-Channel Bot Fingerprint (направление 03 master-plan.html):
    executor.py пишет в fingerprints.db только после успешного BAN."""

    async def test_successful_ban_records_fingerprint(
        self, store: ModerationStore, fingerprint_store: FingerprintStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="bot1"))
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok",
            fingerprint_store=fingerprint_store, channel_login="dobriy_yura",
        )
        request = parse_payload(
            {"action": "BAN", "target_user_ids": ["1"], "reason": "known bot pattern"}
        )

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        actor = await fingerprint_store.get("1")
        assert actor is not None
        assert actor.login == "bot1"
        assert actor.banned_on_broadcaster_id == "B"
        assert actor.banned_on_login == "dobriy_yura"
        assert actor.reason == "known bot pattern"
        await helix.close()

    async def test_failed_ban_does_not_record_fingerprint(
        self, store: ModerationStore, fingerprint_store: FingerprintStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1", login="bot1"))
        helix = make_helix(lambda request: httpx.Response(400, text="cannot ban broadcaster"))
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok",
            fingerprint_store=fingerprint_store, channel_login="dobriy_yura",
        )
        request = parse_payload({"action": "BAN", "target_user_ids": ["1"], "reason": "x"})

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert await fingerprint_store.get("1") is None
        await helix.close()

    async def test_without_fingerprint_store_ban_still_succeeds(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        # fingerprint_store не передан (дефолт None, как во всех тестах
        # TestActionExecutorBan выше) — BAN не должен падать из-за этого.
        await store.upsert_user(event_factory(user_id="1", login="bot1"))
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "BAN", "target_user_ids": ["1"], "reason": "x"})

        outcome = await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert outcome.succeeded == ("1",)
        await helix.close()

    async def test_unknown_user_falls_back_to_user_id_as_login(
        self, store: ModerationStore, fingerprint_store: FingerprintStore
    ) -> None:
        # user_id без записи в mod_users (например, из-за гонки — BAN
        # исполнился раньше, чем upsert_user успел закоммититься) не должен
        # ронять запись в fingerprints.db.
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok",
            fingerprint_store=fingerprint_store, channel_login="dobriy_yura",
        )
        request = parse_payload({"action": "BAN", "target_user_ids": ["999"], "reason": "x"})

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        actor = await fingerprint_store.get("999")
        assert actor is not None
        assert actor.login == "999"
        await helix.close()


class TestActionExecutorTimeout:
    async def test_uses_configured_duration(self, store: ModerationStore) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            captured["duration"] = body["data"].get("duration")
            return httpx.Response(200, json={"data": [{"user_id": body["data"]["user_id"]}]})

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload(
            {"action": "TIMEOUT", "target_user_ids": ["1"], "duration_seconds": 900, "reason": "x"}
        )

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert captured["duration"] == 900
        await helix.close()

    async def test_explicit_duration_does_not_increment_prior_timeouts(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload(
            {"action": "TIMEOUT", "target_user_ids": ["1"], "duration_seconds": 900, "reason": "x"}
        )

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        state = await store.get_user_state("1")
        assert state is not None
        assert state.prior_timeouts == 0
        await helix.close()

    async def test_no_duration_uses_default_for_first_timeout(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            captured["duration"] = body["data"].get("duration")
            return httpx.Response(200, json={"data": [{"user_id": body["data"]["user_id"]}]})

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "TIMEOUT", "target_user_ids": ["1"], "reason": "x"})

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert captured["duration"] == DEFAULT_TIMEOUT_DURATION_SECONDS
        state = await store.get_user_state("1")
        assert state is not None
        assert state.prior_timeouts == 1
        await helix.close()

    async def test_no_duration_escalates_per_user_prior_timeouts(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        # "1" уже получал таймаут дважды, "2" — новичок в одном и том же
        # batch-запросе: длительность считается по каждому отдельно, а не
        # одним числом на весь кластер.
        await store.upsert_user(event_factory(user_id="1"))
        await store.increment_prior_timeouts("1")
        await store.increment_prior_timeouts("1")
        await store.upsert_user(event_factory(user_id="2"))

        durations = {}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            uid = body["data"]["user_id"]
            durations[uid] = body["data"].get("duration")
            return httpx.Response(200, json={"data": [{"user_id": uid}]})

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload(
            {"action": "TIMEOUT", "target_user_ids": ["1", "2"], "reason": "x"}
        )

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert durations["1"] == DEFAULT_TIMEOUT_DURATION_SECONDS * 4  # 2^2
        assert durations["2"] == DEFAULT_TIMEOUT_DURATION_SECONDS  # 2^0

        state1 = await store.get_user_state("1")
        state2 = await store.get_user_state("2")
        assert state1 is not None and state1.prior_timeouts == 3
        assert state2 is not None and state2.prior_timeouts == 1
        await helix.close()

    async def test_escalation_caps_at_max_duration(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))
        for _ in range(10):
            await store.increment_prior_timeouts("1")

        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            captured["duration"] = body["data"].get("duration")
            return httpx.Response(200, json={"data": [{"user_id": body["data"]["user_id"]}]})

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "TIMEOUT", "target_user_ids": ["1"], "reason": "x"})

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert captured["duration"] == MAX_TIMEOUT_DURATION_SECONDS
        await helix.close()

    async def test_failed_timeout_does_not_increment_prior_timeouts(
        self, store: ModerationStore, event_factory: EventFactory
    ) -> None:
        await store.upsert_user(event_factory(user_id="1"))
        helix = make_helix(lambda request: httpx.Response(400, text="user is a moderator"))
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "TIMEOUT", "target_user_ids": ["1"], "reason": "x"})

        await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        state = await store.get_user_state("1")
        assert state is not None
        assert state.prior_timeouts == 0
        await helix.close()


class TestActionExecutorDeleteMessages:
    async def test_deletes_each_message(self, store: ModerationStore) -> None:
        deleted_ids = []

        def handler(request: httpx.Request) -> httpx.Response:
            deleted_ids.append(request.url.params.get("message_id"))
            return httpx.Response(204)

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        request = parse_payload({"action": "DELETE_MESSAGES", "message_ids": ["m1", "m2"]})

        outcome = await executor.execute(request, actor="mod1", actor_role="MODERATOR")

        assert outcome.succeeded == ("m1", "m2")
        assert deleted_ids == ["m1", "m2"]
        await helix.close()


class TestProcessPending:
    async def test_processes_queued_item(self, store: ModerationStore) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1", "2"], "reason": "spam"},
        )

        processed = await process_pending(executor, store)

        assert processed == 1
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, progress_done, progress_total FROM mod_action_queue WHERE id = ?",
            (queue_id,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert tuple(row) == ("completed", 2, 2)
        await helix.close()

    async def test_malformed_payload_marks_failed_without_crashing(
        self, store: ModerationStore
    ) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR", payload={"action": "NOT_A_REAL_ACTION"}
        )

        processed = await process_pending(executor, store)

        assert processed == 1
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "failed"
        await helix.close()

    async def test_empty_queue_processes_zero(self, store: ModerationStore) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        processed = await process_pending(executor, store)
        assert processed == 0
        await helix.close()

    async def test_per_target_helix_failure_still_completes_queue_item(
        self, store: ModerationStore
    ) -> None:
        # Транспортная/HTTP ошибка на КОНКРЕТНОМ пользователе перехватывается
        # внутри HelixClient и превращается в ActionResult(success=False) —
        # задание в очереди при этом всё равно "completed" (с записью в
        # result_json.failed), а не "failed" целиком. Статус queue-level
        # "failed" зарезервирован за некорректным payload или неожиданным
        # исключением ВНУТРИ execute() — см. следующий тест.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        helix = make_helix(handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )

        processed = await process_pending(executor, store)

        assert processed == 1
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, result_json FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        status, result_json = row
        assert status == "completed"
        assert json.loads(result_json)["failed"]
        await helix.close()

    async def test_unexpected_exception_in_execute_marks_queue_item_failed(
        self, store: ModerationStore
    ) -> None:
        helix = make_helix(ban_ok_handler)

        class BrokenExecutor(ActionExecutor):
            async def execute(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
                raise RuntimeError("неожиданный сбой внутри execute")

        executor = BrokenExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )

        processed = await process_pending(executor, store)

        assert processed == 1
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "failed"
        await helix.close()

    async def test_reclaims_stuck_running_action_before_polling_pending(
        self, store: ModerationStore
    ) -> None:
        # BUG-003 аудита: задание, застрявшее в 'running' дольше
        # stuck_timeout_seconds (бот упал посреди исполнения в прошлом
        # цикле), должно вернуться в 'pending' и быть подхвачено этим же
        # вызовом process_pending() — не требует отдельного цикла.
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        await store.mark_action_started(queue_id)
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - 300.0, queue_id),
        )
        await store._db.commit()  # noqa: SLF001

        processed = await process_pending(executor, store, stuck_timeout_seconds=120.0)

        assert processed == 1
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "completed"
        await helix.close()

    async def test_recent_running_action_not_reclaimed_or_reprocessed(
        self, store: ModerationStore
    ) -> None:
        helix = make_helix(ban_ok_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        await store.mark_action_started(queue_id)  # started_at = сейчас

        processed = await process_pending(executor, store, stuck_timeout_seconds=120.0)

        # Задание всё ещё "недавно running" — не должно ни попасть в
        # pending, ни быть обработано повторно этим вызовом.
        assert processed == 0
        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "running"
        await helix.close()
