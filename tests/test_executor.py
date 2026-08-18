"""Тесты executor.py: разбор payload, исполнение, прогресс, аудит.

Всё на моках Helix через httpx.MockTransport — ни одного реального
запроса к Twitch (см. докстринг twitch_api.py).
"""

from __future__ import annotations

import asyncio
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


class TestReclaimRaceCondition:
    """bug-аудит 2026-08-18: reclaim_stuck_actions определял "зависшее"
    задание только по возрасту started_at, не проверяя, жив ли исполнитель
    — если задание реально ещё исполняется (просто долго, много целей +
    временные 5xx), реклейм мог вернуть его в pending и отдать второму
    исполнителю, пока первый ещё физически работает. Для TIMEOUT это не
    no-op: повторный вызов продлевает длительность, а prior_timeouts
    инкрементируется дважды за одно логическое действие.

    lease_token (mark_action_started возвращает случайную строку, CAS через
    WHERE status='pending') + heartbeat (update_action_progress продлевает
    started_at) закрывают это структурно:
    - CAS не даёт двум конкурентным mark_action_started() оба "выиграть"
      одно и то же задание;
    - heartbeat не даёт реклейму сработать на реально прогрессирующем
      задании;
    - даже если реклейм всё же сработал (исполнитель завис БЕЗ прогресса),
      старый lease_token сбрасывается, и поздние update_action_progress/
      complete_action от зомби-исполнителя находят 0 строк и не
      применяются — не портят данные нового исполнителя.
    """

    async def test_concurrent_mark_action_started_only_one_wins(
        self, store: ModerationStore
    ) -> None:
        """Два конкурентных вызова mark_action_started на одно и то же
        задание — ровно один получает токен, второй None."""
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )

        results = await asyncio.gather(
            store.mark_action_started(queue_id),
            store.mark_action_started(queue_id),
        )

        tokens = [t for t in results if t is not None]
        assert len(tokens) == 1, "ровно один вызов должен получить lease_token"
        assert results.count(None) == 1

    async def test_mark_action_started_returns_none_for_already_running(
        self, store: ModerationStore
    ) -> None:
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        first_token = await store.mark_action_started(queue_id)
        assert first_token is not None

        second_token = await store.mark_action_started(queue_id)

        assert second_token is None

    async def test_reclaim_resets_lease_token(self, store: ModerationStore) -> None:
        """Реклейм обнуляет lease_token вместе с started_at/status — иначе
        старый исполнитель мог бы продолжать писать под ним."""
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        token = await store.mark_action_started(queue_id)
        assert token is not None
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - 300.0, queue_id),
        )
        await store._db.commit()  # noqa: SLF001

        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)
        assert reclaimed == 1

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT lease_token FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is None

    async def test_zombie_executor_cannot_overwrite_progress_after_reclaim(
        self, store: ModerationStore
    ) -> None:
        """Главный сценарий аудита: исполнитель A берёт задание, зависает
        (не пишет прогресс), реклейм возвращает задание в pending и его
        забирает исполнитель B. Когда "зомби" A наконец пытается записать
        свой (устаревший) прогресс под старым токеном — запись не должна
        применяться, чтобы не затереть то, что уже сделал B."""
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1", "2", "3"], "reason": "x"},
        )
        token_a = await store.mark_action_started(queue_id)
        assert token_a is not None
        # A завис без единого прогресс-апдейта — состариваем started_at,
        # как это сделал бы реальный timeout.
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - 300.0, queue_id),
        )
        await store._db.commit()  # noqa: SLF001

        # Реклейм + новый исполнитель B забирает задание.
        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)
        assert reclaimed == 1
        token_b = await store.mark_action_started(queue_id)
        assert token_b is not None
        assert token_b != token_a
        await store.update_action_progress(queue_id, 3, 3, lease_token=token_b)
        await store.complete_action(
            queue_id, status="completed", result={"succeeded": ["1", "2", "3"], "failed": []},
            lease_token=token_b,
        )

        # "Зомби" A наконец просыпается и пытается дописать СВОЙ (устаревший)
        # прогресс под token_a — не должно ничего изменить.
        await store.update_action_progress(queue_id, 1, 3, lease_token=token_a)

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, progress_done, progress_total, result_json "
            "FROM mod_action_queue WHERE id = ?",
            (queue_id,),
        )
        row = await cursor.fetchone()
        assert row is not None
        status, done, total, result_json = row
        assert status == "completed"
        assert (done, total) == (3, 3), "прогресс зомби-исполнителя не должен был примениться"
        assert json.loads(result_json)["succeeded"] == ["1", "2", "3"]

    async def test_zombie_executor_cannot_overwrite_completed_result(
        self, store: ModerationStore
    ) -> None:
        """complete_action от зомби-исполнителя (устаревший lease_token)
        не должен перезаписать результат, который уже записал актуальный
        исполнитель под своим токеном."""
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        token_a = await store.mark_action_started(queue_id)
        assert token_a is not None
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - 300.0, queue_id),
        )
        await store._db.commit()  # noqa: SLF001
        await store.reclaim_stuck_actions(timeout_seconds=120.0)

        token_b = await store.mark_action_started(queue_id)
        assert token_b is not None
        await store.complete_action(
            queue_id, status="completed", result={"succeeded": ["1"], "failed": []},
            lease_token=token_b,
        )

        # Зомби A пытается завершить задание "с ошибкой" под своим старым
        # токеном — не должно перезаписать успешный результат B.
        await store.complete_action(
            queue_id, status="failed", result={"error": "зомби-исполнитель A"},
            lease_token=token_a,
        )

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, result_json FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        status, result_json = row
        assert status == "completed"
        assert json.loads(result_json) == {"succeeded": ["1"], "failed": []}

    async def test_progress_heartbeat_extends_lease_prevents_reclaim(
        self, store: ModerationStore
    ) -> None:
        """Задание, реально прогрессирующее (update_action_progress
        вызывается по ходу дела), не должно реклеймиться только потому,
        что started_at изначально был старым — heartbeat продлевает
        аренду на каждый успешный апдейт."""
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1", "2"], "reason": "x"},
        )
        token = await store.mark_action_started(queue_id)
        assert token is not None
        # Изначальный started_at уже "старый" (как если бы первая цель
        # исполнялась долго) — но прогресс-апдейт должен его продлить.
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - 300.0, queue_id),
        )
        await store._db.commit()  # noqa: SLF001

        await store.update_action_progress(queue_id, 1, 2, lease_token=token)

        # started_at теперь свежий (продлён heartbeat) — реклейм с тем же
        # timeout_seconds=120 больше не должен считать задание застрявшим.
        reclaimed = await store.reclaim_stuck_actions(timeout_seconds=120.0)
        assert reclaimed == 0

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status, lease_token FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "running"
        assert row[1] == token, "lease_token не должен был сброситься — реклейм не сработал"

    async def test_process_pending_end_to_end_no_double_execution(
        self, store: ModerationStore
    ) -> None:
        """Сквозной сценарий через process_pending(): задание зависает без
        прогресса, реклеймится, второй вызов process_pending исполняет
        его — итог: ровно один набор Helix-вызовов в аудите, не два."""
        call_count = {"n": 0}

        def counting_handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return ban_ok_handler(request)

        helix = make_helix(counting_handler)
        executor = ActionExecutor(
            helix, store, broadcaster_id="B", moderator_id="M", user_token="tok"
        )
        queue_id = await store.enqueue_action(
            requested_by="mod1", requested_role="MODERATOR",
            payload={"action": "BAN", "target_user_ids": ["1"], "reason": "x"},
        )
        # Первый "исполнитель" берёт задание и зависает без прогресса.
        stale_token = await store.mark_action_started(queue_id)
        assert stale_token is not None
        await store._db.execute(  # noqa: SLF001
            "UPDATE mod_action_queue SET started_at = ? WHERE id = ?",
            (time.time() - 300.0, queue_id),
        )
        await store._db.commit()  # noqa: SLF001

        processed = await process_pending(executor, store, stuck_timeout_seconds=120.0)
        assert processed == 1
        assert call_count["n"] == 1, "Helix должен быть вызван ровно один раз"

        # "Зомби"-исполнитель наконец просыпается и пытается завершить
        # задание под протухшим токеном — не должен ничего изменить.
        await store.complete_action(
            queue_id, status="failed", result={"error": "zombie"}, lease_token=stale_token
        )

        cursor = await store._db.execute(  # noqa: SLF001
            "SELECT status FROM mod_action_queue WHERE id = ?", (queue_id,)
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "completed", "результат актуального исполнения не должен быть затёрт"
        await helix.close()
