"""Тесты report.py: агрегация get_daily_stats()/mod_feedback в текстовую сводку.

get_daily_stats() считается напрямую по mod_messages/mod_verdicts/
mod_clusters/mod_actions (bug-аудит store.py, 2026-08-17) — тестовые данные
здесь пишутся через реальные save_message/save_verdict, не через удалённый
increment_daily_stats().
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.types import Action, ChatEvent, Verdict
from cigilbot.orchestration.report import build_report
from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "report_test.db"))
    await s.connect()
    return s


def make_event(*, user_id: str, login: str, timestamp: float) -> ChatEvent:
    return ChatEvent(
        user_id=user_id, login=login, text="привет чат", timestamp=timestamp, channel="test",
    )


class TestBuildReport:
    async def test_empty_db_gives_zeroed_report(self, store: ModerationStore) -> None:
        report = await build_report(store)

        assert report.total_messages == 0
        assert report.total_suspicious == 0
        assert report.signal_fp_stats == []

    async def test_sums_messages_and_suspicious_verdicts(self, store: ModerationStore) -> None:
        now = time.time()
        for i in range(3):
            event = make_event(user_id=str(i), login=f"viewer{i}", timestamp=now)
            await store.save_message(event, fingerprint(event.text))
        verdict = Verdict(
            user_id="1", login="a", risk_score=90, confidence=0.9, signals=(),
            recommended_action=Action.BAN, reason="test", timestamp=now,
        )
        await store.save_verdict(verdict)

        report = await build_report(store)

        assert report.total_messages == 3
        assert report.total_suspicious == 1

    async def test_respects_days_window(self, store: ModerationStore) -> None:
        now = time.time()
        old_event = make_event(user_id="1", login="old", timestamp=now - 10 * 86400)
        recent_event = make_event(user_id="2", login="recent", timestamp=now)
        await store.save_message(old_event, fingerprint(old_event.text))
        await store.save_message(recent_event, fingerprint(recent_event.text))

        report = await build_report(store, days=3)

        assert report.total_messages == 1

    async def test_signal_fp_stats_aggregated_per_signal(self, store: ModerationStore) -> None:
        await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="FALSE_POSITIVE"
        )
        await store.record_feedback(
            signal_name="unexpected_language", moderator="mod1", decision="CONFIRMED_BOT"
        )
        await store.record_feedback(
            signal_name="exact_duplicate", moderator="mod1", decision="CONFIRMED_BOT"
        )

        report = await build_report(store)

        by_name = {s.signal_name: s for s in report.signal_fp_stats}
        assert by_name["unexpected_language"].total_feedback == 2
        assert by_name["unexpected_language"].false_positive_count == 1
        assert by_name["unexpected_language"].fp_rate == 0.5
        assert by_name["exact_duplicate"].fp_rate == 0.0


class TestFormatSummary:
    async def test_includes_key_numbers(self, store: ModerationStore) -> None:
        now = time.time()
        for i in range(200):
            event = make_event(user_id=str(i), login=f"v{i}", timestamp=now)
            await store.save_message(event, fingerprint(event.text))
        for i in range(20):
            verdict = Verdict(
                user_id=str(i), login=f"v{i}", risk_score=90, confidence=0.9, signals=(),
                recommended_action=Action.BAN, reason="test", timestamp=now,
            )
            await store.save_verdict(verdict)

        report = await build_report(store)
        text = report.format_summary()

        assert "200" in text
        assert "20" in text

    async def test_signal_stats_sorted_by_fp_rate_descending(
        self, store: ModerationStore
    ) -> None:
        await store.record_feedback(
            signal_name="low_fp", moderator="mod1", decision="CONFIRMED_BOT"
        )
        await store.record_feedback(
            signal_name="high_fp", moderator="mod1", decision="FALSE_POSITIVE"
        )

        report = await build_report(store)
        text = report.format_summary()

        assert text.index("high_fp") < text.index("low_fp")

    async def test_empty_report_does_not_crash(self, store: ModerationStore) -> None:
        report = await build_report(store)
        text = report.format_summary()
        assert isinstance(text, str)
        assert len(text) > 0
