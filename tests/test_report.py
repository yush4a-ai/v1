"""Тесты report.py: агрегация mod_stats_daily/mod_feedback в текстовую сводку."""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.orchestration.report import build_report
from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "report_test.db"))
    await s.connect()
    return s


class TestBuildReport:
    async def test_empty_db_gives_zeroed_report(self, store: ModerationStore) -> None:
        report = await build_report(store)

        assert report.total_messages == 0
        assert report.total_suspicious == 0
        assert report.signal_fp_stats == []

    async def test_sums_across_multiple_days(self, store: ModerationStore) -> None:
        await store.increment_daily_stats(date="2026-08-07", total_messages=100, suspicious=10)
        await store.increment_daily_stats(date="2026-08-08", total_messages=50, suspicious=5)

        report = await build_report(store)

        assert report.total_messages == 150
        assert report.total_suspicious == 15

    async def test_respects_days_window(self, store: ModerationStore) -> None:
        for day in range(1, 11):
            await store.increment_daily_stats(date=f"2026-08-{day:02d}", total_messages=1)

        report = await build_report(store, days=3)

        assert report.total_messages == 3

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
        await store.increment_daily_stats(
            date="2026-08-08", total_messages=200, suspicious=20,
            would_timeout=5, would_ban=1, actual_timeouts=0, actual_bans=0,
            clusters=2, false_positives=1,
        )

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
