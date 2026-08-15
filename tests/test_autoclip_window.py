"""Тесты BurstWindow — чистая логика, без времени реального часа: все
timestamp'ы передаются явно."""

from __future__ import annotations

from bot.autoclip_window import BurstWindow


class TestBurstWindow:
    def test_counts_unique_authors(self) -> None:
        window = BurstWindow(window_seconds=10.0)
        assert window.add(author_id="a", timestamp=0.0) == 1
        assert window.add(author_id="b", timestamp=1.0) == 2
        assert window.add(author_id="c", timestamp=2.0) == 3

    def test_same_author_does_not_grow_count(self) -> None:
        window = BurstWindow(window_seconds=10.0)
        window.add(author_id="a", timestamp=0.0)
        window.add(author_id="a", timestamp=1.0)
        count = window.add(author_id="a", timestamp=2.0)
        assert count == 1

    def test_flooding_single_author_does_not_trigger_burst(self) -> None:
        window = BurstWindow(window_seconds=10.0)
        count = 0
        for i in range(20):
            count = window.add(author_id="flooder", timestamp=float(i) * 0.1)
        assert count == 1

    def test_entries_outside_window_are_pruned(self) -> None:
        window = BurstWindow(window_seconds=10.0)
        window.add(author_id="a", timestamp=0.0)
        window.add(author_id="b", timestamp=1.0)
        # оба должны выпасть из окна к моменту t=15 (cutoff = 15 - 10 = 5)
        count = window.add(author_id="c", timestamp=15.0)
        assert count == 1

    def test_boundary_exactly_at_window_seconds_is_pruned(self) -> None:
        window = BurstWindow(window_seconds=10.0)
        window.add(author_id="a", timestamp=0.0)
        # timestamp - window_seconds == 0.0 -> cutoff, запись строго
        # старше cutoff отбрасывается, запись РОВНО на cutoff — нет
        # (0.0 < cutoff=0.0 ложно) значит "a" ещё в окне
        count = window.add(author_id="b", timestamp=10.0)
        assert count == 2

    def test_just_past_boundary_prunes_old_entry(self) -> None:
        window = BurstWindow(window_seconds=10.0)
        window.add(author_id="a", timestamp=0.0)
        count = window.add(author_id="b", timestamp=10.001)
        assert count == 1
