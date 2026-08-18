"""Тесты скользящего окна: добавление, вытеснение старых записей, срезы."""

from __future__ import annotations

from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.window import SlidingWindow
from tests.conftest import EventFactory


def add(window: SlidingWindow, event_factory: EventFactory, **kwargs: object) -> None:
    event = event_factory(**kwargs)
    window.add(event, fingerprint(event.text))


class TestBasicAddAndRecent:
    def test_empty_window(self) -> None:
        window = SlidingWindow()
        assert len(window) == 0
        assert window.recent(60) == []

    def test_single_message_visible(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add(window, event_factory, timestamp=100.0)
        assert len(window) == 1
        assert len(window.recent(60, now=100.0)) == 1

    def test_recent_excludes_messages_outside_window(self, event_factory: EventFactory) -> None:
        window = SlidingWindow(max_age_seconds=200.0)
        add(window, event_factory, timestamp=0.0)
        add(window, event_factory, timestamp=100.0)

        # окно в 10 сек на момент t=100 — видно только второе сообщение
        recent = window.recent(10.0, now=100.0)
        assert len(recent) == 1
        assert recent[0].event.timestamp == 100.0

    def test_recent_is_chronologically_ordered(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        for ts in (10.0, 11.0, 12.0):
            add(window, event_factory, timestamp=ts)
        recent = window.recent(60, now=12.0)
        timestamps = [e.event.timestamp for e in recent]
        assert timestamps == sorted(timestamps)


class TestPruning:
    def test_old_entries_pruned_on_add(self, event_factory: EventFactory) -> None:
        window = SlidingWindow(max_age_seconds=5.0)
        add(window, event_factory, timestamp=0.0)
        assert len(window) == 1

        # следующее сообщение приходит через 10 сек — окно 5 сек, первое устарело
        add(window, event_factory, timestamp=10.0)
        assert len(window) == 1

    def test_pruning_is_per_user_too(self, event_factory: EventFactory) -> None:
        window = SlidingWindow(max_age_seconds=5.0)
        add(window, event_factory, user_id="alice", timestamp=0.0)
        add(window, event_factory, user_id="alice", timestamp=1.0)
        add(window, event_factory, user_id="bob", timestamp=10.0)

        # alice больше не должна быть в _by_user после вытеснения
        assert window.user_message_count("alice", 60, now=10.0) == 0
        assert window.user_message_count("bob", 60, now=10.0) == 1

class TestPerUserQueries:
    def test_user_message_count_within_window(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        for ts in (0.0, 1.0, 2.0, 3.0, 4.0):
            add(window, event_factory, user_id="spammer", timestamp=ts)

        assert window.user_message_count("spammer", 5.0, now=4.0) == 5

    def test_user_message_count_respects_seconds_arg(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        for ts in (0.0, 1.0, 2.0, 3.0, 4.0):
            add(window, event_factory, user_id="spammer", timestamp=ts)

        # последние 2 секунды на момент t=4.0: граница включительно, t=2.0
        # тоже входит (сообщению ровно 2 секунды — оно ещё "в последних двух")
        assert window.user_message_count("spammer", 2.0, now=4.0) == 3

    def test_unknown_user_returns_zero(self) -> None:
        window = SlidingWindow()
        assert window.user_message_count("ghost", 60) == 0

    def test_different_users_dont_mix(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add(window, event_factory, user_id="alice", timestamp=0.0)
        add(window, event_factory, user_id="alice", timestamp=1.0)
        add(window, event_factory, user_id="bob", timestamp=1.5)

        assert window.user_message_count("alice", 60, now=1.5) == 2
        assert window.user_message_count("bob", 60, now=1.5) == 1


class TestChannelRate:
    def test_rate_per_minute_scales_correctly(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        # 10 сообщений за 5 секунд -> 120 сообщений в минуту
        for i in range(10):
            add(window, event_factory, user_id=f"u{i}", timestamp=float(i) * 0.5)

        rate = window.channel_rate_per_minute(seconds=5.0, now=4.5)
        assert 110 < rate < 130

    def test_zero_seconds_does_not_crash(self) -> None:
        window = SlidingWindow()
        assert window.channel_rate_per_minute(seconds=0.0) == 0.0

    def test_empty_window_zero_rate(self) -> None:
        window = SlidingWindow()
        assert window.channel_rate_per_minute() == 0.0


class TestUniqueChatters:
    def test_counts_distinct_users(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add(window, event_factory, user_id="alice", timestamp=0.0)
        add(window, event_factory, user_id="alice", timestamp=1.0)
        add(window, event_factory, user_id="bob", timestamp=1.0)

        assert window.unique_chatters(60, now=1.0) == {"alice", "bob"}


