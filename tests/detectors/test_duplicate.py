"""Тесты детектора дубликатов: сравнение с недавними сообщениями чата."""

from __future__ import annotations

from cigilbot.detectors import duplicate
from cigilbot.domain.window import SlidingWindow
from tests.conftest import EventFactory, add_message, make_context


class TestExactDuplicate:
    def test_flags_exact_duplicate_from_other_user(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add_message(
            window, event_factory(user_id="bot1", text="BUY CHEAP FOLLOWERS!!!", timestamp=0.0)
        )

        event = event_factory(user_id="bot2", text="buy cheap followers!!!", timestamp=1.0)
        ctx = make_context(event, window=window)

        signals = duplicate.detect(ctx)
        assert any(s.name == "exact_duplicate" for s in signals)

    def test_own_previous_messages_not_counted(self, event_factory: EventFactory) -> None:
        # активный зритель трижды пишет одно и то же за розыгрыш — не должен
        # сам себе создавать сигнал дубликата. Текст длиннее порога
        # min_content_length, чтобы тест проверял именно исключение "своих"
        # сообщений, а не совпадал с защитой от коротких фраз.
        window = SlidingWindow()
        for i in range(3):
            add_message(
                window, event_factory(user_id="regular", text="участвую в розыгрыше", timestamp=float(i))
            )

        event = event_factory(user_id="regular", text="участвую в розыгрыше", timestamp=3.0)
        ctx = make_context(event, window=window)

        signals = duplicate.detect(ctx)
        assert signals == []

    def test_no_signal_for_unique_message(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add_message(window, event_factory(user_id="a", text="привет всем", timestamp=0.0))

        event = event_factory(user_id="b", text="кто-нибудь знает время старта стрима", timestamp=1.0)
        ctx = make_context(event, window=window)

        assert duplicate.detect(ctx) == []

    def test_short_common_greeting_from_different_users_no_signal(
        self, event_factory: EventFactory
    ) -> None:
        # Найдено прогоном по реальному чату (этап 6 плана): "ку" — обычное
        # приветствие, разные зрители пишут его независимо друг от друга.
        # Без min_content_length это давало ложный exact_duplicate.
        window = SlidingWindow()
        add_message(window, event_factory(user_id="a", text="ку", timestamp=0.0))

        event = event_factory(user_id="b", text="ку", timestamp=1.0)
        ctx = make_context(event, window=window)

        assert duplicate.detect(ctx) == []

    def test_short_reaction_variants_no_signal(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        for i, text in enumerate(("гг", "wp", "+1", "лол")):
            add_message(window, event_factory(user_id=f"u{i}", text=text, timestamp=float(i)))

        event = event_factory(user_id="u5", text="гг", timestamp=5.0)
        ctx = make_context(event, window=window)

        assert duplicate.detect(ctx) == []

    def test_empty_message_produces_no_signal(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add_message(window, event_factory(user_id="a", text="!!!", timestamp=0.0))

        event = event_factory(user_id="b", text="???", timestamp=1.0)
        ctx = make_context(event, window=window)

        assert duplicate.detect(ctx) == []


class TestNearDuplicate:
    def test_flags_near_duplicate(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add_message(
            window,
            event_factory(user_id="bot1", text="переходи скорее на сайт super-promo.com", timestamp=0.0),
        )

        event = event_factory(
            user_id="bot2", text="переходи скорееее на сайт super-promo.com", timestamp=1.0
        )
        ctx = make_context(event, window=window)

        signals = duplicate.detect(ctx)
        names = {s.name for s in signals}
        assert "near_duplicate" in names or "exact_duplicate" in names


class TestSkeletonMatch:
    def test_flags_same_structure_different_payload(self, event_factory: EventFactory) -> None:
        # Разные (не повторяющиеся подряд) цифры одинаковой длины: скелет
        # совпадает, но minhash-схожесть текста ниже near_duplicate_threshold —
        # именно на этот случай и рассчитан отдельный skeleton_match. Если бы
        # цифры повторялись подряд ("111111"), normalize_text схлопнул бы их
        # до двух знаков и тексты оказались бы ещё и near_duplicate раньше,
        # чем очередь дойдёт до skeleton (see duplicate.py: elif-цепочка).
        window = SlidingWindow()
        add_message(
            window,
            event_factory(
                user_id="bot1", text="Забирай суперприз билет 482910 скорее", timestamp=0.0
            ),
        )

        event = event_factory(
            user_id="bot2", text="Забирай суперприз билет 738264 скорее", timestamp=1.0
        )
        ctx = make_context(event, window=window)

        signals = duplicate.detect(ctx)
        assert any(s.name == "skeleton_match" for s in signals)

    def test_short_matching_skeletons_ignored(self, event_factory: EventFactory) -> None:
        # короче skeleton_min_length (12) — структурные совпадения тут
        # слишком часты у обычных фраз ("+1", "gg", "лол")
        window = SlidingWindow()
        add_message(window, event_factory(user_id="a", text="gg", timestamp=0.0))

        event = event_factory(user_id="b", text="wp", timestamp=1.0)
        ctx = make_context(event, window=window)

        signals = duplicate.detect(ctx)
        assert not any(s.name == "skeleton_match" for s in signals)


class TestWindowScoping:
    def test_messages_outside_window_ignored(self, event_factory: EventFactory) -> None:
        window = SlidingWindow(max_age_seconds=200.0)
        add_message(
            window, event_factory(user_id="bot1", text="BUY CHEAP FOLLOWERS", timestamp=0.0)
        )

        # окно дубликатов по умолчанию 25 сек, сообщение пришло через 100
        event = event_factory(user_id="bot2", text="BUY CHEAP FOLLOWERS", timestamp=100.0)
        ctx = make_context(event, window=window)

        assert duplicate.detect(ctx) == []
