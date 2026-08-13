"""Тесты детектора ссылок: наличие, шортенеры, скам-домены, общие ссылки."""

from __future__ import annotations

from dataclasses import replace

from cigilbot.detectors import links
from cigilbot.domain.config import default_config
from cigilbot.domain.window import SlidingWindow
from tests.conftest import EventFactory, add_message, make_context


class TestLinkPresent:
    def test_no_signal_without_link(self, event_factory: EventFactory) -> None:
        event = event_factory(text="привет как дела")
        ctx = make_context(event)
        assert links.detect(ctx) == []

    def test_signal_for_bare_domain(self, event_factory: EventFactory) -> None:
        event = event_factory(text="загляните на vk.com/mygroup")
        ctx = make_context(event)
        signals = links.detect(ctx)
        assert any(s.name == "link_present" for s in signals)


class TestShortener:
    def test_shortener_adds_extra_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="переходи bit.ly/abc123")
        ctx = make_context(event)
        signals = links.detect(ctx)
        names = {s.name for s in signals}
        assert "url_shortener" in names
        assert "link_present" in names

    def test_regular_domain_no_shortener_signal(self, event_factory: EventFactory) -> None:
        event = event_factory(text="vk.com/mygroup")
        ctx = make_context(event)
        signals = links.detect(ctx)
        assert not any(s.name == "url_shortener" for s in signals)


class TestKnownScamDomain:
    def test_flags_configured_scam_domain(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(
            cfg,
            detectors=replace(
                cfg.detectors,
                links=replace(cfg.detectors.links, known_scam_domains=("scam-site.com",)),
            ),
        )
        event = event_factory(text="заходи на scam-site.com/promo")
        ctx = make_context(event, config=cfg)

        signals = links.detect(ctx)
        names = {s.name for s in signals}
        assert "known_scam_domain" in names
        # link_present не дублируется, если это уже известный скам
        assert "link_present" not in names


class TestSharedLinkMultiUser:
    def test_flags_when_enough_distinct_users_share_domain(
        self, event_factory: EventFactory
    ) -> None:
        window = SlidingWindow()
        for i in range(3):
            add_message(
                window,
                event_factory(user_id=f"bot{i}", text="promo-site.com/deal", timestamp=float(i)),
            )

        event = event_factory(user_id="bot3", text="promo-site.com/deal", timestamp=3.0)
        ctx = make_context(event, window=window)

        signals = links.detect(ctx)
        assert any(s.name == "shared_link_multi_user" for s in signals)

    def test_no_signal_below_min_users(self, event_factory: EventFactory) -> None:
        window = SlidingWindow()
        add_message(
            window, event_factory(user_id="a", text="promo-site.com/deal", timestamp=0.0)
        )

        # порог по умолчанию — 3 пользователя; всего 2 (a + текущий)
        event = event_factory(user_id="b", text="promo-site.com/deal", timestamp=1.0)
        ctx = make_context(event, window=window)

        signals = links.detect(ctx)
        assert not any(s.name == "shared_link_multi_user" for s in signals)

    def test_outside_window_not_counted(self, event_factory: EventFactory) -> None:
        window = SlidingWindow(max_age_seconds=200.0)
        for i in range(3):
            add_message(
                window,
                event_factory(user_id=f"bot{i}", text="promo-site.com/deal", timestamp=float(i)),
            )

        # окно shared_link по умолчанию 30 сек
        event = event_factory(user_id="bot3", text="promo-site.com/deal", timestamp=100.0)
        ctx = make_context(event, window=window)

        signals = links.detect(ctx)
        assert not any(s.name == "shared_link_multi_user" for s in signals)
