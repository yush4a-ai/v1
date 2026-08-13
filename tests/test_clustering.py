"""Тесты кластеризации: union-find по рёбрам схожести, валидация, инварианты.

Два теста в конце файла — прямая проверка требований ТЗ (раздел 18):
50 ботов за 20 секунд с похожими сообщениями обязаны образовать кластер;
10 обычных пользователей, пишущих на польском, не должны образовать НИ ОДНОГО.
"""

from __future__ import annotations

from dataclasses import replace

from cigilbot.domain.clustering import find_clusters
from cigilbot.domain.config import default_config
from cigilbot.domain.types import ChannelContext
from cigilbot.domain.window import SlidingWindow
from tests.conftest import EventFactory, add_message, make_user_state


class TestNoClusterBelowMinUsers:
    def test_three_similar_messages_below_default_min_users(
        self, event_factory: EventFactory
    ) -> None:
        cfg = default_config()  # min_users по умолчанию — 4
        window = SlidingWindow()
        for i in range(3):
            add_message(
                window,
                event_factory(
                    user_id=f"bot{i}", text="переходи на super-promo-site.com/deal",
                    timestamp=float(i),
                ),
            )
        clusters = find_clusters(window, cfg, now=3.0)
        assert clusters == []

    def test_empty_window_no_clusters(self) -> None:
        cfg = default_config()
        window = SlidingWindow()
        assert find_clusters(window, cfg) == []


class TestSharedLinkCluster:
    def test_forms_cluster_on_shared_domain(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        for i in range(5):
            add_message(
                window,
                event_factory(
                    user_id=f"bot{i}", text=f"заходи скорее promo-domain.com/x{i}",
                    timestamp=i * 0.5, is_first_message=True,
                ),
            )
        clusters = find_clusters(window, cfg, now=5.0)
        assert len(clusters) == 1
        assert clusters[0].size == 5
        assert clusters[0].shared_domains == ("promo-domain.com",)

    def test_different_domains_and_different_text_do_not_cluster(
        self, event_factory: EventFactory
    ) -> None:
        # Тексты должны быть по-настоящему разными, а не "шаблон + одна
        # буква" — иначе даже с разными доменами сообщения окажутся
        # near_duplicate по содержимому (что было бы честным срабатыванием
        # detector'а, но не тем, что здесь проверяется).
        cfg = default_config()
        window = SlidingWindow()
        messages = [
            ("u0", "кто-нибудь знает во сколько сегодня начало стрима"),
            ("u1", "новая карта в игре выглядит очень красиво, автор молодец"),
            ("u2", "спасибо за прошлый стрим, было очень весело смотреть"),
            ("u3", "а можно ссылку на плейлист с музыкой из фона стрима"),
            ("u4", "поздравляю с новым уровнем, давно так не играл никто"),
        ]
        for i, (uid, text) in enumerate(messages):
            add_message(window, event_factory(user_id=uid, text=text, timestamp=float(i)))
        clusters = find_clusters(window, cfg, now=5.0)
        assert clusters == []


class TestSimilarContentCluster:
    def test_near_duplicate_messages_cluster(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        base = "покупайте дешёвые подписчики прямо сейчас у нас"
        variants = [
            base,
            base.upper(),
            base + "!!!",
            base.replace("покупайте", "покупайтe"),
            "  ".join(base.split()),
        ]
        for i, text in enumerate(variants):
            add_message(window, event_factory(user_id=f"bot{i}", text=text, timestamp=i * 0.3))

        clusters = find_clusters(window, cfg, now=2.0)
        assert len(clusters) == 1
        assert clusters[0].size == 5

    def test_short_common_phrases_do_not_cluster(self, event_factory: EventFactory) -> None:
        # Ключевая защита от хайпа: "+", "гг", "лол" от многих зрителей —
        # это не кластер, min_content_length_for_edge их исключает целиком.
        cfg = default_config()
        window = SlidingWindow()
        phrases = ["+", "гг", "лол", "+1", "ахах", "круто", "wp", "ого"]
        for i, text in enumerate(phrases):
            add_message(window, event_factory(user_id=f"u{i}", text=text, timestamp=i * 0.2))

        clusters = find_clusters(window, cfg, now=2.0)
        assert clusters == []


class TestArrivalWindowValidation:
    def test_spread_out_similar_messages_do_not_cluster(self, event_factory: EventFactory) -> None:
        # Похожие сообщения есть, но растянуты по времени сильно шире
        # arrival_window_seconds (20 по умолчанию) — не "синхронное появление"
        cfg = default_config()
        window = SlidingWindow(max_age_seconds=200.0)
        base = "покупайте дешёвые подписчики прямо у нас сейчас"
        for i in range(5):
            add_message(
                window, event_factory(user_id=f"bot{i}", text=base, timestamp=i * 15.0)
            )
        clusters = find_clusters(window, cfg, now=60.0)
        assert clusters == []

    def test_tight_arrival_window_clusters(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        base = "покупайте дешёвые подписчики прямо у нас сейчас"
        for i in range(5):
            add_message(window, event_factory(user_id=f"bot{i}", text=base, timestamp=i * 1.0))
        clusters = find_clusters(window, cfg, now=4.0)
        assert len(clusters) == 1


class TestClusterFieldsAndSignals:
    def test_cluster_has_expected_signals(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        for i in range(6):
            add_message(
                window,
                event_factory(
                    user_id=f"bot{i}", text=f"заходи scam-domain.com/x{i}",
                    timestamp=i * 0.3, is_first_message=True,
                ),
            )
        clusters = find_clusters(window, cfg, now=2.0)
        assert len(clusters) == 1
        names = {s.name for s in clusters[0].signals}
        assert "synchronized_arrival" in names
        assert "cluster_membership" in names
        assert "mass_first_messages" in names  # все is_first_message=True

    def test_cluster_risk_and_confidence_populated(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        for i in range(6):
            add_message(
                window,
                event_factory(user_id=f"bot{i}", text=f"заходи scam-domain.com/x{i}", timestamp=i * 0.3),
            )
        clusters = find_clusters(window, cfg, now=2.0)
        assert clusters[0].risk_score > 0
        assert 0.0 <= clusters[0].confidence <= 1.0

    def test_first_message_ratio_reflects_mix(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        for i in range(6):
            add_message(
                window,
                event_factory(
                    user_id=f"bot{i}", text=f"заходи scam-domain.com/x{i}",
                    timestamp=i * 0.3, is_first_message=(i % 2 == 0),
                ),
            )
        clusters = find_clusters(window, cfg, now=2.0)
        assert clusters[0].first_message_ratio == 0.5


class TestNewAccountRatioWithUserStates:
    def test_uses_user_states_when_provided(self, event_factory: EventFactory) -> None:
        import time

        cfg = default_config()
        window = SlidingWindow()
        events = []
        for i in range(5):
            ev = event_factory(user_id=f"bot{i}", text=f"заходи scam-domain.com/x{i}", timestamp=i * 0.3)
            events.append(ev)
            add_message(window, ev)

        # 3 из 5 — свежие аккаунты (младше порога new_account_days=7)
        user_states = {
            events[0].user_id: make_user_state(events[0], account_created_at=time.time() - 3600),
            events[1].user_id: make_user_state(events[1], account_created_at=time.time() - 3600),
            events[2].user_id: make_user_state(events[2], account_created_at=time.time() - 3600),
            events[3].user_id: make_user_state(events[3], account_created_at=time.time() - 365 * 86400),
            events[4].user_id: make_user_state(events[4], account_created_at=time.time() - 365 * 86400),
        }

        clusters = find_clusters(window, cfg, user_states=user_states, now=2.0)
        assert len(clusters) == 1
        assert clusters[0].new_account_ratio == 0.6


class TestChannelContextLowersConfidence:
    def test_raid_context_lowers_cluster_confidence(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        window = SlidingWindow()
        for i in range(6):
            add_message(
                window,
                event_factory(user_id=f"bot{i}", text=f"заходи scam-domain.com/x{i}", timestamp=i * 0.3),
            )
        normal = find_clusters(window, cfg, now=2.0, channel_context=ChannelContext())
        raid = find_clusters(window, cfg, now=2.0, channel_context=ChannelContext(is_raid=True))
        assert raid[0].confidence < normal[0].confidence


class TestDisabled:
    def test_disabled_cluster_detection_returns_nothing(self, event_factory: EventFactory) -> None:
        cfg = default_config()
        cfg = replace(cfg, cluster=replace(cfg.cluster, enabled=False))
        window = SlidingWindow()
        for i in range(10):
            add_message(
                window,
                event_factory(user_id=f"bot{i}", text=f"заходи scam-domain.com/x{i}", timestamp=i * 0.3),
            )
        assert find_clusters(window, cfg, now=3.0) == []


class TestExcludedPhrases:
    def test_manually_excluded_phrase_does_not_cluster(self, event_factory: EventFactory) -> None:
        from cigilbot.domain.normalize import normalize_for_matching

        cfg = default_config()
        common = "спасибо стример хороший стрим было очень интересно"
        cfg = replace(
            cfg, cluster=replace(cfg.cluster, excluded_phrases=(normalize_for_matching(common),))
        )
        window = SlidingWindow()
        for i in range(6):
            add_message(window, event_factory(user_id=f"u{i}", text=common, timestamp=i * 0.3))

        assert find_clusters(window, cfg, now=2.0) == []


# ---------------------------------------------------------------------------
# Прямые сценарии из ТЗ (раздел 18 "Testing" / раздел 3 "User Cluster")
# ---------------------------------------------------------------------------

class TestSpecMandatedScenarios:
    def test_50_bots_in_20_seconds_form_cluster(self, event_factory: EventFactory) -> None:
        """50 новых пользователей за 20 секунд с похожими сообщениями и
        одинаковой ссылкой — система обязана обнаружить это как кластер."""
        cfg = default_config()
        window = SlidingWindow()
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            add_message(
                window,
                event_factory(
                    user_id=f"bot{i}", login=f"bot{i}", text=text,
                    timestamp=i * (20.0 / 50), is_first_message=True,
                ),
            )

        clusters = find_clusters(window, cfg, now=20.0)
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.size == 50
        # find_clusters() в одиночку видит только TIMING/NETWORK-сигналы —
        # для TIMEOUT/BAN не хватит и полного веса этих трёх сигналов, нужны
        # ещё CONTENT/IDENTITY/ENCODING конкретных сообщений, которые
        # подмешивает engine.py на этапе 5. Растянутые ровно на весь
        # arrival_window_seconds 50 пользователей — это более слабая
        # синхронизация, чем плотный залп: честный результат для ЭТОГО слоя —
        # как минимум OBSERVE, а не автоматическое действие в одиночку.
        assert cluster.risk_score >= cfg.risk.observe

    def test_tight_bot_burst_reaches_timeout_level_risk(self, event_factory: EventFactory) -> None:
        """Тот же сценарий, но плотнее по времени (3 сек вместо 20) — более
        реалистичная бот-атака должна получать более высокий risk_score.

        confidence при этом сознательно НЕ достигает порога автодействия:
        find_clusters() в одиночку задействует только 2 семейства сигналов
        (TIMING + NETWORK), а family_factor_for(2)=0.70 в конфиге —
        меньше minimum_for_timeout=0.75. Это и есть защита от false positive
        "в лоб": даже очень плотный и большой кластер не должен сам по себе
        включать автотаймаут без подтверждения от CONTENT/IDENTITY/ENCODING
        сигналов конкретных сообщений — их добавляет engine.py на этапе 5.
        """
        cfg = default_config()
        window = SlidingWindow()
        for i in range(50):
            text = f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}"
            add_message(
                window,
                event_factory(
                    user_id=f"bot{i}", login=f"bot{i}", text=text,
                    timestamp=i * (3.0 / 50), is_first_message=True,
                ),
            )

        clusters = find_clusters(window, cfg, now=3.0)
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.size == 50
        assert cluster.risk_score >= cfg.risk.timeout
        assert cluster.confidence < cfg.confidence.minimum_for_timeout

    def test_10_polish_speaking_viewers_do_not_form_cluster(
        self, event_factory: EventFactory
    ) -> None:
        """10 обычных пользователей, пишущих на польском — это НЕ должно
        превращаться в массовый timeout/ban через кластеризацию. Сообщения
        разные по содержанию и не образуют рёбер, несмотря на общий язык."""
        cfg = default_config()
        window = SlidingWindow()
        messages = [
            "dzień dobry wszystkim, jak się dzisiaj macie",
            "super stream jak zawsze, pozdrawiam wszystkich",
            "czy ktoś wie kiedy zaczyna się kolejny odcinek",
            "świetna gra, gratulacje za wygraną w tym meczu",
            "przepraszam za pytanie ale co to za gra jest",
            "no i super, dzięki za miły wieczór wszystkim",
            "czekam na kolejny stream z wielką niecierpliwością",
            "pierwszy raz oglądam, bardzo mi się podoba klimat",
            "ale klimat na tym kanale, super sprawa naprawdę",
            "dzięki za rozrywkę, do zobaczenia jutro wieczorem",
        ]
        for i, text in enumerate(messages):
            add_message(
                window,
                event_factory(
                    user_id=f"pl{i}", login=f"pl{i}", text=text,
                    timestamp=i * 1.5, is_first_message=(i % 3 == 0),
                ),
            )

        clusters = find_clusters(window, cfg, now=15.0)
        assert clusters == []
