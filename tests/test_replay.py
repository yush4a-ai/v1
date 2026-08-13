"""Тесты replay.py: чтение истории, синтез ChatEvent, прогон через движок."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from cigilbot.domain.config import ChannelProfile, default_config
from cigilbot.domain.types import Action
from cigilbot.orchestration.replay import ReplayRow, read_messages, run_replay, to_events


def make_legacy_db(path: Path, rows: list[tuple[str, str, float]]) -> None:
    """Собрать SQLite-файл со схемой recent_messages, как в bot/database.py —
    без похода в реальный Database, чтобы тест не тянул лишнюю зависимость."""
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE recent_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.executemany(
        "INSERT INTO recent_messages (username, content, created_at) VALUES (?, ?, ?)", rows
    )
    conn.commit()
    conn.close()


class TestReadMessages:
    def test_reads_in_chronological_order(self, tmp_path: Path) -> None:
        db_path = tmp_path / "legacy.db"
        make_legacy_db(
            db_path,
            [("a", "первое", 1.0), ("b", "второе", 2.0), ("a", "третье", 3.0)],
        )
        rows = read_messages(db_path)
        assert [r.content for r in rows] == ["первое", "второе", "третье"]

    def test_empty_table(self, tmp_path: Path) -> None:
        db_path = tmp_path / "empty.db"
        make_legacy_db(db_path, [])
        assert read_messages(db_path) == []

    def test_readonly_does_not_lock_original(self, tmp_path: Path) -> None:
        # открывается в режиме mode=ro — повторное чтение не должно падать
        db_path = tmp_path / "legacy.db"
        make_legacy_db(db_path, [("a", "текст", 1.0)])
        read_messages(db_path)
        rows = read_messages(db_path)
        assert len(rows) == 1


class TestToEvents:
    def test_first_occurrence_marked_as_first_message(self) -> None:
        rows = [
            ReplayRow(username="a", content="привет", created_at=1.0),
            ReplayRow(username="a", content="снова я", created_at=2.0),
            ReplayRow(username="b", content="и я тут", created_at=3.0),
        ]
        events = to_events(rows, channel="test")
        assert events[0].is_first_message is True
        assert events[1].is_first_message is False
        assert events[2].is_first_message is True

    def test_user_id_equals_username(self) -> None:
        rows = [ReplayRow(username="viewer1", content="текст", created_at=1.0)]
        events = to_events(rows, channel="test")
        assert events[0].user_id == "viewer1"
        assert events[0].login == "viewer1"

    def test_no_privilege_flags_by_default(self) -> None:
        rows = [ReplayRow(username="a", content="текст", created_at=1.0)]
        events = to_events(rows, channel="test")
        assert events[0].is_moderator is False
        assert events[0].is_subscriber is False
        assert events[0].account_created_at is None

    def test_channel_propagated(self) -> None:
        rows = [ReplayRow(username="a", content="текст", created_at=1.0)]
        events = to_events(rows, channel="mychannel")
        assert events[0].channel == "mychannel"


class TestRunReplay:
    async def test_clean_chat_produces_zero_flagged(self) -> None:
        # Реально разный по содержанию чат, растянутый по времени — не
        # шаблонный текст с меняющимся числом (это структурно совпало бы
        # с формой атаки: одинаковый skeleton, все "первые", синхронно).
        messages = [
            "кто-нибудь знает во сколько сегодня начало стрима",
            "новая карта в игре выглядит очень красиво",
            "спасибо за прошлый стрим, было очень весело",
            "а можно ссылку на плейлист с музыкой",
            "поздравляю с новым уровнем, давно так не играл",
            "ору с этого момента",
            "го дальше основной квест проходить",
            "камон ты сможешь пройти этот босс",
            "у меня тоже так было на прошлой неделе",
            "красиво сыграно, respect",
            "кто-то знает название этой песни в фоне",
            "первый раз смотрю, очень нравится подача",
            "ахахах ору с чата",
            "го читать чат внимательнее плиз",
            "спасибо что стримишь именно в это время",
            "интересно что будет дальше по сюжету",
            "звук иногда пропадает, у всех так",
            "красивая locations в этой игре",
            "надеюсь дальше будет ещё сложнее",
            "до связи, отличного стрима всем",
        ]
        rows = [
            ReplayRow(username=f"viewer{i}", content=text, created_at=i * 12.0)
            for i, text in enumerate(messages)
        ]
        events = to_events(rows, channel="test")
        report = await run_replay(events, default_config(), ChannelProfile(channel="test"))

        assert report.total_messages == 20
        assert report.false_positive_candidates == 0
        assert report.action_counts["BAN"] == 0
        assert report.action_counts["TIMEOUT"] == 0

    async def test_bot_attack_produces_flagged_verdicts(self) -> None:
        rows = [
            ReplayRow(
                username=f"bot{i}",
                content=f"Забирай бесплатные подписчики прямо сейчас bit.ly/promo{i % 5}",
                created_at=i * (3.0 / 50),
            )
            for i in range(50)
        ]
        events = to_events(rows, channel="test")
        report = await run_replay(events, default_config(), ChannelProfile(channel="test"))

        assert report.in_cluster_count > 0
        assert any(v.recommended_action != Action.NOTHING for v in report.top_risk)

    async def test_report_format_summary_contains_counts(self) -> None:
        rows = [ReplayRow(username="a", content="привет всем в чате", created_at=1.0)]
        events = to_events(rows, channel="test")
        report = await run_replay(events, default_config(), ChannelProfile(channel="test"))

        text = report.format_summary()
        assert "Сообщений проанализировано: 1" in text
        assert "NOTHING" in text

    async def test_top_risk_respects_top_n(self) -> None:
        rows = [
            ReplayRow(username=f"u{i}", content=f"сообщение с уникальным текстом {i}", created_at=float(i))
            for i in range(30)
        ]
        events = to_events(rows, channel="test")
        report = await run_replay(events, default_config(), ChannelProfile(channel="test"), top_n=5)
        assert len(report.top_risk) <= 5
