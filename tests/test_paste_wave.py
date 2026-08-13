"""Тесты cigilbot/store.py::find_paste_wave — ручная зачистка волны копипасты.

Пользователь 2026-08-13: сценарий "весь чат кидает одну и ту же пасту,
стримеру это не нравится, нужен способ быстро остановить волну".
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.types import ChatEvent
from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "test.db"))
    await s.connect()
    return s


async def save(store: ModerationStore, *, user_id: str, login: str, text: str, age_seconds: float = 0.0) -> None:
    event = ChatEvent(
        user_id=user_id, login=login, text=text, timestamp=time.time() - age_seconds,
    )
    await store.save_message(event, fingerprint(text))


PASTE = (
    "Привет, это я - твой единственный зритель. Я на протяжении многих лет "
    "создавал иллюзию того, что тебя смотрят много людей, но это был я."
)


class TestFindPasteWave:
    async def test_finds_exact_copies(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text=PASTE)
        await save(store, user_id="2", login="b", text=PASTE)
        await save(store, user_id="3", login="c", text=PASTE)

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        assert len(matches) == 3
        logins = {m["login"] for m in matches}
        assert logins == {"a", "b", "c"}

    async def test_finds_slightly_modified_copies(self, store: ModerationStore) -> None:
        modified = PASTE.replace("единственный", "самый преданный")
        await save(store, user_id="1", login="a", text=PASTE)
        await save(store, user_id="2", login="b", text=modified)

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        logins = {m["login"] for m in matches}
        assert logins == {"a", "b"}

    async def test_does_not_match_unrelated_messages(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text=PASTE)
        await save(store, user_id="2", login="b", text="привет как дела у всех сегодня")

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        logins = {m["login"] for m in matches}
        assert logins == {"a"}

    async def test_ignores_messages_outside_window(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text=PASTE, age_seconds=10)
        await save(store, user_id="2", login="b", text=PASTE, age_seconds=300)

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        logins = {m["login"] for m in matches}
        assert logins == {"a"}

    async def test_one_result_per_user(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text=PASTE, age_seconds=5)
        await save(store, user_id="1", login="a", text=PASTE, age_seconds=1)

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        assert len(matches) == 1

    async def test_no_matches_returns_empty_list(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text="обычное безобидное сообщение")

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        assert matches == []

    async def test_empty_database_returns_empty_list(self, store: ModerationStore) -> None:
        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)
        assert matches == []

    async def test_similarity_score_included(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text=PASTE)

        matches = await store.find_paste_wave(sample_text=PASTE, window_seconds=120)

        assert matches[0]["similarity"] == 1.0

    async def test_custom_threshold_is_stricter(self, store: ModerationStore) -> None:
        # Сильно перефразированный вариант — похож по теме, но не по тексту.
        loosely_related = "я тебя годами смотрел один во всём чате, представляешь"
        await save(store, user_id="1", login="a", text=loosely_related)

        matches = await store.find_paste_wave(
            sample_text=PASTE, window_seconds=120, similarity_threshold=0.95
        )

        assert matches == []


class TestListRecentMessages:
    """Источник для клика "вставить как образец пасты" в UI (пользователь
    2026-08-13: "сделай привязку к чату, чтобы на 1 кнопку нажал и паста
    вставилась") — без фильтра по risk_score, в отличие от get_recent_verdicts."""

    async def test_newest_first(self, store: ModerationStore) -> None:
        await save(store, user_id="1", login="a", text="первое", age_seconds=10)
        await save(store, user_id="2", login="b", text="второе", age_seconds=1)

        messages = await store.list_recent_messages()

        assert messages[0]["login"] == "b"
        assert messages[1]["login"] == "a"

    async def test_respects_limit(self, store: ModerationStore) -> None:
        for i in range(5):
            await save(store, user_id=str(i), login=f"user{i}", text="сообщение")

        messages = await store.list_recent_messages(limit=2)

        assert len(messages) == 2

    async def test_empty_database_returns_empty_list(self, store: ModerationStore) -> None:
        assert await store.list_recent_messages() == []

    async def test_includes_low_risk_messages(self, store: ModerationStore) -> None:
        # В отличие от get_recent_verdicts (risk_score >= 30), здесь нет
        # фильтра — паста от доверенных зрителей туда бы не попала.
        await save(store, user_id="1", login="a", text="привет как дела у всех")

        messages = await store.list_recent_messages()

        assert len(messages) == 1
        assert messages[0]["text"] == "привет как дела у всех"
