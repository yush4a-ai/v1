"""Скользящие окна недавних сообщений — в памяти, без БД.

Детекторам burst/duplicate/cluster на каждое новое сообщение нужен быстрый
ответ "что происходило за последние N секунд". Ходить в SQLite ради этого
на каждое сообщение при атаке в сотни сообщений в секунду означало бы
упереться в диск раньше, чем в Twitch rate-limit. Поэтому окно живёт в
памяти процесса бота и пересобирается с нуля при перезапуске — это
нормально, устойчивая история хранится отдельно, в mod_messages (store.py).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass

from cigilbot.domain.normalize import MessageFingerprint
from cigilbot.domain.types import ChatEvent


@dataclass(frozen=True, slots=True)
class WindowEntry:
    event: ChatEvent
    fingerprint: MessageFingerprint


class SlidingWindow:
    """Кольцевой буфер последних сообщений одного канала.

    max_age_seconds — сколько держим в памяти. Берём максимум из того, что
    нужно детекторам (burst — секунды-десятки) и кластеризации (обычно
    минута на синхронность прибытия), а точные под-интервалы каждый
    детектор запрашивает сам через recent()/recent_by_user().
    """

    def __init__(self, max_age_seconds: float = 90.0):
        self._max_age = max_age_seconds
        self._entries: deque[WindowEntry] = deque()
        self._by_user: dict[str, deque[WindowEntry]] = defaultdict(deque)
        # Момент, с которого пользователь непрерывно присутствует в окне —
        # НЕ первое сообщение вообще (это ChatEvent.is_first_message из тегов
        # Twitch), а начало текущей "серии" активности. Сбрасывается, если
        # пользователь пропадает из окна дольше max_age.
        self._streak_start: dict[str, float] = {}

    def add(self, event: ChatEvent, fp: MessageFingerprint) -> None:
        entry = WindowEntry(event=event, fingerprint=fp)
        self._entries.append(entry)
        self._by_user[event.user_id].append(entry)
        self._streak_start.setdefault(event.user_id, event.timestamp)
        self._prune(event.timestamp)

    def _prune(self, now: float) -> None:
        cutoff = now - self._max_age
        while self._entries and self._entries[0].event.timestamp < cutoff:
            old = self._entries.popleft()
            uq = self._by_user.get(old.event.user_id)
            if uq is None:
                continue
            while uq and uq[0].event.timestamp < cutoff:
                uq.popleft()
            if not uq:
                del self._by_user[old.event.user_id]
                self._streak_start.pop(old.event.user_id, None)

    @staticmethod
    def _slice_from_right(entries: deque[WindowEntry], cutoff: float) -> list[WindowEntry]:
        """Взять хвост окна начиная с cutoff, идя с конца.

        Детектор вызывается на каждое новое сообщение и почти всегда просит
        короткий интервал (секунды) из буфера в десятки-сотни записей.
        Сканировать весь deque с начала — O(размер буфера) на каждый вызов,
        то есть O(n²) на серию сообщений при атаке. Идём с конца и
        останавливаемся на первой устаревшей записи — O(размер интервала).
        """
        result: list[WindowEntry] = []
        for entry in reversed(entries):
            if entry.event.timestamp < cutoff:
                break
            result.append(entry)
        result.reverse()
        return result

    def recent(self, seconds: float, now: float | None = None) -> list[WindowEntry]:
        now = time.time() if now is None else now
        return self._slice_from_right(self._entries, now - seconds)

    def recent_by_user(
        self, user_id: str, seconds: float, now: float | None = None
    ) -> list[WindowEntry]:
        now = time.time() if now is None else now
        uq = self._by_user.get(user_id)
        if not uq:
            return []
        return self._slice_from_right(uq, now - seconds)

    def user_message_count(
        self, user_id: str, seconds: float, now: float | None = None
    ) -> int:
        return len(self.recent_by_user(user_id, seconds, now))

    def channel_rate_per_minute(self, seconds: float = 20.0, now: float | None = None) -> float:
        """Скорость сообщений в канале, приведённая к сообщениям/минуту.

        Приведение к общей единице позволяет сравнивать окна разной длины
        (детектор burst смотрит последние 5 сек, контекст канала — последнюю
        минуту) по одной и той же шкале.
        """
        if seconds <= 0:
            return 0.0
        return len(self.recent(seconds, now)) / seconds * 60.0

    def unique_chatters(self, seconds: float, now: float | None = None) -> set[str]:
        return {e.event.user_id for e in self.recent(seconds, now)}

    def streak_start(self, user_id: str) -> float | None:
        """С какого момента пользователь непрерывно активен в окне."""
        return self._streak_start.get(user_id)

    def recent_arrivals(self, seconds: float, now: float | None = None) -> dict[str, float]:
        """user_id -> момент начала серии, для тех, кто начал недавно.

        Используется кластеризацией: много пользователей, чья серия
        началась в одном узком интервале — признак синхронного появления.
        """
        now = time.time() if now is None else now
        cutoff = now - seconds
        return {uid: ts for uid, ts in self._streak_start.items() if ts >= cutoff}

    def __len__(self) -> int:
        return len(self._entries)
