"""Лёгкое скользящее окно для детекции всплеска активности чата.

Специально для автоклипа (bot/autoclip.py), НЕ переиспользует
cigilbot.domain.window.SlidingWindow: тот сигнал настроен под
спам-детекцию (учитывает похожесть сообщений, кластеры), а здесь нужен
только счётчик уникальных авторов за окно — хайп, а не спам.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _Entry:
    timestamp: float
    author_id: str


class BurstWindow:
    """Считает уникальных авторов сообщений за последние window_seconds.

    Дедуп по автору намеренный: один флудящий зритель не должен считаться
    "хайпом" — важно число РАЗНЫХ людей, написавших почти одновременно.
    """

    def __init__(self, window_seconds: float) -> None:
        # Публичный, изменяемый атрибут, не приватный с property: панель
        # может поменять порог живьём (AutoclipHub._sync_thresholds_override)
        # без пересоздания BurstWindow — новое значение вступает в силу на
        # следующем add(), накопленные записи не теряются, просто следующая
        # чистка использует новую границу.
        self.window_seconds = window_seconds
        self._entries: deque[_Entry] = deque()

    def add(self, *, author_id: str, timestamp: float) -> int:
        """Добавляет сообщение, возвращает текущее число уникальных
        авторов в окне (после добавления и чистки устаревших записей)."""
        self._entries.append(_Entry(timestamp=timestamp, author_id=author_id))
        self._prune(timestamp)
        return len({entry.author_id for entry in self._entries})

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._entries and self._entries[0].timestamp < cutoff:
            self._entries.popleft()
