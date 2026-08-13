"""Протокол детектора и контекст, который ему передаётся.

Ключевое архитектурное ограничение: DetectionContext не содержит ничего,
умеющего сеть или диск. Детектор физически не может отправить запрос в
Twitch — у него просто нет такой зависимости в сигнатуре. Действие
принимает решение дальше по цепочке (policy.py), детектор только наблюдает.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cigilbot.domain.config import ChannelProfile, ModerationConfig
from cigilbot.domain.normalize import MessageFingerprint
from cigilbot.domain.types import ChannelContext, ChatEvent, Signal, UserState
from cigilbot.domain.window import SlidingWindow


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Всё, что нужно детектору для оценки одного сообщения.

    known_bad_actor_ids — снимок Cross-Channel Bot Fingerprint (направление
    03 master-plan.html): user_id, забаненные хотя бы на одном канале
    оператора. Не поле ChannelContext — тот описывает состояние канала
    (рейд, розыгрыш), а это про конкретных пользователей, общих для всех
    каналов сразу. Движок обновляет множество из ModerationHub раз в тик
    (см. engine.py::sync_known_bad_actors), детектор только читает."""

    event: ChatEvent
    fingerprint: MessageFingerprint
    user: UserState
    window: SlidingWindow
    config: ModerationConfig
    channel_profile: ChannelProfile
    channel_context: ChannelContext
    known_bad_actor_ids: frozenset[str] = frozenset()


class Detector(Protocol):
    """Контракт детектора: чистая функция события в список сигналов.

    Расширяемость намеренно устроена так: новый детектор — это новый файл
    с функцией такой сигнатуры плюс строка в реестре (detectors/__init__.py).
    Ни scoring.py, ни policy.py, ни панель при этом не меняются — они
    работают с абстракцией Signal, а не со списком известных проверок.
    """

    name: str

    def detect(self, ctx: DetectionContext) -> list[Signal]: ...
