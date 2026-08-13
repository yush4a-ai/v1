"""Общие фикстуры для тестов движка модерации.

make_event — единая точка создания ChatEvent в тестах. Все опциональные
поля закрыты разумными дефолтами, чтобы тест на конкретный признак
(например burst) не обрастал шумом из несвязанных полей.
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Callable

import pytest

from cigilbot.detectors.base import DetectionContext
from cigilbot.domain.config import ChannelProfile, ModerationConfig, default_config
from cigilbot.domain.normalize import fingerprint
from cigilbot.domain.types import ChannelContext, ChatEvent, UserState
from cigilbot.domain.window import SlidingWindow

_user_id_counter = itertools.count(1)


def _next_user_id() -> str:
    return str(1000 + next(_user_id_counter))


def make_event(
    login: str = "viewer",
    text: str = "привет",
    *,
    user_id: str | None = None,
    timestamp: float | None = None,
    channel: str = "testchannel",
    is_first_message: bool = False,
    is_returning_chatter: bool = False,
    is_subscriber: bool = False,
    is_moderator: bool = False,
    is_vip: bool = False,
    is_broadcaster: bool = False,
    badges: tuple[str, ...] = (),
    account_created_at: float | None = None,
) -> ChatEvent:
    return ChatEvent(
        user_id=user_id or _next_user_id(),
        login=login,
        text=text,
        timestamp=time.time() if timestamp is None else timestamp,
        channel=channel,
        display_name=login,
        message_id=f"msg-{next(_user_id_counter)}",
        is_first_message=is_first_message,
        is_returning_chatter=is_returning_chatter,
        is_subscriber=is_subscriber,
        is_moderator=is_moderator,
        is_vip=is_vip,
        is_broadcaster=is_broadcaster,
        badges=badges,
        account_created_at=account_created_at,
    )


EventFactory = Callable[..., ChatEvent]


@pytest.fixture
def event_factory() -> EventFactory:
    return make_event


def add_message(window: SlidingWindow, event: ChatEvent) -> None:
    """Добавить сообщение в окно, посчитав отпечаток — то, что в реальности
    делает Normalizer перед тем, как отдать событие детекторам."""
    window.add(event, fingerprint(event.text))


def make_user_state(event: ChatEvent, **overrides: object) -> UserState:
    defaults: dict[str, object] = {
        "user_id": event.user_id,
        "login": event.login,
        "first_seen": event.timestamp,
        "last_seen": event.timestamp,
        "message_count": 0,
    }
    defaults.update(overrides)
    return UserState(**defaults)  # type: ignore[arg-type]


def make_context(
    event: ChatEvent,
    *,
    window: SlidingWindow | None = None,
    user: UserState | None = None,
    config: ModerationConfig | None = None,
    channel_profile: ChannelProfile | None = None,
    channel_context: ChannelContext | None = None,
    known_bad_actor_ids: frozenset[str] = frozenset(),
) -> DetectionContext:
    """Собрать DetectionContext с разумными дефолтами для теста одного детектора.

    По умолчанию окно пустое и не содержит само event — большинство
    детекторов (burst, duplicate, links) читают ИСТОРИЮ из окна, поэтому
    если тест хочет, чтобы текущее сообщение "увидело" соседей, их нужно
    добавить в window заранее через add_message(), а событие детектору
    передаётся отдельно как ctx.event (совпадать с содержимым окна не обязано).
    """
    return DetectionContext(
        event=event,
        fingerprint=fingerprint(event.text),
        user=user if user is not None else make_user_state(event),
        window=window if window is not None else SlidingWindow(),
        config=config if config is not None else default_config(),
        channel_profile=(
            channel_profile if channel_profile is not None else ChannelProfile(channel="test")
        ),
        channel_context=channel_context if channel_context is not None else ChannelContext(),
        known_bad_actor_ids=known_bad_actor_ids,
    )
