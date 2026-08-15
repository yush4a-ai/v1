"""Тесты store-методов токена клиппинга: mod_clip_token (миграция 020).
Та же структура, что TestAutoclipSettings в test_autoclip_store.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from cigilbot.storage.store import ModerationStore


@pytest.fixture
async def store(tmp_path: Path) -> ModerationStore:
    s = ModerationStore(str(tmp_path / "test.db"))
    await s.connect()
    return s


class TestClipToken:
    async def test_default_is_none(self, store: ModerationStore) -> None:
        """None — на этом канале ещё не проходили /auth/clip/login."""
        token = await store.get_clip_token()
        assert token is None

    async def test_set_persists(self, store: ModerationStore) -> None:
        await store.set_clip_token(
            access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99"
        )
        token = await store.get_clip_token()
        assert token is not None
        assert token.access_token == "access-1"
        assert token.refresh_token == "refresh-1"
        assert token.user_login == "mybot"
        assert token.user_id == "99"

    async def test_set_overwrites_previous(self, store: ModerationStore) -> None:
        await store.set_clip_token(
            access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99"
        )
        await store.set_clip_token(
            access_token="access-2", refresh_token="refresh-2", user_login="otherbot", user_id="42"
        )
        token = await store.get_clip_token()
        assert token is not None
        assert token.access_token == "access-2"
        assert token.user_login == "otherbot"
        assert token.user_id == "42"

    async def test_update_access_token_keeps_identity(self, store: ModerationStore) -> None:
        """update_clip_access_token не должен трогать user_login/user_id —
        владелец токена не меняется при lazy-refresh, только сам токен."""
        await store.set_clip_token(
            access_token="access-1", refresh_token="refresh-1", user_login="mybot", user_id="99"
        )
        await store.update_clip_access_token(access_token="access-2", refresh_token="refresh-2")
        token = await store.get_clip_token()
        assert token is not None
        assert token.access_token == "access-2"
        assert token.refresh_token == "refresh-2"
        assert token.user_login == "mybot"
        assert token.user_id == "99"

    async def test_two_channels_are_independent(self, tmp_path: Path) -> None:
        """Разные файлы БД (разные каналы) не должны видеть чужой токен —
        сама суть per-channel хранения (см. докстринг миграции 020)."""
        store_a = ModerationStore(str(tmp_path / "mod.a.db"))
        await store_a.connect()
        store_b = ModerationStore(str(tmp_path / "mod.b.db"))
        await store_b.connect()

        await store_a.set_clip_token(
            access_token="access-a", refresh_token="refresh-a", user_login="bot-a", user_id="1"
        )

        token_a = await store_a.get_clip_token()
        token_b = await store_b.get_clip_token()

        assert token_a is not None
        assert token_a.access_token == "access-a"
        assert token_b is None
