"""Тесты HelixClient — целиком на моках через httpx.MockTransport.

Ни один тест здесь не обращается к реальному Twitch API — это то, ради
чего клиент был отделён от объектной модели twitchio (см. докстринг
cigilbot/twitch_api.py).
"""

from __future__ import annotations

import httpx
import pytest

from cigilbot.integrations.twitch_api import (
    MAX_USERS_PER_REQUEST,
    HelixClient,
    HelixError,
)


def make_client(handler) -> HelixClient:  # type: ignore[no-untyped-def]
    return HelixClient(
        "cid",
        "csecret",
        transport=httpx.MockTransport(handler),
        max_requests_per_second=1000.0,
        backoff_base_seconds=0.0,
    )


def token_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"access_token": "app_tok", "expires_in": 3600})


class TestAppTokenCaching:
    async def test_reuses_cached_token(self) -> None:
        calls = {"token": 0, "users": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                calls["token"] += 1
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
            calls["users"] += 1
            return httpx.Response(200, json={"data": []})

        client = make_client(handler)
        await client.get_users(logins=["a"])
        await client.get_users(logins=["b"])
        await client.close()

        assert calls["token"] == 1
        assert calls["users"] == 2

    async def test_refetches_expired_token(self) -> None:
        calls = {"token": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                calls["token"] += 1
                # почти сразу истекает — второй вызов должен обновить токен
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 30})
            return httpx.Response(200, json={"data": []})

        client = make_client(handler)
        await client.get_users(logins=["a"])
        # запас "protected" окно — 60 сек до истечения уже считается протухшим
        await client.get_users(logins=["b"])
        await client.close()

        assert calls["token"] == 2

    async def test_token_fetch_failure_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="invalid client")

        client = make_client(handler)
        with pytest.raises(HelixError):
            await client.get_users(logins=["a"])
        await client.close()


class TestGetUsers:
    async def test_empty_request_returns_empty_without_network_call(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("не должно быть сетевых вызовов на пустой запрос")

        client = make_client(handler)
        result = await client.get_users()
        assert result == []
        await client.close()

    async def test_parses_created_at(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "1", "login": "viewer1", "display_name": "Viewer1",
                            "created_at": "2020-05-14T12:00:00Z",
                        }
                    ]
                },
            )

        client = make_client(handler)
        users = await client.get_users(logins=["viewer1"])
        await client.close()

        assert len(users) == 1
        assert users[0].id == "1"
        assert users[0].login == "viewer1"
        assert users[0].created_at > 0

    async def test_batches_over_100_users(self) -> None:
        received_batches: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            n = len(request.url.params.get_list("login"))
            received_batches.append(n)
            return httpx.Response(200, json={"data": []})

        client = make_client(handler)
        logins = [f"user{i}" for i in range(250)]
        await client.get_users(logins=logins)
        await client.close()

        assert received_batches == [MAX_USERS_PER_REQUEST, MAX_USERS_PER_REQUEST, 50]

    async def test_error_response_raises_helix_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            return httpx.Response(400, text="bad request")

        client = make_client(handler)
        with pytest.raises(HelixError):
            await client.get_users(logins=["a"])
        await client.close()


class TestBanUser:
    async def test_success(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert request.url.path == "/helix/moderation/bans"
            return httpx.Response(200, json={"data": [{"user_id": "123"}]})

        client = make_client(handler)
        result = await client.ban_user(
            broadcaster_id="1", moderator_id="1", user_id="123", reason="spam", user_token="usertok"
        )
        await client.close()

        assert result.success is True
        assert result.user_id == "123"

    async def test_no_duration_field_for_permanent_ban(self) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": [{"user_id": "123"}]})

        client = make_client(handler)
        await client.ban_user(
            broadcaster_id="1", moderator_id="1", user_id="123", reason="spam", user_token="usertok"
        )
        await client.close()

        assert "duration" not in captured["body"]["data"]

    async def test_unauthorized_returns_failure_not_exception(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="Missing scope: moderator:manage:banned_users")

        client = make_client(handler)
        result = await client.ban_user(
            broadcaster_id="1", moderator_id="1", user_id="123", reason="spam", user_token="usertok"
        )
        await client.close()

        assert result.success is False
        assert "401" in result.error


class TestTimeoutUser:
    async def test_includes_duration(self) -> None:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": [{"user_id": "123"}]})

        client = make_client(handler)
        result = await client.timeout_user(
            broadcaster_id="1", moderator_id="1", user_id="123", duration=600,
            reason="spam burst", user_token="usertok",
        )
        await client.close()

        assert result.success is True
        assert captured["body"]["data"]["duration"] == 600


class TestDeleteChatMessages:
    async def test_success_204(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "DELETE"
            return httpx.Response(204)

        client = make_client(handler)
        result = await client.delete_chat_messages(
            broadcaster_id="1", moderator_id="1", user_token="usertok", message_id="msg1"
        )
        await client.close()

        assert result.success is True

    async def test_failure_returns_result_not_raise(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="message not found")

        client = make_client(handler)
        result = await client.delete_chat_messages(
            broadcaster_id="1", moderator_id="1", user_token="usertok", message_id="gone"
        )
        await client.close()

        assert result.success is False


class TestCreateClip:
    async def test_success_202(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert request.url.path == "/helix/clips"
            assert request.url.params["broadcaster_id"] == "1"
            return httpx.Response(
                202,
                json={"data": [{"id": "clip123", "edit_url": "https://clips.twitch.tv/clip123/edit"}]},
            )

        client = make_client(handler)
        result = await client.create_clip(broadcaster_id="1", user_token="usertok")
        await client.close()

        assert result.success is True
        assert result.clip_id == "clip123"
        assert result.edit_url == "https://clips.twitch.tv/clip123/edit"

    async def test_non_202_returns_failure_not_exception(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, text="Missing scope: clips:edit")

        client = make_client(handler)
        result = await client.create_clip(broadcaster_id="1", user_token="usertok")
        await client.close()

        assert result.success is False
        assert "403" in result.error

    async def test_exhausted_retries_returns_failure_not_raise(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        client = make_client(handler)
        result = await client.create_clip(broadcaster_id="1", user_token="usertok")
        await client.close()

        assert result.success is False
        assert result.broadcaster_id == "1"


class TestGetStreams:
    async def test_empty_request_returns_empty_without_network_call(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("не должно быть сетевых вызовов на пустой запрос")

        client = make_client(handler)
        result = await client.get_streams(broadcaster_ids=[])
        assert result == []
        await client.close()

    async def test_live_channel_returns_viewer_count(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            assert request.url.params.get_list("user_id") == ["1"]
            return httpx.Response(200, json={"data": [{"user_id": "1", "viewer_count": 342}]})

        client = make_client(handler)
        streams = await client.get_streams(broadcaster_ids=["1"])
        await client.close()

        assert len(streams) == 1
        assert streams[0].is_live is True
        assert streams[0].viewer_count == 342

    async def test_offline_channel_returns_is_live_false(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            return httpx.Response(200, json={"data": []})

        client = make_client(handler)
        streams = await client.get_streams(broadcaster_ids=["1"])
        await client.close()

        assert len(streams) == 1
        assert streams[0].broadcaster_id == "1"
        assert streams[0].is_live is False
        assert streams[0].viewer_count == 0

    async def test_mixed_live_and_offline_preserves_order(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            return httpx.Response(200, json={"data": [{"user_id": "2", "viewer_count": 10}]})

        client = make_client(handler)
        streams = await client.get_streams(broadcaster_ids=["1", "2", "3"])
        await client.close()

        assert [s.broadcaster_id for s in streams] == ["1", "2", "3"]
        assert [s.is_live for s in streams] == [False, True, False]
        assert streams[1].viewer_count == 10

    async def test_batches_over_100_channels(self) -> None:
        received_batches: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            n = len(request.url.params.get_list("user_id"))
            received_batches.append(n)
            return httpx.Response(200, json={"data": []})

        client = make_client(handler)
        ids = [str(i) for i in range(250)]
        await client.get_streams(broadcaster_ids=ids)
        await client.close()

        assert received_batches == [MAX_USERS_PER_REQUEST, MAX_USERS_PER_REQUEST, 50]

    async def test_error_response_raises_helix_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            return httpx.Response(400, text="bad request")

        client = make_client(handler)
        with pytest.raises(HelixError):
            await client.get_streams(broadcaster_ids=["1"])
        await client.close()


class TestRetryAndRateLimit:
    async def test_retries_on_5xx_then_succeeds(self) -> None:
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(500, text="internal error")
            return httpx.Response(200, json={"data": []})

        client = make_client(handler)
        await client.get_users(logins=["a"])
        await client.close()

        assert attempts["n"] == 2

    async def test_gives_up_after_max_retries(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/token" in str(request.url):
                return token_handler(request)
            return httpx.Response(500, text="internal error")

        client = make_client(handler)
        with pytest.raises(HelixError):
            await client.get_users(logins=["a"])
        await client.close()
