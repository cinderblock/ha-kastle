"""Tests for the KastleApi client (error handling, cookie parsing)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from custom_components.kastle.api import (
    KastleApi,
    KastleApiError,
    KastleAuthError,
    generate_ec_keypair,
)


def _make_response(
    body: str,
    status: int = 200,
    cookies: list[str] | None = None,
) -> AsyncMock:
    """Create a mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.headers = MagicMock()
    resp.headers.getall = MagicMock(return_value=cookies or [])
    return resp


def _make_session(response: AsyncMock) -> AsyncMock:
    """Create a mock aiohttp session that returns the given response."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    session.post = MagicMock(return_value=ctx)
    return session


@pytest.mark.asyncio
async def test_api_call_success():
    """Successful API call should return parsed data."""
    resp = _make_response('{"IsSuccess": true, "Data": {"foo": "bar"}}')
    session = _make_session(resp)
    api = KastleApi(session)

    result = await api._api_call("test/path", {"key": "val"})
    assert result["IsSuccess"] is True
    assert result["Data"]["foo"] == "bar"


@pytest.mark.asyncio
async def test_api_call_error_raises():
    """API returning IsSuccess=false should raise KastleApiError."""
    resp = _make_response(
        '{"IsSuccess": false, "ErrorCode": 123, "Message": "Something broke"}'
    )
    session = _make_session(resp)
    api = KastleApi(session)

    with pytest.raises(KastleApiError, match="Something broke") as exc_info:
        await api._api_call("test/path")
    assert exc_info.value.error_code == 123


@pytest.mark.asyncio
async def test_api_call_auth_error():
    """API returning ERR_NOT_REGISTERED should raise KastleAuthError."""
    resp = _make_response(
        '{"IsSuccess": false, "ErrorCode": 60134, "Message": "Not registered"}'
    )
    session = _make_session(resp)
    api = KastleApi(session)

    with pytest.raises(KastleAuthError, match="Not registered"):
        await api._api_call("test/path")


@pytest.mark.asyncio
async def test_api_call_invalid_token_status():
    """API returning TokenStatus=INVALID should raise KastleAuthError."""
    resp = _make_response(
        '{"IsSuccess": false, "TokenStatus": "INVALID", "Message": "Token expired"}'
    )
    session = _make_session(resp)
    api = KastleApi(session)

    with pytest.raises(KastleAuthError, match="Token expired"):
        await api._api_call("test/path")


@pytest.mark.asyncio
async def test_api_call_invalid_json():
    """Non-JSON response should raise KastleApiError."""
    resp = _make_response("<html>error</html>")
    session = _make_session(resp)
    api = KastleApi(session)

    with pytest.raises(KastleApiError, match="Invalid JSON"):
        await api._api_call("test/path")


@pytest.mark.asyncio
async def test_api_call_non_dict_response():
    """Response that parses to non-dict should raise KastleApiError."""
    resp = _make_response('"just a string"')
    session = _make_session(resp)
    api = KastleApi(session)

    with pytest.raises(KastleApiError, match="Unexpected response"):
        await api._api_call("test/path")


@pytest.mark.asyncio
async def test_api_call_captures_cookies():
    """Set-Cookie headers should be captured."""
    resp = _make_response(
        '{"IsSuccess": true}',
        cookies=["session=abc123; Path=/", "token=xyz; HttpOnly"],
    )
    session = _make_session(resp)
    api = KastleApi(session)

    await api._api_call("test/path")
    assert api.cookies["session"] == "abc123"
    assert api.cookies["token"] == "xyz"


@pytest.mark.asyncio
async def test_api_call_sends_cookies():
    """Stored cookies should be sent in the Cookie header."""
    resp = _make_response('{"IsSuccess": true}')
    session = _make_session(resp)
    api = KastleApi(session, cookies={"session": "abc"})

    await api._api_call("test/path")

    call_args = session.post.call_args
    headers = call_args.kwargs.get("headers", {})
    assert "session=abc" in headers.get("Cookie", "")


def test_generate_keys():
    """generate_keys should create both IPK and PKOC keypairs."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    api = KastleApi(session)

    assert api.ipk_private is None
    assert api.pkoc_private is None

    ipk_hex, pkoc_hex = api.generate_keys()

    assert api.ipk_private is not None
    assert api.pkoc_private is not None
    assert len(ipk_hex) == 130
    assert len(pkoc_hex) == 130
    assert ipk_hex != pkoc_hex


@pytest.mark.asyncio
async def test_unlock_door_requires_registration():
    """unlock_door should raise if not registered."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    api = KastleApi(session)

    with pytest.raises(KastleApiError, match="Not registered"):
        await api.unlock_door(
            reader_designator="R1",
            external_number="E1",
            reader_id="100",
            card_id="200",
            first_name="Test",
            last_name="User",
        )


@pytest.mark.asyncio
async def test_get_authorized_readers_requires_registration():
    """get_authorized_readers should raise if not registered."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    api = KastleApi(session)

    with pytest.raises(KastleApiError, match="Not registered"):
        await api.get_authorized_readers()
