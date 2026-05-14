"""
tests/unit/test_vault_client.py

Unit tests for shared/vault_client.py.
All Vault HTTP calls are mocked with httpx.MockTransport — no real Vault needed.

Run:
    pip install pytest pytest-asyncio httpx structlog tenacity
    pytest tests/unit/test_vault_client.py -v
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from shared.vault_client import (
    VaultAuthError,
    VaultClient,
    VaultError,
    VaultSecretNotFoundError,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

FAKE_TOKEN = "s.faketoken123"
FAKE_TTL = 3600

LOGIN_RESPONSE = {
    "auth": {
        "client_token": FAKE_TOKEN,
        "lease_duration": FAKE_TTL,
        "renewable": True,
        "policies": ["contextmesh-crawler-k8s"],
    }
}

SECRET_RESPONSE = {
    "data": {
        "data": {
            "bootstrap_servers": "kafka:9092",
            "ssl_cafile": "/certs/ca.crt",
        }
    }
}

RENEW_RESPONSE = {
    "auth": {
        "client_token": FAKE_TOKEN,
        "lease_duration": FAKE_TTL,
        "renewable": True,
    }
}


def _make_client(sa_token_path: Path) -> VaultClient:
    return VaultClient(
        vault_addr="https://vault.test:8200",
        role="crawler-k8s",
        cacert=None,
        sa_token_path=sa_token_path,
    )


def _mock_http(responses: list[httpx.Response]) -> MagicMock:
    """Return a mock httpx.AsyncClient that returns each response in order."""
    mock = MagicMock()
    mock.aclose = AsyncMock()

    async def post_side_effect(*args: Any, **kwargs: Any) -> httpx.Response:
        return responses.pop(0)

    async def get_side_effect(*args: Any, **kwargs: Any) -> httpx.Response:
        return responses.pop(0)

    mock.post = AsyncMock(side_effect=post_side_effect)
    mock.get = AsyncMock(side_effect=get_side_effect)
    mock.request = AsyncMock(side_effect=get_side_effect)
    return mock


def _json_resp(body: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(status_code=status, json=body)


# ── Tests: login ──────────────────────────────────────────────────────────────


class TestVaultLogin:
    @pytest.mark.asyncio
    async def test_login_success_sets_token(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._http = _mock_http([_json_resp(LOGIN_RESPONSE)])

        await client._login()

        assert client._vault_token == FAKE_TOKEN
        assert client._token_ttl == FAKE_TTL
        assert client._token_issued_at > 0

    @pytest.mark.asyncio
    async def test_login_missing_sa_token_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "no-such-token"
        client = _make_client(missing)
        client._http = MagicMock()

        with pytest.raises(VaultAuthError, match="ServiceAccount token not found"):
            await client._login()

    @pytest.mark.asyncio
    async def test_login_http_403_raises_auth_error(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._http = _mock_http([_json_resp({"errors": ["permission denied"]}, 403)])

        with pytest.raises(VaultAuthError, match="HTTP 403"):
            await client._login()


# ── Tests: get_secret ─────────────────────────────────────────────────────────


class TestGetSecret:
    @pytest.mark.asyncio
    async def test_returns_secret_data(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_ttl = FAKE_TTL
        client._token_issued_at = time.monotonic()
        client._token_expiry = client._token_issued_at + FAKE_TTL
        client._http = _mock_http([_json_resp(SECRET_RESPONSE)])

        result = await client.get_secret("kafka-credentials")

        assert result["bootstrap_servers"] == "kafka:9092"

    @pytest.mark.asyncio
    async def test_404_raises_secret_not_found(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_expiry = time.monotonic() + FAKE_TTL
        client._token_issued_at = time.monotonic()
        client._token_ttl = FAKE_TTL
        client._http = _mock_http([_json_resp({"errors": []}, 404)])

        with pytest.raises(VaultSecretNotFoundError, match="kafka-credentials"):
            await client.get_secret("kafka-credentials")

    @pytest.mark.asyncio
    async def test_403_triggers_re_login_and_retries(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = "stale-token"
        client._token_expiry = time.monotonic() + FAKE_TTL
        client._token_issued_at = time.monotonic()
        client._token_ttl = FAKE_TTL

        # First get → 403, then login, then get → success
        mock = MagicMock()
        mock.aclose = AsyncMock()
        call_count = {"get": 0, "post": 0}

        async def get_side(*args: Any, **kwargs: Any) -> httpx.Response:
            call_count["get"] += 1
            if call_count["get"] == 1:
                return _json_resp({"errors": ["permission denied"]}, 403)
            return _json_resp(SECRET_RESPONSE)

        async def post_side(*args: Any, **kwargs: Any) -> httpx.Response:
            call_count["post"] += 1
            return _json_resp(LOGIN_RESPONSE)

        mock.get = AsyncMock(side_effect=get_side)
        mock.post = AsyncMock(side_effect=post_side)
        client._http = mock

        result = await client.get_secret("kafka-credentials")
        assert result["bootstrap_servers"] == "kafka:9092"
        assert call_count["post"] == 1  # re-login was called

    @pytest.mark.asyncio
    async def test_non_200_non_403_404_raises_vault_error(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_expiry = time.monotonic() + FAKE_TTL
        client._token_issued_at = time.monotonic()
        client._token_ttl = FAKE_TTL
        client._http = _mock_http([_json_resp({"errors": ["internal error"]}, 500)])

        with pytest.raises(VaultError):
            await client.get_secret("kafka-credentials")


# ── Tests: token renewal ──────────────────────────────────────────────────────


class TestTokenRenewal:
    @pytest.mark.asyncio
    async def test_renew_token_updates_expiry(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_ttl = 100
        client._token_issued_at = time.monotonic()
        client._token_expiry = client._token_issued_at + 100
        client._refresh_lock = asyncio.Lock()

        mock = MagicMock()
        mock.aclose = AsyncMock()
        mock.post = AsyncMock(return_value=_json_resp(RENEW_RESPONSE))
        client._http = mock

        old_expiry = client._token_expiry
        await client._renew_token()

        assert client._token_expiry > old_expiry or client._token_ttl == FAKE_TTL

    @pytest.mark.asyncio
    async def test_renew_403_raises_auth_error(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = "non-renewable-token"
        client._token_ttl = 100
        client._token_issued_at = time.monotonic()
        client._token_expiry = client._token_issued_at + 100
        client._refresh_lock = asyncio.Lock()

        mock = MagicMock()
        mock.post = AsyncMock(return_value=_json_resp({}, 403))
        client._http = mock

        with pytest.raises(VaultAuthError, match="not renewable"):
            await client._renew_token()


# ── Tests: ensure_token_fresh ─────────────────────────────────────────────────


class TestEnsureTokenFresh:
    @pytest.mark.asyncio
    async def test_expired_token_triggers_relogin(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = "old-token"
        client._token_expiry = time.monotonic() - 1  # already expired
        client._refresh_lock = asyncio.Lock()

        mock = MagicMock()
        mock.aclose = AsyncMock()
        mock.post = AsyncMock(return_value=_json_resp(LOGIN_RESPONSE))
        client._http = mock

        await client._ensure_token_fresh()

        assert client._vault_token == FAKE_TOKEN

    @pytest.mark.asyncio
    async def test_fresh_token_does_not_relogin(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_expiry = time.monotonic() + 3600  # still valid
        client._refresh_lock = asyncio.Lock()

        mock = MagicMock()
        mock.post = AsyncMock()  # should NOT be called
        client._http = mock

        await client._ensure_token_fresh()

        mock.post.assert_not_called()


# ── Tests: list_secrets ───────────────────────────────────────────────────────


class TestListSecrets:
    @pytest.mark.asyncio
    async def test_list_returns_keys(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_expiry = time.monotonic() + FAKE_TTL
        client._token_issued_at = time.monotonic()
        client._token_ttl = FAKE_TTL

        mock = MagicMock()
        mock.request = AsyncMock(
            return_value=_json_resp(
                {"data": {"keys": ["kafka-credentials", "postgres-credentials"]}}
            )
        )
        client._http = mock

        keys = await client.list_secrets()
        assert "kafka-credentials" in keys

    @pytest.mark.asyncio
    async def test_list_404_returns_empty(self, tmp_path: Path) -> None:
        sa_token = tmp_path / "token"
        sa_token.write_text("fake-sa-jwt")

        client = _make_client(sa_token)
        client._vault_token = FAKE_TOKEN
        client._token_expiry = time.monotonic() + FAKE_TTL
        client._token_issued_at = time.monotonic()
        client._token_ttl = FAKE_TTL

        mock = MagicMock()
        mock.request = AsyncMock(return_value=_json_resp({}, 404))
        client._http = mock

        keys = await client.list_secrets("nonexistent/")
        assert keys == []
