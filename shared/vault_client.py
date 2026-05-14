"""
shared/vault_client.py

Production Vault client used by every ContextMesh service.

Features:
- Kubernetes auth login (ServiceAccount JWT) with automatic re-login on 403
- Tenant-scoped secret path (secret/data/<secret_name>)
- TTL-aware lease renewal: renews at 75% of TTL elapsed
- Tenacity retry on transient network errors
- Full structlog structured logging on every operation
- Never exposes secret values in logs
- Thread-safe token refresh via asyncio.Lock
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, cast

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)

_K8S_SA_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_DEFAULT_VAULT_ADDR = "https://vault.vault.svc:8200"
_DEFAULT_VAULT_CACERT = "/vault/tls/ca.crt"
_LEASE_RENEWAL_THRESHOLD = 0.75


class VaultError(Exception):
    """Raised for unrecoverable Vault errors."""


class VaultAuthError(VaultError):
    """Raised when Vault auth fails."""


class VaultSecretNotFoundError(VaultError):
    """Raised when a secret path does not exist."""


class VaultClient:
    """
    Async Vault client with Kubernetes auth, lease renewal, and retries.
    """

    def __init__(
        self,
        *,
        vault_addr: str,
        role: str,
        cacert: str | None = None,
        sa_token_path: Path = _K8S_SA_TOKEN_PATH,
    ) -> None:
        self._vault_addr = vault_addr.rstrip("/")
        self._role = role
        self._cacert = cacert
        self._sa_token_path = sa_token_path

        self._vault_token: str | None = None
        self._token_expiry: float = 0.0
        self._token_ttl: int = 0
        self._token_issued_at: float = 0.0

        self._refresh_lock = asyncio.Lock()
        self._http: httpx.AsyncClient | None = None

        self._log = logger.bind(vault_addr=vault_addr, role=role)

    # ──────────────────────────────────────────────────────────────────────
    # Construction / lifecycle
    # ──────────────────────────────────────────────────────────────────────

    @classmethod
    @asynccontextmanager
    async def from_k8s_auth(
        cls,
        role: str,
        vault_addr: str | None = None,
        cacert: str | None = None,
    ) -> AsyncIterator[VaultClient]:
        addr = vault_addr or os.environ.get(
            "VAULT_ADDR",
            _DEFAULT_VAULT_ADDR,
        )

        ca = cacert or os.environ.get(
            "VAULT_CACERT",
            _DEFAULT_VAULT_CACERT,
        )

        client = cls(
            vault_addr=addr,
            role=role,
            cacert=ca,
        )

        await client._start()

        try:
            yield client
        finally:
            await client._stop()

    async def _start(self) -> None:
        ssl_context: bool | str = self._cacert if self._cacert else True

        self._http = httpx.AsyncClient(
            verify=ssl_context,
            timeout=httpx.Timeout(10.0, connect=5.0),
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
            ),
        )

        await self._login()
        self._renewal_task = asyncio.create_task(self._renewal_loop())

    async def _stop(self) -> None:
        if self._http:
            await self._http.aclose()

        self._log.info("vault_client.stopped")

    # ──────────────────────────────────────────────────────────────────────
    # Authentication
    # ──────────────────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(httpx.TransportError),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        reraise=True,
    )
    async def _login(self) -> None:
        async with self._refresh_lock:
            if not self._sa_token_path.exists():
                raise VaultAuthError(f"ServiceAccount token not found at " f"{self._sa_token_path}")

            sa_jwt = self._sa_token_path.read_text().strip()

            url = f"{self._vault_addr}" "/v1/auth/kubernetes/login"

            self._log.info(
                "vault.login.attempt",
                url=url,
            )

            resp = await self._http.post(  # type: ignore[union-attr]
                url,
                json={
                    "role": self._role,
                    "jwt": sa_jwt,
                },
            )

            if resp.status_code == 403:
                raise VaultAuthError("Vault Kubernetes auth failed: HTTP 403")

            if resp.status_code >= 400:
                raise VaultError(f"Vault login failed: " f"HTTP {resp.status_code}")

            data = resp.json()
            auth = data["auth"]

            self._vault_token = auth["client_token"]
            self._token_ttl = auth["lease_duration"]

            self._token_issued_at = time.monotonic()

            self._token_expiry = self._token_issued_at + self._token_ttl

            self._log.info(
                "vault.login.success",
                policies=auth.get("policies"),
                ttl_seconds=self._token_ttl,
                renewable=auth.get("renewable"),
            )

    # ──────────────────────────────────────────────────────────────────────
    # Token renewal
    # ──────────────────────────────────────────────────────────────────────

    async def _renewal_loop(self) -> None:
        while True:
            elapsed = time.monotonic() - self._token_issued_at

            renew_at = self._token_ttl * _LEASE_RENEWAL_THRESHOLD

            sleep_for = max(renew_at - elapsed, 1.0)

            await asyncio.sleep(sleep_for)

            try:
                await self._renew_token()

            except VaultAuthError:
                self._log.warning("vault.token_renewal.failed_re_login")
                await self._login()

            except asyncio.CancelledError:
                return

    @retry(
        retry=retry_if_exception_type(httpx.TransportError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _renew_token(self) -> None:
        async with self._refresh_lock:
            url = f"{self._vault_addr}" "/v1/auth/token/renew-self"

            resp = await self._http.post(  # type: ignore[union-attr]
                url,
                headers={"X-Vault-Token": self._vault_token or ""},
            )

            if resp.status_code == 403:
                raise VaultAuthError("Token not renewable — must re-login")

            if resp.status_code >= 400:
                raise VaultError(f"Vault token renewal failed: " f"HTTP {resp.status_code}")

            auth = resp.json()["auth"]

            self._token_ttl = auth["lease_duration"]

            self._token_issued_at = time.monotonic()

            self._token_expiry = self._token_issued_at + self._token_ttl

            self._log.info(
                "vault.token_renewed",
                new_ttl_seconds=self._token_ttl,
            )

    # ──────────────────────────────────────────────────────────────────────
    # Secret reads
    # ──────────────────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(httpx.TransportError),
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=1, max=15),
        reraise=True,
    )
    async def get_secret(
        self,
        secret_name: str,
    ) -> dict[str, Any]:
        await self._ensure_token_fresh()

        url = f"{self._vault_addr}" f"/v1/secret/data/{secret_name}"

        self._log.info(
            "vault.secret.read",
            secret_name=secret_name,
        )

        try:
            resp = await self._http.get(  # type: ignore[union-attr]
                url,
                headers={"X-Vault-Token": self._vault_token or ""},
            )

        except httpx.TransportError as exc:
            self._log.error(
                "vault.secret.transport_error",
                secret_name=secret_name,
                error=str(exc),
            )
            raise

        if resp.status_code == 403:
            self._log.warning(
                "vault.secret.auth_error_re_login",
                secret_name=secret_name,
            )

            await self._login()

            secret = await self.get_secret(secret_name)
            return cast(dict[str, Any], secret)

        if resp.status_code == 404:
            raise VaultSecretNotFoundError(f"Secret '{secret_name}' not found")

        if resp.status_code >= 400:
            raise VaultError(
                f"Vault returned HTTP " f"{resp.status_code} " f"for secret '{secret_name}'"
            )

        response_data = cast(dict[str, Any], resp.json())
        payload = cast(dict[str, Any], response_data["data"]["data"])

        self._log.info(
            "vault.secret.read_success",
            secret_name=secret_name,
            keys=list(payload.keys()),
        )

        return payload

    async def get_secret_version(
        self,
        secret_name: str,
        version: int,
    ) -> dict[str, Any]:
        await self._ensure_token_fresh()

        url = f"{self._vault_addr}" f"/v1/secret/data/{secret_name}" f"?version={version}"

        self._log.info(
            "vault.secret.read_version",
            secret_name=secret_name,
            version=version,
        )

        resp = await self._http.get(  # type: ignore[union-attr]
            url,
            headers={"X-Vault-Token": self._vault_token or ""},
        )

        if resp.status_code == 404:
            raise VaultSecretNotFoundError(
                f"Secret '{secret_name}' " f"version {version} not found"
            )

        if resp.status_code >= 400:
            raise VaultError(
                f"Failed reading secret "
                f"'{secret_name}' "
                f"version {version}: "
                f"HTTP {resp.status_code}"
            )

        response_data = cast(dict[str, Any], resp.json())
        return cast(dict[str, Any], response_data["data"]["data"])

    async def list_secrets(
        self,
        path: str = "",
    ) -> list[str]:
        await self._ensure_token_fresh()

        url = f"{self._vault_addr}" f"/v1/secret/metadata/{path}"

        resp = await self._http.request(  # type: ignore[union-attr]
            "LIST",
            url,
            headers={"X-Vault-Token": self._vault_token or ""},
        )

        if resp.status_code == 404:
            return []

        if resp.status_code >= 400:
            raise VaultError(f"Failed listing secrets: " f"HTTP {resp.status_code}")

        response_data = cast(dict[str, Any], resp.json())
        data = cast(dict[str, Any], response_data.get("data", {}))
        return cast(list[str], data.get("keys", []))

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    async def _ensure_token_fresh(self) -> None:
        if self._vault_token is None or time.monotonic() >= self._token_expiry:
            self._log.warning("vault.token_expired.re_login")

            await self._login()

    @property
    def token_ttl_remaining(self) -> float:
        return max(
            self._token_expiry - time.monotonic(),
            0.0,
        )
