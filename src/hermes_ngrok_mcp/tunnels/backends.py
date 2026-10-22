"""Tunnel providers. Production uses the embedded ngrok agent SDK (no ngrok binary needed)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from hermes_ngrok_mcp import __version__

log = logging.getLogger(__name__)

TunnelProtocol = Literal["http", "tcp"]

_NGROK_ERROR_RE = re.compile(r"ERR_NGROK_(\d+)")
_NGROK_HINTS = {
    "105": "the ngrok authtoken is invalid: check NGROK_AUTHTOKEN",
    "107": "the ngrok authtoken is invalid or was revoked: check NGROK_AUTHTOKEN",
    "108": "another ngrok agent session is already running with this account (free plans allow one)",
    "334": "this endpoint/domain is already online elsewhere (free plans have a single dev domain)",
    "8013": "TCP endpoints require a payment method on the ngrok account, even on the free plan",
}


class BackendError(Exception):
    """A provider failure, with a message safe to show (secrets redacted)."""


@dataclass(frozen=True)
class EndpointSpec:
    protocol: TunnelProtocol
    upstream: str
    traffic_policy: str | None = None
    domain: str | None = None
    metadata: str = ""
    description: str = ""


class Endpoint(Protocol):
    @property
    def url(self) -> str: ...

    async def close(self) -> None: ...


class TunnelBackend(Protocol):
    async def open(self, spec: EndpointSpec) -> Endpoint: ...

    async def aclose(self) -> None: ...


def basic_auth_policy(username: str, password: str, *, realm: str = "Hermes") -> str:
    """ngrok Traffic Policy enforcing HTTP basic authentication at the ngrok edge."""
    policy = {
        "on_http_request": [
            {
                "actions": [
                    {
                        "type": "basic-auth",
                        "config": {
                            "realm": realm,
                            "credentials": [f"{username}:{password}"],
                            "enforce": True,
                        },
                    }
                ]
            }
        ]
    }
    return json.dumps(policy, separators=(",", ":"))


def describe_ngrok_error(exc: BaseException, *, secrets: tuple[str, ...] = ()) -> str:
    text = " — ".join(str(arg) for arg in exc.args) if exc.args else type(exc).__name__
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    match = _NGROK_ERROR_RE.search(text)
    if match:
        code = match.group(1)
        hint = _NGROK_HINTS.get(code)
        reference = f"https://ngrok.com/docs/errors/err_ngrok_{code}"
        text = f"{text} (likely cause: {hint}; see {reference})" if hint else f"{text} (see {reference})"
    return text


class _NgrokEndpoint:
    def __init__(self, listener: Any, backend: NgrokBackend) -> None:
        self._listener = listener
        self._backend = backend
        self._url = str(listener.url())
        self._closed = False

    @property
    def url(self) -> str:
        return self._url

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await asyncio.wait_for(self._listener.close(), timeout=15)
        except Exception as exc:  # the session teardown below closes it anyway
            log.warning("closing ngrok endpoint %s failed: %s", self._url, describe_ngrok_error(exc))
        finally:
            await self._backend._release()


class NgrokBackend:
    """One lazily-created ngrok session, shared by all tunnels and closed when none is left.

    Keeping no session open while no tunnel exists means the server has no outbound
    connection to ngrok at rest.
    """

    def __init__(self, authtoken: str, *, connect_timeout: float = 30.0) -> None:
        self._authtoken = authtoken
        self._connect_timeout = connect_timeout
        self._lock = asyncio.Lock()
        self._session: Any = None
        self._open_endpoints = 0

    async def open(self, spec: EndpointSpec) -> Endpoint:
        async with self._lock:
            try:
                session = await self._ensure_session()
                if spec.protocol == "http":
                    builder = session.http_endpoint()
                    if spec.domain:
                        builder = builder.domain(spec.domain)
                    scheme = "http"
                else:
                    builder = session.tcp_endpoint()
                    scheme = "tcp"
                if spec.traffic_policy:
                    builder = builder.traffic_policy(spec.traffic_policy)
                if spec.metadata:
                    builder = builder.metadata(spec.metadata)
                if spec.description:
                    builder = builder.forwards_to(spec.description)
                listener = await asyncio.wait_for(
                    builder.listen_and_forward(f"{scheme}://{spec.upstream}"), timeout=self._connect_timeout
                )
            except Exception as exc:
                if self._open_endpoints == 0:
                    await self._close_session()
                if isinstance(exc, TimeoutError):
                    raise BackendError("timed out while contacting ngrok") from exc
                raise BackendError(describe_ngrok_error(exc, secrets=(self._authtoken,))) from exc
            self._open_endpoints += 1
            return _NgrokEndpoint(listener, self)

    async def aclose(self) -> None:
        async with self._lock:
            await self._close_session()
            self._open_endpoints = 0

    async def _ensure_session(self) -> Any:
        if self._session is None:
            import ngrok  # noqa: PLC0415 - native module, loaded only once a tunnel is requested

            builder = (
                ngrok.SessionBuilder()
                .authtoken(self._authtoken)
                .client_info("hermes-ngrok-mcp", __version__)
                .metadata("hermes-ngrok-mcp")
                .handle_disconnection(self._on_disconnection)
            )
            self._session = await asyncio.wait_for(builder.connect(), timeout=self._connect_timeout)
            log.info("ngrok session established")
        return self._session

    async def _release(self) -> None:
        async with self._lock:
            self._open_endpoints = max(0, self._open_endpoints - 1)
            if self._open_endpoints == 0:
                await self._close_session()

    async def _close_session(self) -> None:
        session, self._session = self._session, None
        if session is None:
            return
        try:
            await asyncio.wait_for(session.close(), timeout=15)
            log.info("ngrok session closed")
        except Exception as exc:
            log.warning("closing ngrok session failed: %s", describe_ngrok_error(exc))

    def _on_disconnection(self, addr: str, error: str) -> None:
        # Called from the SDK's own thread; logging is thread-safe. The SDK reconnects by itself.
        log.warning("ngrok session disconnected from %s (%s); reconnecting", addr, error)
