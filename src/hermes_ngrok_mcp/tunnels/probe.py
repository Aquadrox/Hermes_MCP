"""End-to-end verification of a freshly opened tunnel.

The server calls its own public URL, through the Internet and the ngrok edge. The tunnel
is considered working when that request reaches the local relay, whatever the exposed
service answers (a 404 or a 502 from the service still proves that the tunnel works).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx2

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.tunnels.proxy import ActivityProxy

_HEADERS = {
    "User-Agent": f"hermes-ngrok-mcp/{__version__} (tunnel verification)",
    # Skips the interstitial ngrok shows to browsers on free domains.
    "ngrok-skip-browser-warning": "1",
}


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    detail: str
    http_status: int | None = None
    elapsed: float = 0.0


async def verify_endpoint(
    protocol: str,
    url: str,
    proxy: ActivityProxy,
    *,
    credentials: tuple[str, str] | None = None,
    timeout: float = 20.0,
) -> VerificationResult:
    started = time.monotonic()
    deadline = started + timeout
    last_detail = "no attempt made"
    status: int | None = None
    attempt = 0
    async with proxy.probing() as reached:
        while (remaining := deadline - time.monotonic()) > 0:
            attempt += 1
            per_attempt = min(8.0, remaining)
            if protocol == "http":
                status, last_detail = await _http_attempt(url, credentials, per_attempt)
            else:
                last_detail = await _tcp_attempt(url, per_attempt, reached)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    reached.wait(), timeout=max(0.05, min(1.0, deadline - time.monotonic()))
                )
            if reached.is_set():
                elapsed = time.monotonic() - started
                return VerificationResult(True, f"public endpoint reachable ({last_detail})", status, elapsed)
            await asyncio.sleep(max(0.0, min(0.5 * attempt, 2.0, deadline - time.monotonic())))
    elapsed = time.monotonic() - started
    return VerificationResult(
        False,
        f"no request reached the server through {url} within {timeout:.0f}s (last attempt: {last_detail})",
        status,
        elapsed,
    )


async def _http_attempt(
    url: str, credentials: tuple[str, str] | None, timeout: float
) -> tuple[int | None, str]:
    auth = httpx2.BasicAuth(*credentials) if credentials else None
    try:
        async with (
            httpx2.AsyncClient(
                timeout=timeout, headers=_HEADERS, auth=auth, follow_redirects=False
            ) as client,
            client.stream("GET", url) as response,
        ):
            error_code = response.headers.get("ngrok-error-code")
            detail = f"HTTP {response.status_code}"
            if error_code:
                detail += f" from ngrok, error {error_code}"
            return response.status_code, detail
    except httpx2.HTTPError as exc:
        return None, f"{type(exc).__name__}"


async def _tcp_attempt(url: str, timeout: float, reached: asyncio.Event) -> str:
    parts = urlsplit(url)
    if not parts.hostname or not parts.port:
        return f"unexpected TCP address {url!r}"
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(parts.hostname, parts.port), timeout=timeout
        )
    except (OSError, TimeoutError) as exc:
        return f"TCP connect failed ({type(exc).__name__})"
    try:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(reached.wait(), timeout=min(3.0, timeout))
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    return "TCP connection accepted"
