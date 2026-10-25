"""Calls from the MCP server to the hermes-nas service: health probe, tunnel credentials."""

from __future__ import annotations

from dataclasses import dataclass

import httpx2

from hermes_ngrok_mcp.nas import ACCESS_KEY_HEADER, CREDENTIALS_PATH, HEALTH_PATH


@dataclass(frozen=True)
class NasHealth:
    reachable: bool
    detail: str
    version: str | None = None
    root: str | None = None
    writable: bool | None = None
    disk_total: int | None = None
    disk_free: int | None = None


async def probe_nas(host: str, port: int, access_key: str, *, timeout: float = 15.0) -> NasHealth:
    """Ask the NAS for its health. The first request also starts it (systemd socket activation)."""
    url = f"http://{host}:{port}{HEALTH_PATH}"
    try:
        async with httpx2.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers={ACCESS_KEY_HEADER: access_key})
    except httpx2.HTTPError as exc:
        return NasHealth(False, f"the NAS service does not answer on {host}:{port} ({type(exc).__name__})")
    if response.status_code == 403:
        return NasHealth(
            False, "the NAS refused the access key: HERMES_NGROK_NAS_ACCESS_KEY differs from its own"
        )
    if response.status_code != 200:
        return NasHealth(False, f"the NAS answered HTTP {response.status_code}")
    try:
        data = response.json()
        disk = data.get("disk") or {}
        return NasHealth(
            True,
            "ok",
            version=data.get("version"),
            root=data.get("root"),
            writable=data.get("writable"),
            disk_total=disk.get("total"),
            disk_free=disk.get("free"),
        )
    except (ValueError, AttributeError):
        return NasHealth(False, "the NAS answered with an unexpected health document")


class NasAdminError(Exception):
    """The NAS refused or did not answer an administrative call."""


class NasCredentials:
    """Hands the tunnel's basic-auth credentials to the NAS, which then enforces them itself.

    The calls stay on the loopback interface and carry the access key shared with hermes-nas,
    which the agent cannot read.
    """

    def __init__(self, host: str, port: int, access_key: str, *, timeout: float = 15.0) -> None:
        self._url = f"http://{host}:{port}{CREDENTIALS_PATH}"
        self._headers = {ACCESS_KEY_HEADER: access_key}
        self._timeout = timeout

    async def grant(self, username: str, password: str) -> None:
        await self._call("PUT", {"username": username, "password": password})

    async def revoke(self) -> None:
        await self._call("DELETE", None)

    async def _call(self, method: str, body: dict[str, str] | None) -> None:
        try:
            async with httpx2.AsyncClient(timeout=self._timeout) as client:
                response = await client.request(method, self._url, headers=self._headers, json=body)
        except httpx2.HTTPError as exc:
            raise NasAdminError(f"the NAS does not answer ({type(exc).__name__})") from exc
        if response.status_code == 403:
            raise NasAdminError("the NAS refused the access key")
        if response.status_code >= 300:
            raise NasAdminError(f"the NAS answered HTTP {response.status_code}")
