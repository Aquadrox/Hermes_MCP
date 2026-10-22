"""Tunnel lifecycle: validation, opening, verification, usage tracking and automatic closing.

Lifecycle rules (all configurable):

* a tunnel is closed after ``idle_timeout`` without traffic. For TCP tunnels an open
  client connection (e.g. an SSH session) also counts as use;
* a tunnel never lives longer than ``max_lifetime`` unless it is extended, each extension
  requiring a fresh MFA code (checked by the caller) and adding ``extension`` seconds;
* the user is warned on Telegram ``expiry_warning`` seconds before the hard expiry, and
  told when a tunnel is closed automatically.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from hermes_ngrok_mcp.clock import Clock
from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.messages import Messages, TunnelFacts
from hermes_ngrok_mcp.notify import Notifier
from hermes_ngrok_mcp.tunnels.backends import (
    BackendError,
    Endpoint,
    EndpointSpec,
    TunnelBackend,
    TunnelProtocol,
    basic_auth_policy,
)
from hermes_ngrok_mcp.tunnels.probe import VerificationResult, verify_endpoint
from hermes_ngrok_mcp.tunnels.proxy import ActivityProxy, UsageStats

log = logging.getLogger(__name__)

Verifier = Callable[..., Awaitable[VerificationResult]]

# A tunnel counts as "in use" when it carried traffic during the last minute.
_IN_USE_WINDOW = 60.0


class CloseReason(StrEnum):
    MANUAL = "manual"
    IDLE = "idle"
    EXPIRED = "expired"
    SHUTDOWN = "shutdown"


class TunnelError(Exception):
    """A refused or failed tunnel operation; the message is meant for the agent."""


class TunnelNotFoundError(TunnelError):
    pass


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str


@dataclass
class _Tunnel:
    id: str
    protocol: TunnelProtocol
    local_port: int
    label: str | None
    public_url: str
    credentials: Credentials | None
    opened_at: float
    expires_mono: float | None
    proxy: ActivityProxy
    endpoint: Endpoint
    verification: VerificationResult | None
    extensions: int = 0
    warned: bool = False
    credentials_sent_to_user: bool = False


@dataclass(frozen=True)
class TunnelView:
    """Read-only snapshot of a tunnel, as reported to the agent."""

    id: str
    protocol: TunnelProtocol
    local_port: int
    label: str | None
    public_url: str
    username: str | None
    password: str | None
    credentials_sent_to_user: bool
    opened_at: float
    expires_at: float | None
    expires_in: float | None
    idle_timeout: int
    idle_for: float
    closes_if_idle_in: float | None
    in_use: bool
    extensions: int
    usage: UsageStats
    verification: VerificationResult | None
    closed_reason: str | None = None


class TunnelManager:
    def __init__(
        self,
        settings: Settings,
        *,
        backend: TunnelBackend | None,
        clock: Clock,
        notifier: Notifier,
        messages: Messages,
        verifier: Verifier = verify_endpoint,
        reserved_ports: frozenset[int] = frozenset(),
    ) -> None:
        self._settings = settings
        self._backend = backend
        self._clock = clock
        self._notifier = notifier
        self._messages = messages
        self._verifier = verifier
        self._reserved_ports = reserved_ports
        self._tunnels: dict[str, _Tunnel] = {}
        self._lock = asyncio.Lock()
        self._reaper: asyncio.Task[None] | None = None

    # --- service lifecycle -----------------------------------------------------------------------
    async def start(self) -> None:
        if self._reaper is None:
            self._reaper = asyncio.create_task(self._reap_forever(), name="tunnel-reaper")

    async def aclose(self) -> None:
        reaper, self._reaper = self._reaper, None
        if reaper is not None:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper
        if self._tunnels:
            log.info("shutting down: closing %d open tunnel(s)", len(self._tunnels))
        await self.close_all(CloseReason.SHUTDOWN, notify=True)
        if self._backend is not None:
            await self._backend.aclose()

    # --- requests ------------------------------------------------------------------------------------
    async def check_open(self, port: int, protocol: TunnelProtocol, protect: bool | None) -> None:
        """Refuse early (before an MFA code is consumed) a request that cannot succeed."""
        self._check_open_policy(port, protocol, protect)
        if not await self._target_listening(port):
            raise TunnelError(
                f"Nothing is listening on {self._settings.target_host}:{port}. "
                "Start the service first, then ask again."
            )

    async def open(
        self,
        port: int,
        protocol: TunnelProtocol = "http",
        *,
        protect: bool | None = None,
        label: str | None = None,
    ) -> TunnelView:
        async with self._lock:
            backend = self._check_open_policy(port, protocol, protect)
            tunnel_id = self._new_id()
            use_auth = protocol == "http" and (self._settings.basic_auth if protect is None else protect)
            credentials = (
                Credentials(self._settings.basic_auth_user, secrets.token_urlsafe(18)) if use_auth else None
            )
            proxy = ActivityProxy(self._settings.target_host, port, clock=self._clock)
            await proxy.start()
            endpoint: Endpoint | None = None
            try:
                endpoint = await backend.open(
                    EndpointSpec(
                        protocol=protocol,
                        upstream=proxy.address,
                        traffic_policy=(
                            basic_auth_policy(credentials.username, credentials.password)
                            if credentials
                            else None
                        ),
                        domain=self._settings.domain if protocol == "http" else None,
                        metadata=json.dumps({"tunnel_id": tunnel_id, "local_port": port}),
                        description=f"hermes-ngrok-mcp {tunnel_id} -> {self._settings.target_host}:{port}",
                    )
                )
                verification = await self._verify_new(protocol, endpoint.url, proxy, credentials)
            except BaseException as exc:
                if endpoint is not None:
                    await endpoint.close()
                await proxy.aclose()
                if isinstance(exc, BackendError):
                    raise TunnelError(f"ngrok refused to open the tunnel: {exc}") from exc
                raise
            proxy.reset_idle_timer()
            max_lifetime = self._settings.max_lifetime
            tunnel = _Tunnel(
                id=tunnel_id,
                protocol=protocol,
                local_port=port,
                label=label,
                public_url=endpoint.url,
                credentials=credentials,
                opened_at=self._clock.time(),
                expires_mono=self._clock.monotonic() + max_lifetime if max_lifetime else None,
                proxy=proxy,
                endpoint=endpoint,
                verification=verification,
            )
            self._tunnels[tunnel_id] = tunnel
        log.info(
            "tunnel opened id=%s protocol=%s port=%s url=%s basic_auth=%s",
            tunnel_id,
            protocol,
            port,
            tunnel.public_url,
            credentials is not None,
        )
        if self._notifier.enabled:
            message_id = await self._notifier.send_text(
                self._messages.tunnel_opened(self._facts(tunnel)), protect=credentials is not None
            )
            tunnel.credentials_sent_to_user = message_id is not None and credentials is not None
            if (
                message_id is None
                and credentials is not None
                and not self._settings.share_credentials_with_agent
            ):
                # The password must reach the user through Telegram only. Failing closed also
                # defeats an agent that would provoke the failure to get the password itself.
                async with self._lock:
                    if self._tunnels.get(tunnel_id) is tunnel:
                        await self._close_locked(tunnel, CloseReason.MANUAL)
                raise TunnelError(
                    "The tunnel was opened, but its access details could not be delivered on Telegram, so "
                    "it was closed again for safety. Wait a minute and retry with a new MFA code."
                )
        return self._view(tunnel)

    async def _verify_new(
        self, protocol: TunnelProtocol, url: str, proxy: ActivityProxy, credentials: Credentials | None
    ) -> VerificationResult | None:
        if not self._settings.verify_tunnels:
            return None
        verification = await self._verifier(
            protocol,
            url,
            proxy,
            credentials=(credentials.username, credentials.password) if credentials else None,
            timeout=float(self._settings.verify_timeout),
        )
        if not verification.ok:
            raise TunnelError(
                "The tunnel was opened but could not be verified, so it was closed again: "
                + verification.detail
            )
        return verification

    def check_extend(self, tunnel_id: str) -> None:
        self._get(tunnel_id)
        if not self._settings.max_lifetime:
            raise TunnelError(
                "Tunnels have no maximum lifetime on this server, so there is nothing to extend."
            )

    async def extend(self, tunnel_id: str) -> TunnelView:
        async with self._lock:
            self.check_extend(tunnel_id)
            tunnel = self._get(tunnel_id)
            now = self._clock.monotonic()
            base = max(tunnel.expires_mono or now, now)
            tunnel.expires_mono = base + self._settings.extension
            tunnel.extensions += 1
            tunnel.warned = False
            tunnel.proxy.reset_idle_timer()
        log.info(
            "tunnel extended id=%s by=%ss extensions=%s",
            tunnel_id,
            self._settings.extension,
            tunnel.extensions,
        )
        return self._view(tunnel)

    async def close(self, tunnel_id: str, reason: CloseReason = CloseReason.MANUAL) -> TunnelView:
        async with self._lock:
            return await self._close_locked(self._get(tunnel_id), reason)

    async def close_all(
        self, reason: CloseReason = CloseReason.MANUAL, *, notify: bool = False
    ) -> list[TunnelView]:
        async with self._lock:
            views = [await self._close_locked(tunnel, reason) for tunnel in list(self._tunnels.values())]
        if notify:
            for view in views:
                await self._notify_closed(view)
        return views

    async def reverify(self, tunnel_id: str) -> TunnelView:
        tunnel = self._get(tunnel_id)
        credentials = tunnel.credentials
        tunnel.verification = await self._verifier(
            tunnel.protocol,
            tunnel.public_url,
            tunnel.proxy,
            credentials=(credentials.username, credentials.password) if credentials else None,
            timeout=float(self._settings.verify_timeout),
        )
        return self._view(tunnel)

    def list(self) -> list[TunnelView]:
        return [self._view(tunnel) for tunnel in sorted(self._tunnels.values(), key=lambda t: t.opened_at)]

    def get(self, tunnel_id: str) -> TunnelView:
        return self._view(self._get(tunnel_id))

    def resolve(self, tunnel_id: str | None) -> str:
        """Accept an omitted id when exactly one tunnel is open."""
        if tunnel_id:
            self._get(tunnel_id)
            return tunnel_id
        if len(self._tunnels) == 1:
            return next(iter(self._tunnels))
        if not self._tunnels:
            raise TunnelNotFoundError("No tunnel is open.")
        raise TunnelError(
            "Several tunnels are open; specify tunnel_id. Open tunnels: "
            + ", ".join(f"{t.id} (port {t.local_port})" for t in self._tunnels.values())
        )

    # --- automatic closing ----------------------------------------------------------------------------
    async def tick(self) -> None:
        """One pass of the reaper: expire, close idle tunnels, send expiry warnings."""
        now = self._clock.monotonic()
        for tunnel in list(self._tunnels.values()):
            reason: CloseReason | None = None
            if tunnel.expires_mono is not None and now >= tunnel.expires_mono:
                reason = CloseReason.EXPIRED
            elif self._settings.idle_timeout and self._is_idle(tunnel, now):
                reason = CloseReason.IDLE
            if reason is not None:
                async with self._lock:
                    if self._tunnels.get(tunnel.id) is not tunnel:
                        continue
                    view = await self._close_locked(tunnel, reason)
                await self._notify_closed(view)
                continue
            warning = self._settings.expiry_warning
            if tunnel.expires_mono is not None and warning and not tunnel.warned:
                remaining = tunnel.expires_mono - now
                if remaining <= warning:
                    tunnel.warned = True
                    log.info("tunnel expiry warning id=%s remaining=%.0fs", tunnel.id, remaining)
                    if self._notifier.enabled:
                        await self._notifier.send_text(
                            self._messages.expiry_warning(self._facts(tunnel), remaining=remaining)
                        )

    async def _reap_forever(self) -> None:
        while True:
            await asyncio.sleep(self._settings.reaper_interval)
            try:
                await self.tick()
            except Exception:
                log.exception("tunnel reaper pass failed")

    def _is_idle(self, tunnel: _Tunnel, now: float) -> bool:
        if tunnel.protocol == "tcp" and tunnel.proxy.active_connections > 0:
            return False
        return tunnel.proxy.idle_for(now) >= self._settings.idle_timeout

    # --- internals --------------------------------------------------------------------------------------
    def _check_open_policy(self, port: int, protocol: TunnelProtocol, protect: bool | None) -> TunnelBackend:
        settings = self._settings
        if self._backend is None:
            raise TunnelError(
                "ngrok is not configured on the server: NGROK_AUTHTOKEN is empty. The administrator must "
                "set it in the service's .env file and restart the service."
            )
        if protocol not in ("http", "tcp"):
            raise TunnelError("protocol must be 'http' or 'tcp'.")
        if not 1 <= port <= 65_535:
            raise TunnelError("port must be between 1 and 65535.")
        if port in self._reserved_ports:
            raise TunnelError(f"Port {port} is used by this MCP server itself and can never be exposed.")
        if port not in settings.allowed_ports or port in settings.denied_ports:
            raise TunnelError(
                f"Port {port} is not allowed by the server policy (allowed: {settings.allowed_ports}; "
                f"denied: {settings.denied_ports or 'none'})."
            )
        if protocol == "tcp" and protect:
            raise TunnelError(
                "Password protection is only available for HTTP tunnels. Retry without protect, "
                "or use protocol 'http'."
            )
        if protocol == "http" and protect is False and not settings.allow_unprotected_http:
            raise TunnelError("Unprotected HTTP tunnels are disabled on this server; retry with protection.")
        for tunnel in self._tunnels.values():
            if tunnel.local_port == port and tunnel.protocol == protocol:
                raise TunnelError(
                    f"Tunnel {tunnel.id} already exposes port {port} at {tunnel.public_url}. "
                    "Use tunnel_status, tunnel_extend or tunnel_close instead of opening another one."
                )
        if len(self._tunnels) >= settings.max_tunnels:
            raise TunnelError(
                f"The maximum of {settings.max_tunnels} simultaneous tunnel(s) is reached; close one first."
            )
        return self._backend

    async def _target_listening(self, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self._settings.target_host, port), timeout=3.0
            )
        except (OSError, TimeoutError):
            return False
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return True

    def _get(self, tunnel_id: str) -> _Tunnel:
        tunnel = self._tunnels.get(tunnel_id.strip())
        if tunnel is None:
            known = ", ".join(self._tunnels) or "none"
            raise TunnelNotFoundError(f"No open tunnel with id {tunnel_id!r} (open tunnels: {known}).")
        return tunnel

    def _new_id(self) -> str:
        while True:
            candidate = "t" + secrets.token_hex(3)
            if candidate not in self._tunnels:
                return candidate

    async def _close_locked(self, tunnel: _Tunnel, reason: CloseReason) -> TunnelView:
        self._tunnels.pop(tunnel.id, None)
        view = self._view(tunnel, closed_reason=reason.value)
        try:
            await tunnel.endpoint.close()
        except Exception:
            log.exception("closing endpoint of tunnel %s failed", tunnel.id)
        await tunnel.proxy.aclose()
        log.info("tunnel closed id=%s reason=%s", tunnel.id, reason.value)
        return view

    async def _notify_closed(self, view: TunnelView) -> None:
        if self._notifier.enabled and view.closed_reason:
            facts = TunnelFacts(
                tunnel_id=view.id,
                protocol=view.protocol,
                local_port=view.local_port,
                label=view.label,
                public_url=view.public_url,
                idle_timeout=view.idle_timeout,
            )
            await self._notifier.send_text(self._messages.tunnel_closed(facts, reason=view.closed_reason))

    def _expires_at(self, tunnel: _Tunnel) -> float | None:
        if tunnel.expires_mono is None:
            return None
        return self._clock.time() + (tunnel.expires_mono - self._clock.monotonic())

    def _facts(self, tunnel: _Tunnel) -> TunnelFacts:
        credentials = tunnel.credentials
        return TunnelFacts(
            tunnel_id=tunnel.id,
            protocol=tunnel.protocol,
            local_port=tunnel.local_port,
            label=tunnel.label,
            public_url=tunnel.public_url,
            username=credentials.username if credentials else None,
            password=credentials.password if credentials else None,
            expires_at=self._expires_at(tunnel),
            idle_timeout=self._settings.idle_timeout,
        )

    def _view(self, tunnel: _Tunnel, *, closed_reason: str | None = None) -> TunnelView:
        now = self._clock.monotonic()
        idle_for = tunnel.proxy.idle_for(now)
        idle_timeout = self._settings.idle_timeout
        tcp_session_open = tunnel.protocol == "tcp" and tunnel.proxy.active_connections > 0
        closes_if_idle_in: float | None = None
        if idle_timeout and not tcp_session_open:
            closes_if_idle_in = max(0.0, idle_timeout - idle_for)
        usage = tunnel.proxy.stats()
        recently_active = (
            usage.last_activity_wall is not None
            and usage.connections_total > 0
            and self._clock.time() - usage.last_activity_wall < _IN_USE_WINDOW
        )
        credentials = tunnel.credentials
        hide_password = tunnel.credentials_sent_to_user and not self._settings.share_credentials_with_agent
        return TunnelView(
            id=tunnel.id,
            protocol=tunnel.protocol,
            local_port=tunnel.local_port,
            label=tunnel.label,
            public_url=tunnel.public_url,
            username=credentials.username if credentials else None,
            password=None if credentials is None or hide_password else credentials.password,
            credentials_sent_to_user=tunnel.credentials_sent_to_user,
            opened_at=tunnel.opened_at,
            expires_at=self._expires_at(tunnel),
            expires_in=max(0.0, tunnel.expires_mono - now) if tunnel.expires_mono is not None else None,
            idle_timeout=idle_timeout,
            idle_for=idle_for,
            closes_if_idle_in=closes_if_idle_in,
            in_use=tcp_session_open or recently_active,
            extensions=tunnel.extensions,
            usage=usage,
            verification=tunnel.verification,
            closed_reason=closed_reason,
        )
