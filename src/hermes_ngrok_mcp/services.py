"""Wiring of the long-lived components shared by every MCP session."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.audit import AuditLog
from hermes_ngrok_mcp.clock import Clock, SystemClock
from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.messages import Messages
from hermes_ngrok_mcp.mfa import MfaManager
from hermes_ngrok_mcp.nas.client import NasCredentials
from hermes_ngrok_mcp.notify import Notifier, NullNotifier, TelegramNotifier
from hermes_ngrok_mcp.tunnels.backends import NgrokBackend, TunnelBackend
from hermes_ngrok_mcp.tunnels.manager import TunnelManager, Verifier
from hermes_ngrok_mcp.tunnels.probe import verify_endpoint

log = logging.getLogger(__name__)


@dataclass
class Services:
    settings: Settings
    clock: Clock
    messages: Messages
    notifier: Notifier
    mfa: MfaManager
    tunnels: TunnelManager
    audit: AuditLog
    enrollment_message_ids: list[int] = field(default_factory=list)


def build_notifier(settings: Settings) -> Notifier:
    if settings.telegram_bot_token is None or settings.telegram_chat_id is None:
        return NullNotifier()
    return TelegramNotifier(
        settings.telegram_bot_token.get_secret_value(),
        settings.telegram_chat_id,
        api_base=settings.telegram_api_base,
    )


def build_audit(settings: Settings, clock: Clock, *, origin: str = "service") -> AuditLog:
    return AuditLog(
        settings.audit_file,
        clock=clock,
        tz=settings.tz,
        origin=origin,
        max_bytes=settings.audit_max_bytes,
        backups=settings.audit_backups,
    )


def build_backend(settings: Settings) -> TunnelBackend | None:
    if settings.ngrok_authtoken is None:
        return None
    return NgrokBackend(settings.ngrok_authtoken.get_secret_value())


@contextlib.asynccontextmanager
async def open_services(
    settings: Settings,
    *,
    clock: Clock | None = None,
    notifier: Notifier | None = None,
    backend_factory: Callable[[Settings], TunnelBackend | None] = build_backend,
    verifier: Verifier = verify_endpoint,
) -> AsyncIterator[Services]:
    clock = clock or SystemClock()
    notifier = notifier if notifier is not None else build_notifier(settings)
    tunnel_backend = backend_factory(settings)
    messages = Messages(settings.language, settings.tz)
    audit = build_audit(settings, clock)
    tunnels = TunnelManager(
        settings,
        backend=tunnel_backend,
        clock=clock,
        notifier=notifier,
        messages=messages,
        verifier=verifier,
        reserved_ports=frozenset({settings.port}),
        nas_port=settings.nas_port if settings.nas_enabled else None,
        nas_auth=(
            NasCredentials(
                settings.target_host, settings.nas_port, settings.nas_access_key.get_secret_value()
            )
            if settings.nas_access_key is not None
            else None
        ),
        audit=audit,
    )
    services = Services(
        settings=settings,
        clock=clock,
        messages=messages,
        notifier=notifier,
        mfa=MfaManager.from_settings(settings, clock, audit),
        tunnels=tunnels,
        audit=audit,
    )
    if tunnel_backend is None:
        log.warning("NGROK_AUTHTOKEN is not set: tunnels cannot be opened until it is configured")
    if not notifier.enabled:
        log.warning("Telegram is not configured: no notifications, secrets are returned to the agent")
    await tunnels.start()
    audit.record(
        "service.started",
        version=__version__,
        ngrok_configured=tunnel_backend is not None,
        telegram=notifier.enabled,
        nas_enabled=settings.nas_enabled,
    )
    try:
        yield services
    finally:
        try:
            await tunnels.aclose()
        finally:
            audit.record("service.stopped", version=__version__)
            await notifier.aclose()
