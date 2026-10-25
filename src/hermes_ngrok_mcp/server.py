"""MCP tool surface exposed to the Hermes agent."""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterator
from datetime import datetime
from typing import Annotated, Any, Literal, ParamSpec, TypeVar

from mcp.server.mcpserver import Image, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import BaseModel, Field

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.audit import AuditLog, summarize
from hermes_ngrok_mcp.durations import format_duration, parse_duration
from hermes_ngrok_mcp.mfa import Enrollment, MfaError, MfaLockedError
from hermes_ngrok_mcp.nas.client import NasHealth, probe_nas
from hermes_ngrok_mcp.services import Services
from hermes_ngrok_mcp.tunnels.manager import TunnelError, TunnelView

log = logging.getLogger(__name__)

T = TypeVar("T")
P = ParamSpec("P")

# Tool arguments never written to the audit trail.
_SECRET_ARGUMENTS = frozenset({"mfa_code", "current_mfa_code"})
_MAX_AUDIT_WINDOW = 90 * 86_400

MfaCode = Annotated[
    str,
    Field(
        description=(
            "The current 6-digit code shown in the user's authenticator app (Proton Authenticator). "
            "Always ask the user for it right before the call; never invent, guess or reuse a code."
        ),
        min_length=6,
        max_length=9,
    ),
]
TunnelId = Annotated[
    str | None,
    Field(description="Tunnel id (e.g. 't3fa9c1'). May be omitted when exactly one tunnel is open."),
]


# --- output models ---------------------------------------------------------------------------------
class MfaStatusOut(BaseModel):
    configured: bool
    configured_at: str | None
    locked: bool
    retry_after_seconds: int | None
    enrollment_pending: bool
    enrollment_expires_at: str | None
    secrets_delivered_via: Literal["telegram", "agent"]
    message: str


class MfaConfirmOut(BaseModel):
    configured: bool
    message: str


class AccessOut(BaseModel):
    username: str | None = Field(description="Basic-auth username, if the tunnel is password-protected.")
    password: str | None = Field(
        description="Basic-auth password; null when it was sent to the user directly."
    )
    password_delivery: Literal["telegram", "in_this_result", "none"]


class UsageOut(BaseModel):
    connections_total: int
    connections_active: int
    bytes_in: int
    bytes_out: int
    last_activity_at: str | None
    distinct_client_ips: int = Field(description="Distinct Internet client addresses seen (PROXY protocol).")
    last_client_ip: str | None


class VerificationOut(BaseModel):
    ok: bool
    detail: str
    http_status: int | None


class TunnelOut(BaseModel):
    tunnel_id: str
    kind: Literal["generic", "nas"] = Field(description="'nas' for the NAS file manager opened by nas_open.")
    protocol: Literal["http", "tcp"]
    local_port: int
    label: str | None
    public_url: str
    access: AccessOut
    opened_at: str
    expires_at: str | None
    expires_in_seconds: int | None
    idle_timeout_seconds: int
    idle_for_seconds: int
    closes_if_idle_in_seconds: int | None
    in_use: bool = Field(description="True if the tunnel carried traffic during the last minute.")
    extensions: int
    usage: UsageOut
    verification: VerificationOut | None
    summary: str


class TunnelOpenOut(BaseModel):
    tunnel: TunnelOut
    message: str


class PolicyOut(BaseModel):
    idle_timeout_seconds: int
    max_lifetime_seconds: int
    expiry_warning_seconds: int
    extension_seconds: int
    max_tunnels: int
    basic_auth_by_default: bool


class TunnelStatusOut(BaseModel):
    tunnels: list[TunnelOut]
    ngrok_configured: bool
    mfa_configured: bool
    telegram_notifications: bool
    policy: PolicyOut


class ClosedTunnelOut(BaseModel):
    tunnel_id: str
    local_port: int
    public_url: str


class TunnelCloseOut(BaseModel):
    closed: list[ClosedTunnelOut]
    message: str


class NasStatusOut(BaseModel):
    enabled: bool = Field(
        description="False until the administrator installs the NAS (install.sh --nas-dir)."
    )
    reachable: bool
    detail: str
    root: str | None
    writable: bool | None
    disk_total_bytes: int | None
    disk_free_bytes: int | None
    tunnel: TunnelOut | None = Field(description="The open NAS tunnel, if any.")
    message: str


class AuditEventOut(BaseModel):
    time: str
    event: str = Field(description="e.g. tunnel.opened, tunnel.closed, connection.closed, mfa.rejected.")
    details: dict[str, Any]


class SourceCountOut(BaseModel):
    ip: str
    count: int


class AuditSummaryOut(BaseModel):
    events: int
    tunnels_opened: int
    tunnels_closed: int
    tunnel_open_failures: int
    mfa_successes: int
    mfa_failures: int
    mfa_lockouts: int
    mcp_tool_calls: int
    mcp_tool_errors: int
    mcp_auth_rejections: int
    client_connections: int
    top_client_ips: list[SourceCountOut]


class AuditLogOut(BaseModel):
    since: str | None
    category: str
    returned: int
    truncated: bool = Field(description="True when older matching events were left out (raise limit).")
    events: list[AuditEventOut]
    summary: AuditSummaryOut = Field(
        description="Counters over every matching event, not only those returned."
    )
    message: str


def _instructions(services: Services) -> str:
    s = services.settings
    lifetime = format_duration(s.max_lifetime) if s.max_lifetime else "no limit"
    idle = format_duration(s.idle_timeout) if s.idle_timeout else "never"
    return f"""\
Opens temporary ngrok tunnels that expose a local port of this server to the Internet, protected
by a TOTP second factor (the user's Proton Authenticator app).

Rules you must follow:
- Opening (tunnel_open) and extending (tunnel_extend) a tunnel require a fresh 6-digit MFA code.
  Ask the user for it right before the call. Never invent, guess, store or reuse a code: each code is
  single-use and changes every 30 seconds. Repeated wrong codes lock MFA temporarily.
- If MFA is not configured, call mfa_setup_start, let the user add the key to Proton Authenticator,
  then call mfa_setup_confirm with the code they read. Do this only when the user asks for it.
- Tunnels close automatically after {idle} without activity and at the latest {lifetime} after
  opening, unless extended with tunnel_extend (one MFA code per extension).
- The server sends access details, warnings and closing notices to the user on Telegram itself.
  Never ask the user to send you a password that was delivered to them that way.
- Closing a tunnel (tunnel_close) needs no code. Offer to close tunnels that are no longer needed.
- The NAS file manager (browse, upload, download, new folder) is opened with nas_open and one MFA code;
  it is a regular tunnel afterwards (tunnel_status / tunnel_extend / tunnel_close). nas_status needs no code.
- audit_log reports what happened (tunnels opened/closed, client IPs, MFA attempts, tool calls).
"""


def _iso(services: Services, epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=services.settings.tz).isoformat(timespec="seconds")


def _round(value: float | None) -> int | None:
    return None if value is None else round(value)


def _tunnel_out(services: Services, view: TunnelView) -> TunnelOut:
    if view.username is None:
        access = AccessOut(username=None, password=None, password_delivery="none")
    elif view.password is None:
        access = AccessOut(username=view.username, password=None, password_delivery="telegram")
    else:
        access = AccessOut(username=view.username, password=view.password, password_delivery="in_this_result")
    usage = view.usage
    parts = [f"{view.protocol.upper()} tunnel {view.id}: {view.public_url} -> local port {view.local_port}"]
    if view.expires_in is not None:
        parts.append(f"expires in {format_duration(view.expires_in)}")
    if view.closes_if_idle_in is not None:
        parts.append(f"closes if idle in {format_duration(view.closes_if_idle_in)}")
    parts.append("in use" if view.in_use else "not used recently")
    verification = view.verification
    return TunnelOut(
        tunnel_id=view.id,
        kind=view.kind,
        protocol=view.protocol,
        local_port=view.local_port,
        label=view.label,
        public_url=view.public_url,
        access=access,
        opened_at=_iso(services, view.opened_at) or "",
        expires_at=_iso(services, view.expires_at),
        expires_in_seconds=_round(view.expires_in),
        idle_timeout_seconds=view.idle_timeout,
        idle_for_seconds=round(view.idle_for),
        closes_if_idle_in_seconds=_round(view.closes_if_idle_in),
        in_use=view.in_use,
        extensions=view.extensions,
        usage=UsageOut(
            connections_total=usage.connections_total,
            connections_active=usage.connections_active,
            bytes_in=usage.bytes_in,
            bytes_out=usage.bytes_out,
            last_activity_at=_iso(services, usage.last_activity_wall),
            distinct_client_ips=usage.distinct_sources,
            last_client_ip=usage.last_source,
        ),
        verification=(
            VerificationOut(
                ok=verification.ok, detail=verification.detail, http_status=verification.http_status
            )
            if verification
            else None
        ),
        summary="; ".join(parts) + ".",
    )


def audited(audit: AuditLog) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Record every call of a tool (outcome, duration, non-secret arguments) in the audit trail.

    Unexpected exceptions are logged with their traceback and turned into a clean tool error,
    so the agent always gets an ``isError`` result instead of a broken session.
    """

    def decorate(function: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        name = function.__name__

        @functools.wraps(function)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            started = time.monotonic()
            arguments = {k: v for k, v in kwargs.items() if k not in _SECRET_ARGUMENTS}
            codes = sorted(k for k, v in kwargs.items() if k in _SECRET_ARGUMENTS and v is not None)

            def record(outcome: str, error: str | None = None) -> None:
                audit.record(
                    "mcp.tool_call",
                    tool=name,
                    outcome=outcome,
                    duration_ms=round((time.monotonic() - started) * 1000),
                    arguments=arguments or None,
                    mfa_code_provided=codes or None,
                    error=error,
                )

            try:
                result = await function(*args, **kwargs)
            except ToolError as exc:
                record("error", str(exc)[:500])
                raise
            except Exception as exc:
                log.exception("tool %s failed unexpectedly", name)
                record("crash", type(exc).__name__)
                raise ToolError(
                    f"Internal error in {name}. Nothing was exposed; the administrator can find the details "
                    "with 'sudo journalctl -u hermes-ngrok-mcp'."
                ) from exc
            record("ok")
            return result

        return wrapper

    return decorate


def build_server(services: Services) -> MCPServer:  # noqa: PLR0915 - registers every tool
    settings = services.settings
    mfa = services.mfa
    tunnels = services.tunnels
    notifier = services.notifier
    messages = services.messages
    audit = audited(services.audit)

    server = MCPServer(
        name="hermes-ngrok",
        title="Hermes ngrok tunnels",
        version=__version__,
        instructions=_instructions(services),
        website_url="https://github.com/Aquadrox/Hermes_MCP",
    )

    @contextlib.contextmanager
    def agent_errors() -> Iterator[None]:
        try:
            yield
        except (MfaError, TunnelError) as exc:
            raise ToolError(str(exc)) from exc

    async def alert_on_lockout(operation: Callable[[], T]) -> T:
        """Run an MFA operation, warning the user on Telegram when it triggers a lockout."""
        try:
            return operation()
        except MfaLockedError as exc:
            if exc.newly_locked and notifier.enabled:
                await notifier.send_text(messages.mfa_locked(retry_after=exc.retry_after))
            raise

    async def forget_enrollment_messages() -> None:
        while services.enrollment_message_ids:
            await notifier.delete(services.enrollment_message_ids.pop())

    # --- MFA -----------------------------------------------------------------------------------------
    @server.tool(
        title="MFA status",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
    )
    @audit
    async def mfa_status() -> MfaStatusOut:
        """Report whether the TOTP second factor is configured, locked or being enrolled."""
        status = mfa.status()
        now = services.clock.time()
        if not status.configured:
            message = "MFA is not configured. Offer to set it up with mfa_setup_start."
        elif status.locked_until:
            message = "MFA is temporarily locked after too many invalid codes."
        else:
            message = "MFA is configured; tunnel_open and tunnel_extend need a code from the user."
        return MfaStatusOut(
            configured=status.configured,
            configured_at=_iso(services, status.configured_at),
            locked=status.locked_until is not None,
            retry_after_seconds=round(status.locked_until - now) if status.locked_until else None,
            enrollment_pending=status.enrollment_pending,
            enrollment_expires_at=_iso(services, status.enrollment_expires_at),
            secrets_delivered_via="telegram" if notifier.enabled else "agent",
            message=message,
        )

    @server.tool(
        title="Start MFA enrollment",
        structured_output=False,
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
    )
    @audit
    async def mfa_setup_start(
        current_mfa_code: Annotated[
            str | None,
            Field(
                description=(
                    "Only when MFA is already configured and the user wants to replace their "
                    "authenticator: a valid code from the CURRENT authenticator."
                )
            ),
        ] = None,
    ) -> list[Any]:
        """Start configuring the TOTP second factor (Proton Authenticator or any authenticator app).

        Generates a new secret. When Telegram is configured, the QR code and key are sent to the
        user directly and are never returned to you. Then ask the user to add it in Proton
        Authenticator and give you the 6-digit code it shows, and call mfa_setup_confirm.
        """
        with agent_errors():
            enrollment = await alert_on_lockout(lambda: mfa.begin_enrollment(current_mfa_code))
        await forget_enrollment_messages()
        expires_in = round(enrollment.expires_at - services.clock.time())
        base: dict[str, Any] = {
            "status": "pending_confirmation",
            "rotation": enrollment.rotation,
            "expires_at": _iso(services, enrollment.expires_at),
            "expires_in_seconds": expires_in,
            "authenticator_settings": {
                "type": "TOTP",
                "issuer": enrollment.issuer,
                "account": enrollment.account,
                "algorithm": "SHA1",
                "digits": 6,
                "period_seconds": 30,
            },
        }
        if notifier.enabled:
            caption = messages.enrollment_caption(
                issuer=enrollment.issuer,
                account=enrollment.account,
                secret=enrollment.secret,
                expires_in=expires_in,
                rotation=enrollment.rotation,
            )
            message_id = await notifier.send_photo(enrollment.qr_png(), caption, protect=True)
            if message_id is not None:
                services.enrollment_message_ids.append(message_id)
                base |= {
                    "delivered_via": "telegram",
                    "next_step": (
                        "The QR code and the key were sent to the user directly on Telegram (not to you). "
                        "Ask them to add the account in Proton Authenticator (scan, or 'enter manually' with "
                        "the key), then to give you the 6-digit code it shows, and call mfa_setup_confirm."
                    ),
                }
                return [json.dumps(base, indent=2)]
            # Never fall back to the agent once Telegram is configured: the agent knows the bot
            # token and could provoke the failure (e.g. by exhausting the rate limit).
            mfa.cancel_enrollment()
            raise ToolError(
                "The QR code could not be delivered on Telegram, so the enrollment was cancelled. "
                "Wait a minute and call mfa_setup_start again; if it keeps failing, the administrator "
                "can enroll from the server with 'sudo hermes-ngrok-admin mfa setup'."
            )
        if not settings.mfa_allow_inline_enrollment:
            mfa.cancel_enrollment()
            raise ToolError(
                "Telegram is not configured and inline delivery is disabled "
                "(HERMES_NGROK_MFA_ALLOW_INLINE_ENROLLMENT=false). Ask the administrator to run "
                "'sudo hermes-ngrok-admin mfa setup' on the server instead."
            )
        return _inline_enrollment(base, enrollment)

    @server.tool(
        title="Confirm MFA enrollment",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
    )
    @audit
    async def mfa_setup_confirm(mfa_code: MfaCode) -> MfaConfirmOut:
        """Finish the MFA enrollment started by mfa_setup_start with a code from the new authenticator."""
        rotation = mfa.is_configured()
        with agent_errors():
            await alert_on_lockout(lambda: mfa.confirm_enrollment(mfa_code))
        await forget_enrollment_messages()
        if notifier.enabled:
            await notifier.send_text(messages.mfa_enabled(rotation=rotation))
        return MfaConfirmOut(
            configured=True,
            message=(
                "MFA is active. From now on, opening or extending a tunnel requires a fresh code. If the "
                "key was shown in this conversation, advise the user to delete those messages."
            ),
        )

    # --- tunnels ---------------------------------------------------------------------------------------
    @server.tool(
        title="Open a tunnel",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True),
    )
    @audit
    async def tunnel_open(
        port: Annotated[int, Field(ge=1, le=65_535, description="Local TCP port of the service to expose.")],
        mfa_code: MfaCode,
        protocol: Annotated[
            Literal["http", "tcp"],
            Field(
                description=(
                    "'http' for websites and HTTP APIs (an https:// URL), 'tcp' for anything else "
                    "(SSH, databases...). TCP needs a payment method on the ngrok account."
                )
            ),
        ] = "http",
        protect: Annotated[
            bool | None,
            Field(
                description=(
                    "HTTP only: protect the URL with a generated username/password (default: server "
                    "policy, normally on). Set false only if the user explicitly asks for no password."
                )
            ),
        ] = None,
        label: Annotated[
            str | None, Field(max_length=60, description="Optional short name, e.g. 'grafana'.")
        ] = None,
    ) -> TunnelOpenOut:
        """Open a public ngrok tunnel to a local port, verify it end to end and return its address.

        Requires a fresh MFA code from the user. The tunnel closes by itself when unused, and at the
        latest when it expires (it can be extended with tunnel_extend).
        """
        with agent_errors():
            await tunnels.check_open(port, protocol, protect)
            await alert_on_lockout(lambda: mfa.verify(mfa_code, purpose="tunnel_open"))
            view = await tunnels.open(port, protocol, protect=protect, label=label)
        out = _tunnel_out(services, view)
        if out.access.password_delivery == "telegram":
            delivery = (
                "The username and password were sent to the user directly on Telegram, together with the "
                "URL; do not ask for them."
            )
        elif out.access.password_delivery == "in_this_result":
            delivery = "Give the user the URL, username and password (send them only to the user)."
        else:
            delivery = "The URL is not password-protected."
        state = "Tunnel open and verified end to end." if out.verification else "Tunnel open (not verified)."
        return TunnelOpenOut(tunnel=out, message=f"{state} {delivery} {out.summary}")

    @server.tool(
        title="Tunnel status",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=True),
    )
    @audit
    async def tunnel_status(
        tunnel_id: Annotated[str | None, Field(description="Restrict to one tunnel (default: all).")] = None,
        verify: Annotated[
            bool, Field(description="Re-check now, end to end, that the tunnel answers from the Internet.")
        ] = False,
    ) -> TunnelStatusOut:
        """List open tunnels with their URL, expiry, idle timer and real usage (connections, bytes)."""
        with agent_errors():
            if tunnel_id:
                views = [await tunnels.reverify(tunnel_id) if verify else tunnels.get(tunnel_id)]
            elif verify:
                views = [await tunnels.reverify(view.id) for view in tunnels.list()]
            else:
                views = tunnels.list()
        return TunnelStatusOut(
            tunnels=[_tunnel_out(services, view) for view in views],
            ngrok_configured=settings.ngrok_authtoken is not None,
            mfa_configured=mfa.is_configured(),
            telegram_notifications=notifier.enabled,
            policy=PolicyOut(
                idle_timeout_seconds=settings.idle_timeout,
                max_lifetime_seconds=settings.max_lifetime,
                expiry_warning_seconds=settings.expiry_warning,
                extension_seconds=settings.extension,
                max_tunnels=settings.max_tunnels,
                basic_auth_by_default=settings.basic_auth,
            ),
        )

    @server.tool(
        title="Extend a tunnel",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
    )
    @audit
    async def tunnel_extend(mfa_code: MfaCode, tunnel_id: TunnelId = None) -> TunnelOpenOut:
        """Push back the expiry of an open tunnel (and reset its idle timer). Requires a fresh MFA code."""
        with agent_errors():
            resolved = tunnels.resolve(tunnel_id)
            tunnels.check_extend(resolved)
            await alert_on_lockout(lambda: mfa.verify(mfa_code, purpose="tunnel_extend"))
            view = await tunnels.extend(resolved)
        out = _tunnel_out(services, view)
        return TunnelOpenOut(tunnel=out, message=f"Tunnel extended. {out.summary}")

    @server.tool(
        title="Close tunnels",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    @audit
    async def tunnel_close(
        tunnel_id: TunnelId = None,
        close_all: Annotated[bool, Field(description="Close every open tunnel.")] = False,
    ) -> TunnelCloseOut:
        """Close a tunnel immediately (or all of them). No MFA code is needed to close."""
        with agent_errors():
            if close_all:
                views = await tunnels.close_all()
            else:
                views = [await tunnels.close(tunnels.resolve(tunnel_id))]
        closed = [
            ClosedTunnelOut(tunnel_id=v.id, local_port=v.local_port, public_url=v.public_url) for v in views
        ]
        message = f"{len(closed)} tunnel(s) closed." if closed else "No tunnel was open."
        return TunnelCloseOut(closed=closed, message=message)

    # --- NAS ---------------------------------------------------------------------------------------------
    def nas_key() -> str:
        if settings.nas_access_key is None:
            raise ToolError(
                "The NAS is not installed on this server (the administrator must run install.sh --nas-dir)."
            )
        return settings.nas_access_key.get_secret_value()

    async def nas_health() -> NasHealth:
        return await probe_nas(settings.target_host, settings.nas_port, nas_key())

    def nas_tunnel() -> TunnelView | None:
        return next((view for view in tunnels.list() if view.kind == "nas"), None)

    @server.tool(
        title="NAS status",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
    )
    @audit
    async def nas_status() -> NasStatusOut:
        """Report whether the NAS file manager is installed and running, its free space, and its open tunnel.

        Needs no MFA code. Calling it starts the NAS web app if it was idle (it only listens locally).
        """
        if not settings.nas_enabled:
            return NasStatusOut(
                enabled=False,
                reachable=False,
                detail="not installed",
                root=None,
                writable=None,
                disk_total_bytes=None,
                disk_free_bytes=None,
                tunnel=None,
                message=(
                    "The NAS is not installed on this server. The administrator must run the installer with "
                    "--nas-dir (see the README); you cannot do it."
                ),
            )
        health = await nas_health()
        view = nas_tunnel()
        if view is not None:
            message = (
                f"The NAS is open at {view.public_url}. Use tunnel_extend or tunnel_close with "
                f"tunnel_id {view.id}."
            )
        elif health.reachable:
            message = "The NAS is ready; nas_open exposes it with an MFA code."
        else:
            message = (
                f"The NAS service is not working: {health.detail}. Ask the administrator to check hermes-nas."
            )
        return NasStatusOut(
            enabled=True,
            reachable=health.reachable,
            detail=health.detail,
            root=health.root,
            writable=health.writable,
            disk_total_bytes=health.disk_total,
            disk_free_bytes=health.disk_free,
            tunnel=_tunnel_out(services, view) if view else None,
            message=message,
        )

    @server.tool(
        title="Open the NAS",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True),
    )
    @audit
    async def nas_open(mfa_code: MfaCode) -> TunnelOpenOut:
        """Expose the NAS file manager (browse, upload, download, new folder) through a password-protected
        HTTPS tunnel, verified end to end. Requires a fresh MFA code from the user.

        The URL, username and password go to the user on Telegram. The tunnel then behaves like any other:
        it closes when unused or expired; use tunnel_extend / tunnel_close with the returned tunnel_id.
        """
        nas_key()  # refuses early when the NAS is not installed
        with agent_errors():
            health = await nas_health()
            if not health.reachable:
                raise TunnelError(
                    f"The NAS service is not working ({health.detail}), so nothing was opened and no MFA "
                    "code was used. Ask the administrator to check "
                    "'systemctl status hermes-nas.socket hermes-nas'."
                )
            await tunnels.check_open(settings.nas_port, "http", True, kind="nas")
            await alert_on_lockout(lambda: mfa.verify(mfa_code, purpose="nas_open"))
            view = await tunnels.open(
                settings.nas_port,
                "http",
                protect=True,
                label="NAS",
                kind="nas",
            )
        out = _tunnel_out(services, view)
        if out.access.password_delivery == "telegram":
            delivery = (
                "The URL, username and password were sent to the user on Telegram; do not ask for them."
            )
        else:
            delivery = "Give the user the URL, username and password (send them only to the user)."
        return TunnelOpenOut(tunnel=out, message=f"NAS open and verified. {delivery} {out.summary}")

    # --- audit -------------------------------------------------------------------------------------------
    @server.tool(
        title="Audit log",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False),
    )
    @audit
    async def audit_log(
        since: Annotated[
            str,
            Field(
                description="How far back: e.g. '30m', '24h', '7d' (at most 90d). '0' means everything kept.",
                max_length=16,
            ),
        ] = "24h",
        category: Annotated[
            Literal["all", "tunnels", "connections", "mfa", "mcp", "service"],
            Field(
                description=(
                    "'tunnels' (opened/closed/extended/failed), 'connections' (each client connection "
                    "with its IP), 'mfa' (codes accepted/rejected, lockouts), 'mcp' (tool calls, rejected "
                    "API requests), 'service' (starts/stops) or 'all'."
                )
            ),
        ] = "all",
        limit: Annotated[int, Field(ge=1, le=500, description="Maximum number of events returned.")] = 50,
    ) -> AuditLogOut:
        """Read the server's audit trail: when tunnels were opened and closed, from which client IPs they
        were used, how many MFA attempts failed, which tools were called. Read-only; needs no MFA code.

        The summary counts every matching event in the window; events lists the most recent ones.
        """
        try:
            window = parse_duration(since)
        except ValueError as exc:
            raise ToolError(f"Invalid 'since' {since!r}: use e.g. '30m', '24h' or '7d'.") from exc
        if window > _MAX_AUDIT_WINDOW:
            raise ToolError("'since' is limited to 90d.")
        start = services.clock.time() - window if window else None
        entries = services.audit.query(since=start, category=category, limit=0)
        summary = summarize(entries)
        recent = entries[-limit:]
        hidden = {"ts", "time", "event"}
        return AuditLogOut(
            since=_iso(services, start),
            category=category,
            returned=len(recent),
            truncated=len(entries) > len(recent),
            events=[
                AuditEventOut(
                    time=str(entry.get("time", "")),
                    event=str(entry.get("event", "")),
                    details={k: v for k, v in entry.items() if k not in hidden},
                )
                for entry in recent
            ],
            summary=AuditSummaryOut(
                events=summary.events,
                tunnels_opened=summary.tunnels_opened,
                tunnels_closed=summary.tunnels_closed,
                tunnel_open_failures=summary.tunnel_open_failures,
                mfa_successes=summary.mfa_successes,
                mfa_failures=summary.mfa_failures,
                mfa_lockouts=summary.mfa_lockouts,
                mcp_tool_calls=summary.mcp_tool_calls,
                mcp_tool_errors=summary.mcp_tool_errors,
                mcp_auth_rejections=summary.mcp_auth_rejections,
                client_connections=summary.connections,
                top_client_ips=[SourceCountOut(ip=ip, count=n) for ip, n in summary.top_sources()],
            ),
            message=(
                f"{summary.events} event(s) since {_iso(services, start) or 'the beginning'}; "
                f"{len(recent)} returned, most recent last. Client IPs come from ngrok (PROXY protocol); "
                "failed basic-auth attempts are stopped by ngrok and never reach this server."
            ),
        )

    return server


def _inline_enrollment(base: dict[str, Any], enrollment: Enrollment) -> list[Any]:
    payload = base | {
        "delivered_via": "this_result",
        "secret": enrollment.secret,
        "secret_grouped": enrollment.grouped_secret,
        "otpauth_uri": enrollment.uri,
        "next_step": (
            "Telegram delivery is not configured, so the secret is in this result. Send the attached QR "
            "image and the key to the user only. In Proton Authenticator: '+' then scan the QR code, or "
            "'enter manually' with the key, issuer and account above. Then ask for the 6-digit code it "
            "shows and call mfa_setup_confirm. Advise the user to delete these messages afterwards."
        ),
    }
    return [json.dumps(payload, indent=2), Image(data=enrollment.qr_png(), format="png")]
