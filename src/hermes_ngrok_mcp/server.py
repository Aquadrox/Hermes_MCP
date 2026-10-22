"""MCP tool surface exposed to the Hermes agent."""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Annotated, Any, Literal, TypeVar

from mcp.server.mcpserver import Image, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import BaseModel, Field

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.durations import format_duration
from hermes_ngrok_mcp.mfa import Enrollment, MfaError, MfaLockedError
from hermes_ngrok_mcp.services import Services
from hermes_ngrok_mcp.tunnels.manager import TunnelError, TunnelView

log = logging.getLogger(__name__)

T = TypeVar("T")

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


class VerificationOut(BaseModel):
    ok: bool
    detail: str
    http_status: int | None


class TunnelOut(BaseModel):
    tunnel_id: str
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


def build_server(services: Services) -> MCPServer:  # noqa: PLR0915 - registers every tool
    settings = services.settings
    mfa = services.mfa
    tunnels = services.tunnels
    notifier = services.notifier
    messages = services.messages

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
            await alert_on_lockout(lambda: mfa.verify(mfa_code))
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
    async def tunnel_extend(mfa_code: MfaCode, tunnel_id: TunnelId = None) -> TunnelOpenOut:
        """Push back the expiry of an open tunnel (and reset its idle timer). Requires a fresh MFA code."""
        with agent_errors():
            resolved = tunnels.resolve(tunnel_id)
            tunnels.check_extend(resolved)
            await alert_on_lockout(lambda: mfa.verify(mfa_code))
            view = await tunnels.extend(resolved)
        out = _tunnel_out(services, view)
        return TunnelOpenOut(tunnel=out, message=f"Tunnel extended. {out.summary}")

    @server.tool(
        title="Close tunnels",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
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
