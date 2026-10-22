"""Command line: run the MCP server and administer MFA locally.

Examples::

    hermes-ngrok-mcp serve                      # streamable HTTP on 127.0.0.1:8765 (the service)
    hermes-ngrok-mcp serve --transport stdio    # for local testing with an MCP client
    hermes-ngrok-mcp check                      # validate the configuration
    hermes-ngrok-mcp mfa setup                  # enroll from a terminal (QR code printed)
    hermes-ngrok-mcp mfa reset                  # lost phone: forget the current secret
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import secrets
import signal
import socket
import stat
import sys
from collections.abc import Iterator, Sequence
from datetime import datetime
from pathlib import Path

import uvicorn
from pydantic import ValidationError

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.asgi import build_http_app
from hermes_ngrok_mcp.clock import SystemClock
from hermes_ngrok_mcp.config import Settings, load_settings
from hermes_ngrok_mcp.durations import format_duration
from hermes_ngrok_mcp.messages import Messages
from hermes_ngrok_mcp.mfa import MfaError, MfaManager
from hermes_ngrok_mcp.server import build_server
from hermes_ngrok_mcp.services import build_notifier, open_services

log = logging.getLogger("hermes_ngrok_mcp")

_QUIET_LOGGERS = ("httpx", "httpx2", "httpcore", "httpcore2", "uvicorn.access")


def configure_logging(level: str) -> None:
    # journald already timestamps every line.
    fmt = "%(levelname)s %(name)s: %(message)s"
    if not os.environ.get("JOURNAL_STREAM"):
        fmt = "%(asctime)s " + fmt
    logging.basicConfig(level=level, stream=sys.stderr, format=fmt, force=True)
    for name in _QUIET_LOGGERS:
        # httpx logs request URLs at INFO, which would leak the Telegram bot token.
        logging.getLogger(name).setLevel(logging.WARNING)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-ngrok-mcp", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=os.environ.get("HERMES_NGROK_ENV_FILE"),
        help="dotenv file to load (environment variables take precedence)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the MCP server")
    serve.add_argument("--transport", choices=("http", "stdio"), default="http")
    serve.add_argument("--host", help="override HERMES_NGROK_HOST")
    serve.add_argument("--port", type=int, help="override HERMES_NGROK_PORT")
    serve.add_argument(
        "--insecure-no-auth",
        action="store_true",
        help="allow the HTTP transport without HERMES_NGROK_API_TOKEN (development only)",
    )

    commands.add_parser("check", help="validate the configuration and report problems")
    commands.add_parser("token", help="print a new random API token")
    commands.add_parser("notify-test", help="send a test notification on Telegram")

    mfa = commands.add_parser("mfa", help="manage the TOTP second factor")
    mfa_commands = mfa.add_subparsers(dest="mfa_command", required=True)
    mfa_commands.add_parser("status", help="show the MFA state")
    setup = mfa_commands.add_parser("setup", help="enroll an authenticator from this terminal")
    setup.add_argument("--force", action="store_true", help="replace an existing secret without a code")
    reset = mfa_commands.add_parser("reset", help="forget the secret (e.g. lost phone)")
    reset.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "token":
        print(secrets.token_urlsafe(32))
        return 0
    try:
        settings = load_settings(args.env_file)
    except (ValidationError, FileNotFoundError) as exc:
        print(f"Invalid configuration:\n{exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level)
    if args.command == "serve":
        return _serve(settings, args)
    if args.command == "check":
        return _check(settings)
    if args.command == "notify-test":
        return asyncio.run(_notify_test(settings))
    return _mfa(settings, args)


# --- serve ---------------------------------------------------------------------------------------
class _UvicornServer(uvicorn.Server):
    """uvicorn re-raises SIGTERM once it has stopped, which would kill the process before the
    tunnels are closed and the user notified. Handle the signals without re-raising them."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        original = {sig: signal.signal(sig, self.handle_exit) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            yield
        finally:
            for sig, handler in original.items():
                signal.signal(sig, handler)


def _serve(settings: Settings, args: argparse.Namespace) -> int:
    overrides = {k: v for k, v in (("host", args.host), ("port", args.port)) if v is not None}
    if overrides:
        settings = settings.model_copy(update=overrides)
    if args.transport == "stdio":
        asyncio.run(_serve_stdio(settings))
        return 0
    if settings.api_token is None and not args.insecure_no_auth:
        print(
            "HERMES_NGROK_API_TOKEN is required for the HTTP transport. Generate one with "
            "'hermes-ngrok-mcp token' (or pass --insecure-no-auth for local development).",
            file=sys.stderr,
        )
        return 2
    if not settings.host_is_loopback:
        log.warning("listening on non-loopback address %s: make sure a firewall protects it", settings.host)
    asyncio.run(_serve_http(settings, require_token=not args.insecure_no_auth))
    return 0


async def _serve_http(settings: Settings, *, require_token: bool) -> None:
    async with open_services(settings) as services:
        app = build_http_app(build_server(services), settings, require_token=require_token)
        config = uvicorn.Config(
            app,
            host=settings.host,
            port=settings.port,
            log_config=None,
            access_log=False,
            server_header=False,
            proxy_headers=False,
            timeout_graceful_shutdown=10,
        )
        log.info(
            "hermes-ngrok-mcp %s listening on http://%s:%s%s",
            __version__,
            settings.host,
            settings.port,
            settings.path,
        )
        await _UvicornServer(config).serve()
    log.info("hermes-ngrok-mcp stopped")


async def _serve_stdio(settings: Settings) -> None:
    async with open_services(settings) as services:
        await build_server(services).run_stdio_async()


# --- check -------------------------------------------------------------------------------------------
def _check(settings: Settings) -> int:
    problems: list[str] = []
    warnings: list[str] = []

    def line(label: str, value: object) -> None:
        print(f"  {label:<28} {value}")

    print(f"hermes-ngrok-mcp {__version__}")
    line("ngrok authtoken", "set" if settings.ngrok_authtoken else "MISSING")
    if settings.ngrok_authtoken is None:
        problems.append("NGROK_AUTHTOKEN is empty: tunnels cannot be opened")
    line("API token (HTTP transport)", "set" if settings.api_token else "MISSING")
    if settings.api_token is None:
        problems.append("HERMES_NGROK_API_TOKEN is empty: the HTTP service refuses to start")
    elif len(settings.api_token.get_secret_value()) < 32:
        problems.append("HERMES_NGROK_API_TOKEN must be at least 32 characters long")
    line(
        "Telegram notifications", f"chat {settings.telegram_chat_id}" if settings.telegram_enabled else "off"
    )
    if not settings.telegram_enabled:
        warnings.append("Telegram is off: no notifications, and secrets transit through the agent")
    line("listen", f"http://{settings.host}:{settings.port}{settings.path}")
    if not settings.host_is_loopback:
        warnings.append(f"HERMES_NGROK_HOST={settings.host} is not a loopback address")
    line("idle timeout", format_duration(settings.idle_timeout) if settings.idle_timeout else "disabled")
    line("max lifetime", format_duration(settings.max_lifetime) if settings.max_lifetime else "unlimited")
    line("expiry warning", f"{format_duration(settings.expiry_warning)} before expiry")
    line("extension", format_duration(settings.extension))
    line("allowed / denied ports", f"{settings.allowed_ports} / {settings.denied_ports or '-'}")
    line("basic auth by default", settings.basic_auth)
    line("state directory", settings.state_dir)
    try:
        mfa = MfaManager.from_settings(settings, SystemClock())
        status = mfa.status()
        line("MFA", "configured" if status.configured else "NOT CONFIGURED")
        if not status.configured:
            warnings.append("MFA is not configured: ask Hermes to set it up, or run 'mfa setup'")
        mode = stat.S_IMODE(settings.state_dir.stat().st_mode)
        if mode & 0o077:
            problems.append(f"state directory {settings.state_dir} has mode {mode:o}; expected 700")
    except (OSError, ValueError) as exc:
        problems.append(f"cannot use the state directory {settings.state_dir}: {exc}")
    for message in warnings:
        print(f"WARNING: {message}")
    for message in problems:
        print(f"ERROR: {message}")
    return 1 if problems else 0


# --- notify-test ------------------------------------------------------------------------------------------
async def _notify_test(settings: Settings) -> int:
    if not settings.telegram_enabled:
        print("Telegram is not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID).", file=sys.stderr)
        return 1
    notifier = build_notifier(settings)
    try:
        message_id = await notifier.send_text(
            Messages(settings.language, settings.tz).test_message(socket.gethostname())
        )
    finally:
        await notifier.aclose()
    if message_id is None:
        print("Sending failed; see the log above.", file=sys.stderr)
        return 1
    print("Test message sent.")
    return 0


# --- mfa -------------------------------------------------------------------------------------------------
def _mfa(settings: Settings, args: argparse.Namespace) -> int:
    mfa = MfaManager.from_settings(settings, SystemClock())
    if args.mfa_command == "status":
        status = mfa.status()
        print(f"configured: {status.configured}")
        if status.configured_at:
            print(f"configured at: {datetime.fromtimestamp(status.configured_at, settings.tz).isoformat()}")
        if status.locked_until:
            print(f"locked until: {datetime.fromtimestamp(status.locked_until, settings.tz).isoformat()}")
        print(f"recent failures: {status.recent_failures}")
        return 0
    if args.mfa_command == "reset":
        if not args.yes:
            answer = input("This forgets the current authenticator. Type 'reset' to confirm: ")
            if answer.strip() != "reset":
                print("Aborted.")
                return 1
        mfa.reset()
        print("MFA reset. Enroll again with 'mfa setup' or ask Hermes to do it.")
        return 0
    return _mfa_setup(mfa, force=args.force)


def _mfa_setup(mfa: MfaManager, *, force: bool) -> int:
    if mfa.is_configured() and not force:
        print("MFA is already configured. Use --force to replace it, or 'mfa reset' first.", file=sys.stderr)
        return 1
    enrollment = mfa.begin_enrollment(force=True)
    print(enrollment.qr_terminal())
    print("Add this account to Proton Authenticator: '+' then scan the QR code, or enter it manually.")
    print(f"  Key:     {enrollment.grouped_secret}")
    print(f"  Issuer:  {enrollment.issuer}")
    print(f"  Account: {enrollment.account}")
    print("  Type TOTP, SHA-1, 6 digits, 30 seconds")
    for _ in range(3):
        try:
            code = input("Code shown by the app: ")
        except EOFError:
            return 1
        try:
            mfa.confirm_enrollment(code)
        except MfaError as exc:
            print(exc, file=sys.stderr)
            continue
        print("MFA configured.")
        return 0
    mfa.cancel_enrollment()
    return 1
