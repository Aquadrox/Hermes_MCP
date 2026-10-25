"""``hermes-nas``: run the NAS file manager and inspect its audit trail.

Examples::

    hermes-nas serve              # socket-activated by systemd (hermes-nas.socket), or binds 127.0.0.1
    hermes-nas check              # validate the configuration and the permissions on the NAS folder
    hermes-nas audit --since 7d   # uploads, downloads, new folders, refused requests
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import socket
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn
from pydantic import ValidationError

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.audit import AuditLog
from hermes_ngrok_mcp.cli import add_audit_arguments, configure_logging, print_audit
from hermes_ngrok_mcp.clock import SystemClock
from hermes_ngrok_mcp.nas.app import Activity, create_app
from hermes_ngrok_mcp.nas.config import NasSettings, load_nas_settings

_SD_LISTEN_FDS_START = 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-nas", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=os.environ.get("HERMES_NAS_ENV_FILE"),
        help="dotenv file to load (environment variables take precedence)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the file manager")
    serve.add_argument("--root", type=Path, help="override HERMES_NAS_ROOT")
    serve.add_argument("--port", type=int, help="override HERMES_NAS_PORT (ignored under socket activation)")
    commands.add_parser("check", help="validate the configuration and the NAS folder")
    add_audit_arguments(commands.add_parser("audit", help="show the NAS audit trail"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = load_nas_settings(args.env_file)
    except (ValidationError, FileNotFoundError) as exc:
        print(f"Invalid configuration:\n{exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level)
    if args.command == "serve":
        overrides = {k: v for k, v in (("root", args.root), ("port", args.port)) if v is not None}
        return _serve(settings.model_copy(update=overrides) if overrides else settings)
    if args.command == "check":
        return _check(settings)
    clock = SystemClock()
    return print_audit(_audit(settings, origin="admin-cli"), args, clock.time())


def _audit(settings: NasSettings, *, origin: str = "nas") -> AuditLog:
    return AuditLog(settings.audit_file, clock=SystemClock(), tz=settings.tz, origin=origin)


def _problems(settings: NasSettings) -> list[str]:
    problems: list[str] = []
    if settings.access_key is None:
        problems.append("HERMES_NAS_ACCESS_KEY is empty: every request would be refused")
    if not settings.root.is_dir():
        problems.append(f"{settings.root} is not a directory")
    elif not os.access(settings.root, os.R_OK | os.X_OK):
        problems.append(f"{settings.root} is not readable by this user")
    return problems


def _check(settings: NasSettings) -> int:
    print(f"hermes-nas {__version__}")
    print(f"  {'folder':<16} {settings.root}")
    print(f"  {'listen':<16} http://{settings.host}:{settings.port} (or the systemd socket)")
    print(f"  {'access key':<16} {'set' if settings.access_key else 'MISSING'}")
    print(f"  {'max upload':<16} {settings.max_upload} bytes")
    print(f"  {'idle exit':<16} {settings.idle_exit or 'never'} s")
    print(f"  {'audit trail':<16} {settings.audit_file}")
    problems = _problems(settings)
    if settings.root.is_dir() and not os.access(settings.root, os.W_OK | os.X_OK):
        print("WARNING: the folder is read-only for this user: uploads and new folders will fail")
    for message in problems:
        print(f"ERROR: {message}")
    return 1 if problems else 0


# --- serve ---------------------------------------------------------------------------------------------
def listening_socket(settings: NasSettings) -> tuple[socket.socket, str]:
    """The socket passed by systemd (``hermes-nas.socket``), or a fresh loopback one."""
    if os.environ.get("LISTEN_PID") == str(os.getpid()) and int(os.environ.get("LISTEN_FDS", "0")) >= 1:
        for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            os.environ.pop(name, None)
        sock = socket.socket(fileno=_SD_LISTEN_FDS_START)
        origin = "systemd"
    else:
        family = socket.AF_INET6 if ":" in settings.host else socket.AF_INET
        sock = socket.create_server((settings.host, settings.port), family=family, reuse_port=False)
        origin = "bind"
    address = sock.getsockname()[0]
    if sock.family not in (socket.AF_INET, socket.AF_INET6) or not ipaddress.ip_address(address).is_loopback:
        sock.close()
        raise ValueError(f"refusing to serve on {address}: the NAS must only listen on a loopback address")
    return sock, origin


async def _stop_when_idle(server: uvicorn.Server, activity: Activity, idle_exit: int) -> None:
    step = max(1.0, min(30.0, idle_exit / 10))
    while not server.should_exit:
        await asyncio.sleep(step)
        if activity.idle_for() >= idle_exit:
            server.should_exit = True


async def _run(settings: NasSettings, sock: socket.socket, audit: AuditLog) -> None:
    activity = Activity()
    app = create_app(settings, audit=audit, activity=activity)
    config = uvicorn.Config(
        app,
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=False,
        timeout_graceful_shutdown=10,
    )
    server = uvicorn.Server(config)
    watcher = (
        asyncio.create_task(_stop_when_idle(server, activity, settings.idle_exit))
        if settings.idle_exit
        else None
    )
    try:
        await server.serve(sockets=[sock])
    finally:
        if watcher is not None:
            watcher.cancel()
    idle = settings.idle_exit and activity.idle_for() >= settings.idle_exit
    audit.record("nas.stopped", reason="idle" if idle else "signal")


def _serve(settings: NasSettings) -> int:
    problems = _problems(settings)
    if problems:
        for message in problems:
            print(f"ERROR: {message}", file=sys.stderr)
        return 2
    try:
        sock, origin = listening_socket(settings)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    audit = _audit(settings)
    address = sock.getsockname()
    audit.record(
        "nas.started", version=__version__, root=str(settings.root), listen=f"{address[0]}:{address[1]}"
    )
    print(
        f"hermes-nas {__version__} serving {settings.root} on {address[0]}:{address[1]} ({origin})",
        file=sys.stderr,
    )
    asyncio.run(_run(settings, sock, audit))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
