"""Append-only audit trail of security-relevant events, as JSON Lines.

Every event (tool call, MFA attempt, tunnel opened or closed, client connection...) is
appended to ``audit.jsonl`` in the state directory (owner-only, rotated by size) and
mirrored to the service log, hence to journald. The file is outside the agent's reach:
the agent can only read it through the read-only ``audit_log`` tool.

Events never contain secrets: no MFA code, password, token or key.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
from collections import Counter
from collections.abc import Collection, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from hermes_ngrok_mcp.clock import Clock
from hermes_ngrok_mcp.storage import ensure_private_dir

log = logging.getLogger("hermes_ngrok_mcp.audit")

_FILE_MODE = 0o600
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUPS = 5

# Event name prefixes, as exposed to the agent and the admin CLI.
CATEGORIES: dict[str, tuple[str, ...]] = {
    "all": (),
    "tunnels": ("tunnel.",),
    "connections": ("connection.",),
    "mfa": ("mfa.",),
    "mcp": ("mcp.",),
    "nas": ("nas.",),
    "service": ("service.",),
}


def _jsonable(value: object) -> object:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v) for v in value]
    return str(value)


class AuditLog:
    """Record and query audit events. ``path=None`` keeps them in the service log only."""

    def __init__(
        self,
        path: Path | None,
        *,
        clock: Clock,
        tz: ZoneInfo,
        origin: str = "service",
        max_bytes: int = DEFAULT_MAX_BYTES,
        backups: int = DEFAULT_BACKUPS,
    ) -> None:
        self.path = path
        self._clock = clock
        self._tz = tz
        self._origin = origin
        self._max_bytes = max_bytes
        self._backups = backups

    def record(self, event: str, **fields: object) -> None:
        """Append one event. Never raises: auditing must not break the audited operation."""
        now = self._clock.time()
        entry: dict[str, object] = {
            "ts": round(now, 3),
            "time": datetime.fromtimestamp(now, tz=self._tz).isoformat(timespec="seconds"),
            "event": event,
            "origin": self._origin,
        }
        entry.update({key: _jsonable(value) for key, value in fields.items() if value is not None})
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        log.info("AUDIT %s", line)
        if self.path is None:
            return
        try:
            self._append(self.path, line + "\n")
        except OSError as exc:
            log.warning("cannot write the audit log %s: %s", self.path, exc)

    # --- query ------------------------------------------------------------------------------------
    def query(
        self,
        *,
        since: float | None = None,
        category: str = "all",
        events: Collection[str] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Most recent matching events, oldest first, at most ``limit`` of them."""
        prefixes = CATEGORIES.get(category, ())
        matched: list[dict[str, Any]] = []
        for entry in self._entries():
            name = str(entry.get("event", ""))
            if since is not None and float(entry.get("ts", 0)) < since:
                continue
            if prefixes and not name.startswith(prefixes):
                continue
            if events and name not in events:
                continue
            matched.append(entry)
        return matched[-limit:] if limit > 0 else matched

    def _files(self) -> list[Path]:
        if self.path is None:
            return []
        rotated = [self.path.with_name(f"{self.path.name}.{i}") for i in range(self._backups, 0, -1)]
        return [*rotated, self.path]

    def _entries(self) -> Iterator[dict[str, Any]]:
        for file in self._files():
            try:
                handle = file.open(encoding="utf-8")
            except FileNotFoundError:
                continue
            with handle:
                for raw in handle:
                    with contextlib.suppress(ValueError):
                        entry = json.loads(raw)
                        if isinstance(entry, dict):
                            yield entry

    # --- storage ------------------------------------------------------------------------------------
    def _append(self, path: Path, line: str) -> None:
        ensure_private_dir(path.parent)
        lock_path = path.with_name(path.name + ".lock")
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, _FILE_MODE)
        try:
            # The service and the admin CLI may write concurrently; rotation must not race.
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            with contextlib.suppress(FileNotFoundError):
                if path.stat().st_size >= self._max_bytes:
                    self._rotate(path)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, _FILE_MODE)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        finally:
            os.close(lock_fd)

    def _rotate(self, path: Path) -> None:
        for index in range(self._backups - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            if source.exists():
                os.replace(source, path.with_name(f"{path.name}.{index + 1}"))
        if self._backups > 0:
            os.replace(path, path.with_name(f"{path.name}.1"))
        else:
            path.unlink()


# --- summaries --------------------------------------------------------------------------------------
@dataclass
class AuditSummary:
    """Counters over a set of events, for "how many attempts / from where" questions."""

    events: int = 0
    tunnels_opened: int = 0
    tunnels_closed: int = 0
    tunnel_open_failures: int = 0
    mfa_successes: int = 0
    mfa_failures: int = 0
    mfa_lockouts: int = 0
    mcp_tool_calls: int = 0
    mcp_tool_errors: int = 0
    mcp_auth_rejections: int = 0
    nas_access_denied: int = 0
    connections: int = 0
    sources: Counter[str] = field(default_factory=Counter)

    def top_sources(self, count: int = 10) -> list[tuple[str, int]]:
        return self.sources.most_common(count)


_COUNTERS = {
    "tunnel.opened": "tunnels_opened",
    "tunnel.closed": "tunnels_closed",
    "tunnel.open_failed": "tunnel_open_failures",
    "mfa.verified": "mfa_successes",
    "mfa.rejected": "mfa_failures",
    "mfa.locked": "mfa_lockouts",
    "mcp.tool_call": "mcp_tool_calls",
    "mcp.auth_rejected": "mcp_auth_rejections",
    "nas.access_denied": "nas_access_denied",
    "connection.closed": "connections",
}
# Events whose source_ip is an Internet (or local) client worth reporting.
_SOURCE_EVENTS = frozenset(
    {"connection.closed", "nas.download", "nas.upload", "nas.mkdir", "nas.access_denied", "mcp.auth_rejected"}
)


def summarize(entries: Collection[dict[str, Any]]) -> AuditSummary:
    summary = AuditSummary(events=len(entries))
    for entry in entries:
        name = str(entry.get("event"))
        counter = _COUNTERS.get(name)
        if counter is not None:
            setattr(summary, counter, getattr(summary, counter) + 1)
        if name == "mcp.tool_call" and entry.get("outcome") != "ok":
            summary.mcp_tool_errors += 1
        source = entry.get("source_ip")
        if isinstance(source, str) and name in _SOURCE_EVENTS:
            summary.sources[source] += 1
    return summary


def format_entry(entry: dict[str, Any]) -> str:
    """One human-readable line for the admin CLI."""
    skip = {"ts", "time", "event", "origin"}
    details = " ".join(
        f"{key}={json.dumps(value, ensure_ascii=False)}" for key, value in entry.items() if key not in skip
    )
    return f"{entry.get('time', '?')}  {entry.get('event', '?'):<22} {details}".rstrip()
