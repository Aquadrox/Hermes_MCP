"""Basic-auth credentials of the current NAS tunnel, and brute-force protection.

The MCP server generates a username and password for each NAS tunnel, sends them to the user
on Telegram and hands them to the NAS (``PUT /api/admin/credentials``), then revokes them when
the tunnel closes. Only a SHA-256 digest of the password is kept, in memory and in the state
directory, so that a restart of the service (idle exit, crash) does not lock the user out.

After too many wrong passwords in a short window, every login is refused for a while; a new
``nas_open`` (new credentials) lifts the lock.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from hermes_ngrok_mcp.storage import JsonStateFile

MAX_FAILURES = 20
FAILURE_WINDOW = 300.0
LOCKOUT = 900.0
# Credentials never outlive this, even if the MCP server could not revoke them.
MAX_AGE = 24 * 3600.0


def _digest(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class Verdict(StrEnum):
    OK = "ok"
    MISSING = "missing"  # no Authorization header: the browser has not asked the user yet
    INVALID = "invalid"
    LOCKED = "locked"
    NOT_OPEN = "not_open"  # no NAS tunnel is open


@dataclass
class _Credentials:
    username: str
    digest: str
    granted_at: float


@dataclass
class CredentialStore:
    path: Path | None
    clock: Callable[[], float] = time.time
    _current: _Credentials | None = None
    _failures: list[float] = field(default_factory=list)
    _locked_until: float = 0.0

    def __post_init__(self) -> None:
        self._state = JsonStateFile(self.path) if self.path is not None else None
        if self._state is not None:
            self._current = self._load(self._state.read())

    # --- administration (MCP server) -----------------------------------------------------------
    def grant(self, username: str, password: str) -> None:
        if not username or ":" in username or len(password) < 16:
            raise ValueError("invalid credentials")
        self._current = _Credentials(username, _digest(password), self.clock())
        self._failures.clear()
        self._locked_until = 0.0
        self._save()

    def revoke(self) -> None:
        self._current = None
        self._save()

    @property
    def active(self) -> bool:
        return self._live() is not None

    @property
    def locked_for(self) -> float:
        return max(0.0, self._locked_until - self.clock())

    # --- users -----------------------------------------------------------------------------------
    def check(self, authorization: bytes | None) -> tuple[Verdict, str | None]:
        """Check an ``Authorization`` header value. Returns the verdict and the username tried."""
        current = self._live()
        if current is None:
            return Verdict.NOT_OPEN, None
        if self.locked_for > 0:
            return Verdict.LOCKED, None
        if authorization is None:
            return Verdict.MISSING, None
        username, password = _parse_basic(authorization)
        if username is None or password is None:
            return self._fail(), username
        user_ok = hmac.compare_digest(username.encode("utf-8"), current.username.encode("utf-8"))
        password_ok = hmac.compare_digest(_digest(password), current.digest)
        if user_ok and password_ok:
            return Verdict.OK, username
        return self._fail(), username

    # --- internals --------------------------------------------------------------------------------
    def _fail(self) -> Verdict:
        now = self.clock()
        self._failures = [t for t in self._failures if now - t < FAILURE_WINDOW]
        self._failures.append(now)
        if len(self._failures) >= MAX_FAILURES:
            self._failures.clear()
            self._locked_until = now + LOCKOUT
            return Verdict.LOCKED
        return Verdict.INVALID

    def _live(self) -> _Credentials | None:
        current = self._current
        if current is not None and self.clock() - current.granted_at > MAX_AGE:
            self.revoke()
            return None
        return current

    def _save(self) -> None:
        if self._state is None:
            return
        with self._state.transaction() as state:
            state.clear()
            if self._current is not None:
                state.update(
                    {
                        "username": self._current.username,
                        "sha256": self._current.digest,
                        "granted_at": self._current.granted_at,
                    }
                )

    @staticmethod
    def _load(state: dict[str, Any]) -> _Credentials | None:
        try:
            return _Credentials(str(state["username"]), str(state["sha256"]), float(state["granted_at"]))
        except (KeyError, TypeError, ValueError):
            return None


def _parse_basic(header: bytes) -> tuple[str | None, str | None]:
    scheme, _, encoded = header.strip().partition(b" ")
    if scheme.lower() != b"basic" or not encoded:
        return None, None
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None, None
    username, sep, password = decoded.partition(":")
    return (username, password) if sep else (username, None)
