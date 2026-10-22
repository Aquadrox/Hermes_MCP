"""Second factor based on TOTP (RFC 6238), compatible with Proton Authenticator.

Design notes
------------
* The secret is 160 random bits (RFC 4226 §4), SHA-1 / 6 digits / 30 s: the parameters
  every authenticator app supports, Proton Authenticator included.
* A code is accepted at most once: the matching time-step counter is persisted and any
  code from the same or an earlier step is refused (replay protection).
* Failed attempts are counted in a sliding window and trigger a lockout whose duration
  doubles at each consecutive lockout (up to a day) until a code is accepted again. Both
  survive restarts because they live in the state file, next to the secret.
* An enrollment stays in memory until it is confirmed with a valid code, so an unconfirmed
  secret never reaches the disk. Replacing an active secret requires a valid current code;
  a forgotten device can only be reset locally with the admin CLI.
"""

from __future__ import annotations

import base64
import hmac
import io
import logging
import math
import secrets
from dataclasses import dataclass
from typing import Any

import pyotp
import segno

from hermes_ngrok_mcp.clock import Clock
from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.storage import JsonStateFile

log = logging.getLogger(__name__)

DIGITS = 6
PERIOD = 30
ALGORITHM = "SHA1"
_SECRET_BYTES = 20
MAX_LOCKOUT = 86_400
_STATE_VERSION = 1


class MfaError(Exception):
    """Base class. The message is safe to show to the agent and to the user."""


class MfaNotConfiguredError(MfaError):
    def __init__(self) -> None:
        super().__init__(
            "MFA is not configured yet. Run mfa_setup_start first, then confirm with mfa_setup_confirm."
        )


class MfaCodeFormatError(MfaError):
    def __init__(self) -> None:
        super().__init__(
            f"An MFA code is exactly {DIGITS} digits. Ask the user for the code shown in their app."
        )


class MfaInvalidCodeError(MfaError):
    def __init__(self, remaining_attempts: int) -> None:
        self.remaining_attempts = remaining_attempts
        super().__init__(
            f"Invalid MFA code. {remaining_attempts} attempt(s) left before a temporary lockout. "
            "Ask the user for the current code; never guess or reuse one."
        )


class MfaCodeReusedError(MfaError):
    def __init__(self) -> None:
        super().__init__(
            "This MFA code was already used. Each code is single-use: ask the user for the next code "
            "(it changes every 30 seconds)."
        )


class MfaLockedError(MfaError):
    def __init__(self, retry_after: int, *, newly_locked: bool = False) -> None:
        self.retry_after = retry_after
        self.newly_locked = newly_locked
        super().__init__(
            f"Too many invalid MFA codes: verification is locked for {retry_after} more second(s). "
            "Do not retry before then."
        )


class MfaEnrollmentError(MfaError):
    pass


@dataclass(frozen=True)
class Enrollment:
    secret: str
    uri: str
    issuer: str
    account: str
    expires_at: float
    rotation: bool

    @property
    def grouped_secret(self) -> str:
        return " ".join(self.secret[i : i + 4] for i in range(0, len(self.secret), 4))

    def qr_png(self, scale: int = 8) -> bytes:
        buffer = io.BytesIO()
        segno.make(self.uri, error="m").save(buffer, kind="png", scale=scale, border=4)
        return buffer.getvalue()

    def qr_terminal(self) -> str:
        buffer = io.StringIO()
        segno.make(self.uri, error="m").terminal(out=buffer, compact=True)
        return buffer.getvalue()


@dataclass(frozen=True)
class MfaStatus:
    configured: bool
    configured_at: float | None
    locked_until: float | None
    recent_failures: int
    enrollment_pending: bool
    enrollment_expires_at: float | None


@dataclass
class _Pending:
    secret: str
    expires_at: float
    rotation: bool


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii").rstrip("=")


def normalize_code(code: object) -> str:
    if not isinstance(code, str | int) or isinstance(code, bool):
        raise MfaCodeFormatError
    text = str(code).strip().replace(" ", "").replace("-", "")
    if len(text) != DIGITS or not text.isascii() or not text.isdigit():
        raise MfaCodeFormatError
    return text


class MfaManager:
    def __init__(
        self,
        store: JsonStateFile,
        *,
        clock: Clock,
        issuer: str,
        account: str,
        valid_window: int = 1,
        max_failures: int = 5,
        failure_window: int = 300,
        lockout: int = 900,
        enrollment_ttl: int = 600,
    ) -> None:
        self._store = store
        self._clock = clock
        self.issuer = issuer
        self.account = account
        self._valid_window = valid_window
        self._max_failures = max_failures
        self._failure_window = failure_window
        self._lockout = lockout
        self._enrollment_ttl = enrollment_ttl
        self._pending: _Pending | None = None

    @classmethod
    def from_settings(cls, settings: Settings, clock: Clock) -> MfaManager:
        return cls(
            JsonStateFile(settings.mfa_state_file),
            clock=clock,
            issuer=settings.mfa_issuer,
            account=settings.mfa_account,
            valid_window=settings.mfa_valid_window,
            max_failures=settings.mfa_max_failures,
            failure_window=settings.mfa_failure_window,
            lockout=settings.mfa_lockout,
            enrollment_ttl=settings.mfa_enrollment_ttl,
        )

    # --- queries ------------------------------------------------------------------------------
    def status(self) -> MfaStatus:
        now = self._clock.time()
        state = self._store.read()
        totp = state.get("totp")
        locked_until = state.get("locked_until")
        failures = [t for t in state.get("failures", []) if now - t < self._failure_window]
        pending = self._live_pending(now)
        return MfaStatus(
            configured=bool(totp),
            configured_at=totp.get("created_at") if totp else None,
            locked_until=locked_until if locked_until and locked_until > now else None,
            recent_failures=len(failures),
            enrollment_pending=pending is not None,
            enrollment_expires_at=pending.expires_at if pending else None,
        )

    def is_configured(self) -> bool:
        return bool(self._store.read().get("totp"))

    # --- enrollment ----------------------------------------------------------------------------
    def begin_enrollment(self, current_code: str | None = None, *, force: bool = False) -> Enrollment:
        """Start (or restart) an enrollment.

        When a secret is already active, ``current_code`` must be a valid code for it, unless
        ``force`` is set (reserved for the local admin CLI).
        """
        rotation = self.is_configured()
        if rotation and not force:
            if current_code is None:
                raise MfaEnrollmentError(
                    "MFA is already configured. To replace the authenticator, provide a valid current "
                    "code (current_code). If the device is lost, an administrator must reset MFA on the "
                    "server with: hermes-ngrok-admin mfa reset"
                )
            self.verify(current_code)
        secret = generate_secret()
        expires_at = self._clock.time() + self._enrollment_ttl
        self._pending = _Pending(secret=secret, expires_at=expires_at, rotation=rotation)
        uri = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD).provisioning_uri(
            name=self.account, issuer_name=self.issuer
        )
        log.info("MFA enrollment started (rotation=%s)", rotation)
        return Enrollment(
            secret=secret,
            uri=uri,
            issuer=self.issuer,
            account=self.account,
            expires_at=expires_at,
            rotation=rotation,
        )

    def confirm_enrollment(self, code: str) -> None:
        normalized = normalize_code(code)
        now = self._clock.time()
        pending = self._live_pending(now)
        if pending is None:
            raise MfaEnrollmentError(
                "No MFA enrollment in progress (or it expired). Start again with mfa_setup_start."
            )
        error: MfaError | None = None
        with self._store.transaction() as state:
            error = self._check_lock(state, now)
            if error is None and not pending.rotation and state.get("totp"):
                error = MfaEnrollmentError(
                    "MFA was configured in the meantime. Start again with mfa_setup_start."
                )
            if error is None:
                counter = self._match(pending.secret, normalized, now)
                if counter is None:
                    error = self._register_failure(state, now)
                else:
                    state.clear()
                    state.update(
                        {
                            "version": _STATE_VERSION,
                            "totp": {
                                "secret": pending.secret,
                                "algorithm": ALGORITHM,
                                "digits": DIGITS,
                                "period": PERIOD,
                                "created_at": now,
                                "last_counter": counter,
                            },
                            "failures": [],
                            "locked_until": None,
                        }
                    )
        if error is not None:
            log.warning("MFA enrollment confirmation failed: %s", type(error).__name__)
            raise error
        self._pending = None
        log.info("MFA enrollment confirmed (rotation=%s)", pending.rotation)

    def cancel_enrollment(self) -> None:
        self._pending = None

    def reset(self) -> None:
        """Forget the secret, failures and lockout. Local administrative action only."""
        with self._store.transaction() as state:
            state.clear()
        self._pending = None
        log.warning("MFA reset: the authenticator must be enrolled again")

    # --- verification -----------------------------------------------------------------------------
    def verify(self, code: str) -> None:
        """Validate a code for the active secret, consuming it. Raises an :class:`MfaError`."""
        normalized = normalize_code(code)
        now = self._clock.time()
        error: MfaError | None = None
        with self._store.transaction() as state:
            error = self._check_lock(state, now)
            totp = state.get("totp")
            if error is None and not totp:
                error = MfaNotConfiguredError()
            if error is None and totp:
                counter = self._match(totp["secret"], normalized, now)
                if counter is None:
                    error = self._register_failure(state, now)
                elif counter <= int(totp.get("last_counter", -1)):
                    error = MfaCodeReusedError()
                else:
                    totp["last_counter"] = counter
                    state["failures"] = []
                    state["lockouts"] = 0
        if error is not None:
            log.warning("MFA verification refused: %s", type(error).__name__)
            raise error
        log.info("MFA verification succeeded")

    # --- internals ------------------------------------------------------------------------------------
    def _live_pending(self, now: float) -> _Pending | None:
        if self._pending is not None and now >= self._pending.expires_at:
            self._pending = None
        return self._pending

    def _match(self, secret: str, code: str, now: float) -> int | None:
        totp = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD)
        current = int(now) // PERIOD
        matched: int | None = None
        # Compare every candidate in constant time; keep the most recent matching step.
        for offset in range(-self._valid_window, self._valid_window + 1):
            counter = current + offset
            if counter >= 0 and hmac.compare_digest(totp.generate_otp(counter), code):
                matched = counter if matched is None else max(matched, counter)
        return matched

    def _check_lock(self, state: dict[str, Any], now: float) -> MfaLockedError | None:
        locked_until = state.get("locked_until")
        if locked_until is None:
            return None
        if now < locked_until:
            return MfaLockedError(math.ceil(locked_until - now))
        state["locked_until"] = None
        return None

    def _register_failure(self, state: dict[str, Any], now: float) -> MfaError:
        failures = [t for t in state.get("failures", []) if now - t < self._failure_window]
        failures.append(now)
        if len(failures) >= self._max_failures:
            # Each consecutive lockout doubles (RFC 4226 §7.3 throttling), up to a day.
            lockouts = int(state.get("lockouts", 0))
            duration = min(self._lockout * 2**lockouts, MAX_LOCKOUT)
            state["failures"] = []
            state["locked_until"] = now + duration
            state["lockouts"] = lockouts + 1
            log.warning("MFA locked for %ss after %s failed attempts", duration, len(failures))
            return MfaLockedError(duration, newly_locked=True)
        state["failures"] = failures
        return MfaInvalidCodeError(self._max_failures - len(failures))
