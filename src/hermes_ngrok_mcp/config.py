"""Runtime configuration, loaded from environment variables and an optional ``.env`` file.

Every setting uses the ``HERMES_NGROK_`` prefix, except the well-known third-party names
``NGROK_AUTHTOKEN``, ``TELEGRAM_BOT_TOKEN`` and ``TELEGRAM_CHAT_ID``.
Durations accept seconds or compact strings such as ``10m`` / ``1h30m``.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AliasChoices, BeforeValidator, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from hermes_ngrok_mcp.durations import parse_duration

Duration = Annotated[int, BeforeValidator(parse_duration)]

APP_NAME = "hermes-ngrok-mcp"


class PortRanges:
    """An immutable set of TCP ports described as ``"22,80,8000-8999"``."""

    __slots__ = ("_ranges", "_text")

    def __init__(self, ranges: tuple[tuple[int, int], ...], text: str) -> None:
        self._ranges = ranges
        self._text = text

    @classmethod
    def parse(cls, value: object) -> PortRanges:
        if isinstance(value, PortRanges):
            return value
        if not isinstance(value, str):
            raise ValueError("port ranges must be a string such as '22,8000-8999'")
        ranges: list[tuple[int, int]] = []
        for raw_part in value.split(","):
            part = raw_part.strip()
            if not part:
                continue
            low_text, sep, high_text = part.partition("-")
            try:
                low = int(low_text)
                high = int(high_text) if sep else low
            except ValueError as exc:
                raise ValueError(f"invalid port range {part!r}") from exc
            if not 1 <= low <= high <= 65_535:
                raise ValueError(f"invalid port range {part!r} (ports are 1-65535)")
            ranges.append((low, high))
        return cls(tuple(ranges), ",".join(f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in ranges))

    def __contains__(self, port: object) -> bool:
        return isinstance(port, int) and any(lo <= port <= hi for lo, hi in self._ranges)

    def __bool__(self) -> bool:
        return bool(self._ranges)

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"PortRanges({self._text!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PortRanges) and other._ranges == self._ranges

    def __hash__(self) -> int:
        return hash(self._ranges)


Ports = Annotated[PortRanges, NoDecode, BeforeValidator(PortRanges.parse)]


def default_state_dir() -> Path:
    """systemd's ``StateDirectory=`` when running as a service, the XDG state dir otherwise."""
    systemd_dirs = os.environ.get("STATE_DIRECTORY")
    if systemd_dirs:
        return Path(systemd_dirs.split(":")[0])
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / APP_NAME


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HERMES_NGROK_",
        extra="ignore",
        case_sensitive=False,
        env_file_encoding="utf-8",
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    # --- ngrok -------------------------------------------------------------------------
    ngrok_authtoken: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("NGROK_AUTHTOKEN", "HERMES_NGROK_AUTHTOKEN")
    )
    domain: str | None = Field(default=None, description="Reserved ngrok domain for HTTP tunnels.")

    # --- tunnel lifecycle ----------------------------------------------------------------
    idle_timeout: Duration = Field(
        default=600, description="Close a tunnel unused for this long (0 = never)."
    )
    max_lifetime: Duration = Field(default=1200, description="Hard lifetime of a tunnel (0 = unlimited).")
    expiry_warning: Duration = Field(default=300, description="Warn this long before the hard expiry.")
    extension: Duration = Field(default=1200, description="Time added by each MFA-approved extension.")
    max_tunnels: int = Field(default=3, ge=1, le=20)
    verify_tunnels: bool = True
    verify_timeout: Duration = 20
    reaper_interval: float = Field(default=5.0, gt=0, le=60)

    # --- what may be exposed ---------------------------------------------------------------
    target_host: str = "127.0.0.1"
    allowed_ports: Ports = PortRanges.parse("1-65535")
    denied_ports: Ports = PortRanges.parse("")
    proxy_protocol: bool = Field(
        default=False,
        description="Ask ngrok for PROXY headers to audit the clients' real addresses (paid ngrok plans).",
    )

    # --- protection of public HTTP endpoints ----------------------------------------------------
    basic_auth: bool = Field(default=True, description="Protect HTTP tunnels with generated basic-auth.")
    basic_auth_user: str = Field(default="hermes", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    allow_unprotected_http: bool = True
    share_credentials_with_agent: bool = False

    # --- MFA (TOTP, RFC 6238) ---------------------------------------------------------------
    state_dir: Path = Field(default_factory=default_state_dir)
    mfa_issuer: str = Field(default="Hermes ngrok", min_length=1, max_length=64)
    mfa_account: str = Field(default_factory=lambda: f"hermes@{socket.gethostname()}", max_length=128)
    mfa_valid_window: int = Field(default=1, ge=0, le=2)
    mfa_max_failures: int = Field(default=5, ge=1, le=100)
    mfa_failure_window: Duration = 300
    mfa_lockout: Duration = 900
    mfa_enrollment_ttl: Duration = 600
    mfa_allow_inline_enrollment: bool = True

    # --- NAS file manager (separate hermes-nas service, reached through a tunnel) ---------------------
    nas_port: int = Field(default=8766, ge=1, le=65_535)
    nas_access_key: SecretStr | None = Field(
        default=None, description="Admin key shared with hermes-nas (health, tunnel credentials)."
    )

    # --- audit trail --------------------------------------------------------------------------------
    audit_max_bytes: int = Field(default=10 * 1024 * 1024, ge=64 * 1024)
    audit_backups: int = Field(default=5, ge=0, le=100)

    # --- MCP server ---------------------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65_535)
    path: str = Field(default="/mcp", pattern=r"^/[A-Za-z0-9/_-]*$")
    api_token: SecretStr | None = None

    # --- Telegram notifications ------------------------------------------------------------------
    telegram_bot_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("TELEGRAM_BOT_TOKEN", "HERMES_NGROK_TELEGRAM_BOT_TOKEN")
    )
    telegram_chat_id: str | None = Field(
        default=None, validation_alias=AliasChoices("TELEGRAM_CHAT_ID", "HERMES_NGROK_TELEGRAM_CHAT_ID")
    )
    telegram_api_base: str = "https://api.telegram.org"

    # --- presentation ------------------------------------------------------------------------------
    language: Literal["fr", "en"] = "fr"
    timezone: str = "UTC"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("ngrok_authtoken", "api_token", "telegram_bot_token", "nas_access_key", mode="before")
    @classmethod
    def _blank_secret_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("domain", "telegram_chat_id", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone {value!r}") from exc
        return value

    @field_validator("telegram_api_base")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("telegram_api_base must be an http(s) URL")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _coherent(self) -> Settings:
        if self.max_lifetime and self.expiry_warning >= self.max_lifetime:
            raise ValueError("expiry_warning must be shorter than max_lifetime")
        if self.max_lifetime and self.extension == 0:
            raise ValueError("extension must be > 0 when max_lifetime is set")
        if (self.telegram_bot_token is None) != (self.telegram_chat_id is None):
            raise ValueError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set together")
        if self.nas_access_key is not None and len(self.nas_access_key.get_secret_value()) < 32:
            raise ValueError("HERMES_NGROK_NAS_ACCESS_KEY must be at least 32 characters long")
        if self.nas_port == self.port:
            raise ValueError("HERMES_NGROK_NAS_PORT must differ from HERMES_NGROK_PORT")
        return self

    # --- derived helpers -----------------------------------------------------------------------------
    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def telegram_enabled(self) -> bool:
        return self.telegram_bot_token is not None and self.telegram_chat_id is not None

    @property
    def host_is_loopback(self) -> bool:
        if self.host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False

    @property
    def mfa_state_file(self) -> Path:
        return self.state_dir / "mfa.json"

    @property
    def audit_file(self) -> Path:
        return self.state_dir / "audit.jsonl"

    @property
    def nas_enabled(self) -> bool:
        return self.nas_access_key is not None


def load_settings(env_file: Path | None = None) -> Settings:
    """Load settings from the process environment, optionally layered over ``env_file``."""
    if env_file is not None and not env_file.is_file():
        raise FileNotFoundError(f"env file not found: {env_file}")
    # Environment variables take precedence over the file, as with systemd's EnvironmentFile.
    return Settings(_env_file=env_file)  # type: ignore[call-arg]
