"""Configuration of the hermes-nas service (``HERMES_NAS_*`` variables, /etc/hermes-nas/hermes-nas.env)."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BeforeValidator, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from hermes_ngrok_mcp.durations import parse_duration

Duration = Annotated[int, BeforeValidator(parse_duration)]

_SIZE_RE = re.compile(r"^(?P<amount>\d+(?:\.\d+)?)\s*(?P<unit>[kmgt]?)(?:i?b)?$")
_SIZE_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(value: object) -> int:
    """``"10G"``, ``"512M"``, ``"1.5GiB"`` or a plain number of bytes (binary units)."""
    if isinstance(value, bool):
        raise ValueError("a size cannot be a boolean")
    if isinstance(value, int):
        size = value
    elif isinstance(value, str):
        match = _SIZE_RE.fullmatch(value.strip().lower())
        if match is None:
            raise ValueError(f"invalid size {value!r}; use e.g. '10G' or '512M'")
        size = int(float(match["amount"]) * _SIZE_UNITS[match["unit"]])
    else:
        raise ValueError(f"invalid size type {type(value).__name__}")
    if size <= 0:
        raise ValueError("a size must be positive")
    return size


Size = Annotated[int, BeforeValidator(parse_size)]


def _default_state_dir() -> Path:
    systemd_dirs = os.environ.get("STATE_DIRECTORY")
    if systemd_dirs:
        return Path(systemd_dirs.split(":")[0])
    xdg = os.environ.get("XDG_STATE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "state") / "hermes-nas"


class NasSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HERMES_NAS_", extra="ignore", case_sensitive=False, env_file_encoding="utf-8"
    )

    root: Path = Field(default=Path("/var/MonNAS"), description="Directory served by the file manager.")
    title: str = Field(default="MonNAS", min_length=1, max_length=40)
    host: str = "127.0.0.1"
    port: int = Field(default=8766, ge=1, le=65_535)
    access_key: SecretStr | None = None
    max_upload: Size = 10 * 1024**3
    idle_exit: Duration = Field(default=600, description="Exit after this long without requests (0 = never).")
    state_dir: Path = Field(default_factory=_default_state_dir)
    timezone: str = "UTC"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("access_key", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("access_key")
    @classmethod
    def _long_enough(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError("HERMES_NAS_ACCESS_KEY must be at least 32 characters long")
        return value

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, value: str) -> str:
        # The NAS is never exposed directly: only the ngrok tunnel may reach it.
        if value != "localhost" and not ipaddress.ip_address(value).is_loopback:
            raise ValueError("HERMES_NAS_HOST must be a loopback address (127.0.0.1 or ::1)")
        return value

    @field_validator("root")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("HERMES_NAS_ROOT must be an absolute path")
        return value

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone {value!r}") from exc
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def audit_file(self) -> Path:
        return self.state_dir / "audit.jsonl"

    @property
    def credentials_file(self) -> Path:
        return self.state_dir / "credentials.json"


def load_nas_settings(env_file: Path | None = None) -> NasSettings:
    if env_file is not None and not env_file.is_file():
        raise FileNotFoundError(f"env file not found: {env_file}")
    return NasSettings(_env_file=env_file)  # type: ignore[call-arg]
