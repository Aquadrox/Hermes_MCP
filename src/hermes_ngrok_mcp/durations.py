"""Human-friendly durations for configuration values ("10m", "1h30m", "90s", "600")."""

from __future__ import annotations

import re

_DURATION_RE = re.compile(r"^(?:(?P<d>\d+)d)?(?:(?P<h>\d+)h)?(?:(?P<m>\d+)m(?:in)?)?(?:(?P<s>\d+)s)?$")
_UNITS = {"d": 86_400, "h": 3_600, "m": 60, "s": 1}


def parse_duration(value: object) -> int:
    """Parse a duration into whole seconds.

    Accepts plain integers (seconds) or compact strings such as ``"10m"``, ``"1h30m"``,
    ``"45s"`` or ``"2d"``. Negative values are rejected; ``0`` is allowed and means
    "disabled" wherever the setting supports it.
    """
    if isinstance(value, bool):
        raise ValueError("a duration cannot be a boolean")
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, float):
        if not value.is_integer():
            raise ValueError("durations are expressed in whole seconds")
        seconds = int(value)
    elif isinstance(value, str):
        text = value.strip().lower().replace(" ", "")
        if text.lstrip("-").isdigit():
            seconds = int(text)
        else:
            match = _DURATION_RE.fullmatch(text) if text else None
            if match is None or not any(match.groupdict().values()):
                raise ValueError(f"invalid duration {value!r}; use e.g. '600', '10m', '1h30m'")
            seconds = sum(int(amount) * _UNITS[unit] for unit, amount in match.groupdict().items() if amount)
    else:
        raise ValueError(f"invalid duration type {type(value).__name__}")
    if seconds < 0:
        raise ValueError("a duration cannot be negative")
    return seconds


def format_duration(seconds: float) -> str:
    """Render a duration for humans ("12 min", "1 h 05 min", "45 s"); same notation in FR and EN."""
    total = max(0, round(seconds))
    hours, rest = divmod(total, 3_600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes:02d} min" if minutes else f"{hours} h"
    if minutes:
        if secs and minutes < 5:
            return f"{minutes} min {secs:02d} s"
        return f"{minutes} min"
    return f"{secs} s"
