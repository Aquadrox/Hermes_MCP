"""Time sources, injectable so that lifecycles and TOTP windows are testable."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def time(self) -> float:
        """Wall-clock seconds since the epoch (used for TOTP and display)."""
        ...

    def monotonic(self) -> float:
        """Monotonic seconds (used for timeouts, immune to clock changes)."""
        ...


class SystemClock:
    def time(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()
