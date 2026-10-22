"""Small JSON state file with inter-process locking and atomic, owner-only writes.

The MCP service and the admin CLI may touch the MFA state concurrently, so every
read-modify-write cycle happens under an exclusive ``flock`` on a sidecar lock file.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (owner-only) if needed and warn if it is readable by others."""
    path.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        log.warning("state directory %s has permissive mode %o; expected 700", path, mode)


class JsonStateFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock_path = path.with_name(path.name + ".lock")

    @contextlib.contextmanager
    def transaction(self) -> Iterator[dict[str, Any]]:
        """Yield the current state; persist it on normal exit if it was modified."""
        ensure_private_dir(self.path.parent)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, _FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            state = self._read()
            snapshot = json.dumps(state, sort_keys=True)
            yield state
            if json.dumps(state, sort_keys=True) != snapshot:
                self._write(state)
        finally:
            os.close(fd)  # closing releases the flock

    def read(self) -> dict[str, Any]:
        with self.transaction() as state:
            return dict(state)

    def _read(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError(f"corrupted state file {self.path}: expected a JSON object")
        return data

    def _write(self, state: dict[str, Any]) -> None:
        directory = self.path.parent
        fd, tmp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), _FILE_MODE)
                json.dump(state, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
