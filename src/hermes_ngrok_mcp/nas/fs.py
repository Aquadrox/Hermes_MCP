"""Confined access to the NAS directory.

Every path is resolved component by component from a descriptor of the root directory,
with ``O_NOFOLLOW``: ``..``, absolute paths and symbolic links can never lead outside of
it, even if the tree changes between two calls (no check-then-use race on path strings).

Operations are limited to what the file manager offers: list a folder, read a file,
create a folder and upload a file. Nothing is ever overwritten or deleted: an upload
whose name is taken gets a free name such as ``photo (1).jpg``.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

TEMP_PREFIX = ".hermes-upload-"
_TEMP_SUFFIX = ".part"
_STALE_UPLOAD = 24 * 3600
MAX_ENTRIES = 10_000
_MAX_NAME_BYTES = 255
_MAX_PATH_BYTES = 4096
_MAX_RENAME_ATTEMPTS = 1000
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

EntryKind = Literal["dir", "file", "symlink", "other"]


class NasError(Exception):
    """A refused operation. ``status`` is the HTTP status; the message is shown to the user."""

    status = 400
    code = "bad_request"


class InvalidPathError(NasError):
    code = "invalid_path"


class NotFoundError(NasError):
    status = 404
    code = "not_found"


class ForbiddenError(NasError):
    status = 403
    code = "forbidden"


class ConflictError(NasError):
    status = 409
    code = "conflict"


class TooLargeError(NasError):
    status = 413
    code = "too_large"


class InsufficientStorageError(NasError):
    status = 507
    code = "insufficient_storage"


@dataclass(frozen=True)
class Entry:
    name: str
    kind: EntryKind
    size: int
    modified: float


@dataclass(frozen=True)
class Listing:
    path: str
    entries: list[Entry]
    truncated: bool


@dataclass(frozen=True)
class DiskUsage:
    total: int
    free: int


# --- names and paths -----------------------------------------------------------------------------------
def validate_name(name: str) -> str:
    """Check one path component typed or chosen by the user."""
    if not name or name in (".", ".."):
        raise InvalidPathError("Choose a non-empty name other than '.' or '..'.")
    if "/" in name or "\\" in name:
        raise InvalidPathError("A name cannot contain '/' or '\\'.")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise InvalidPathError("A name cannot contain control characters.")
    if name != name.strip():
        raise InvalidPathError("A name cannot start or end with a space.")
    if len(name.encode("utf-8", "surrogateescape")) > _MAX_NAME_BYTES:
        raise InvalidPathError("This name is too long (255 bytes at most).")
    if name.startswith(TEMP_PREFIX):
        raise InvalidPathError("This name is reserved for uploads in progress.")
    return name


def split_path(path: str) -> tuple[str, ...]:
    """``"a/b/c"`` (relative to the root; leading or doubled slashes ignored) -> ``("a", "b", "c")``."""
    if "\x00" in path or len(path.encode("utf-8", "surrogateescape")) > _MAX_PATH_BYTES:
        raise InvalidPathError("Invalid path.")
    parts = tuple(part for part in path.split("/") if part)
    for part in parts:
        if part in (".", ".."):
            raise InvalidPathError("A path cannot contain '.' or '..'.")
    return parts


def join_path(parts: tuple[str, ...]) -> str:
    return "/".join(parts)


def free_names(name: str) -> Iterator[str]:
    """``name``, then ``stem (1).ext``, ``stem (2).ext``..."""
    yield name
    stem, dot, extension = name.rpartition(".")
    if not stem:  # no extension, or a dotfile such as ".bashrc"
        stem, dot, extension = name, "", ""
    for index in range(1, _MAX_RENAME_ATTEMPTS):
        yield f"{stem} ({index}){dot}{extension}"


_ERRORS: dict[int, tuple[type[NasError], str]] = {
    errno.ENOENT: (NotFoundError, "{what} does not exist."),
    errno.ENOTDIR: (NotFoundError, "{what} does not exist."),
    errno.ELOOP: (ForbiddenError, "Symbolic links are not followed."),
    errno.EACCES: (ForbiddenError, "Permission denied for {what}."),
    errno.EPERM: (ForbiddenError, "Permission denied for {what}."),
    errno.ENOSPC: (InsufficientStorageError, "The disk is full."),
    errno.EDQUOT: (InsufficientStorageError, "The disk quota is exceeded."),
    errno.EEXIST: (ConflictError, "{what} already exists."),
    errno.ENAMETOOLONG: (InvalidPathError, "This name is too long."),
}


def _translate(exc: OSError, what: str) -> NasError:
    kind, template = _ERRORS.get(exc.errno or 0, (NasError, "{what}: " + os.strerror(exc.errno or 0) + "."))
    return kind(template.format(what=what))


def _is_symlink(name: str, dir_fd: int) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


# --- the root ----------------------------------------------------------------------------------------------
class NasRoot:
    def __init__(self, root: Path, *, max_upload: int) -> None:
        self.root = root
        self.max_upload = max_upload

    @contextlib.contextmanager
    def open_dir(self, parts: tuple[str, ...]) -> Iterator[int]:
        """Yield a descriptor of the folder ``parts``, opened without following any link."""
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError as exc:
            raise _translate(exc, "The NAS folder") from exc
        try:
            for index, part in enumerate(parts):
                try:
                    child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                except OSError as exc:
                    if _is_symlink(part, fd):  # O_DIRECTORY|O_NOFOLLOW reports a link as ENOTDIR
                        raise ForbiddenError("Symbolic links are not followed.") from exc
                    raise _translate(exc, f"The folder '{join_path(parts[: index + 1])}'") from exc
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    def disk_usage(self) -> DiskUsage:
        usage = os.statvfs(self.root)
        return DiskUsage(total=usage.f_blocks * usage.f_frsize, free=usage.f_bavail * usage.f_frsize)

    def writable(self) -> bool:
        return os.access(self.root, os.W_OK | os.X_OK)

    def list(self, path: str) -> Listing:
        parts = split_path(path)
        entries: list[Entry] = []
        truncated = False
        now = time.time()
        with self.open_dir(parts) as fd, os.scandir(fd) as iterator:
            for item in iterator:
                if item.name.startswith(TEMP_PREFIX):
                    self._forget_stale_upload(fd, item, now)
                    continue
                if len(entries) >= MAX_ENTRIES:
                    truncated = True
                    break
                try:
                    info = item.stat(follow_symlinks=False)
                except OSError:
                    continue
                entries.append(Entry(item.name, _kind(info.st_mode), info.st_size, info.st_mtime))
        entries.sort(key=lambda e: (e.kind != "dir", e.name.casefold()))
        return Listing(join_path(parts), entries, truncated)

    def open_file(self, path: str) -> tuple[int, os.stat_result]:
        """Open a regular file for reading. The caller closes the returned descriptor."""
        parts = split_path(path)
        if not parts:
            raise InvalidPathError("This is a folder, not a file.")
        with self.open_dir(parts[:-1]) as parent:
            try:
                # O_NONBLOCK: opening a FIFO must not hang; it has no effect on regular files.
                fd = os.open(
                    parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent
                )
            except OSError as exc:
                if _is_symlink(parts[-1], parent):
                    raise ForbiddenError("Symbolic links are not followed.") from exc
                raise _translate(exc, f"The file '{path}'") from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise NotFoundError("Only regular files can be downloaded.")
        os.set_blocking(fd, True)
        return fd, info

    def mkdir(self, path: str, name: str) -> str:
        parts = split_path(path)
        validate_name(name)
        with self.open_dir(parts) as parent:
            try:
                os.mkdir(name, 0o777, dir_fd=parent)
            except OSError as exc:
                raise _translate(exc, f"The folder '{name}'") from exc
        return join_path((*parts, name))

    def begin_upload(self, path: str, name: str, *, expected_size: int | None) -> Upload:
        parts = split_path(path)
        validate_name(name)
        if expected_size is not None and expected_size > self.max_upload:
            raise TooLargeError(f"Files are limited to {_human(self.max_upload)}.")
        with self.open_dir(parts) as parent:
            if expected_size is not None and expected_size > self._free_bytes(parent):
                raise InsufficientStorageError("Not enough free space on the NAS for this file.")
            directory = os.dup(parent)
        temp_name = f"{TEMP_PREFIX}{secrets.token_hex(8)}{_TEMP_SUFFIX}"
        try:
            fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o666,
                dir_fd=directory,
            )
        except OSError as exc:
            os.close(directory)
            raise _translate(exc, f"The folder '{join_path(parts) or '/'}'") from exc
        return Upload(
            directory=directory, temp_name=temp_name, fd=fd, name=name, parts=parts, max_size=self.max_upload
        )

    def _free_bytes(self, fd: int) -> int:
        usage = os.statvfs(fd)
        return usage.f_bavail * usage.f_frsize

    def _forget_stale_upload(self, fd: int, item: os.DirEntry[str], now: float) -> None:
        """Remove what an interrupted upload left behind (crash, power loss) after a day."""
        with contextlib.suppress(OSError):
            if now - item.stat(follow_symlinks=False).st_mtime > _STALE_UPLOAD:
                os.unlink(item.name, dir_fd=fd)


class Upload:
    """A file being received: written to a hidden temporary file, published atomically by :meth:`commit`."""

    def __init__(
        self, *, directory: int, temp_name: str, fd: int, name: str, parts: tuple[str, ...], max_size: int
    ) -> None:
        self._directory = directory
        self._temp_name = temp_name
        self._fd: int | None = fd
        self.name = name
        self._parts = parts
        self._max_size = max_size
        self.size = 0

    def write(self, data: bytes) -> None:
        if self._fd is None:
            raise RuntimeError("upload already finished")
        if self.size + len(data) > self._max_size:
            raise TooLargeError(f"Files are limited to {_human(self._max_size)}.")
        view = memoryview(data)
        try:
            while view:
                written = os.write(self._fd, view)
                view = view[written:]
        except OSError as exc:
            raise _translate(exc, "The upload") from exc
        self.size += len(data)

    def commit(self) -> str:
        """Publish under the requested name, or the first free variant. Returns the relative path."""
        if self._fd is None:
            raise RuntimeError("upload already finished")
        try:
            os.fsync(self._fd)
        finally:
            os.close(self._fd)
            self._fd = None
        try:
            for candidate in free_names(self.name):
                try:
                    # link() fails if the name exists: no file is ever replaced, even by a racing upload.
                    os.link(
                        self._temp_name,
                        candidate,
                        src_dir_fd=self._directory,
                        dst_dir_fd=self._directory,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    continue
                except OSError as exc:
                    raise _translate(exc, f"The file '{candidate}'") from exc
                return join_path((*self._parts, candidate))
            raise ConflictError("Too many files with this name already exist.")
        finally:
            self._cleanup()

    def abort(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
        self._cleanup()

    def _cleanup(self) -> None:
        if self._directory < 0:
            return
        with contextlib.suppress(OSError):
            os.unlink(self._temp_name, dir_fd=self._directory)
        os.close(self._directory)
        self._directory = -1


def _kind(mode: int) -> EntryKind:
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"  # pragma: no cover


# --- byte ranges -------------------------------------------------------------------------------------------
class RangeNotSatisfiableError(NasError):
    status = 416
    code = "range_not_satisfiable"


def parse_range(header: str | None, size: int) -> tuple[int, int] | None:  # noqa: PLR0911 - one exit per case
    """A single ``bytes=`` range as inclusive ``(start, end)``; ``None`` serves the whole file.

    Multi-range and malformed headers are ignored (RFC 9110 allows serving the full content).
    """
    if not header:
        return None
    unit, _, spec = header.strip().partition("=")
    if unit.strip().lower() != "bytes" or "," in spec:
        return None
    first, dash, last = spec.strip().partition("-")
    if not dash:
        return None
    try:
        if not first:  # suffix range: the last N bytes
            length = int(last)
            if length <= 0:
                raise RangeNotSatisfiableError("Invalid range.")
            return (max(0, size - length), size - 1) if size else None
        start = int(first)
        end = int(last) if last else size - 1
    except ValueError:
        return None
    if start >= size:
        raise RangeNotSatisfiableError("The requested range is beyond the end of the file.")
    if end < start:
        return None
    return start, min(end, size - 1)
