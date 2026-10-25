from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from hermes_ngrok_mcp.nas.config import NasSettings, parse_size
from hermes_ngrok_mcp.nas.fs import (
    MAX_ENTRIES,
    TEMP_PREFIX,
    ConflictError,
    ForbiddenError,
    InsufficientStorageError,
    InvalidPathError,
    NasRoot,
    NotFoundError,
    RangeNotSatisfiableError,
    TooLargeError,
    free_names,
    parse_range,
    split_path,
    validate_name,
)


@pytest.fixture
def root(tmp_path: Path) -> NasRoot:
    base = tmp_path / "nas"
    (base / "Photos" / "2024").mkdir(parents=True)
    (base / "Photos" / "beach.jpg").write_bytes(b"jpeg")
    (base / "notes.txt").write_text("hello")
    return NasRoot(base, max_upload=1024)


def upload(root: NasRoot, path: str, name: str, data: bytes) -> str:
    handle = root.begin_upload(path, name, expected_size=len(data))
    handle.write(data)
    return handle.commit()


# --- paths ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("path", "parts"), [("", ()), ("/", ()), ("a/b", ("a", "b")), ("//a//b/", ("a", "b"))]
)
def test_split_path(path: str, parts: tuple[str, ...]) -> None:
    assert split_path(path) == parts


@pytest.mark.parametrize("path", ["..", "a/../b", "./a", "a\x00b", "x" * 5000])
def test_split_path_rejects_traversal(path: str) -> None:
    with pytest.raises(InvalidPathError):
        split_path(path)


@pytest.mark.parametrize(
    "name", ["", ".", "..", "a/b", "a\\b", "tab\tname", " lead", "trail ", "é" * 200, TEMP_PREFIX + "x"]
)
def test_validate_name_rejects(name: str) -> None:
    with pytest.raises(InvalidPathError):
        validate_name(name)


def test_validate_name_accepts_unicode() -> None:
    assert validate_name("Vacances d'été 🌞.mp4") == "Vacances d'été 🌞.mp4"


def test_free_names() -> None:
    names = free_names("photo.tar.gz")
    assert [next(names) for _ in range(3)] == ["photo.tar.gz", "photo.tar (1).gz", "photo.tar (2).gz"]
    assert list(free_names(".bashrc"))[1] == ".bashrc (1)"
    assert list(free_names("README"))[1] == "README (1)"


# --- listing ---------------------------------------------------------------------------------------------
def test_list_sorts_folders_first(root: NasRoot) -> None:
    listing = root.list("")
    assert [(e.name, e.kind) for e in listing.entries] == [("Photos", "dir"), ("notes.txt", "file")]
    assert listing.entries[1].size == 5
    assert root.list("Photos").path == "Photos"
    assert [e.name for e in root.list("/Photos/").entries] == ["2024", "beach.jpg"]


def test_list_missing_or_file(root: NasRoot) -> None:
    with pytest.raises(NotFoundError):
        root.list("nope")
    with pytest.raises(NotFoundError):
        root.list("notes.txt")


def test_symlinks_are_listed_but_never_followed(root: NasRoot, tmp_path: Path) -> None:
    outside = tmp_path / "secret"
    outside.mkdir()
    (outside / "key").write_text("s3cret")
    (root.root / "escape").symlink_to(outside)
    (root.root / "file-link").symlink_to(outside / "key")
    kinds = {e.name: e.kind for e in root.list("").entries}
    assert kinds["escape"] == "symlink"
    with pytest.raises(ForbiddenError):
        root.list("escape")
    with pytest.raises(ForbiddenError):
        root.open_file("escape/key")
    with pytest.raises(ForbiddenError):
        root.open_file("file-link")
    with pytest.raises(ForbiddenError):
        upload(root, "escape", "x.txt", b"x")
    assert not (outside / "x.txt").exists()


def test_listing_is_capped(root: NasRoot) -> None:
    big = root.root / "big"
    big.mkdir()
    for index in range(MAX_ENTRIES + 5):
        (big / f"f{index}").touch()
    listing = root.list("big")
    assert listing.truncated
    assert len(listing.entries) == MAX_ENTRIES


def test_stale_uploads_are_hidden_then_removed(root: NasRoot) -> None:
    fresh = root.root / f"{TEMP_PREFIX}fresh.part"
    stale = root.root / f"{TEMP_PREFIX}stale.part"
    fresh.touch()
    stale.touch()
    old = time.time() - 2 * 86_400
    os.utime(stale, (old, old))
    assert all(not e.name.startswith(TEMP_PREFIX) for e in root.list("").entries)
    assert fresh.exists()
    assert not stale.exists()


# --- reading -----------------------------------------------------------------------------------------------
def test_open_file(root: NasRoot) -> None:
    fd, info = root.open_file("Photos/beach.jpg")
    try:
        assert info.st_size == 4
        assert os.read(fd, 10) == b"jpeg"
    finally:
        os.close(fd)
    with pytest.raises(NotFoundError):
        root.open_file("Photos")
    with pytest.raises(InvalidPathError):
        root.open_file("")
    with pytest.raises(NotFoundError):
        root.open_file("missing.bin")


def test_fifo_is_not_served(root: NasRoot) -> None:
    os.mkfifo(root.root / "pipe")
    with pytest.raises(NotFoundError):
        root.open_file("pipe")


# --- writing ------------------------------------------------------------------------------------------------
def test_mkdir(root: NasRoot) -> None:
    assert root.mkdir("Photos", "2025") == "Photos/2025"
    assert (root.root / "Photos" / "2025").is_dir()
    with pytest.raises(ConflictError):
        root.mkdir("Photos", "2025")
    with pytest.raises(InvalidPathError):
        root.mkdir("", "../evil")
    with pytest.raises(NotFoundError):
        root.mkdir("nope", "x")


def test_upload_never_overwrites(root: NasRoot) -> None:
    assert upload(root, "", "notes.txt", b"second") == "notes (1).txt"
    assert upload(root, "", "notes.txt", b"third") == "notes (2).txt"
    assert (root.root / "notes.txt").read_text() == "hello"
    assert (root.root / "notes (2).txt").read_bytes() == b"third"
    assert upload(root, "Photos/2024", "new.bin", b"\x00\x01") == "Photos/2024/new.bin"
    assert not list(root.root.rglob(f"{TEMP_PREFIX}*"))


def test_upload_limits(root: NasRoot) -> None:
    with pytest.raises(TooLargeError):
        root.begin_upload("", "big.bin", expected_size=2048)
    handle = root.begin_upload("", "big.bin", expected_size=None)
    handle.write(b"x" * 1000)
    with pytest.raises(TooLargeError):
        handle.write(b"x" * 100)
    handle.abort()
    assert not (root.root / "big.bin").exists()
    assert not list(root.root.glob(f"{TEMP_PREFIX}*"))


def test_upload_checks_free_space(root: NasRoot, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NasRoot, "_free_bytes", lambda self, fd: 10)
    with pytest.raises(InsufficientStorageError):
        root.begin_upload("", "a.bin", expected_size=100)


def test_finished_upload_cannot_be_reused(root: NasRoot) -> None:
    handle = root.begin_upload("", "a.txt", expected_size=1)
    handle.write(b"a")
    handle.commit()
    with pytest.raises(RuntimeError):
        handle.write(b"b")
    with pytest.raises(RuntimeError):
        handle.commit()
    handle.abort()  # harmless


def test_disk_usage(root: NasRoot) -> None:
    usage = root.disk_usage()
    assert usage.total >= usage.free > 0
    assert root.writable()


# --- ranges -------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("bytes=0-9", (0, 9)),
        ("bytes=10-", (10, 99)),
        ("bytes=-10", (90, 99)),
        ("bytes=50-500", (50, 99)),
        ("bytes=0-1,5-6", None),
        ("items=0-1", None),
        ("bytes=abc", None),
        ("bytes=9-3", None),
    ],
)
def test_parse_range(header: str | None, expected: tuple[int, int] | None) -> None:
    assert parse_range(header, 100) == expected


def test_unsatisfiable_range() -> None:
    with pytest.raises(RangeNotSatisfiableError):
        parse_range("bytes=100-", 100)
    with pytest.raises(RangeNotSatisfiableError):
        parse_range("bytes=-0", 100)


# --- settings -----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "size"),
    [
        ("10G", 10 * 1024**3),
        ("512M", 512 * 1024**2),
        ("1.5GiB", 3 * 1024**3 // 2),
        ("2048", 2048),
        ("1kb", 1024),
    ],
)
def test_parse_size(text: str, size: int) -> None:
    assert parse_size(text) == size


@pytest.mark.parametrize("text", ["", "-1", "0", "ten", "5X"])
def test_parse_size_rejects(text: str) -> None:
    with pytest.raises(ValueError, match="size"):
        parse_size(text)


def test_nas_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HERMES_NAS_ROOT", str(tmp_path))
    monkeypatch.setenv("HERMES_NAS_MAX_UPLOAD", "1G")
    monkeypatch.setenv("HERMES_NAS_ACCESS_KEY", "a" * 32)
    settings = NasSettings()
    assert settings.max_upload == 1024**3
    assert settings.access_key is not None
    with pytest.raises(ValueError, match="loopback"):
        NasSettings(host="0.0.0.0")  # noqa: S104 - the point is to refuse it
    with pytest.raises(ValueError, match="32 characters"):
        NasSettings(access_key="short")
    with pytest.raises(ValueError, match="absolute"):
        NasSettings(root=Path("relative"))
