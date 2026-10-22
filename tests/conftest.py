"""Shared test doubles: a controllable clock, a recording notifier and a local fake ngrok edge."""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyotp
import pytest

from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.tunnels.backends import BackendError, EndpointSpec

T0 = 1_800_000_000.0  # fixed wall-clock start, aligned on a 30 s TOTP step


class FakeClock:
    def __init__(self, start: float = T0) -> None:
        self._time = start
        self._mono = 1_000.0

    def time(self) -> float:
        return self._time

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._time += seconds
        self._mono += seconds


@dataclass
class SentMessage:
    kind: str
    text: str
    protect: bool
    message_id: int
    image: bytes | None = None


@dataclass
class FakeNotifier:
    enabled: bool = True
    fail: bool = False
    sent: list[SentMessage] = field(default_factory=list)
    deleted: list[int] = field(default_factory=list)
    closed: bool = False
    _next_id: int = 100

    def _record(self, kind: str, text: str, protect: bool, image: bytes | None = None) -> int | None:
        if not self.enabled or self.fail:
            return None
        self._next_id += 1
        self.sent.append(SentMessage(kind, text, protect, self._next_id, image))
        return self._next_id

    async def send_text(self, text: str, *, protect: bool = False) -> int | None:
        return self._record("text", text, protect)

    async def send_photo(self, image: bytes, caption: str, *, protect: bool = True) -> int | None:
        return self._record("photo", caption, protect, image)

    async def delete(self, message_id: int) -> bool:
        self.deleted.append(message_id)
        return True

    async def aclose(self) -> None:
        self.closed = True

    def texts(self) -> list[str]:
        return [message.text for message in self.sent]


class _FakeEndpoint:
    """Stands for the ngrok edge: a local listener relaying to the upstream (our activity proxy)."""

    def __init__(self, backend: FakeBackend, spec: EndpointSpec, server: asyncio.Server) -> None:
        self._backend = backend
        self.spec = spec
        self._server = server
        port = server.sockets[0].getsockname()[1]
        scheme = "http" if spec.protocol == "http" else "tcp"
        self._url = f"{scheme}://127.0.0.1:{port}"
        self.closed = False

    @property
    def url(self) -> str:
        return self._url

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._server.close()
            self._backend.open_endpoints.remove(self)


class FakeBackend:
    def __init__(self) -> None:
        self.specs: list[EndpointSpec] = []
        self.open_endpoints: list[_FakeEndpoint] = []
        self.fail_with: str | None = None
        self.unreachable = False
        self.closed = False
        self._tasks: set[asyncio.Task[Any]] = set()

    async def open(self, spec: EndpointSpec) -> _FakeEndpoint:
        self.specs.append(spec)
        if self.fail_with:
            raise BackendError(self.fail_with)
        host, _, port = spec.upstream.rpartition(":")

        async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if self.unreachable:  # the edge accepts but never reaches the agent
                writer.close()
                return
            self._tasks.add(asyncio.current_task())  # type: ignore[arg-type]
            try:
                up_reader, up_writer = await asyncio.open_connection(host, int(port))
            except OSError:
                writer.close()
                return

            async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                with contextlib.suppress(OSError):
                    while data := await src.read(65536):
                        dst.write(data)
                        await dst.drain()
                with contextlib.suppress(OSError, RuntimeError):
                    dst.write_eof()

            try:
                await asyncio.gather(pump(reader, up_writer), pump(up_reader, writer))
            finally:
                writer.close()
                up_writer.close()

        server = await asyncio.start_server(relay, "127.0.0.1", 0)
        endpoint = _FakeEndpoint(self, spec, server)
        self.open_endpoints.append(endpoint)
        return endpoint

    async def aclose(self) -> None:
        self.closed = True
        for endpoint in list(self.open_endpoints):
            await endpoint.close()
        for task in list(self._tasks):
            task.cancel()


# --- local services to expose ------------------------------------------------------------------------
@dataclass
class LocalService:
    port: int
    server: asyncio.Server


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(OSError, asyncio.IncompleteReadError):
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            if not head:
                break
            body = b"hello from the exposed service"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            await writer.drain()
    writer.close()


async def _echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(OSError):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    writer.close()


@pytest.fixture
async def http_service() -> AsyncIterator[LocalService]:
    server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
    yield LocalService(server.sockets[0].getsockname()[1], server)
    server.close()


@pytest.fixture
async def echo_service() -> AsyncIterator[LocalService]:
    server = await asyncio.start_server(_echo_handler, "127.0.0.1", 0)
    yield LocalService(server.sockets[0].getsockname()[1], server)
    server.close()


def unused_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --- configuration -------------------------------------------------------------------------------------
@pytest.fixture
def anyio_backend() -> str:
    # The ngrok SDK and the relay are asyncio-based.
    return "asyncio"


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith(("HERMES_NGROK_", "TELEGRAM_", "NGROK_")) or name == "STATE_DIRECTORY":
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def notifier() -> FakeNotifier:
    return FakeNotifier()


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "ngrok_authtoken": "test-ngrok-token",
        "state_dir": tmp_path / "state",
        "verify_timeout": 5,
        "mfa_account": "hermes@test",
        "telegram_bot_token": "123:ABC",
        "telegram_chat_id": "42",
        "api_token": "x" * 40,
        "port": unused_port(),
    }
    values.update(overrides)
    return Settings(**values)


def totp_code(secret: str, clock: FakeClock, offset_steps: int = 0) -> str:
    return str(pyotp.TOTP(secret).at(clock.time() + 30 * offset_steps))
