"""Local TCP relay inserted between ngrok and the exposed service.

ngrok forwards to this relay, which forwards to the real service. Counting connections
and bytes here tells us whether a tunnel is actually used, independently of the ngrok
plan or API, for HTTP, WebSocket and raw TCP alike.

Connections accepted while the tunnel is being verified are flagged as probes: they are
left out of the usage statistics, and their bytes only count once verification is over
(the ngrok edge may reuse such a connection for real traffic afterwards).

With ``proxy_protocol`` on, each connection starts with a PROXY header from the ngrok edge
giving the Internet client's address; it is stripped here and reported for auditing.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import Counter
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

from hermes_ngrok_mcp.clock import Clock
from hermes_ngrok_mcp.tunnels.proxy_protocol import ProxyAddress, read_proxy_header

log = logging.getLogger(__name__)

_BUFFER_SIZE = 64 * 1024


@dataclass(frozen=True)
class UsageStats:
    connections_total: int
    connections_active: int
    bytes_in: int
    bytes_out: int
    last_activity_wall: float | None
    distinct_sources: int = 0
    last_source: str | None = None


@dataclass(frozen=True)
class ConnectionRecord:
    """A finished client connection, as reported to the audit trail."""

    source: ProxyAddress | None
    opened_at: float
    duration: float
    bytes_in: int
    bytes_out: int


@dataclass
class _Connection:
    probe: bool
    opened_at: float = 0.0
    opened_mono: float = 0.0
    source: ProxyAddress | None = None
    bytes_in: int = 0
    bytes_out: int = 0


class ActivityProxy:
    def __init__(
        self,
        target_host: str,
        target_port: int,
        *,
        clock: Clock,
        connect_timeout: float = 5.0,
        listen_host: str = "127.0.0.1",
        proxy_protocol: bool = False,
        on_connection: Callable[[ConnectionRecord], None] | None = None,
    ) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self._clock = clock
        self._connect_timeout = connect_timeout
        self._listen_host = listen_host
        self._proxy_protocol = proxy_protocol
        self._on_connection = on_connection
        self._sources: Counter[str] = Counter()
        self._last_source: str | None = None
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._probe_event: asyncio.Event | None = None
        self._port: int | None = None
        self._connections_total = 0
        self._connections_active = 0
        self._bytes_in = 0
        self._bytes_out = 0
        self._last_activity: float | None = None
        self._last_activity_wall: float | None = None
        self._baseline = clock.monotonic()

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError("proxy not started")
        return self._port

    @property
    def address(self) -> str:
        return f"{self._listen_host}:{self.port}"

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, host=self._listen_host, port=0)
        self._port = int(self._server.sockets[0].getsockname()[1])
        self._baseline = self._clock.monotonic()
        return self._port

    async def aclose(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if server is not None:
            await server.wait_closed()

    # --- usage -------------------------------------------------------------------------------
    def stats(self) -> UsageStats:
        return UsageStats(
            connections_total=self._connections_total,
            connections_active=self._connections_active,
            bytes_in=self._bytes_in,
            bytes_out=self._bytes_out,
            last_activity_wall=self._last_activity_wall,
            distinct_sources=len(self._sources),
            last_source=self._last_source,
        )

    def sources(self) -> Counter[str]:
        """Connections per client IP (known only with the PROXY protocol)."""
        return Counter(self._sources)

    @property
    def active_connections(self) -> int:
        return self._connections_active

    def idle_for(self, now: float) -> float:
        """Seconds since the last real traffic (or since the idle timer was last reset)."""
        reference = (
            self._baseline if self._last_activity is None else max(self._baseline, self._last_activity)
        )
        return max(0.0, now - reference)

    def reset_idle_timer(self) -> None:
        self._baseline = self._clock.monotonic()

    @contextlib.asynccontextmanager
    async def probing(self) -> AsyncIterator[asyncio.Event]:
        """Flag connections accepted in this block as verification probes.

        The yielded event is set as soon as a probe connection reaches the relay, which
        proves that the public endpoint is routed all the way to this machine. Probing does
        not count as use: it leaves the idle timer untouched.
        """
        event = asyncio.Event()
        self._probe_event = event
        try:
            yield event
        finally:
            self._probe_event = None

    # --- relay ---------------------------------------------------------------------------------
    def _touch(self) -> None:
        self._last_activity = self._clock.monotonic()
        self._last_activity_wall = self._clock.time()

    def _count(self, connection: _Connection, size: int, *, inbound: bool) -> None:
        if connection.probe and self._probe_event is not None:
            return
        if inbound:
            self._bytes_in += size
            connection.bytes_in += size
        else:
            self._bytes_out += size
            connection.bytes_out += size
        self._touch()

    async def _handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        probe_event = self._probe_event
        connection = _Connection(
            probe=probe_event is not None, opened_at=self._clock.time(), opened_mono=self._clock.monotonic()
        )
        if probe_event is not None:
            probe_event.set()
        else:
            self._connections_total += 1
            self._connections_active += 1
            self._touch()
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            preamble = b""
            if self._proxy_protocol:
                connection.source, preamble = await read_proxy_header(client_reader)
                if connection.source is not None and not connection.probe:
                    self._sources[connection.source.ip] += 1
                    self._last_source = connection.source.ip
            try:
                upstream_reader, upstream = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port), timeout=self._connect_timeout
                )
            except (OSError, TimeoutError) as exc:
                log.info(
                    "relay could not reach %s:%s: %s", self.target_host, self.target_port, type(exc).__name__
                )
                return
            upstream_writer = upstream
            if preamble:
                self._count(connection, len(preamble), inbound=True)
                upstream.write(preamble)
            await self._relay(connection, client_reader, client_writer, upstream_reader, upstream)
        finally:
            for writer in (client_writer, upstream_writer):
                if writer is not None:
                    writer.close()
            if not connection.probe:
                self._connections_active -= 1
                self._touch()
                self._report(connection)
            if task is not None:
                self._tasks.discard(task)

    def _report(self, connection: _Connection) -> None:
        if self._on_connection is None:
            return
        try:
            self._on_connection(
                ConnectionRecord(
                    source=connection.source,
                    opened_at=connection.opened_at,
                    duration=max(0.0, self._clock.monotonic() - connection.opened_mono),
                    bytes_in=connection.bytes_in,
                    bytes_out=connection.bytes_out,
                )
            )
        except Exception:
            log.exception("connection callback failed")

    async def _relay(
        self,
        connection: _Connection,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        inbound = asyncio.create_task(self._pump(connection, client_reader, upstream_writer, inbound=True))
        outbound = asyncio.create_task(self._pump(connection, upstream_reader, client_writer, inbound=False))
        try:
            done, pending = await asyncio.wait({inbound, outbound}, return_when=asyncio.FIRST_COMPLETED)
            # A clean EOF was propagated as a half-close: let the other direction finish.
            # A reset or error tears the whole connection down.
            if pending and all(task.result() for task in done):
                await asyncio.wait(pending)
        finally:
            for task in (inbound, outbound):
                task.cancel()
            await asyncio.gather(inbound, outbound, return_exceptions=True)

    async def _pump(
        self,
        connection: _Connection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        inbound: bool,
    ) -> bool:
        try:
            while data := await reader.read(_BUFFER_SIZE):
                self._count(connection, len(data), inbound=inbound)
                writer.write(data)
                await writer.drain()
        except OSError:
            return False
        with contextlib.suppress(OSError, RuntimeError):
            if writer.can_write_eof():
                writer.write_eof()
        return True
