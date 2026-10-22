from __future__ import annotations

import asyncio

import pytest

from hermes_ngrok_mcp.tunnels.proxy import ActivityProxy
from tests.conftest import FakeClock, LocalService, unused_port

pytestmark = pytest.mark.anyio


async def _roundtrip(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    data = await reader.readexactly(len(payload))
    writer.close()
    await writer.wait_closed()
    return data


async def _settle() -> None:
    for _ in range(20):
        await asyncio.sleep(0.01)


async def test_relays_and_counts_traffic(echo_service: LocalService, clock: FakeClock) -> None:
    proxy = ActivityProxy("127.0.0.1", echo_service.port, clock=clock)
    await proxy.start()
    try:
        assert proxy.stats().connections_total == 0
        clock.advance(100)
        assert proxy.idle_for(clock.monotonic()) == 100
        assert await _roundtrip(proxy.port, b"ping" * 1000) == b"ping" * 1000
        await _settle()
        stats = proxy.stats()
        assert stats.connections_total == 1
        assert stats.connections_active == 0
        assert stats.bytes_in == 4000
        assert stats.bytes_out == 4000
        assert stats.last_activity_wall == clock.time()
        assert proxy.idle_for(clock.monotonic()) == 0
        clock.advance(42)
        assert proxy.idle_for(clock.monotonic()) == 42
    finally:
        await proxy.aclose()


async def test_probe_connections_are_not_usage(echo_service: LocalService, clock: FakeClock) -> None:
    proxy = ActivityProxy("127.0.0.1", echo_service.port, clock=clock)
    await proxy.start()
    try:
        clock.advance(50)
        async with proxy.probing() as reached:
            assert await _roundtrip(proxy.port, b"probe") == b"probe"
            await asyncio.wait_for(reached.wait(), 1)
        await _settle()
        assert proxy.idle_for(clock.monotonic()) == 50
        stats = proxy.stats()
        assert stats.connections_total == 0
        assert stats.bytes_in == 0
        assert stats.last_activity_wall is None
    finally:
        await proxy.aclose()


async def test_active_connection_is_tracked_and_closed_on_shutdown(
    echo_service: LocalService, clock: FakeClock
) -> None:
    proxy = ActivityProxy("127.0.0.1", echo_service.port, clock=clock)
    await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(b"hi")
    assert await reader.readexactly(2) == b"hi"
    assert proxy.active_connections == 1
    await proxy.aclose()
    assert await asyncio.wait_for(reader.read(), 2) == b""
    assert proxy.active_connections == 0
    writer.close()


async def test_unreachable_target_closes_the_client(clock: FakeClock) -> None:
    proxy = ActivityProxy("127.0.0.1", unused_port(), clock=clock)
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await _settle()
        assert proxy.active_connections == 0
        assert proxy.stats().connections_total == 1
    finally:
        await proxy.aclose()


async def test_reset_idle_timer(echo_service: LocalService, clock: FakeClock) -> None:
    proxy = ActivityProxy("127.0.0.1", echo_service.port, clock=clock)
    await proxy.start()
    try:
        clock.advance(300)
        proxy.reset_idle_timer()
        assert proxy.idle_for(clock.monotonic()) == 0
    finally:
        await proxy.aclose()
