from __future__ import annotations

import asyncio

import pytest

from hermes_ngrok_mcp.tunnels.proxy import ActivityProxy, ConnectionRecord
from hermes_ngrok_mcp.tunnels.proxy_protocol import V2_SIGNATURE, ProxyAddress, encode_v2, read_proxy_header
from tests.conftest import FakeClock, LocalService

pytestmark = pytest.mark.anyio


def reader_with(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


async def test_v2_ipv4_header_is_stripped() -> None:
    source, rest = await read_proxy_header(reader_with(encode_v2("203.0.113.7", 51234) + b"GET / HTTP/1.1"))
    assert source == ProxyAddress("203.0.113.7", 51234)
    assert rest == b""  # the payload stays in the reader


async def test_v2_ipv6_header() -> None:
    source, _ = await read_proxy_header(reader_with(encode_v2("2001:db8::1", 443)))
    assert source == ProxyAddress("2001:db8::1", 443)


async def test_v2_local_command_has_no_address() -> None:
    header = V2_SIGNATURE + bytes([0x20, 0x00]) + (0).to_bytes(2, "big")
    assert await read_proxy_header(reader_with(header + b"x")) == (None, b"")


async def test_v1_header() -> None:
    reader = reader_with(b"PROXY TCP4 198.51.100.1 127.0.0.1 40000 22\r\nSSH-2.0-OpenSSH\r\n")
    source, rest = await read_proxy_header(reader)
    assert source == ProxyAddress("198.51.100.1", 40000)
    assert rest + await reader.read() == b"SSH-2.0-OpenSSH\r\n"


async def test_short_v1_unknown_header() -> None:
    assert await read_proxy_header(reader_with(b"PROXY UNKNOWN\r\n", eof=False), timeout=0.2) == (None, b"")


@pytest.mark.parametrize(
    "payload",
    [
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"SSH-2.0-OpenSSH_9.6\r\n",
        b"\r\n\r\nnot-a-proxy",
        b"PROXY garbage",
    ],
)
async def test_anything_else_is_forwarded_untouched(payload: bytes) -> None:
    reader = reader_with(payload)
    source, rest = await read_proxy_header(reader, timeout=0.2)
    assert source is None
    assert rest + await reader.read() == payload


async def test_silent_client_times_out_without_data_loss() -> None:
    reader = reader_with(b"", eof=False)
    assert await read_proxy_header(reader, timeout=0.05) == (None, b"")


async def test_relay_reports_sources_and_strips_the_header(
    echo_service: LocalService, clock: FakeClock
) -> None:
    records: list[ConnectionRecord] = []
    proxy = ActivityProxy(
        "127.0.0.1", echo_service.port, clock=clock, proxy_protocol=True, on_connection=records.append
    )
    await proxy.start()
    try:
        for port in (1000, 1001):
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
            writer.write(encode_v2("203.0.113.7", port) + b"hello")
            await writer.drain()
            assert await reader.readexactly(5) == b"hello"
            writer.close()
            await writer.wait_closed()
        for _ in range(50):
            if len(records) == 2:
                break
            await asyncio.sleep(0.01)
        stats = proxy.stats()
        assert stats.distinct_sources == 1
        assert stats.last_source == "203.0.113.7"
        assert proxy.sources() == {"203.0.113.7": 2}
        assert [r.source for r in records] == [
            ProxyAddress("203.0.113.7", 1000),
            ProxyAddress("203.0.113.7", 1001),
        ]
        assert records[0].bytes_in == 5
        assert records[0].bytes_out == 5
    finally:
        await proxy.aclose()
