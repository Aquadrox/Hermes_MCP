"""PROXY protocol (v1 and v2) header parsing, to learn the real client address of a connection.

When ``HERMES_NGROK_PROXY_PROTOCOL`` is on, the ngrok edge prefixes every connection it
forwards with a PROXY header carrying the Internet client's address. The local relay
strips it before forwarding, so the exposed service sees an unchanged byte stream.

Parsing fails open: a connection without a valid header is relayed untouched, with an
unknown source. The source is only ever used for auditing, never for access control.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
from dataclasses import dataclass

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
_V1_PREFIX = b"PROXY "
_V1_MAX = 107  # longest v1 header, CRLF included
_V2_FIXED = 16
_V2_MAX_PAYLOAD = 4096


@dataclass(frozen=True)
class ProxyAddress:
    ip: str
    port: int


async def read_proxy_header(  # noqa: PLR0911 - every malformed case fails open
    reader: asyncio.StreamReader, *, timeout: float = 2.0
) -> tuple[ProxyAddress | None, bytes]:
    """Read and strip a PROXY header. Returns ``(source, bytes_to_forward)``."""
    buffer = b""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while len(buffer) < _V2_FIXED:
        if not (V2_SIGNATURE.startswith(buffer[:12]) or _V1_PREFIX.startswith(buffer[:6])):
            return None, buffer
        if buffer.startswith(_V1_PREFIX) and b"\r\n" in buffer:
            break
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None, buffer
        try:
            chunk = await asyncio.wait_for(reader.read(_V2_FIXED - len(buffer)), timeout=remaining)
        except (TimeoutError, OSError):
            return None, buffer
        if not chunk:
            return None, buffer
        buffer += chunk
    if buffer.startswith(V2_SIGNATURE):
        return await _read_v2(reader, buffer, deadline - loop.time())
    if buffer.startswith(_V1_PREFIX):
        return await _read_v1(reader, buffer, deadline - loop.time())
    return None, buffer


async def _read_v2(
    reader: asyncio.StreamReader, head: bytes, timeout: float
) -> tuple[ProxyAddress | None, bytes]:
    version_command, family = head[12], head[13]
    length = int.from_bytes(head[14:16], "big")
    if version_command >> 4 != 2 or length > _V2_MAX_PAYLOAD:
        return None, head
    try:
        payload = await asyncio.wait_for(reader.readexactly(length), timeout=max(0.01, timeout))
    except (TimeoutError, OSError, asyncio.IncompleteReadError):
        return None, head
    if version_command & 0x0F != 1:  # LOCAL command (health checks): no address
        return None, b""
    address: ProxyAddress | None = None
    with contextlib.suppress(ValueError):
        if family >> 4 == 1 and len(payload) >= 12:  # AF_INET
            address = ProxyAddress(
                str(ipaddress.IPv4Address(payload[0:4])), int.from_bytes(payload[8:10], "big")
            )
        elif family >> 4 == 2 and len(payload) >= 36:  # AF_INET6
            ip = ipaddress.IPv6Address(payload[0:16])
            shown = str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)
            address = ProxyAddress(shown, int.from_bytes(payload[32:34], "big"))
    return address, b""


async def _read_v1(
    reader: asyncio.StreamReader, head: bytes, timeout: float
) -> tuple[ProxyAddress | None, bytes]:
    buffer = head
    try:
        while b"\r\n" not in buffer:
            if len(buffer) >= _V1_MAX:
                return None, buffer
            chunk = await asyncio.wait_for(reader.read(_V1_MAX - len(buffer)), timeout=max(0.01, timeout))
            if not chunk:
                return None, buffer
            buffer += chunk
    except (TimeoutError, OSError):
        return None, buffer
    line, _, rest = buffer.partition(b"\r\n")
    fields = line.decode("ascii", "replace").split(" ")
    if len(fields) == 6 and fields[1] in ("TCP4", "TCP6"):
        with contextlib.suppress(ValueError):
            ip = ipaddress.ip_address(fields[2])
            return ProxyAddress(str(ip), int(fields[4])), rest
    return None, rest


def encode_v2(ip: str, port: int, *, dest_ip: str = "127.0.0.1", dest_port: int = 0) -> bytes:
    """Build a v2 PROXY header (used by tests and the fake ngrok edge)."""
    source, destination = ipaddress.ip_address(ip), ipaddress.ip_address(dest_ip)
    if source.version != destination.version:
        destination = ipaddress.ip_address("::1" if source.version == 6 else "127.0.0.1")
    family = 0x11 if source.version == 4 else 0x21
    payload = source.packed + destination.packed + port.to_bytes(2, "big") + dest_port.to_bytes(2, "big")
    return V2_SIGNATURE + bytes([0x21, family]) + len(payload).to_bytes(2, "big") + payload
