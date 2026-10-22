from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
import pytest

from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.messages import Messages
from hermes_ngrok_mcp.tunnels.manager import TunnelError, TunnelManager, TunnelNotFoundError, TunnelView
from tests.conftest import FakeBackend, FakeClock, FakeNotifier, LocalService, make_settings, unused_port

pytestmark = pytest.mark.anyio


def build_manager(
    settings: Settings, backend: FakeBackend | None, clock: FakeClock, notifier: FakeNotifier
) -> TunnelManager:
    return TunnelManager(
        settings,
        backend=backend,
        clock=clock,
        notifier=notifier,
        messages=Messages("fr", settings.tz),
        reserved_ports=frozenset({settings.port}),
    )


@pytest.fixture
async def manager(
    settings: Settings, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier
) -> AsyncIterator[TunnelManager]:
    instance = build_manager(settings, backend, clock, notifier)
    yield instance
    await instance.aclose()


async def http_get(view: TunnelView) -> httpx2.Response:
    auth = httpx2.BasicAuth(view.username, view.password) if view.username and view.password else None
    async with httpx2.AsyncClient(timeout=5, auth=auth) as client:
        return await client.get(view.public_url)


async def settle() -> None:
    for _ in range(20):
        await asyncio.sleep(0.01)


# --- opening -----------------------------------------------------------------------------------------
async def test_open_http_tunnel_with_generated_basic_auth(
    manager: TunnelManager, backend: FakeBackend, notifier: FakeNotifier, http_service: LocalService
) -> None:
    view = await manager.open(http_service.port, label="grafana")

    spec = backend.specs[0]
    assert spec.protocol == "http"
    policy: dict[str, Any] = json.loads(spec.traffic_policy or "{}")
    action = policy["on_http_request"][0]["actions"][0]
    assert action["type"] == "basic-auth"
    username, password = action["config"]["credentials"][0].split(":", 1)
    assert username == "hermes"
    assert len(password) >= 20

    assert view.verification is not None
    assert view.verification.ok
    assert view.verification.http_status == 200
    # The probe is not counted as usage.
    assert view.usage.connections_total == 0
    assert not view.in_use
    assert view.expires_in == 1_200
    assert view.closes_if_idle_in == 600

    # Credentials went straight to the user on Telegram, so the agent does not get the password.
    assert view.credentials_sent_to_user
    assert view.username == "hermes"
    assert view.password is None
    access_card = notifier.sent[-1]
    assert access_card.protect
    assert view.public_url in access_card.text
    assert password in access_card.text
    assert "grafana" in access_card.text


async def test_password_returned_when_telegram_is_unavailable(
    settings: Settings, backend: FakeBackend, clock: FakeClock, http_service: LocalService
) -> None:
    notifier = FakeNotifier(enabled=False)
    manager = build_manager(settings, backend, clock, notifier)
    try:
        view = await manager.open(http_service.port)
        assert not view.credentials_sent_to_user
        assert view.password
        response = await http_get(view)
        assert response.text == "hello from the exposed service"
    finally:
        await manager.aclose()


async def test_password_shared_with_agent_when_configured(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    settings = make_settings(tmp_path, share_credentials_with_agent=True)
    manager = build_manager(settings, backend, clock, notifier)
    try:
        view = await manager.open(http_service.port)
        assert view.credentials_sent_to_user
        assert view.password
    finally:
        await manager.aclose()


async def test_credentials_never_fall_back_to_the_agent(
    manager: TunnelManager,
    backend: FakeBackend,
    notifier: FakeNotifier,
    http_service: LocalService,
    echo_service: LocalService,
) -> None:
    notifier.fail = True
    with pytest.raises(TunnelError, match="closed again for safety"):
        await manager.open(http_service.port)
    assert manager.list() == []
    assert backend.open_endpoints == []
    # Without a password there is nothing to protect: the tunnel stays open.
    view = await manager.open(echo_service.port, "tcp")
    assert manager.get(view.id)


async def test_unprotected_http_and_tcp_tunnels(
    manager: TunnelManager, backend: FakeBackend, http_service: LocalService, echo_service: LocalService
) -> None:
    http_view = await manager.open(http_service.port, protect=False)
    assert backend.specs[0].traffic_policy is None
    assert http_view.username is None
    tcp_view = await manager.open(echo_service.port, "tcp")
    assert backend.specs[1].protocol == "tcp"
    assert backend.specs[1].traffic_policy is None
    assert tcp_view.public_url.startswith("tcp://")
    assert tcp_view.verification is not None
    assert tcp_view.verification.ok


async def test_end_to_end_traffic_is_counted(manager: TunnelManager, http_service: LocalService) -> None:
    view = await manager.open(http_service.port, protect=False)
    response = await http_get(view)
    assert response.status_code == 200
    await settle()
    refreshed = manager.get(view.id)
    assert refreshed.usage.connections_total == 1
    assert refreshed.usage.bytes_in > 0
    assert refreshed.usage.bytes_out > 0
    assert refreshed.in_use


# --- automatic closing ---------------------------------------------------------------------------------
async def test_idle_tunnel_is_closed_after_ten_minutes(
    manager: TunnelManager,
    backend: FakeBackend,
    clock: FakeClock,
    notifier: FakeNotifier,
    http_service: LocalService,
) -> None:
    view = await manager.open(http_service.port)
    clock.advance(599)
    await manager.tick()
    assert manager.get(view.id)
    clock.advance(1)
    await manager.tick()
    assert manager.list() == []
    assert backend.open_endpoints == []
    assert "aucune activité depuis 10 min" in notifier.sent[-1].text


async def test_traffic_postpones_the_idle_timeout(
    manager: TunnelManager, clock: FakeClock, http_service: LocalService
) -> None:
    view = await manager.open(http_service.port, protect=False)
    clock.advance(500)
    await http_get(view)
    await settle()
    clock.advance(500)
    await manager.tick()
    assert manager.get(view.id).closes_if_idle_in == 100
    clock.advance(100)
    await manager.tick()
    assert manager.list() == []


async def test_status_verification_is_not_usage(
    manager: TunnelManager, clock: FakeClock, http_service: LocalService
) -> None:
    view = await manager.open(http_service.port)
    clock.advance(300)
    reverified = await manager.reverify(view.id)
    assert reverified.verification is not None
    assert reverified.verification.ok
    assert reverified.idle_for == 300
    assert reverified.usage.connections_total == 0


async def test_open_tcp_session_counts_as_use(
    manager: TunnelManager, clock: FakeClock, echo_service: LocalService
) -> None:
    view = await manager.open(echo_service.port, "tcp")
    host, _, port = view.public_url.removeprefix("tcp://").rpartition(":")
    reader, writer = await asyncio.open_connection(host, int(port))
    writer.write(b"hello")
    assert await reader.readexactly(5) == b"hello"
    clock.advance(700)
    await manager.tick()
    current = manager.get(view.id)
    assert current.in_use
    assert current.closes_if_idle_in is None
    writer.close()
    await writer.wait_closed()
    await settle()
    clock.advance(600)
    await manager.tick()
    assert manager.list() == []


async def test_expiry_warning_then_expiry(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    settings = make_settings(tmp_path, idle_timeout=0)
    manager = build_manager(settings, backend, clock, notifier)
    try:
        view = await manager.open(http_service.port)
        sent_before = len(notifier.sent)
        clock.advance(899)
        await manager.tick()
        assert len(notifier.sent) == sent_before
        clock.advance(1)  # 15 min: 5 min before the 20 min limit
        await manager.tick()
        assert "se ferme dans <b>5 min</b>" in notifier.sent[-1].text
        await manager.tick()
        assert len(notifier.sent) == sent_before + 1  # warned once
        clock.advance(299)
        await manager.tick()
        assert manager.get(view.id)
        clock.advance(1)
        await manager.tick()
        assert manager.list() == []
        assert "durée de vie maximale atteinte" in notifier.sent[-1].text
    finally:
        await manager.aclose()


async def test_extension_pushes_back_the_expiry(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    settings = make_settings(tmp_path, idle_timeout=0)
    manager = build_manager(settings, backend, clock, notifier)
    try:
        view = await manager.open(http_service.port)
        clock.advance(950)
        await manager.tick()  # warning sent
        extended = await manager.extend(view.id)
        assert extended.extensions == 1
        assert extended.expires_in == 250 + 1_200
        assert extended.idle_for == 0
        warnings = sum("se ferme dans" in text for text in notifier.texts())
        clock.advance(250 + 1_200 - 300)
        await manager.tick()
        assert sum("se ferme dans" in text for text in notifier.texts()) == warnings + 1
    finally:
        await manager.aclose()


async def test_extension_unavailable_without_lifetime(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    settings = make_settings(tmp_path, max_lifetime=0)
    manager = build_manager(settings, backend, clock, notifier)
    try:
        view = await manager.open(http_service.port)
        assert view.expires_at is None
        with pytest.raises(TunnelError, match="no maximum lifetime"):
            manager.check_extend(view.id)
    finally:
        await manager.aclose()


# --- refusals ---------------------------------------------------------------------------------------
async def test_refuses_to_expose_itself(manager: TunnelManager, settings: Settings) -> None:
    with pytest.raises(TunnelError, match="MCP server itself"):
        await manager.open(settings.port)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"denied_ports": "1-65535"}, "not allowed"),
        ({"allowed_ports": "1-1023"}, "not allowed"),
        ({"allow_unprotected_http": False}, "Unprotected HTTP"),
    ],
)
async def test_port_and_protection_policy(
    tmp_path: Path,
    backend: FakeBackend,
    clock: FakeClock,
    notifier: FakeNotifier,
    http_service: LocalService,
    overrides: dict[str, Any],
    message: str,
) -> None:
    manager = build_manager(make_settings(tmp_path, **overrides), backend, clock, notifier)
    try:
        with pytest.raises(TunnelError, match=message):
            await manager.check_open(http_service.port, "http", False)
        assert backend.specs == []
    finally:
        await manager.aclose()


async def test_duplicate_and_limit(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    manager = build_manager(make_settings(tmp_path, max_tunnels=1), backend, clock, notifier)
    try:
        view = await manager.open(http_service.port)
        with pytest.raises(TunnelError, match=f"{view.id} already exposes"):
            await manager.check_open(http_service.port, "http", None)
        with pytest.raises(TunnelError, match="maximum of 1"):
            await manager.check_open(http_service.port, "tcp", None)
    finally:
        await manager.aclose()


async def test_nothing_listening(manager: TunnelManager) -> None:
    with pytest.raises(TunnelError, match="Nothing is listening"):
        await manager.check_open(unused_port(), "http", None)


async def test_tcp_cannot_be_password_protected(manager: TunnelManager, echo_service: LocalService) -> None:
    with pytest.raises(TunnelError, match="only available for HTTP"):
        await manager.check_open(echo_service.port, "tcp", True)


async def test_ngrok_not_configured(
    settings: Settings, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    manager = build_manager(settings, None, clock, notifier)
    with pytest.raises(TunnelError, match="NGROK_AUTHTOKEN"):
        await manager.check_open(http_service.port, "http", None)
    await manager.aclose()


async def test_backend_failure_is_reported(
    manager: TunnelManager, backend: FakeBackend, http_service: LocalService
) -> None:
    backend.fail_with = "failed to start listener — ERR_NGROK_8013"
    with pytest.raises(TunnelError, match=r"ngrok refused to open the tunnel: .*ERR_NGROK_8013"):
        await manager.open(http_service.port)
    assert manager.list() == []


async def test_unverifiable_tunnel_is_closed(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    manager = build_manager(make_settings(tmp_path, verify_timeout=1), backend, clock, notifier)
    backend.unreachable = True
    try:
        with pytest.raises(TunnelError, match="could not be verified"):
            await manager.open(http_service.port)
        assert manager.list() == []
        assert backend.open_endpoints == []
    finally:
        await manager.aclose()


async def test_verification_can_be_disabled(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    manager = build_manager(make_settings(tmp_path, verify_tunnels=False), backend, clock, notifier)
    backend.unreachable = True
    try:
        view = await manager.open(http_service.port)
        assert view.verification is None
        reverified = await manager.reverify(view.id)
        assert reverified.verification is not None
    finally:
        await manager.aclose()


# --- closing ----------------------------------------------------------------------------------------
async def test_close_and_resolve(
    manager: TunnelManager, backend: FakeBackend, http_service: LocalService, echo_service: LocalService
) -> None:
    with pytest.raises(TunnelNotFoundError):
        manager.resolve(None)
    first = await manager.open(http_service.port)
    assert manager.resolve(None) == first.id
    second = await manager.open(echo_service.port, "tcp")
    with pytest.raises(TunnelError, match="Several tunnels"):
        manager.resolve(None)
    with pytest.raises(TunnelNotFoundError, match="nope"):
        manager.resolve("nope")
    closed = await manager.close(first.id)
    assert closed.closed_reason == "manual"
    assert manager.resolve(None) == second.id
    assert [view.id for view in await manager.close_all()] == [second.id]
    assert backend.open_endpoints == []


async def test_shutdown_closes_and_notifies(
    settings: Settings,
    backend: FakeBackend,
    clock: FakeClock,
    notifier: FakeNotifier,
    http_service: LocalService,
) -> None:
    manager = build_manager(settings, backend, clock, notifier)
    await manager.start()
    await manager.open(http_service.port)
    await manager.aclose()
    assert "arrêt du service" in notifier.sent[-1].text
    assert backend.closed
    assert manager.list() == []


async def test_reaper_runs_in_background(
    tmp_path: Path, backend: FakeBackend, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    manager = build_manager(make_settings(tmp_path, reaper_interval=0.05), backend, clock, notifier)
    await manager.start()
    try:
        await manager.open(http_service.port)
        clock.advance(601)
        for _ in range(50):
            if not manager.list():
                break
            await asyncio.sleep(0.02)
        assert manager.list() == []
    finally:
        await manager.aclose()
