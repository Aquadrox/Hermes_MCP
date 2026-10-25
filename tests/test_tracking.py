"""Audit trail and NAS tunnels, end to end through the tunnel manager and the MCP tools."""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx2
import pytest
import uvicorn
from mcp import Client

from hermes_ngrok_mcp.audit import AuditLog
from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.nas.app import create_app
from hermes_ngrok_mcp.nas.config import NasSettings
from hermes_ngrok_mcp.server import build_server
from hermes_ngrok_mcp.services import Services, open_services
from hermes_ngrok_mcp.tunnels.manager import TunnelError
from tests.conftest import (
    CLIENT_IP,
    FakeBackend,
    FakeClock,
    FakeNotifier,
    LocalService,
    make_settings,
    totp_code,
    unused_port,
)
from tests.test_server import call, configure_mfa, text_of, wrong_code

pytestmark = pytest.mark.anyio

NAS_KEY = "k" * 40


def events(services: Services, name: str | None = None) -> list[dict[str, Any]]:
    return [e for e in services.audit.query(limit=0) if name is None or e["event"] == name]


async def settle() -> None:
    for _ in range(30):
        await asyncio.sleep(0.01)


@contextlib.asynccontextmanager
async def running(
    settings: Settings, clock: FakeClock, backend: FakeBackend, notifier: FakeNotifier | None = None
) -> AsyncIterator[tuple[Services, Client]]:
    async with (
        open_services(
            settings, clock=clock, notifier=notifier or FakeNotifier(), backend_factory=lambda _: backend
        ) as svc,
        Client(build_server(svc)) as client,
    ):
        yield svc, client


# --- the real hermes-nas application, served locally ---------------------------------------------------
@dataclass
class RunningNas:
    port: int
    root: Path
    audit: AuditLog


@pytest.fixture
async def real_nas(tmp_path: Path) -> AsyncIterator[RunningNas]:
    root = tmp_path / "MonNAS"
    root.mkdir()
    (root / "hello.txt").write_text("hello from the NAS")
    nas_settings = NasSettings(root=root, access_key=NAS_KEY, state_dir=tmp_path / "nas-state")
    audit = AuditLog(nas_settings.audit_file, clock=FakeClock(), tz=ZoneInfo("UTC"), origin="nas")
    port = unused_port()
    config = uvicorn.Config(
        create_app(nas_settings, audit=audit), host="127.0.0.1", port=port, log_config=None, access_log=False
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    yield RunningNas(port, root, audit)
    server.should_exit = True
    await task


# --- audit trail --------------------------------------------------------------------------------------
async def test_tunnel_lifecycle_is_audited_with_client_addresses(
    tmp_path: Path, clock: FakeClock, backend: FakeBackend, http_service: LocalService
) -> None:
    settings = make_settings(tmp_path, share_credentials_with_agent=True, proxy_protocol=True)
    async with running(settings, clock, backend) as (services, client):
        secret = configure_mfa(services, clock)
        opened = await call(client, "tunnel_open", port=http_service.port, mfa_code=totp_code(secret, clock))
        assert not opened.is_error, text_of(opened)
        assert backend.specs[-1].proxy_protocol
        tunnel = opened.structured_content["tunnel"]  # type: ignore[index]
        auth = httpx2.BasicAuth(tunnel["access"]["username"], tunnel["access"]["password"])
        async with httpx2.AsyncClient(auth=auth) as http:
            assert (await http.get(tunnel["public_url"])).status_code == 200
        await settle()
        status = await call(client, "tunnel_status")
        usage = status.structured_content["tunnels"][0]["usage"]  # type: ignore[index]
        assert usage["last_client_ip"] == CLIENT_IP
        assert usage["distinct_client_ips"] == 1
        await call(client, "tunnel_close")

        [opened_event] = events(services, "tunnel.opened")
        assert opened_event["local_port"] == http_service.port
        assert opened_event["basic_auth"] is True
        [connection] = events(services, "connection.closed")
        assert connection["source_ip"] == CLIENT_IP
        assert connection["bytes_out"] > 0
        [closed] = events(services, "tunnel.closed")
        assert closed["reason"] == "manual"
        assert closed["sources"] == {CLIENT_IP: 1}
        assert [e["purpose"] for e in events(services, "mfa.verified")] == ["tunnel_open"]
        assert events(services, "service.started")


async def test_tool_calls_are_audited_without_secrets(
    settings: Settings, clock: FakeClock, backend: FakeBackend, http_service: LocalService
) -> None:
    async with running(settings, clock, backend) as (services, client):
        secret = configure_mfa(services, clock)
        bad = wrong_code(secret, clock)
        refused = await call(client, "tunnel_open", port=http_service.port, mfa_code=bad)
        assert refused.is_error
        calls = events(services, "mcp.tool_call")
        assert calls[-1]["tool"] == "tunnel_open"
        assert calls[-1]["outcome"] == "error"
        assert calls[-1]["arguments"]["port"] == http_service.port
        assert calls[-1]["mfa_code_provided"] == ["mfa_code"]
        assert "duration_ms" in calls[-1]
        [rejection] = events(services, "mfa.rejected")
        assert rejection["reason"] == "invalid_code"
        assert rejection["remaining_attempts"] == 4
        assert services.settings.audit_file.exists()
        assert f'"{bad}"' not in services.settings.audit_file.read_text()


async def test_lockout_is_audited(settings: Settings, clock: FakeClock, backend: FakeBackend) -> None:
    async with running(settings, clock, backend) as (services, _):
        secret = configure_mfa(services, clock)
        for _ in range(5):
            with contextlib.suppress(Exception):
                services.mfa.verify(wrong_code(secret, clock), purpose="tunnel_open")
        [locked] = events(services, "mfa.locked")
        assert locked["duration_seconds"] == 900
        with contextlib.suppress(Exception):
            services.mfa.verify("12", purpose="tunnel_open")
        assert events(services, "mfa.rejected")[-1]["reason"] == "bad_format"


async def test_unexpected_errors_become_clean_tool_errors(
    settings: Settings, clock: FakeClock, backend: FakeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with running(settings, clock, backend) as (services, client):

        def explode() -> list[Any]:
            raise RuntimeError("boom")

        monkeypatch.setattr(services.tunnels, "list", explode)
        result = await call(client, "tunnel_status")
        assert result.is_error
        assert "Internal error in tunnel_status" in text_of(result)
        assert events(services, "mcp.tool_call")[-1]["outcome"] == "crash"


async def test_audit_log_tool(
    tmp_path: Path, clock: FakeClock, backend: FakeBackend, echo_service: LocalService
) -> None:
    settings = make_settings(tmp_path, proxy_protocol=True)
    async with running(settings, clock, backend) as (services, client):
        secret = configure_mfa(services, clock)
        await call(
            client, "tunnel_open", port=echo_service.port, protocol="tcp", mfa_code=wrong_code(secret, clock)
        )
        clock.advance(30)
        opened = await call(
            client, "tunnel_open", port=echo_service.port, protocol="tcp", mfa_code=totp_code(secret, clock)
        )
        assert not opened.is_error, text_of(opened)
        url = opened.structured_content["tunnel"]["public_url"]  # type: ignore[index]
        host, _, port = url.removeprefix("tcp://").rpartition(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        writer.write(b"ping")
        await reader.readexactly(4)
        writer.close()
        await settle()

        result = await call(client, "audit_log", since="1h")
        assert not result.is_error, text_of(result)
        out = result.structured_content
        assert out is not None
        summary = out["summary"]
        assert summary["tunnels_opened"] == 1
        assert summary["mfa_failures"] == 1
        assert summary["mfa_successes"] == 1
        assert summary["client_connections"] == 1
        assert summary["top_client_ips"] == [{"ip": CLIENT_IP, "count": 1}]
        mfa_only = await call(client, "audit_log", category="mfa", limit=1)
        assert mfa_only.structured_content is not None
        assert [e["event"] for e in mfa_only.structured_content["events"]] == ["mfa.verified"]
        assert mfa_only.structured_content["truncated"] is True
        assert (await call(client, "audit_log", since="100d")).is_error
        assert (await call(client, "audit_log", since="tomorrow")).is_error


async def test_rejected_api_requests_are_audited(
    settings: Settings, clock: FakeClock, backend: FakeBackend
) -> None:
    from hermes_ngrok_mcp.asgi import build_http_app

    async with open_services(
        settings, clock=clock, notifier=FakeNotifier(), backend_factory=lambda _: backend
    ) as svc:
        app = build_http_app(build_server(svc), settings, audit=svc.audit)
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://mcp") as http:
            response = await http.post("/mcp", headers={"Authorization": "Bearer wrong"}, json={})
        assert response.status_code == 401
        [rejected] = events(svc, "mcp.auth_rejected")
        assert rejected["had_credentials"] is True
        assert rejected["path"] == "/mcp"


# --- NAS tunnels ----------------------------------------------------------------------------------------
@pytest.fixture
def nas_settings(tmp_path: Path, real_nas: RunningNas) -> Settings:
    return make_settings(tmp_path / "mcp", nas_access_key=NAS_KEY, nas_port=real_nas.port, port=unused_port())


async def test_nas_status_when_not_installed(
    settings: Settings, clock: FakeClock, backend: FakeBackend
) -> None:
    async with running(settings, clock, backend) as (_, client):
        result = await call(client, "nas_status")
        assert result.structured_content is not None
        assert result.structured_content["enabled"] is False
        opened = await call(client, "nas_open", mfa_code="123456")
        assert opened.is_error
        assert "not installed" in text_of(opened)


async def test_nas_tunnel_end_to_end_on_the_free_plan(
    nas_settings: Settings, clock: FakeClock, backend: FakeBackend, real_nas: RunningNas
) -> None:
    notifier = FakeNotifier()
    async with running(nas_settings, clock, backend, notifier) as (services, client):
        status = await call(client, "nas_status")
        assert status.structured_content is not None
        assert status.structured_content["reachable"] is True
        assert status.structured_content["root"] == str(real_nas.root)

        secret = configure_mfa(services, clock)
        opened = await call(client, "nas_open", mfa_code=totp_code(secret, clock))
        assert not opened.is_error, text_of(opened)
        tunnel = opened.structured_content["tunnel"]  # type: ignore[index]
        assert tunnel["kind"] == "nas"
        assert tunnel["label"] == "NAS"
        assert tunnel["access"]["password_delivery"] == "telegram"
        # No Traffic Policy at all: nothing that the free ngrok plan would refuse.
        assert backend.specs[-1].traffic_policy is None
        assert not backend.specs[-1].proxy_protocol
        assert NAS_KEY not in text_of(opened)

        # The password only went to the user (Telegram); the NAS enforces it itself.
        card = notifier.texts()[-1]
        password = re.search(r"<code>([A-Za-z0-9_-]{20,})</code>", card)
        assert password, card
        url = tunnel["public_url"]
        async with httpx2.AsyncClient(base_url=url) as http:
            assert (await http.get("/api/list")).status_code == 401
            assert (await http.get("/api/list", auth=("hermes", "guess-guess-guess"))).status_code == 401
            listing = await http.get("/api/list", auth=("hermes", password.group(1)))
            assert listing.status_code == 200
            assert [e["name"] for e in listing.json()["entries"]] == ["hello.txt"]

        again = await call(client, "nas_open", mfa_code=totp_code(secret, clock, 1))
        assert again.is_error
        assert "already exposes" in text_of(again)

        closed = await call(client, "tunnel_close", tunnel_id=tunnel["tunnel_id"])
        assert not closed.is_error
        # Revoked on close: the same password no longer opens anything, even locally.
        async with httpx2.AsyncClient(base_url=f"http://127.0.0.1:{real_nas.port}") as http:
            refused = await http.get("/api/list", auth=("hermes", password.group(1)))
            assert refused.status_code == 403
    nas_events = [e["event"] for e in real_nas.audit.query(limit=0)]
    assert "nas.credentials_granted" in nas_events
    assert "nas.auth_failed" in nas_events
    assert nas_events[-2:] == ["nas.credentials_revoked", "nas.access_denied"]


async def test_nas_port_is_reserved_for_nas_open(
    nas_settings: Settings, clock: FakeClock, backend: FakeBackend
) -> None:
    async with running(nas_settings, clock, backend) as (services, client):
        secret = configure_mfa(services, clock)
        result = await call(
            client, "tunnel_open", port=nas_settings.nas_port, mfa_code=totp_code(secret, clock)
        )
        assert result.is_error
        assert "nas_open" in text_of(result)
        with pytest.raises(TunnelError, match="password-protected"):
            await services.tunnels.check_open(nas_settings.nas_port, "http", False, kind="nas")


async def test_nas_tunnel_needs_a_nas(settings: Settings, clock: FakeClock, backend: FakeBackend) -> None:
    async with running(settings, clock, backend) as (services, _):
        with pytest.raises(TunnelError):
            await services.tunnels.open(settings.nas_port, "http", kind="nas")


async def test_credentials_refused_by_the_nas_expose_nothing(
    nas_settings: Settings, clock: FakeClock, backend: FakeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hermes_ngrok_mcp.nas.client import NasAdminError, NasCredentials

    async def refuse(self: NasCredentials, username: str, password: str) -> None:
        raise NasAdminError("the NAS answered HTTP 500")

    monkeypatch.setattr(NasCredentials, "grant", refuse)
    async with running(nas_settings, clock, backend) as (services, client):
        secret = configure_mfa(services, clock)
        result = await call(client, "nas_open", mfa_code=totp_code(secret, clock))
        assert result.is_error
        assert "nothing was exposed" in text_of(result)
        assert backend.specs == []
        assert events(services, "tunnel.open_failed")[-1]["kind"] == "nas"


async def test_unreachable_nas_consumes_no_code(
    tmp_path: Path, clock: FakeClock, backend: FakeBackend
) -> None:
    settings = make_settings(tmp_path, nas_access_key=NAS_KEY, nas_port=unused_port())
    async with running(settings, clock, backend) as (services, client):
        secret = configure_mfa(services, clock)
        code = totp_code(secret, clock)
        result = await call(client, "nas_open", mfa_code=code)
        assert result.is_error
        assert "no MFA code was used" in text_of(result)
        assert not events(services, "mfa.verified")
        # The stale-credential cleanup at startup could not reach the NAS: recorded, not fatal.
        assert events(services, "nas.revoke_failed")[0]["reason"] == "startup"


async def test_wrong_nas_key_is_reported(
    tmp_path: Path, clock: FakeClock, backend: FakeBackend, real_nas: RunningNas
) -> None:
    settings = make_settings(tmp_path / "mcp", nas_access_key="z" * 40, nas_port=real_nas.port)
    async with running(settings, clock, backend) as (_, client):
        result = await call(client, "nas_status")
        assert result.structured_content is not None
        assert result.structured_content["reachable"] is False
        assert "access key" in result.structured_content["detail"]


def test_nas_settings_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least 32"):
        make_settings(tmp_path, nas_access_key="short")
    with pytest.raises(ValueError, match="must differ"):
        make_settings(tmp_path, port=8766, nas_port=8766)
    assert not make_settings(tmp_path, nas_access_key="  ").nas_enabled
