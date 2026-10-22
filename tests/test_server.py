from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp_types import CallToolResult

from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.server import build_server
from hermes_ngrok_mcp.services import Services, open_services
from tests.conftest import (
    FakeBackend,
    FakeClock,
    FakeNotifier,
    LocalService,
    make_settings,
    totp_code,
    unused_port,
)

pytestmark = pytest.mark.anyio


EXPECTED_TOOLS = {
    "mfa_status",
    "mfa_setup_start",
    "mfa_setup_confirm",
    "tunnel_open",
    "tunnel_status",
    "tunnel_extend",
    "tunnel_close",
}


@pytest.fixture
async def services(
    settings: Settings, clock: FakeClock, notifier: FakeNotifier, backend: FakeBackend
) -> AsyncIterator[Services]:
    async with open_services(
        settings, clock=clock, notifier=notifier, backend_factory=lambda _: backend
    ) as svc:
        yield svc


@pytest.fixture
async def client(services: Services) -> AsyncIterator[Client]:
    async with Client(build_server(services)) as mcp_client:
        yield mcp_client


async def call(client: Client, name: str, **arguments: Any) -> CallToolResult:
    return await client.call_tool(name, arguments)


def text_of(result: CallToolResult) -> str:
    return "\n".join(getattr(block, "text", "") for block in result.content)


def configure_mfa(services: Services, clock: FakeClock) -> str:
    enrollment = services.mfa.begin_enrollment()
    services.mfa.confirm_enrollment(totp_code(enrollment.secret, clock))
    clock.advance(30)
    return enrollment.secret


def wrong_code(secret: str, clock: FakeClock) -> str:
    return "000000" if totp_code(secret, clock) != "000000" else "111111"


async def test_tools_are_described_for_the_agent(client: Client) -> None:
    tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert set(tools) == EXPECTED_TOOLS
    open_schema = tools["tunnel_open"].input_schema
    assert set(open_schema["required"]) == {"port", "mfa_code"}
    assert "never invent" in open_schema["properties"]["mfa_code"]["description"]
    assert tools["mfa_status"].annotations is not None
    assert tools["mfa_status"].annotations.read_only_hint
    assert tools["tunnel_close"].annotations is not None
    assert tools["tunnel_close"].annotations.destructive_hint
    for tool in tools.values():
        assert tool.description, tool.name


async def test_enrollment_through_telegram_keeps_the_secret_away_from_the_agent(
    client: Client, notifier: FakeNotifier, clock: FakeClock
) -> None:
    status = await call(client, "mfa_status")
    assert status.structured_content is not None
    assert status.structured_content["configured"] is False
    assert status.structured_content["secrets_delivered_via"] == "telegram"

    started = await call(client, "mfa_setup_start")
    assert not started.is_error
    payload = json.loads(text_of(started))
    assert payload["delivered_via"] == "telegram"
    photo = notifier.sent[-1]
    assert photo.kind == "photo"
    assert photo.protect
    assert photo.image is not None
    assert photo.image.startswith(b"\x89PNG")
    match = re.search(r"<code>([A-Z2-7]{32})</code>", photo.text)
    assert match
    secret = match.group(1)
    assert secret not in text_of(started)
    assert "Proton Authenticator" in photo.text

    confirmed = await call(client, "mfa_setup_confirm", mfa_code=totp_code(secret, clock))
    assert not confirmed.is_error
    assert confirmed.structured_content is not None
    assert confirmed.structured_content["configured"] is True
    assert notifier.deleted == [photo.message_id]
    assert "Le MFA est activé" in notifier.sent[-1].text


async def test_restarting_enrollment_deletes_the_previous_qr_code(
    client: Client, notifier: FakeNotifier
) -> None:
    await call(client, "mfa_setup_start")
    first = notifier.sent[-1].message_id
    await call(client, "mfa_setup_start")
    assert notifier.deleted == [first]


async def test_inline_enrollment_without_telegram(
    tmp_path: Path, clock: FakeClock, backend: FakeBackend
) -> None:
    settings = make_settings(tmp_path, telegram_bot_token=None, telegram_chat_id=None)
    async with (
        open_services(settings, clock=clock, backend_factory=lambda _: backend) as services,
        Client(build_server(services)) as client,
    ):
        started = await call(client, "mfa_setup_start")
        assert [block.type for block in started.content] == ["text", "image"]
        payload = json.loads(text_of(started))
        assert payload["delivered_via"] == "this_result"
        assert payload["otpauth_uri"].startswith("otpauth://totp/")
        confirmed = await call(client, "mfa_setup_confirm", mfa_code=totp_code(payload["secret"], clock))
        assert not confirmed.is_error


async def test_inline_enrollment_can_be_forbidden(
    tmp_path: Path, clock: FakeClock, backend: FakeBackend
) -> None:
    settings = make_settings(
        tmp_path, telegram_bot_token=None, telegram_chat_id=None, mfa_allow_inline_enrollment=False
    )
    async with (
        open_services(settings, clock=clock, backend_factory=lambda _: backend) as services,
        Client(build_server(services)) as client,
    ):
        started = await call(client, "mfa_setup_start")
        assert started.is_error
        assert "hermes-ngrok-admin mfa setup" in text_of(started)
        assert not services.mfa.status().enrollment_pending


async def test_enrollment_fails_closed_when_telegram_fails(
    client: Client, services: Services, notifier: FakeNotifier
) -> None:
    notifier.fail = True
    started = await call(client, "mfa_setup_start")
    assert started.is_error
    assert "could not be delivered on Telegram" in text_of(started)
    assert all(block.type == "text" for block in started.content)
    assert not services.mfa.status().enrollment_pending


async def test_rotation_requires_the_current_code(
    client: Client, services: Services, clock: FakeClock
) -> None:
    secret = configure_mfa(services, clock)
    refused = await call(client, "mfa_setup_start")
    assert refused.is_error
    assert "already configured" in text_of(refused)
    accepted = await call(client, "mfa_setup_start", current_mfa_code=totp_code(secret, clock))
    assert not accepted.is_error
    assert json.loads(text_of(accepted))["rotation"] is True


async def test_full_tunnel_flow(
    client: Client, services: Services, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    secret = configure_mfa(services, clock)

    refused = await call(client, "tunnel_open", port=http_service.port, mfa_code=wrong_code(secret, clock))
    assert refused.is_error
    assert "Invalid MFA code" in text_of(refused)

    code = totp_code(secret, clock)
    opened = await call(client, "tunnel_open", port=http_service.port, mfa_code=code, label="app")
    assert not opened.is_error, text_of(opened)
    assert opened.structured_content is not None
    tunnel = opened.structured_content["tunnel"]
    assert tunnel["public_url"].startswith("http://127.0.0.1:")
    assert tunnel["access"] == {"username": "hermes", "password": None, "password_delivery": "telegram"}
    assert tunnel["verification"]["ok"] is True
    assert tunnel["expires_in_seconds"] == 1_200
    assert tunnel["opened_at"].endswith("+00:00")
    assert "sent to the user directly on Telegram" in opened.structured_content["message"]
    assert "Tunnel ouvert" in notifier.sent[-1].text

    reused = await call(client, "tunnel_extend", mfa_code=code)
    assert reused.is_error
    assert "already used" in text_of(reused)

    clock.advance(600 - 1)
    extended = await call(client, "tunnel_extend", mfa_code=totp_code(secret, clock))
    assert not extended.is_error, text_of(extended)
    assert extended.structured_content is not None
    assert extended.structured_content["tunnel"]["expires_in_seconds"] == 1_200 - 599 + 1_200

    status = await call(client, "tunnel_status")
    assert status.structured_content is not None
    assert len(status.structured_content["tunnels"]) == 1
    assert status.structured_content["policy"]["idle_timeout_seconds"] == 600
    assert status.structured_content["mfa_configured"] is True

    verified = await call(client, "tunnel_status", verify=True)
    assert verified.structured_content is not None
    assert verified.structured_content["tunnels"][0]["verification"]["ok"] is True

    closed = await call(client, "tunnel_close")
    assert closed.structured_content is not None
    assert closed.structured_content["closed"][0]["local_port"] == http_service.port
    nothing = await call(client, "tunnel_close", close_all=True)
    assert nothing.structured_content is not None
    assert nothing.structured_content["message"] == "No tunnel was open."


async def test_invalid_requests_do_not_consume_the_code(
    client: Client, services: Services, clock: FakeClock, http_service: LocalService
) -> None:
    secret = configure_mfa(services, clock)
    code = totp_code(secret, clock)
    refused = await call(client, "tunnel_open", port=unused_port(), mfa_code=code)
    assert refused.is_error
    assert "Nothing is listening" in text_of(refused)
    opened = await call(client, "tunnel_open", port=http_service.port, mfa_code=code)
    assert not opened.is_error, text_of(opened)


async def test_tunnel_requires_configured_mfa(client: Client, http_service: LocalService) -> None:
    refused = await call(client, "tunnel_open", port=http_service.port, mfa_code="123456")
    assert refused.is_error
    assert "MFA is not configured" in text_of(refused)


async def test_lockout_alerts_the_user(
    client: Client, services: Services, clock: FakeClock, notifier: FakeNotifier, http_service: LocalService
) -> None:
    secret = configure_mfa(services, clock)
    results = [
        await call(client, "tunnel_open", port=http_service.port, mfa_code=wrong_code(secret, clock))
        for _ in range(services.settings.mfa_max_failures)
    ]
    assert all(result.is_error for result in results)
    assert "locked" in text_of(results[-1])
    assert "Alerte sécurité" in notifier.sent[-1].text
    locked = await call(client, "mfa_status")
    assert locked.structured_content is not None
    assert locked.structured_content["locked"] is True


async def test_malformed_arguments_are_rejected(client: Client) -> None:
    result = await call(client, "tunnel_open", port=70_000, mfa_code="123456")
    assert result.is_error
    result = await call(client, "tunnel_open", port=8080, mfa_code="12")
    assert result.is_error
