"""End-to-end check of the streamable HTTP transport, as Hermes uses it."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from hermes_ngrok_mcp.asgi import BearerTokenMiddleware, build_http_app
from hermes_ngrok_mcp.config import Settings
from hermes_ngrok_mcp.server import build_server
from hermes_ngrok_mcp.services import open_services
from tests.conftest import FakeBackend, FakeClock, FakeNotifier

pytestmark = pytest.mark.anyio


@pytest.fixture
async def base_url(
    settings: Settings, clock: FakeClock, notifier: FakeNotifier, backend: FakeBackend
) -> AsyncIterator[str]:
    async with open_services(
        settings, clock=clock, notifier=notifier, backend_factory=lambda _: backend
    ) as svc:
        app = build_http_app(build_server(svc), settings)
        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=settings.port, log_config=None, lifespan="on")
        )
        task = asyncio.create_task(server.serve())
        for _ in range(500):
            if server.started:
                break
            await asyncio.sleep(0.01)
        try:
            yield f"http://127.0.0.1:{settings.port}"
        finally:
            server.should_exit = True
            await task


async def test_health_check_needs_no_token(base_url: str) -> None:
    async with httpx2.AsyncClient() as client:
        response = await client.get(f"{base_url}/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong-token-wrong-token-wrong-token"},
        {"Authorization": f"Basic {'x' * 40}"},
        {"Authorization": "Bearer"},
    ],
)
async def test_mcp_endpoint_requires_the_token(base_url: str, headers: dict[str, str]) -> None:
    async with httpx2.AsyncClient() as client:
        response = await client.post(
            f"{base_url}/mcp",
            headers=headers | {"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


async def test_hermes_style_client_with_bearer_token(base_url: str, settings: Settings) -> None:
    assert settings.api_token is not None
    headers = {"Authorization": f"Bearer {settings.api_token.get_secret_value()}"}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=10) as http,
        Client(streamable_http_client(f"{base_url}/mcp", http_client=http)) as client,
    ):
        tools = await client.list_tools()
        assert "tunnel_open" in {tool.name for tool in tools.tools}
        status = await client.call_tool("mfa_status", {})
        assert not status.is_error
        assert status.structured_content is not None
        assert status.structured_content["configured"] is False


async def test_http_app_refuses_to_run_without_token(settings: Settings) -> None:
    unprotected = settings.model_copy(update={"api_token": None})
    async with open_services(unprotected, backend_factory=lambda _: None) as svc:
        with pytest.raises(ValueError, match="HERMES_NGROK_API_TOKEN"):
            build_http_app(build_server(svc), unprotected)
        assert build_http_app(build_server(svc), unprotected, require_token=False) is not None


def test_short_tokens_are_rejected() -> None:
    async def app(scope: object, receive: object, send: object) -> None:
        raise AssertionError

    with pytest.raises(ValueError, match="32 characters"):
        BearerTokenMiddleware(app, "short")  # type: ignore[arg-type]
