"""NgrokBackend against a stand-in for the native ngrok SDK (same builder API, no network)."""

from __future__ import annotations

import json
import logging
import sys
import types
from collections.abc import Callable
from typing import Any

import pytest

from hermes_ngrok_mcp.tunnels.backends import (
    BackendError,
    EndpointSpec,
    NgrokBackend,
    basic_auth_policy,
    describe_ngrok_error,
)

pytestmark = pytest.mark.anyio

TOKEN = "2abcSECRETTOKEN"


class FakeListener:
    def __init__(self, url: str) -> None:
        self._url = url
        self.closed = False

    def url(self) -> str:
        return self._url

    async def close(self) -> None:
        self.closed = True


class FakeEndpointBuilder:
    def __init__(self, sdk: FakeSdk, kind: str) -> None:
        self.sdk = sdk
        self.kind = kind
        self.options: dict[str, str] = {}
        self.forward_to: str | None = None

    def _set(self, key: str, value: str) -> FakeEndpointBuilder:
        self.options[key] = value
        return self

    def domain(self, value: str) -> FakeEndpointBuilder:
        return self._set("domain", value)

    def traffic_policy(self, value: str) -> FakeEndpointBuilder:
        return self._set("traffic_policy", value)

    def metadata(self, value: str) -> FakeEndpointBuilder:
        return self._set("metadata", value)

    def forwards_to(self, value: str) -> FakeEndpointBuilder:
        return self._set("forwards_to", value)

    async def listen_and_forward(self, url: str) -> FakeListener:
        self.forward_to = url
        if self.sdk.listen_error:
            raise ValueError("failed to start listener", self.sdk.listen_error)
        listener = FakeListener(
            "https://abc.ngrok-free.app" if self.kind == "http" else "tcp://0.tcp.eu.ngrok.io:12345"
        )
        self.sdk.listeners.append(listener)
        return listener


class FakeSession:
    def __init__(self, sdk: FakeSdk) -> None:
        self.sdk = sdk
        self.closed = False

    def http_endpoint(self) -> FakeEndpointBuilder:
        builder = FakeEndpointBuilder(self.sdk, "http")
        self.sdk.builders.append(builder)
        return builder

    def tcp_endpoint(self) -> FakeEndpointBuilder:
        builder = FakeEndpointBuilder(self.sdk, "tcp")
        self.sdk.builders.append(builder)
        return builder

    async def close(self) -> None:
        self.closed = True


class FakeSdk:
    def __init__(self) -> None:
        self.sessions: list[FakeSession] = []
        self.builders: list[FakeEndpointBuilder] = []
        self.listeners: list[FakeListener] = []
        self.connect_error: str | None = None
        self.listen_error: str | None = None
        self.disconnection_handler: Callable[[str, str], None] | None = None
        sdk = self

        class SessionBuilder:
            def authtoken(self, token: str) -> SessionBuilder:
                self.token = token
                return self

            def client_info(self, client_type: str, version: str) -> SessionBuilder:
                return self

            def metadata(self, value: str) -> SessionBuilder:
                return self

            def handle_disconnection(self, handler: Callable[[str, str], None]) -> SessionBuilder:
                sdk.disconnection_handler = handler
                return self

            async def connect(self) -> FakeSession:
                if sdk.connect_error:
                    raise ValueError("failed to connect session", sdk.connect_error.format(token=self.token))
                session = FakeSession(sdk)
                sdk.sessions.append(session)
                return session

        self.module: Any = types.SimpleNamespace(SessionBuilder=SessionBuilder)


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> FakeSdk:
    fake = FakeSdk()
    monkeypatch.setitem(sys.modules, "ngrok", fake.module)
    return fake


async def test_session_is_shared_and_closed_with_the_last_endpoint(sdk: FakeSdk) -> None:
    backend = NgrokBackend(TOKEN)
    policy = basic_auth_policy("hermes", "s3cret-password")
    http = await backend.open(
        EndpointSpec("http", "127.0.0.1:4000", traffic_policy=policy, domain="me.ngrok.app", metadata="m")
    )
    tcp = await backend.open(EndpointSpec("tcp", "127.0.0.1:4001", domain="ignored.example", description="d"))

    assert http.url == "https://abc.ngrok-free.app"
    assert tcp.url == "tcp://0.tcp.eu.ngrok.io:12345"
    assert len(sdk.sessions) == 1
    http_builder, tcp_builder = sdk.builders
    assert http_builder.forward_to == "http://127.0.0.1:4000"
    assert http_builder.options == {"domain": "me.ngrok.app", "traffic_policy": policy, "metadata": "m"}
    assert tcp_builder.forward_to == "tcp://127.0.0.1:4001"
    assert tcp_builder.options == {"forwards_to": "d"}

    await http.close()
    await http.close()  # idempotent
    assert not sdk.sessions[0].closed
    await tcp.close()
    assert sdk.sessions[0].closed
    assert all(listener.closed for listener in sdk.listeners)

    # A new tunnel later opens a fresh session.
    again = await backend.open(EndpointSpec("http", "127.0.0.1:4002"))
    assert len(sdk.sessions) == 2
    await backend.aclose()
    assert sdk.sessions[1].closed
    await again.close()


async def test_connection_errors_are_explained_and_redacted(sdk: FakeSdk) -> None:
    sdk.connect_error = "authentication failed: token {token} rejected ERR_NGROK_105"
    with pytest.raises(BackendError) as info:
        await NgrokBackend(TOKEN).open(EndpointSpec("http", "127.0.0.1:1"))
    message = str(info.value)
    assert TOKEN not in message
    assert "<redacted>" in message
    assert "check NGROK_AUTHTOKEN" in message
    assert "https://ngrok.com/docs/errors/err_ngrok_105" in message


async def test_listener_errors_close_the_idle_session(sdk: FakeSdk) -> None:
    sdk.listen_error = "ERR_NGROK_8013: TCP requires a card"
    with pytest.raises(BackendError, match="payment method"):
        await NgrokBackend(TOKEN).open(EndpointSpec("tcp", "127.0.0.1:1"))
    assert sdk.sessions[0].closed


def test_disconnection_is_logged(sdk: FakeSdk, caplog: pytest.LogCaptureFixture) -> None:
    backend = NgrokBackend(TOKEN)
    with caplog.at_level(logging.WARNING):
        backend._on_disconnection("connect.ngrok-agent.com:443", "reset by peer")
    assert "reconnecting" in caplog.text


def test_describe_ngrok_error() -> None:
    assert describe_ngrok_error(ValueError("boom")) == "boom"
    assert describe_ngrok_error(RuntimeError()) == "RuntimeError"
    unknown = describe_ngrok_error(ValueError("failed", "ERR_NGROK_9999"))
    assert unknown == "failed — ERR_NGROK_9999 (see https://ngrok.com/docs/errors/err_ngrok_9999)"


def test_basic_auth_policy_shape() -> None:
    policy = json.loads(basic_auth_policy("u", "password1", realm="R"))
    action = policy["on_http_request"][0]["actions"][0]
    assert action == {
        "type": "basic-auth",
        "config": {"realm": "R", "credentials": ["u:password1"], "enforce": True},
    }
