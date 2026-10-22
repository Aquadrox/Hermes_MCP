from __future__ import annotations

import json
import logging
from zoneinfo import ZoneInfo

import httpx2
import pytest

from hermes_ngrok_mcp.messages import Messages, TunnelFacts
from hermes_ngrok_mcp.notify import NullNotifier, TelegramNotifier

pytestmark = pytest.mark.anyio

TOKEN = "123456:SECRET-BOT-TOKEN"


def make_notifier(handler: httpx2.MockTransport, attempts: int = 3) -> TelegramNotifier:
    client = httpx2.AsyncClient(transport=handler)
    return TelegramNotifier(
        TOKEN, "42", api_base="https://telegram.test", client=client, attempts=attempts, backoff=0
    )


async def test_send_text_photo_and_delete() -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        result: object = True if request.url.path.endswith("deleteMessage") else {"message_id": 7}
        return httpx2.Response(200, json={"ok": True, "result": result})

    notifier = make_notifier(httpx2.MockTransport(handler))
    assert notifier.enabled
    assert await notifier.send_text("<b>hi</b>", protect=True) == 7
    assert await notifier.send_photo(b"\x89PNG...", "caption") == 7
    assert await notifier.delete(7) is True
    await notifier.aclose()

    text_request, photo_request, delete_request = requests
    assert text_request.url.path == f"/bot{TOKEN}/sendMessage"
    body = json.loads(text_request.content)
    assert body["chat_id"] == "42"
    assert body["parse_mode"] == "HTML"
    assert body["protect_content"] is True
    assert photo_request.url.path.endswith("/sendPhoto")
    assert b'name="photo"; filename="qr.png"' in photo_request.content
    assert b"caption" in photo_request.content
    assert json.loads(delete_request.content) == {"chat_id": "42", "message_id": 7}


async def test_failures_are_swallowed_and_token_redacted(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(f"cannot reach {request.url}")

    notifier = make_notifier(httpx2.MockTransport(handler), attempts=1)
    with caplog.at_level(logging.WARNING):
        assert await notifier.send_text("hello") is None
    assert "SECRET-BOT-TOKEN" not in caplog.text
    assert "<redacted>" in caplog.text


async def test_api_errors_are_reported(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"ok": False, "description": "Bad Request: chat not found"})

    notifier = make_notifier(httpx2.MockTransport(handler))
    with caplog.at_level(logging.WARNING):
        assert await notifier.send_text("hello") is None
        assert await notifier.delete(1) is False
    assert "chat not found" in caplog.text


async def test_rate_limits_and_server_errors_are_retried() -> None:
    responses = [
        httpx2.Response(
            429, json={"ok": False, "description": "Too Many Requests", "parameters": {"retry_after": 0}}
        ),
        httpx2.Response(502, json={"ok": False, "description": "Bad Gateway"}),
        httpx2.Response(200, json={"ok": True, "result": {"message_id": 9}}),
    ]
    notifier = make_notifier(httpx2.MockTransport(lambda request: responses.pop(0)))
    assert await notifier.send_text("hello") == 9
    assert responses == []


async def test_long_rate_limits_are_not_waited_for() -> None:
    calls: list[int] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(1)
        return httpx2.Response(429, json={"ok": False, "parameters": {"retry_after": 3600}})

    assert await make_notifier(httpx2.MockTransport(handler)).send_text("hello") is None
    assert len(calls) == 1


async def test_client_errors_are_not_retried_and_network_errors_give_up() -> None:
    calls: list[str] = []

    def bad_request(request: httpx2.Request) -> httpx2.Response:
        calls.append("400")
        return httpx2.Response(400, json={"ok": False, "description": "Bad Request"})

    assert await make_notifier(httpx2.MockTransport(bad_request)).send_text("x") is None
    assert calls == ["400"]

    def offline(request: httpx2.Request) -> httpx2.Response:
        calls.append("offline")
        raise httpx2.ConnectError("offline")

    assert await make_notifier(httpx2.MockTransport(offline), attempts=2).send_text("x") is None
    assert calls == ["400", "offline", "offline"]


async def test_null_notifier() -> None:
    notifier = NullNotifier()
    assert not notifier.enabled
    assert await notifier.send_text("x") is None
    assert await notifier.send_photo(b"", "x") is None
    assert await notifier.delete(1) is False
    await notifier.aclose()


@pytest.mark.parametrize("language", ["fr", "en"])
def test_messages_escape_html_and_cover_every_event(language: str) -> None:
    messages = Messages(language, ZoneInfo("Europe/Paris"))
    facts = TunnelFacts(
        tunnel_id="t1",
        protocol="http",
        local_port=8080,
        label="<script>",
        public_url="https://a.ngrok.app/?a=1&b=2",
        username="hermes",
        password="p<w>d",
        expires_at=1_800_000_000.0,
        idle_timeout=600,
    )
    rendered = [
        messages.tunnel_opened(facts),
        messages.expiry_warning(facts, remaining=300),
        messages.tunnel_closed(facts, reason="idle"),
        messages.tunnel_closed(facts, reason="expired"),
        messages.enrollment_caption(
            issuer="I<", account="a&b", secret="ABCD", expires_in=600, rotation=False
        ),
        messages.mfa_enabled(rotation=True),
        messages.mfa_locked(retry_after=900),
        messages.test_message("vps"),
    ]
    for text in rendered:
        assert "<script>" not in text
        assert "p<w>d" not in text
    assert "&lt;script&gt;" in rendered[0]
    assert "p&lt;w&gt;d" in rendered[0]
    assert "a=1&amp;b=2" in rendered[0]
    assert "(Europe/Paris)" in rendered[0]
    assert "10 min" in rendered[2]


def test_tcp_access_card_shows_host_port_and_ssh_hint() -> None:
    messages = Messages("fr", ZoneInfo("UTC"))
    facts = TunnelFacts("t2", "tcp", 22, None, "tcp://4.tcp.eu.ngrok.io:12345", idle_timeout=600)
    text = messages.tunnel_opened(facts)
    assert "<code>4.tcp.eu.ngrok.io</code>" in text
    assert "<code>12345</code>" in text
    assert "ssh -p 12345" in text
    assert "(UTC)" not in messages.clock_time(0)
