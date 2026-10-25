"""Streamable HTTP transport, restricted to clients presenting the shared bearer token."""

from __future__ import annotations

import hmac
import json
import logging

from mcp.server.mcpserver import MCPServer
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from hermes_ngrok_mcp.audit import AuditLog
from hermes_ngrok_mcp.config import Settings

log = logging.getLogger(__name__)

HEALTH_PATH = "/healthz"


class HealthCheckMiddleware:
    """Answer ``GET /healthz`` without authentication (used by the installer and monitoring)."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == HEALTH_PATH and scope.get("method") == "GET":
            await JSONResponse({"status": "ok"})(scope, receive, send)
            return
        await self._app(scope, receive, send)


class BearerTokenMiddleware:
    """Reject every HTTP request lacking ``Authorization: Bearer <token>``."""

    def __init__(self, app: ASGIApp, token: str, *, audit: AuditLog | None = None) -> None:
        if len(token) < 32:
            raise ValueError("the API token must be at least 32 characters long")
        self._app = app
        self._token = token.encode()
        self._audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self._authorized(scope):
            await self._app(scope, receive, send)
            return
        client = scope.get("client")
        source = client[0] if client else "unknown"
        log.warning("rejected unauthenticated request from %s", source)
        if self._audit is not None:
            self._audit.record(
                "mcp.auth_rejected",
                source_ip=source,
                method=scope.get("method"),
                path=scope.get("path"),
                had_credentials=any(name == b"authorization" for name, _ in scope.get("headers", [])),
            )
        body = json.dumps({"error": "unauthorized"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b'Bearer realm="hermes-ngrok-mcp"'),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    def _authorized(self, scope: Scope) -> bool:
        values = [value for name, value in scope.get("headers", []) if name == b"authorization"]
        if len(values) != 1:
            return False
        scheme, _, credential = values[0].partition(b" ")
        if scheme.lower() != b"bearer":
            return False
        return hmac.compare_digest(credential.strip(), self._token)


def build_http_app(
    server: MCPServer, settings: Settings, *, require_token: bool = True, audit: AuditLog | None = None
) -> ASGIApp:
    app: ASGIApp = server.streamable_http_app(
        streamable_http_path=settings.path,
        stateless_http=True,
        json_response=True,
        host=settings.host,
    )
    if settings.api_token is None:
        if require_token:
            raise ValueError(
                "HERMES_NGROK_API_TOKEN is required for the HTTP transport "
                "(generate one with: hermes-ngrok-mcp token)"
            )
        log.warning("HTTP transport running WITHOUT authentication (development mode)")
        return HealthCheckMiddleware(app)
    return HealthCheckMiddleware(
        BearerTokenMiddleware(app, settings.api_token.get_secret_value(), audit=audit)
    )
