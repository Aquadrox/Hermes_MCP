"""HTTP application of the NAS file manager (Starlette).

Request pipeline, outermost first:

1. :class:`RequestLog` gives each request an id, adds the security headers, counts the
   requests in flight (for the idle exit) and logs one line per request;
2. :class:`AuthGate` admits, before reading anything else, either the MCP server (shared
   access key, health and credential administration only) or the user, with the basic-auth
   credentials of the open NAS tunnel. Wrong passwords are audited and throttled;
3. the routes. State-changing requests (upload, new folder) also require a custom header,
   which a cross-site page cannot send without a CORS preflight that is never granted.

Downloaded files are always served as attachments, except a short list of media types
previewed inline under a sandboxing CSP: a stored HTML or SVG file can never run in the
application's origin.
"""

from __future__ import annotations

import contextlib
import functools
import hmac
import html
import logging
import mimetypes
import os
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from importlib import resources
from urllib.parse import quote

from anyio import to_thread
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hermes_ngrok_mcp import __version__
from hermes_ngrok_mcp.audit import AuditLog
from hermes_ngrok_mcp.nas import ACCESS_KEY_HEADER, CREDENTIALS_PATH, HEALTH_PATH
from hermes_ngrok_mcp.nas.config import NasSettings
from hermes_ngrok_mcp.nas.fs import Listing, NasError, NasRoot, RangeNotSatisfiableError, Upload, parse_range
from hermes_ngrok_mcp.nas.sessions import CredentialStore, Verdict

log = logging.getLogger(__name__)

CSRF_HEADER = "x-nas-request"
_WRITE_CHUNK = 1024 * 1024
_READ_CHUNK = 256 * 1024
_ASSETS = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "icon.svg": "image/svg+xml",
}

_APP_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self'; "
    "connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
# Served files never run code, even when previewed: sandboxed, no script, no plugin.
_FILE_CSP = "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox"
_COMMON_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
]

# Inline preview is limited to passive media; everything else downloads as octet-stream.
_INLINE_TYPES = frozenset(
    {
        "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp",
        "video/mp4", "video/webm", "video/ogg", "video/quicktime",
        "audio/mpeg", "audio/ogg", "audio/wav", "audio/x-wav", "audio/webm", "audio/flac", "audio/mp4",
        "audio/aac",
    }
)  # fmt: skip
_TEXT_EXTENSIONS = frozenset(
    {".txt", ".md", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
     ".env", ".py", ".sh", ".js", ".ts", ".css", ".sql", ".xml", ".srt", ".vtt", ".nfo"}
)  # fmt: skip


# --- activity, logging and security headers --------------------------------------------------------
@dataclass
class Activity:
    """Requests in flight and time of the last one, for the idle exit."""

    in_flight: int = 0
    last_request: float = field(default_factory=time.monotonic)

    def idle_for(self) -> float:
        return 0.0 if self.in_flight else time.monotonic() - self.last_request


def client_ip(scope: Scope) -> str | None:
    """The Internet client: the last X-Forwarded-For hop, appended by the ngrok edge."""
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            hops = [hop.strip() for hop in value.decode("latin-1").split(",") if hop.strip()]
            if hops:
                return str(hops[-1])
    client = scope.get("client")
    return str(client[0]) if client else None


class RequestLog:
    def __init__(self, app: ASGIApp, activity: Activity) -> None:
        self._app = app
        self._activity = activity

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        request_id = secrets.token_hex(4)
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.monotonic()
        status = 0
        sent = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status, sent
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
                names = {name.lower() for name, _ in headers}
                headers.extend(h for h in _COMMON_HEADERS if h[0] not in names)
                if b"content-security-policy" not in names:
                    headers.append((b"content-security-policy", _APP_CSP.encode()))
                headers.append((b"x-request-id", request_id.encode()))
                message = {**message, "headers": headers}
            elif message["type"] == "http.response.body":
                sent += len(message.get("body", b""))
            await send(message)

        self._activity.in_flight += 1
        try:
            await self._app(scope, receive, send_wrapper)
        finally:
            self._activity.in_flight -= 1
            self._activity.last_request = time.monotonic()
            log.info(
                "request id=%s %s %s status=%s bytes=%s ms=%d client=%s",
                request_id,
                scope.get("method"),
                scope.get("path"),
                status or "-",
                sent,
                (time.monotonic() - started) * 1000,
                client_ip(scope) or "-",
            )


_ADMIN_PATHS = frozenset({HEALTH_PATH, CREDENTIALS_PATH})


class AuthGate:
    """Admit the MCP server (access key, admin paths only) or the user (tunnel basic auth)."""

    def __init__(
        self, app: ASGIApp, access_key: str, store: CredentialStore, audit: AuditLog, *, realm: str
    ) -> None:
        if len(access_key) < 32:
            raise ValueError("the NAS access key must be at least 32 characters long")
        self._app = app
        self._key = access_key.encode()
        self._key_header = ACCESS_KEY_HEADER.lower().encode()
        self._store = store
        self._audit = audit
        self._challenge = f'Basic realm="{realm.replace(chr(34), "")}", charset="UTF-8"'

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        response = self._admit(scope)
        if response is None:
            await self._app(scope, receive, send)
        else:
            await response(scope, receive, send)

    def _admit(self, scope: Scope) -> Response | None:  # noqa: PLR0911 - one exit per verdict
        headers = scope.get("headers", [])
        path = scope.get("path", "")
        source = client_ip(scope)
        keys = [value for name, value in headers if name == self._key_header]
        if keys:
            if len(keys) == 1 and hmac.compare_digest(keys[0], self._key) and path in _ADMIN_PATHS:
                return None
            self._audit.record("nas.access_denied", reason="bad_key", source_ip=source, path=path)
            return _error(403, "forbidden", "Access refused.")
        if path in _ADMIN_PATHS:
            self._audit.record("nas.access_denied", reason="admin_path", source_ip=source, path=path)
            return _error(403, "forbidden", "Access refused.")
        authorizations = [value for name, value in headers if name == b"authorization"]
        already_locked = self._store.locked_for > 0
        verdict, username = self._store.check(authorizations[0] if len(authorizations) == 1 else None)
        if verdict is Verdict.OK:
            return None
        if verdict is Verdict.NOT_OPEN:
            self._audit.record("nas.access_denied", reason="no_tunnel", source_ip=source, path=path)
            return _error(403, "forbidden", "No NAS tunnel is open: ask Hermes to open the NAS.")
        if verdict is Verdict.MISSING:
            return _error(401, "unauthorized", "Sign in.", {"www-authenticate": self._challenge})
        if verdict is Verdict.LOCKED:
            if authorizations:
                self._audit.record("nas.auth_failed", username=username, source_ip=source, locked=True)
            if not already_locked:
                self._audit.record(
                    "nas.auth_locked", source_ip=source, duration_seconds=round(self._store.locked_for)
                )
            retry = str(max(1, round(self._store.locked_for)))
            return _error(429, "locked", "Too many wrong passwords: try again later.", {"retry-after": retry})
        self._audit.record("nas.auth_failed", username=username, source_ip=source)
        return _error(
            401, "unauthorized", "Wrong username or password.", {"www-authenticate": self._challenge}
        )


def _error(status: int, code: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": code, "message": message}, status_code=status, headers=headers)


def _json(data: object, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers={"cache-control": "no-store"})


# --- the application ----------------------------------------------------------------------------------
class NasApp:
    def __init__(self, settings: NasSettings, *, audit: AuditLog, store: CredentialStore) -> None:
        self.settings = settings
        self.root = NasRoot(settings.root, max_upload=settings.max_upload)
        self.audit = audit
        self.store = store
        self._index = self._render_index()

    def _render_index(self) -> bytes:
        template = resources.files("hermes_ngrok_mcp.nas").joinpath("static/index.html").read_text("utf-8")
        values = {
            "{{TITLE}}": html.escape(self.settings.title),
            "{{VERSION}}": html.escape(__version__),
            "{{MAX_UPLOAD}}": str(self.settings.max_upload),
        }
        for placeholder, value in values.items():
            template = template.replace(placeholder, value)
        return template.encode("utf-8")

    def routes(self) -> list[Route]:
        return [
            Route("/", _guarded(self.index), methods=["GET"]),
            Route("/assets/{name}", _guarded(self.asset), methods=["GET"]),
            Route(HEALTH_PATH, _guarded(self.health), methods=["GET"]),
            Route("/api/list", _guarded(self.list), methods=["GET"]),
            Route("/api/download", _guarded(self.download), methods=["GET", "HEAD"]),
            Route("/api/upload", _guarded(self.upload), methods=["PUT"]),
            Route("/api/mkdir", _guarded(self.mkdir), methods=["POST"]),
            Route(CREDENTIALS_PATH, _guarded(self.set_credentials), methods=["PUT"]),
            Route(CREDENTIALS_PATH, _guarded(self.revoke_credentials), methods=["DELETE"]),
        ]

    # --- pages ---------------------------------------------------------------------------------------
    async def index(self, request: Request) -> Response:
        return Response(
            self._index, media_type="text/html; charset=utf-8", headers={"cache-control": "no-cache"}
        )

    async def asset(self, request: Request) -> Response:
        name = request.path_params["name"]
        media_type = _ASSETS.get(name)
        if media_type is None:
            return _error(404, "not_found", "Unknown asset.")
        data = resources.files("hermes_ngrok_mcp.nas").joinpath(f"static/{name}").read_bytes()
        return Response(data, media_type=media_type, headers={"cache-control": "public, max-age=3600"})

    # --- API ------------------------------------------------------------------------------------------------
    async def health(self, request: Request) -> Response:
        usage = await to_thread.run_sync(self.root.disk_usage)
        return _json(
            {
                "status": "ok",
                "version": __version__,
                "title": self.settings.title,
                "root": str(self.settings.root),
                "writable": await to_thread.run_sync(self.root.writable),
                "max_upload": self.settings.max_upload,
                "disk": {"total": usage.total, "free": usage.free},
            }
        )

    async def list(self, request: Request) -> Response:
        path = request.query_params.get("path", "")
        listing: Listing = await to_thread.run_sync(self.root.list, path)
        usage = await to_thread.run_sync(self.root.disk_usage)
        prefix = f"{listing.path}/" if listing.path else ""
        crumbs: list[dict[str, str]] = []
        for part in listing.path.split("/") if listing.path else []:
            crumbs.append({"name": part, "path": f"{crumbs[-1]['path']}/{part}" if crumbs else part})
        return _json(
            {
                "path": listing.path,
                "breadcrumbs": crumbs,
                "entries": [
                    {
                        "name": e.name,
                        "path": prefix + e.name,
                        "kind": e.kind,
                        "size": e.size if e.kind == "file" else None,
                        "modified": round(e.modified),
                    }
                    for e in listing.entries
                ],
                "truncated": listing.truncated,
                "disk": {"total": usage.total, "free": usage.free},
            }
        )

    async def download(self, request: Request) -> Response:
        path = request.query_params.get("path", "")
        fd, info = await to_thread.run_sync(self.root.open_file, path)
        stream = _FileChunks(fd)  # owns the descriptor from now on, whatever happens
        handed_over = False
        try:
            size = info.st_size
            etag = f'"{size:x}-{info.st_mtime_ns:x}"'
            range_header = request.headers.get("range")
            if_range = request.headers.get("if-range")
            if if_range is not None and if_range != etag:
                range_header = None  # the file changed since the client's first part: send it whole
            try:
                byte_range = parse_range(range_header, size)
            except RangeNotSatisfiableError:
                return _error(
                    416, "range_not_satisfiable", "Invalid range.", {"content-range": f"bytes */{size}"}
                )
            name = path.rsplit("/", 1)[-1]
            headers = {
                "accept-ranges": "bytes",
                "etag": etag,
                "last-modified": _http_date(info.st_mtime),
                "cache-control": "private, no-cache",
                "content-security-policy": _FILE_CSP,
            }
            media_type, inline = _media_type(name, request.query_params.get("inline") == "1")
            headers["content-disposition"] = _content_disposition(name, inline=inline)
            start, end = byte_range if byte_range else (0, size - 1)
            length = max(0, end - start + 1)
            headers["content-length"] = str(length)
            status = 200
            if byte_range:
                status = 206
                headers["content-range"] = f"bytes {start}-{end}/{size}"
            if request.method == "HEAD":
                return Response(status_code=status, headers=headers, media_type=media_type)
            if start == 0 and not inline:
                self.audit.record(
                    "nas.download",
                    path=path,
                    size=size,
                    source_ip=client_ip(request.scope),
                    request_id=_rid(request),
                )
            stream.select(start, length)
            handed_over = True
            return StreamingResponse(stream, status_code=status, headers=headers, media_type=media_type)
        finally:
            if not handed_over:
                stream.close()

    async def upload(self, request: Request) -> Response:
        self._check_write_request(request)
        path = request.query_params.get("path", "")
        name = request.query_params.get("name", "")
        expected = _content_length(request)
        started = time.monotonic()
        handle: Upload = await to_thread.run_sync(
            lambda: self.root.begin_upload(path, name, expected_size=expected)
        )
        try:
            await _receive(request, handle, expected)
            final = await to_thread.run_sync(handle.commit)
        except BaseException as exc:
            handle.abort()
            reason = "client_disconnected" if isinstance(exc, ClientDisconnect) else type(exc).__name__
            self.audit.record(
                "nas.upload_failed",
                path=path,
                name=name,
                received=handle.size,
                reason=reason,
                source_ip=client_ip(request.scope),
                request_id=_rid(request),
            )
            raise
        self.audit.record(
            "nas.upload",
            path=final,
            size=handle.size,
            duration_seconds=round(time.monotonic() - started, 1),
            renamed=final.rsplit("/", 1)[-1] != name,
            source_ip=client_ip(request.scope),
            request_id=_rid(request),
        )
        return _json({"path": final, "name": final.rsplit("/", 1)[-1], "size": handle.size}, status=201)

    async def mkdir(self, request: Request) -> Response:
        self._check_write_request(request)
        try:
            body = await request.json()
        except ValueError as exc:
            raise NasError("Expected a JSON body.") from exc
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("name"), str)
            or not isinstance(body.get("path", ""), str)
        ):
            raise NasError('Expected {"path": "...", "name": "..."}.')
        created = await to_thread.run_sync(self.root.mkdir, body.get("path", ""), body["name"])
        self.audit.record(
            "nas.mkdir", path=created, source_ip=client_ip(request.scope), request_id=_rid(request)
        )
        return _json({"path": created}, status=201)

    # --- administration (MCP server only, see AuthGate) -------------------------------------------------
    async def set_credentials(self, request: Request) -> Response:
        try:
            body = await request.json()
        except ValueError as exc:
            raise NasError("Expected a JSON body.") from exc
        username, password = _credentials_body(body)
        try:
            await to_thread.run_sync(self.store.grant, username, password)
        except ValueError as exc:
            raise NasError("Invalid credentials (16+ character password, no ':' in the username).") from exc
        self.audit.record("nas.credentials_granted", username=username)
        return Response(status_code=204)

    async def revoke_credentials(self, request: Request) -> Response:
        had = self.store.active
        await to_thread.run_sync(self.store.revoke)
        if had:
            self.audit.record("nas.credentials_revoked")
        return Response(status_code=204)

    def _check_write_request(self, request: Request) -> None:
        if request.headers.get(CSRF_HEADER) != "1":
            raise _CsrfError
        if request.headers.get("sec-fetch-site") in ("cross-site", "same-site"):
            raise _CsrfError


class _CsrfError(NasError):
    status = 403
    code = "csrf"

    def __init__(self) -> None:
        super().__init__("Request refused (missing anti-forgery header).")


Endpoint = Callable[[Request], Awaitable[Response]]


def _guarded(endpoint: Endpoint) -> Endpoint:
    """Turn refusals into JSON errors and crashes into a logged 500, never a broken connection."""

    @functools.wraps(endpoint)
    async def guarded(request: Request) -> Response:
        try:
            return await endpoint(request)
        except NasError as exc:
            if exc.status >= 500:
                log.warning("request id=%s failed: %s", _rid(request), exc)
            return _error(exc.status, exc.code, str(exc))
        except ClientDisconnect:
            return Response(status_code=499)
        except Exception:
            log.exception("request id=%s crashed", _rid(request))
            return _error(500, "internal", f"Internal error (request {_rid(request)}).")

    return guarded


def create_app(
    settings: NasSettings,
    *,
    audit: AuditLog,
    activity: Activity | None = None,
    store: CredentialStore | None = None,
) -> ASGIApp:
    if settings.access_key is None:
        raise ValueError("HERMES_NAS_ACCESS_KEY is required")
    store = store or CredentialStore(settings.credentials_file)
    nas = NasApp(settings, audit=audit, store=store)
    app = Starlette(routes=nas.routes())
    gated = AuthGate(app, settings.access_key.get_secret_value(), store, audit, realm=settings.title)
    return RequestLog(gated, activity or Activity())


# --- helpers --------------------------------------------------------------------------------------------
def _credentials_body(body: object) -> tuple[str, str]:
    if isinstance(body, dict):
        username, password = body.get("username"), body.get("password")
        if isinstance(username, str) and isinstance(password, str):
            return username, password
    raise NasError('Expected {"username": "...", "password": "..."}.')


async def _receive(request: Request, handle: Upload, expected: int | None) -> None:
    buffer = bytearray()
    async for chunk in request.stream():
        buffer += chunk
        if len(buffer) >= _WRITE_CHUNK:
            data, buffer = bytes(buffer), bytearray()
            await to_thread.run_sync(handle.write, data)
    if buffer:
        await to_thread.run_sync(handle.write, bytes(buffer))
    if expected is not None and handle.size != expected:
        raise NasError("The upload was interrupted before the end of the file.")


class _FileChunks:
    """Async iterator over a byte range of an open file; closes the descriptor exactly once,
    at the end, on error, or when dropped unread (e.g. the client left before the body)."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._offset = 0
        self._remaining = 0

    def select(self, start: int, length: int) -> None:
        self._offset, self._remaining = start, length

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        if self._fd < 0 or self._remaining <= 0:
            self.close()
            raise StopAsyncIteration
        try:
            chunk = await to_thread.run_sync(
                os.pread, self._fd, min(_READ_CHUNK, self._remaining), self._offset
            )
        except BaseException:
            self.close()
            raise
        if not chunk:
            self.close()
            raise StopAsyncIteration
        self._offset += len(chunk)
        self._remaining -= len(chunk)
        return chunk

    def close(self) -> None:
        fd, self._fd = self._fd, -1
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)

    def __del__(self) -> None:
        self.close()


def _rid(request: Request) -> str:
    return str(request.scope.get("state", {}).get("request_id", "-"))


def _content_length(request: Request) -> int | None:
    value = request.headers.get("content-length")
    if value is None:
        return None
    if not value.isdigit():
        raise NasError("Invalid Content-Length.")
    return int(value)


def _media_type(name: str, want_inline: bool) -> tuple[str, bool]:
    guessed, _ = mimetypes.guess_type(name, strict=False)
    if want_inline and guessed in _INLINE_TYPES:
        return guessed, True
    extension = os.path.splitext(name)[1].lower()
    if want_inline and extension in _TEXT_EXTENSIONS:
        return "text/plain; charset=utf-8", True
    return "application/octet-stream", False


def _content_disposition(name: str, *, inline: bool) -> str:
    fallback = "".join(c if 32 <= ord(c) < 127 and c not in '"\\;' else "_" for c in name) or "download"
    disposition = "inline" if inline else "attachment"
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quote(name, safe='')}"


def _http_date(epoch: float) -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(epoch))
