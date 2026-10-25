"""The NAS web application, through its ASGI interface."""

from __future__ import annotations

import base64
import os
import socket
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx2
import pytest

from hermes_ngrok_mcp.audit import AuditLog
from hermes_ngrok_mcp.nas import ACCESS_KEY_HEADER, CREDENTIALS_PATH
from hermes_ngrok_mcp.nas import cli as nas_cli
from hermes_ngrok_mcp.nas.app import Activity, create_app
from hermes_ngrok_mcp.nas.config import NasSettings
from hermes_ngrok_mcp.nas.fs import TEMP_PREFIX
from hermes_ngrok_mcp.nas.sessions import MAX_FAILURES, CredentialStore
from tests.conftest import FakeClock

pytestmark = pytest.mark.anyio

KEY = "n" * 40
PASSWORD = "p4ssw0rd-generated-by-hermes"


def basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


ADMIN = {ACCESS_KEY_HEADER: KEY}
AUTH = {"Authorization": basic("hermes", PASSWORD), "X-Forwarded-For": "198.51.100.9, 203.0.113.7"}
WRITE = {**AUTH, "X-NAS-Request": "1"}


@pytest.fixture
def nas_settings(tmp_path: Path) -> NasSettings:
    root = tmp_path / "MonNAS"
    (root / "Photos").mkdir(parents=True)
    (root / "Photos" / "beach.jpg").write_bytes(b"\xff\xd8jpeg-data")
    (root / "notes.txt").write_text("0123456789")
    (root / "page.html").write_text("<script>alert(1)</script>")
    return NasSettings(root=root, access_key=KEY, max_upload=1024, state_dir=tmp_path / "state")


@pytest.fixture
def audit(nas_settings: NasSettings) -> AuditLog:
    return AuditLog(nas_settings.audit_file, clock=FakeClock(), tz=ZoneInfo("UTC"), origin="nas")


@pytest.fixture
def activity() -> Activity:
    return Activity()


@pytest.fixture
def store(nas_settings: NasSettings) -> CredentialStore:
    credentials = CredentialStore(nas_settings.credentials_file)
    credentials.grant("hermes", PASSWORD)
    return credentials


@pytest.fixture
async def http(
    nas_settings: NasSettings, audit: AuditLog, activity: Activity, store: CredentialStore
) -> AsyncIterator[httpx2.AsyncClient]:
    app = create_app(nas_settings, audit=audit, activity=activity, store=store)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://nas.test"
    ) as client:
        yield client


def events(audit: AuditLog, name: str) -> list[dict[str, Any]]:
    return audit.query(events={name}, limit=0)


# --- access control --------------------------------------------------------------------------------------
USER_PATHS = ("/", "/api/list", "/assets/app.js", "/api/download?path=notes.txt")


async def test_browsers_are_asked_to_sign_in(http: httpx2.AsyncClient, audit: AuditLog) -> None:
    for path in USER_PATHS:
        response = await http.get(path)
        assert response.status_code == 401, path
        assert response.headers["www-authenticate"] == 'Basic realm="MonNAS", charset="UTF-8"'
    assert not audit.query()  # a first visit without credentials is not an attempt


@pytest.mark.parametrize(
    "authorization",
    [basic("hermes", "wrong-password-123"), basic("admin", PASSWORD), "Basic !!!", "Bearer x"],
)
async def test_wrong_credentials_are_refused_and_audited(
    http: httpx2.AsyncClient, audit: AuditLog, authorization: str
) -> None:
    for path in USER_PATHS:
        response = await http.get(
            path, headers={"Authorization": authorization, "X-Forwarded-For": "198.51.100.4"}
        )
        assert response.status_code == 401, path
    failures = events(audit, "nas.auth_failed")
    assert len(failures) == len(USER_PATHS)
    assert failures[0]["source_ip"] == "198.51.100.4"


async def test_the_access_key_only_opens_admin_paths(http: httpx2.AsyncClient, audit: AuditLog) -> None:
    for path in USER_PATHS:
        assert (await http.get(path, headers=ADMIN)).status_code == 403, path
    assert (await http.get("/api/health", headers=ADMIN)).status_code == 200
    for headers in ({}, AUTH, {ACCESS_KEY_HEADER: "wrong" * 10}):
        assert (await http.get("/api/health", headers=headers)).status_code == 403
        assert (await http.delete(CREDENTIALS_PATH, headers=headers)).status_code == 403
    reasons = [e["reason"] for e in events(audit, "nas.access_denied")]
    assert reasons.count("bad_key") == len(USER_PATHS) + 2
    assert reasons.count("admin_path") == 4


async def test_credentials_lifecycle(
    http: httpx2.AsyncClient, audit: AuditLog, nas_settings: NasSettings
) -> None:
    assert (await http.get("/api/list", headers=AUTH)).status_code == 200
    assert (await http.delete(CREDENTIALS_PATH, headers=ADMIN)).status_code == 204
    closed = await http.get("/api/list", headers=AUTH)
    assert closed.status_code == 403
    assert "No NAS tunnel is open" in closed.json()["message"]
    new_password = "another-generated-password"
    granted = await http.put(
        CREDENTIALS_PATH, headers=ADMIN, json={"username": "hermes", "password": new_password}
    )
    assert granted.status_code == 204
    assert (await http.get("/api/list", headers=AUTH)).status_code == 401
    fresh = {"Authorization": basic("hermes", new_password)}
    assert (await http.get("/api/list", headers=fresh)).status_code == 200
    assert new_password not in nas_settings.credentials_file.read_text()
    assert [e["event"] for e in audit.query(category="nas") if "credentials" in e["event"]] == [
        "nas.credentials_revoked",
        "nas.credentials_granted",
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"username": "hermes"},
        {"username": "a:b", "password": "x" * 20},
        {"username": "u", "password": "short"},
        [1],
    ],
)
async def test_invalid_credentials_are_rejected(http: httpx2.AsyncClient, body: Any) -> None:
    assert (await http.put(CREDENTIALS_PATH, headers=ADMIN, json=body)).status_code == 400
    assert (await http.put(CREDENTIALS_PATH, headers=ADMIN, content=b"{")).status_code == 400


async def test_credentials_survive_a_restart(
    nas_settings: NasSettings, audit: AuditLog, store: CredentialStore
) -> None:
    app = create_app(nas_settings, audit=audit)  # a fresh process reads the state file
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://nas.test"
    ) as client:
        assert (await client.get("/api/list", headers=AUTH)).status_code == 200


async def test_brute_force_is_locked_out(http: httpx2.AsyncClient, audit: AuditLog) -> None:
    wrong = {"Authorization": basic("hermes", "guess-guess-guess")}
    statuses = [(await http.get("/api/list", headers=wrong)).status_code for _ in range(MAX_FAILURES)]
    assert statuses[:-1] == [401] * (MAX_FAILURES - 1)
    assert statuses[-1] == 429
    locked = await http.get("/api/list", headers=AUTH)  # even the right password waits
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0
    assert len(events(audit, "nas.auth_locked")) == 1
    password = "a-new-tunnel-password-0001"
    await http.put(CREDENTIALS_PATH, headers=ADMIN, json={"username": "hermes", "password": password})
    unlocked = await http.get("/api/list", headers={"Authorization": basic("hermes", password)})
    assert unlocked.status_code == 200


def test_credentials_expire(tmp_path: Path) -> None:
    now = [1000.0]
    credentials = CredentialStore(tmp_path / "c.json", clock=lambda: now[0])
    credentials.grant("hermes", PASSWORD)
    assert credentials.active
    now[0] += 25 * 3600
    assert not credentials.active


async def test_duplicate_headers_are_refused(http: httpx2.AsyncClient) -> None:
    response = await http.get("/api/health", headers=[(ACCESS_KEY_HEADER, KEY), (ACCESS_KEY_HEADER, KEY)])
    assert response.status_code == 403
    twice = [("Authorization", AUTH["Authorization"]), ("Authorization", AUTH["Authorization"])]
    assert (await http.get("/api/list", headers=twice)).status_code == 401


async def test_security_headers(http: httpx2.AsyncClient) -> None:
    response = await http.get("/", headers=AUTH)
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-request-id"]
    assert "<title>MonNAS</title>" in response.text
    assert 'data-max-upload="1024"' in response.text
    assert "{{" not in response.text


async def test_assets(http: httpx2.AsyncClient) -> None:
    for name, media_type in (
        ("app.js", "text/javascript"),
        ("app.css", "text/css"),
        ("icon.svg", "image/svg+xml"),
    ):
        response = await http.get(f"/assets/{name}", headers=AUTH)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(media_type)
    assert (await http.get("/assets/index.html", headers=AUTH)).status_code == 404
    assert (await http.get("/assets/..%2Fapp.py", headers=AUTH)).status_code == 404


async def test_title_is_escaped(tmp_path: Path, audit: AuditLog) -> None:
    settings = NasSettings(root=tmp_path, access_key=KEY, title="<b>Nas</b>", state_dir=tmp_path / "s")
    credentials = CredentialStore(None)
    credentials.grant("hermes", PASSWORD)
    app = create_app(settings, audit=audit, store=credentials)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://nas.test"
    ) as client:
        page = (await client.get("/", headers=AUTH)).text
    assert "<b>Nas</b>" not in page
    assert "&lt;b&gt;Nas&lt;/b&gt;" in page


def test_key_is_required(tmp_path: Path, audit: AuditLog) -> None:
    with pytest.raises(ValueError, match="ACCESS_KEY"):
        create_app(NasSettings(root=tmp_path), audit=audit)


# --- browsing --------------------------------------------------------------------------------------------
async def test_health(http: httpx2.AsyncClient, nas_settings: NasSettings) -> None:
    data = (await http.get("/api/health", headers=ADMIN)).json()
    assert data["status"] == "ok"
    assert data["root"] == str(nas_settings.root)
    assert data["writable"] is True
    assert data["disk"]["total"] >= data["disk"]["free"] > 0


async def test_list(http: httpx2.AsyncClient) -> None:
    response = await http.get("/api/list", headers=AUTH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["path"] == ""
    assert data["breadcrumbs"] == []
    assert [(e["name"], e["kind"]) for e in data["entries"]] == [
        ("Photos", "dir"),
        ("notes.txt", "file"),
        ("page.html", "file"),
    ]
    assert data["entries"][0]["size"] is None
    assert data["entries"][1]["size"] == 10
    nested = (await http.get("/api/list", params={"path": "Photos"}, headers=AUTH)).json()
    assert nested["breadcrumbs"] == [{"name": "Photos", "path": "Photos"}]
    assert nested["entries"][0]["path"] == "Photos/beach.jpg"


@pytest.mark.parametrize(
    ("path", "status"), [("../", 400), ("Photos/../..", 400), ("missing", 404), ("notes.txt", 404)]
)
async def test_list_errors(http: httpx2.AsyncClient, path: str, status: int) -> None:
    response = await http.get("/api/list", params={"path": path}, headers=AUTH)
    assert response.status_code == status
    assert response.json()["message"]


# --- downloads ---------------------------------------------------------------------------------------------
async def test_download_is_an_attachment(http: httpx2.AsyncClient, audit: AuditLog) -> None:
    response = await http.get("/api/download", params={"path": "notes.txt"}, headers=AUTH)
    assert response.status_code == 200
    assert response.content == b"0123456789"
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith('attachment; filename="notes.txt"')
    assert response.headers["accept-ranges"] == "bytes"
    assert "sandbox" in response.headers["content-security-policy"]
    [download] = events(audit, "nas.download")
    assert download["path"] == "notes.txt"
    assert download["source_ip"] == "203.0.113.7"  # the hop appended by ngrok, not the forged one


async def test_html_is_never_rendered(http: httpx2.AsyncClient) -> None:
    response = await http.get("/api/download", params={"path": "page.html", "inline": "1"}, headers=AUTH)
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith("attachment")


async def test_inline_preview_of_media_and_text(http: httpx2.AsyncClient, audit: AuditLog) -> None:
    image = await http.get("/api/download", params={"path": "Photos/beach.jpg", "inline": "1"}, headers=AUTH)
    assert image.headers["content-type"] == "image/jpeg"
    assert image.headers["content-disposition"].startswith("inline")
    text = await http.get("/api/download", params={"path": "notes.txt", "inline": "1"}, headers=AUTH)
    assert text.headers["content-type"] == "text/plain; charset=utf-8"
    assert not events(audit, "nas.download")  # previews are not downloads


async def test_unicode_file_names(http: httpx2.AsyncClient, nas_settings: NasSettings) -> None:
    (nas_settings.root / "Été 2024 « vacances ».txt").write_text("x")
    response = await http.get("/api/download", params={"path": "Été 2024 « vacances ».txt"}, headers=AUTH)
    disposition = response.headers["content-disposition"]
    assert 'filename="_t_ 2024 _ vacances _.txt"' in disposition
    assert "filename*=UTF-8''%C3%89t%C3%A9%202024" in disposition


async def test_range_requests(http: httpx2.AsyncClient) -> None:
    params = {"path": "notes.txt"}
    partial = await http.get("/api/download", params=params, headers={**AUTH, "Range": "bytes=2-5"})
    assert partial.status_code == 206
    assert partial.content == b"2345"
    assert partial.headers["content-range"] == "bytes 2-5/10"
    assert partial.headers["content-length"] == "4"
    suffix = await http.get("/api/download", params=params, headers={**AUTH, "Range": "bytes=-3"})
    assert suffix.content == b"789"
    beyond = await http.get("/api/download", params=params, headers={**AUTH, "Range": "bytes=50-"})
    assert beyond.status_code == 416
    assert beyond.headers["content-range"] == "bytes */10"
    etag = partial.headers["etag"]
    resumed = await http.get(
        "/api/download", params=params, headers={**AUTH, "Range": "bytes=5-", "If-Range": etag}
    )
    assert resumed.status_code == 206
    stale = await http.get(
        "/api/download", params=params, headers={**AUTH, "Range": "bytes=5-", "If-Range": '"x"'}
    )
    assert stale.status_code == 200
    assert stale.content == b"0123456789"


async def test_head_request(http: httpx2.AsyncClient) -> None:
    response = await http.head("/api/download", params={"path": "notes.txt"}, headers=AUTH)
    assert response.status_code == 200
    assert response.headers["content-length"] == "10"
    assert response.content == b""


async def test_download_errors(http: httpx2.AsyncClient, nas_settings: NasSettings, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cret")
    (nas_settings.root / "link").symlink_to(secret)
    for path, status in (("Photos", 404), ("missing", 404), ("link", 403), ("../secret.txt", 400), ("", 400)):
        response = await http.get("/api/download", params={"path": path}, headers=AUTH)
        assert response.status_code == status, path
        assert b"s3cret" not in response.content


async def test_no_descriptor_leak(http: httpx2.AsyncClient) -> None:
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        await http.get("/api/download", params={"path": "notes.txt"}, headers=AUTH)
        await http.head("/api/download", params={"path": "notes.txt"}, headers=AUTH)
        await http.get("/api/download", params={"path": "notes.txt"}, headers={**AUTH, "Range": "bytes=99-"})
    assert len(os.listdir("/proc/self/fd")) <= before + 2


# --- uploads ------------------------------------------------------------------------------------------------
async def test_upload(http: httpx2.AsyncClient, nas_settings: NasSettings, audit: AuditLog) -> None:
    response = await http.put(
        "/api/upload", params={"path": "Photos", "name": "sunset.jpg"}, content=b"new-image", headers=WRITE
    )
    assert response.status_code == 201
    assert response.json() == {"path": "Photos/sunset.jpg", "name": "sunset.jpg", "size": 9}
    assert (nas_settings.root / "Photos" / "sunset.jpg").read_bytes() == b"new-image"
    again = await http.put(
        "/api/upload", params={"path": "Photos", "name": "sunset.jpg"}, content=b"other", headers=WRITE
    )
    assert again.json()["name"] == "sunset (1).jpg"
    assert (nas_settings.root / "Photos" / "sunset.jpg").read_bytes() == b"new-image"
    uploads = events(audit, "nas.upload")
    assert [u["renamed"] for u in uploads] == [False, True]
    assert uploads[0]["source_ip"] == "203.0.113.7"


async def test_streamed_upload_without_length(http: httpx2.AsyncClient, nas_settings: NasSettings) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(4):
            yield b"x" * 100

    response = await http.put("/api/upload", params={"name": "stream.bin"}, content=chunks(), headers=WRITE)
    assert response.status_code == 201
    assert (nas_settings.root / "stream.bin").stat().st_size == 400


async def test_upload_too_large(http: httpx2.AsyncClient, nas_settings: NasSettings, audit: AuditLog) -> None:
    response = await http.put("/api/upload", params={"name": "big.bin"}, content=b"x" * 2048, headers=WRITE)
    assert response.status_code == 413

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(30):
            yield b"x" * 100

    streamed = await http.put("/api/upload", params={"name": "big.bin"}, content=chunks(), headers=WRITE)
    assert streamed.status_code == 413
    assert not (nas_settings.root / "big.bin").exists()
    assert not list(nas_settings.root.glob(f"{TEMP_PREFIX}*"))
    assert events(audit, "nas.upload_failed")[-1]["reason"] == "TooLargeError"


@pytest.mark.parametrize(
    "headers",
    [
        AUTH,
        {**AUTH, "X-NAS-Request": "0"},
        {**WRITE, "Sec-Fetch-Site": "cross-site"},
        {**WRITE, "Sec-Fetch-Site": "same-site"},
    ],
)
async def test_writes_need_the_anti_forgery_header(
    http: httpx2.AsyncClient, nas_settings: NasSettings, headers: dict[str, str]
) -> None:
    upload = await http.put("/api/upload", params={"name": "csrf.txt"}, content=b"x", headers=headers)
    assert upload.status_code == 403
    assert upload.json()["error"] == "csrf"
    mkdir = await http.post("/api/mkdir", json={"path": "", "name": "csrf"}, headers=headers)
    assert mkdir.status_code == 403
    assert not (nas_settings.root / "csrf.txt").exists()
    assert not (nas_settings.root / "csrf").exists()


async def test_same_origin_writes_are_accepted(http: httpx2.AsyncClient) -> None:
    headers = {**WRITE, "Sec-Fetch-Site": "same-origin"}
    response = await http.put("/api/upload", params={"name": "ok.txt"}, content=b"x", headers=headers)
    assert response.status_code == 201


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({"name": "../evil.txt"}, 400),
        ({"name": ""}, 400),
        ({"path": "missing", "name": "a.txt"}, 404),
        ({"path": "..", "name": "a.txt"}, 400),
        ({"name": f"{TEMP_PREFIX}x"}, 400),
    ],
)
async def test_upload_errors(http: httpx2.AsyncClient, params: dict[str, str], status: int) -> None:
    response = await http.put("/api/upload", params=params, content=b"x", headers=WRITE)
    assert response.status_code == status


# --- new folders --------------------------------------------------------------------------------------------
async def test_mkdir(http: httpx2.AsyncClient, nas_settings: NasSettings, audit: AuditLog) -> None:
    response = await http.post("/api/mkdir", json={"path": "Photos", "name": "2025"}, headers=WRITE)
    assert response.status_code == 201
    assert response.json() == {"path": "Photos/2025"}
    assert (nas_settings.root / "Photos" / "2025").is_dir()
    conflict = await http.post("/api/mkdir", json={"path": "Photos", "name": "2025"}, headers=WRITE)
    assert conflict.status_code == 409
    assert events(audit, "nas.mkdir")[0]["path"] == "Photos/2025"


@pytest.mark.parametrize(
    "body", [{"name": 3}, ["x"], {"path": 1, "name": "a"}, {"name": "a/b"}, {"name": ".."}]
)
async def test_mkdir_validation(http: httpx2.AsyncClient, body: Any) -> None:
    response = await http.post("/api/mkdir", json=body, headers=WRITE)
    assert response.status_code == 400


async def test_mkdir_needs_json(http: httpx2.AsyncClient) -> None:
    response = await http.post("/api/mkdir", content=b"not json", headers=WRITE)
    assert response.status_code == 400


# --- activity and serving -----------------------------------------------------------------------------------
async def test_activity_tracks_requests(http: httpx2.AsyncClient, activity: Activity) -> None:
    activity.last_request -= 100
    assert activity.idle_for() >= 100
    await http.get("/api/list", headers=AUTH)
    assert activity.in_flight == 0
    assert activity.idle_for() < 5


async def test_unexpected_errors_are_clean(http: httpx2.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from hermes_ngrok_mcp.nas.fs import NasRoot

    def explode(self: NasRoot, path: str) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(NasRoot, "list", explode)
    response = await http.get("/api/list", headers=AUTH)
    assert response.status_code == 500
    assert response.json()["error"] == "internal"
    assert "boom" not in response.text


def test_listening_socket_is_loopback_only(
    nas_settings: NasSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LISTEN_PID", raising=False)
    sock, origin = nas_cli.listening_socket(nas_settings.model_copy(update={"port": 0}))
    try:
        assert origin == "bind"
        assert sock.getsockname()[0] == "127.0.0.1"
    finally:
        sock.close()


def test_socket_activation(nas_settings: NasSettings, monkeypatch: pytest.MonkeyPatch) -> None:
    public = socket.socket()
    public.bind(("0.0.0.0", 0))  # noqa: S104 - must be refused
    saved = os.dup(3) if _fd_open(3) else None
    try:
        os.dup2(public.fileno(), 3)
        monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
        monkeypatch.setenv("LISTEN_FDS", "1")
        with pytest.raises(ValueError, match="loopback"):
            nas_cli.listening_socket(nas_settings)
        assert "LISTEN_FDS" not in os.environ
    finally:
        public.close()
        if saved is not None:
            os.dup2(saved, 3)
            os.close(saved)


def _fd_open(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True


def test_check_command(nas_settings: NasSettings, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = tmp_path / "nas.env"
    env.write_text(f"HERMES_NAS_ROOT={nas_settings.root}\nHERMES_NAS_ACCESS_KEY={KEY}\n")
    assert nas_cli.main(["--env-file", str(env), "check"]) == 0
    assert "access key       set" in capsys.readouterr().out
    env.write_text(f"HERMES_NAS_ROOT={tmp_path / 'missing'}\n")
    assert nas_cli.main(["--env-file", str(env), "check"]) == 1
    out = capsys.readouterr().out
    assert "ERROR: HERMES_NAS_ACCESS_KEY is empty" in out
    assert "is not a directory" in out
    assert nas_cli.main(["--env-file", str(env), "serve"]) == 2
    env.write_text("HERMES_NAS_HOST=0.0.0.0\n")
    assert nas_cli.main(["--env-file", str(env), "check"]) == 2


def test_audit_command(
    nas_settings: NasSettings, audit: AuditLog, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit.record("nas.upload", path="a.txt", size=1, source_ip="203.0.113.7")
    env = tmp_path / "nas.env"
    env.write_text(f"HERMES_NAS_STATE_DIR={nas_settings.state_dir}\n")
    assert nas_cli.main(["--env-file", str(env), "audit", "--since", "0"]) == 0
    out = capsys.readouterr().out
    assert "nas.upload" in out
    assert "203.0.113.7" in out


async def test_real_process_serves_then_exits_when_idle(nas_settings: NasSettings, tmp_path: Path) -> None:
    import asyncio
    import sys

    from tests.conftest import unused_port

    port = unused_port()
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith(("HERMES_NAS_", "LISTEN_"))},
        "HERMES_NAS_ROOT": str(nas_settings.root),
        "HERMES_NAS_ACCESS_KEY": KEY,
        "HERMES_NAS_PORT": str(port),
        "HERMES_NAS_IDLE_EXIT": "1",
        "HERMES_NAS_STATE_DIR": str(nas_settings.state_dir),
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "hermes_ngrok_mcp.nas.cli", "serve", env=env, stderr=asyncio.subprocess.PIPE
    )
    try:
        async with httpx2.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            for _ in range(100):
                try:
                    response = await client.get("/api/health", headers={ACCESS_KEY_HEADER: KEY})
                    break
                except httpx2.TransportError:
                    await asyncio.sleep(0.05)
            assert response.status_code == 200
            assert (await client.get("/api/health")).status_code == 403
        assert await asyncio.wait_for(process.wait(), timeout=15) == 0
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    events = [
        e["event"] for e in AuditLog(nas_settings.audit_file, clock=FakeClock(), tz=ZoneInfo("UTC")).query()
    ]
    assert events[0] == "nas.started"
    assert "nas.access_denied" in events
    stopped = AuditLog(nas_settings.audit_file, clock=FakeClock(), tz=ZoneInfo("UTC")).query(
        events={"nas.stopped"}
    )
    assert stopped[-1]["reason"] == "idle"
