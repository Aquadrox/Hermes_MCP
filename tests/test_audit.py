from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from hermes_ngrok_mcp import cli
from hermes_ngrok_mcp.audit import AuditLog, format_entry, summarize
from tests.conftest import FakeClock

UTC = ZoneInfo("UTC")


def make_audit(tmp_path: Path, clock: FakeClock, **kwargs: int) -> AuditLog:
    return AuditLog(tmp_path / "state" / "audit.jsonl", clock=clock, tz=UTC, **kwargs)


def test_events_are_appended_as_private_json_lines(tmp_path: Path, clock: FakeClock) -> None:
    audit = make_audit(tmp_path, clock)
    audit.record("tunnel.opened", tunnel_id="t1", local_port=8080, label=None)
    clock.advance(5)
    audit.record("tunnel.closed", tunnel_id="t1", sources={"203.0.113.7": 2})
    assert audit.path is not None
    lines = [json.loads(line) for line in audit.path.read_text().splitlines()]
    assert [entry["event"] for entry in lines] == ["tunnel.opened", "tunnel.closed"]
    assert lines[0]["origin"] == "service"
    assert "label" not in lines[0]  # None values are omitted
    assert lines[1]["ts"] - lines[0]["ts"] == 5
    assert lines[1]["time"].endswith("+00:00")
    assert stat.S_IMODE(audit.path.stat().st_mode) == 0o600


def test_query_filters_by_window_category_and_limit(tmp_path: Path, clock: FakeClock) -> None:
    audit = make_audit(tmp_path, clock)
    audit.record("mfa.rejected", reason="invalid_code")
    clock.advance(3600)
    audit.record("tunnel.opened", tunnel_id="t1")
    audit.record("mfa.verified")
    audit.record("connection.closed", tunnel_id="t1", source_ip="203.0.113.7")
    assert len(audit.query()) == 4
    assert [e["event"] for e in audit.query(category="mfa")] == ["mfa.rejected", "mfa.verified"]
    assert [e["event"] for e in audit.query(since=clock.time() - 60)] == [
        "tunnel.opened",
        "mfa.verified",
        "connection.closed",
    ]
    assert [e["event"] for e in audit.query(limit=1)] == ["connection.closed"]
    assert audit.query(events={"tunnel.opened"})[0]["tunnel_id"] == "t1"


def test_rotation_keeps_history_queryable(tmp_path: Path, clock: FakeClock) -> None:
    audit = make_audit(tmp_path, clock, max_bytes=300, backups=2)
    for index in range(30):
        audit.record("mcp.tool_call", tool="tunnel_status", index=index)
    assert audit.path is not None
    assert audit.path.with_name("audit.jsonl.1").exists()
    assert audit.path.with_name("audit.jsonl.2").exists()
    assert not audit.path.with_name("audit.jsonl.3").exists()
    indexes = [entry["index"] for entry in audit.query(limit=0)]
    assert indexes == sorted(indexes)
    assert indexes[-1] == 29


def test_recording_never_raises(tmp_path: Path, clock: FakeClock, caplog: pytest.LogCaptureFixture) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    audit = AuditLog(blocker / "audit.jsonl", clock=clock, tz=UTC)
    with caplog.at_level("INFO", logger="hermes_ngrok_mcp.audit"):
        audit.record("service.started")  # the parent is a file: writing fails, quietly
    assert "cannot write the audit log" in caplog.text
    assert "AUDIT" in caplog.text


def test_journal_only_audit(clock: FakeClock, caplog: pytest.LogCaptureFixture) -> None:
    audit = AuditLog(None, clock=clock, tz=UTC)
    with caplog.at_level("INFO", logger="hermes_ngrok_mcp.audit"):
        audit.record("service.started", version="1")
    assert '"event":"service.started"' in caplog.text
    assert audit.query() == []


def test_summary_counts_attempts_and_sources() -> None:
    entries = [
        {"event": "tunnel.opened"},
        {"event": "tunnel.closed"},
        {"event": "tunnel.open_failed"},
        {"event": "mfa.verified"},
        {"event": "mfa.rejected"},
        {"event": "mfa.rejected"},
        {"event": "mfa.locked"},
        {"event": "mcp.tool_call", "outcome": "ok"},
        {"event": "mcp.tool_call", "outcome": "error"},
        {"event": "mcp.auth_rejected", "source_ip": "127.0.0.1"},
        {"event": "connection.closed", "source_ip": "203.0.113.7"},
        {"event": "connection.closed", "source_ip": "203.0.113.7"},
        {"event": "connection.closed", "source_ip": "198.51.100.1"},
    ]
    summary = summarize(entries)
    assert (summary.tunnels_opened, summary.tunnels_closed, summary.tunnel_open_failures) == (1, 1, 1)
    assert (summary.mfa_successes, summary.mfa_failures, summary.mfa_lockouts) == (1, 2, 1)
    assert (summary.mcp_tool_calls, summary.mcp_tool_errors, summary.mcp_auth_rejections) == (2, 1, 1)
    assert summary.connections == 3
    assert summary.top_sources()[0] == ("203.0.113.7", 2)


def test_format_entry() -> None:
    line = format_entry(
        {"ts": 1, "time": "T", "event": "tunnel.opened", "origin": "service", "local_port": 80}
    )
    assert line.startswith("T  tunnel.opened")
    assert "local_port=80" in line


def test_audit_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = tmp_path / "test.env"
    env.write_text(f"HERMES_NGROK_STATE_DIR={tmp_path / 'state'}\nHERMES_NGROK_TIMEZONE=UTC\n")
    audit = AuditLog(tmp_path / "state" / "audit.jsonl", clock=FakeClock(start=4_000_000_000), tz=UTC)
    audit.record("connection.closed", tunnel_id="t1", source_ip="203.0.113.7")
    audit.record("mfa.rejected", reason="invalid_code")
    assert cli.main(["--env-file", str(env), "audit", "--since", "0"]) == 0
    out = capsys.readouterr().out
    assert "connection.closed" in out
    assert re.search(r"MFA codes accepted / rejected\s+0 / 1", out)
    assert "203.0.113.7" in out
    assert cli.main(["--env-file", str(env), "audit", "--since", "0", "--json", "--category", "mfa"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["mfa.rejected"]
    assert cli.main(["--env-file", str(env), "audit", "--since", "soon"]) == 2
