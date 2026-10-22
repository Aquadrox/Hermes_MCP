from __future__ import annotations

from pathlib import Path

import pyotp
import pytest

from hermes_ngrok_mcp import cli

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@pytest.fixture(autouse=True)
def _no_global_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "configure_logging", lambda level: None)


def write_env(tmp_path: Path, **values: str) -> Path:
    defaults = {
        "NGROK_AUTHTOKEN": "tok",
        "HERMES_NGROK_API_TOKEN": "a" * 43,
        "HERMES_NGROK_STATE_DIR": str(tmp_path / "state"),
        "HERMES_NGROK_MFA_ACCOUNT": "hermes@test",
    }
    defaults.update(values)
    path = tmp_path / "service.env"
    path.write_text("".join(f"{key}={value}\n" for key, value in defaults.items()))
    return path


def test_token(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["token"]) == 0
    token = capsys.readouterr().out.strip()
    assert len(token) >= 43


def test_check_reports_problems(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = write_env(tmp_path, NGROK_AUTHTOKEN="", HERMES_NGROK_API_TOKEN="short")
    assert cli.main(["--env-file", str(env), "check"]) == 1
    out = capsys.readouterr().out
    assert "ERROR: NGROK_AUTHTOKEN is empty" in out
    assert "at least 32 characters" in out
    assert "WARNING: MFA is not configured" in out


def test_check_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = write_env(tmp_path)
    assert cli.main(["--env-file", str(env), "check"]) == 0
    assert "ERROR" not in capsys.readouterr().out


def test_invalid_configuration(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = write_env(tmp_path, HERMES_NGROK_IDLE_TIMEOUT="soon")
    assert cli.main(["--env-file", str(env), "check"]) == 2
    assert "Invalid configuration" in capsys.readouterr().err


def test_mfa_lifecycle_from_the_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env = str(write_env(tmp_path))
    monkeypatch.setattr("hermes_ngrok_mcp.mfa.generate_secret", lambda: SECRET)
    answers = iter(["000000", pyotp.TOTP(SECRET).now()])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    assert cli.main(["--env-file", env, "mfa", "setup"]) == 0
    out = capsys.readouterr()
    assert "JBSW Y3DP" in out.out
    assert "MFA configured." in out.out

    assert cli.main(["--env-file", env, "mfa", "status"]) == 0
    assert "configured: True" in capsys.readouterr().out
    assert cli.main(["--env-file", env, "mfa", "setup"]) == 1

    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert cli.main(["--env-file", env, "mfa", "reset"]) == 1
    assert cli.main(["--env-file", env, "mfa", "reset", "--yes"]) == 0
    capsys.readouterr()
    assert cli.main(["--env-file", env, "mfa", "status"]) == 0
    assert "configured: False" in capsys.readouterr().out


def test_mfa_setup_gives_up_after_three_wrong_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = str(write_env(tmp_path))
    monkeypatch.setattr("builtins.input", lambda prompt="": "000000")
    assert cli.main(["--env-file", env, "mfa", "setup"]) == 1


def test_notify_test_requires_telegram(tmp_path: Path) -> None:
    assert cli.main(["--env-file", str(write_env(tmp_path)), "notify-test"]) == 1


def test_serve_http_requires_an_api_token(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = write_env(tmp_path, HERMES_NGROK_API_TOKEN="")
    assert cli.main(["--env-file", str(env), "serve"]) == 2
    assert "HERMES_NGROK_API_TOKEN is required" in capsys.readouterr().err


@pytest.mark.anyio
async def test_stdio_transport_in_a_real_process(tmp_path: Path) -> None:
    import os
    import sys

    from mcp import Client, StdioServerParameters

    env = {**os.environ, "HERMES_NGROK_STATE_DIR": str(tmp_path / "state")}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "hermes_ngrok_mcp", "serve", "--transport", "stdio"], env=env
    )
    async with Client(params) as client:
        tools = await client.list_tools()
        assert "tunnel_open" in {tool.name for tool in tools.tools}
        status = await client.call_tool("mfa_status", {})
        assert status.structured_content is not None
        assert status.structured_content["configured"] is False
