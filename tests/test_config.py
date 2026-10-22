from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes_ngrok_mcp.config import PortRanges, Settings, load_settings
from hermes_ngrok_mcp.durations import format_duration, parse_duration


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("600", 600),
        (600, 600),
        (0, 0),
        ("10m", 600),
        ("10min", 600),
        ("1h30m", 5_400),
        ("90s", 90),
        ("2d", 172_800),
        (" 20 m ", 1_200),
        (30.0, 30),
    ],
)
def test_parse_duration(raw: object, expected: int) -> None:
    assert parse_duration(raw) == expected


@pytest.mark.parametrize("raw", ["", "abc", "-5", "1h30", "10x", True, 1.5, None, -1])
def test_parse_duration_rejects(raw: object) -> None:
    with pytest.raises(ValueError, match="duration"):
        parse_duration(raw)


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(45, "45 s"), (150, "2 min 30 s"), (600, "10 min"), (3_900, "1 h 05 min"), (7_200, "2 h"), (-3, "0 s")],
)
def test_format_duration(seconds: float, text: str) -> None:
    assert format_duration(seconds) == text


def test_defaults_match_the_requested_policy(tmp_path: Path) -> None:
    settings = Settings(state_dir=tmp_path)
    assert settings.idle_timeout == 600  # closed after 10 min without use
    assert settings.max_lifetime == 1_200  # hard limit of 20 min
    assert settings.max_lifetime - settings.expiry_warning == 900  # warning at 15 min
    assert settings.extension == 1_200
    assert settings.basic_auth is True
    assert settings.host == "127.0.0.1"
    assert settings.host_is_loopback
    assert not settings.telegram_enabled
    assert settings.ngrok_authtoken is None


def test_environment_and_aliases(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NGROK_AUTHTOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987")
    monkeypatch.setenv("HERMES_NGROK_IDLE_TIMEOUT", "5m")
    monkeypatch.setenv("HERMES_NGROK_MAX_LIFETIME", "1h")
    monkeypatch.setenv("HERMES_NGROK_DENIED_PORTS", "22, 5432,6000-6100")
    monkeypatch.setenv("HERMES_NGROK_STATE_DIR", str(tmp_path))
    settings = Settings()
    assert settings.ngrok_authtoken is not None
    assert settings.ngrok_authtoken.get_secret_value() == "tok"
    assert settings.telegram_enabled
    assert settings.telegram_chat_id == "987"
    assert settings.idle_timeout == 300
    assert settings.max_lifetime == 3_600
    assert 22 in settings.denied_ports
    assert 6050 in settings.denied_ports
    assert 8080 not in settings.denied_ports
    assert str(settings.denied_ports) == "22,5432,6000-6100"


def test_env_file_is_loaded_and_environment_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_file = tmp_path / "service.env"
    env_file.write_text(
        "NGROK_AUTHTOKEN=from-file\nHERMES_NGROK_LANGUAGE=en\nHERMES_NGROK_EXPIRY_WARNING='2m'\n"
        f"HERMES_NGROK_STATE_DIR={tmp_path}\n"
    )
    monkeypatch.setenv("HERMES_NGROK_LANGUAGE", "fr")
    settings = load_settings(env_file)
    assert settings.ngrok_authtoken is not None
    assert settings.ngrok_authtoken.get_secret_value() == "from-file"
    assert settings.language == "fr"
    assert settings.expiry_warning == 120


def test_missing_env_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_settings(tmp_path / "nope.env")


def test_blank_values_mean_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NGROK_AUTHTOKEN", "  ")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")
    monkeypatch.setenv("HERMES_NGROK_DOMAIN", "")
    settings = Settings(state_dir=tmp_path)
    assert settings.ngrok_authtoken is None
    assert not settings.telegram_enabled
    assert settings.domain is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"expiry_warning": 1_200, "max_lifetime": 1_200}, "expiry_warning"),
        ({"telegram_bot_token": "1:a"}, "TELEGRAM_CHAT_ID"),
        ({"timezone": "Mars/Olympus"}, "timezone"),
        ({"denied_ports": "0-10"}, "port range"),
        ({"allowed_ports": "abc"}, "port range"),
        ({"extension": 0}, "extension"),
        ({"telegram_api_base": "ftp://x"}, "http"),
        ({"basic_auth_user": "bad:user"}, "basic_auth_user"),
    ],
)
def test_invalid_settings(tmp_path: Path, overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(state_dir=tmp_path, **overrides)  # type: ignore[arg-type]


def test_lifetime_can_be_disabled(tmp_path: Path) -> None:
    settings = Settings(state_dir=tmp_path, max_lifetime=0, idle_timeout="0")
    assert settings.max_lifetime == 0
    assert settings.idle_timeout == 0


def test_port_ranges() -> None:
    ranges = PortRanges.parse("80, 8000-8002")
    assert 80 in ranges
    assert 8001 in ranges
    assert 8003 not in ranges
    assert "80" not in ranges
    assert ranges == PortRanges.parse("80,8000-8002")
    assert not PortRanges.parse("")


def test_state_dir_follows_systemd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STATE_DIRECTORY", f"{tmp_path}/a:{tmp_path}/b")
    assert Settings().state_dir == tmp_path / "a"
