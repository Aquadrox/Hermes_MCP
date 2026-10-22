from __future__ import annotations

import json
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest

from hermes_ngrok_mcp.mfa import (
    MAX_LOCKOUT,
    MfaCodeFormatError,
    MfaCodeReusedError,
    MfaEnrollmentError,
    MfaInvalidCodeError,
    MfaLockedError,
    MfaManager,
    MfaNotConfiguredError,
)
from hermes_ngrok_mcp.storage import JsonStateFile
from tests.conftest import FakeClock, totp_code


def make_manager(tmp_path: Path, clock: FakeClock, **kwargs: int) -> MfaManager:
    return MfaManager(
        JsonStateFile(tmp_path / "state" / "mfa.json"),
        clock=clock,
        issuer="Hermes ngrok",
        account="hermes@vps",
        **kwargs,
    )


def enroll(manager: MfaManager, clock: FakeClock) -> str:
    enrollment = manager.begin_enrollment()
    manager.confirm_enrollment(totp_code(enrollment.secret, clock))
    clock.advance(30)  # the confirmation code is consumed; move to the next step
    return enrollment.secret


def test_enrollment_round_trip(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock)
    assert not manager.status().configured
    enrollment = manager.begin_enrollment()

    assert len(enrollment.secret) == 32  # 160 bits in base32
    assert pyotp.utils.strings_equal(enrollment.grouped_secret.replace(" ", ""), enrollment.secret)
    uri = urlsplit(enrollment.uri)
    assert uri.scheme == "otpauth"
    assert uri.netloc == "totp"
    query = parse_qs(uri.query)
    assert query["secret"] == [enrollment.secret]
    assert query["issuer"] == ["Hermes ngrok"]
    assert enrollment.qr_png().startswith(b"\x89PNG")
    assert "█" in enrollment.qr_terminal() or "▀" in enrollment.qr_terminal()

    # Nothing is written until the enrollment is confirmed.
    assert not (tmp_path / "state" / "mfa.json").exists()
    assert manager.status().enrollment_pending

    manager.confirm_enrollment(totp_code(enrollment.secret, clock))
    status = manager.status()
    assert status.configured
    assert not status.enrollment_pending
    state_file = tmp_path / "state" / "mfa.json"
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_file.parent.stat().st_mode) == 0o700
    assert json.loads(state_file.read_text())["totp"]["secret"] == enrollment.secret


def test_confirm_requires_pending_enrollment(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock)
    with pytest.raises(MfaEnrollmentError, match="No MFA enrollment"):
        manager.confirm_enrollment("123456")


def test_enrollment_expires(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock, enrollment_ttl=600)
    enrollment = manager.begin_enrollment()
    clock.advance(601)
    with pytest.raises(MfaEnrollmentError, match="expired"):
        manager.confirm_enrollment(totp_code(enrollment.secret, clock))


def test_verify_accepts_each_code_once(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock)
    secret = enroll(manager, clock)
    code = totp_code(secret, clock)
    manager.verify(code)
    with pytest.raises(MfaCodeReusedError):
        manager.verify(code)
    clock.advance(30)
    manager.verify(totp_code(secret, clock))


def test_verify_tolerates_one_step_of_clock_drift(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock, valid_window=1)
    secret = enroll(manager, clock)
    manager.verify(totp_code(secret, clock, offset_steps=1))  # phone slightly ahead
    with pytest.raises(MfaCodeReusedError):
        # still inside the window, but older than the step already used: a replay
        manager.verify(totp_code(secret, clock))
    clock.advance(90)
    manager.verify(totp_code(secret, clock, offset_steps=-1))  # phone slightly behind
    clock.advance(90)
    with pytest.raises(MfaInvalidCodeError):
        manager.verify(totp_code(secret, clock, offset_steps=-2))  # too old


def test_codes_are_normalised(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock)
    secret = enroll(manager, clock)
    code = totp_code(secret, clock)
    manager.verify(f" {code[:3]} {code[3:]} ")


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12345a", "١٢٣٤٥٦"])
def test_malformed_codes_do_not_count_as_failures(tmp_path: Path, clock: FakeClock, bad: str) -> None:
    manager = make_manager(tmp_path, clock)
    enroll(manager, clock)
    with pytest.raises(MfaCodeFormatError):
        manager.verify(bad)
    assert manager.status().recent_failures == 0


def test_lockout_after_repeated_failures(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock, max_failures=3, lockout=900, failure_window=300)
    secret = enroll(manager, clock)
    wrong = "000000" if totp_code(secret, clock) != "000000" else "111111"
    with pytest.raises(MfaInvalidCodeError) as first:
        manager.verify(wrong)
    assert first.value.remaining_attempts == 2
    with pytest.raises(MfaInvalidCodeError):
        manager.verify(wrong)
    with pytest.raises(MfaLockedError) as locked:
        manager.verify(wrong)
    assert locked.value.newly_locked
    assert locked.value.retry_after == 900

    # Even the right code is refused while locked, and the lock survives a restart.
    restarted = make_manager(tmp_path, clock, max_failures=3, lockout=900)
    with pytest.raises(MfaLockedError) as still_locked:
        restarted.verify(totp_code(secret, clock))
    assert not still_locked.value.newly_locked
    assert restarted.status().locked_until is not None

    clock.advance(901)
    restarted.verify(totp_code(secret, clock))
    assert restarted.status().locked_until is None


def test_consecutive_lockouts_double_until_a_code_is_accepted(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock, max_failures=1, lockout=100)
    secret = enroll(manager, clock)

    def fail() -> int:
        wrong = "000000" if totp_code(secret, clock) != "000000" else "111111"
        with pytest.raises(MfaLockedError) as info:
            manager.verify(wrong)
        assert info.value.newly_locked
        return info.value.retry_after

    durations = []
    for _ in range(3):
        durations.append(fail())
        clock.advance(durations[-1] + 1)
    assert durations == [100, 200, 400]
    manager.verify(totp_code(secret, clock))
    assert fail() == 100

    capped = make_manager(tmp_path, clock, max_failures=1, lockout=MAX_LOCKOUT)
    clock.advance(MAX_LOCKOUT + 1)
    wrong = "000000" if totp_code(secret, clock) != "000000" else "111111"
    with pytest.raises(MfaLockedError) as info:
        capped.verify(wrong)
    assert info.value.retry_after == MAX_LOCKOUT


def test_failures_outside_the_window_are_forgotten(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock, max_failures=2, failure_window=60)
    secret = enroll(manager, clock)
    wrong = "000000" if totp_code(secret, clock) != "000000" else "111111"
    with pytest.raises(MfaInvalidCodeError):
        manager.verify(wrong)
    clock.advance(61)
    wrong = "000000" if totp_code(secret, clock) != "000000" else "111111"
    with pytest.raises(MfaInvalidCodeError):
        manager.verify(wrong)


def test_verify_without_configuration(tmp_path: Path, clock: FakeClock) -> None:
    with pytest.raises(MfaNotConfiguredError):
        make_manager(tmp_path, clock).verify("123456")


def test_rotation_requires_a_current_code(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock)
    old_secret = enroll(manager, clock)
    with pytest.raises(MfaEnrollmentError, match="already configured"):
        manager.begin_enrollment()

    rotation = manager.begin_enrollment(totp_code(old_secret, clock))
    assert rotation.rotation
    # The old secret stays active until the new one is confirmed.
    assert json.loads((tmp_path / "state" / "mfa.json").read_text())["totp"]["secret"] == old_secret
    manager.confirm_enrollment(totp_code(rotation.secret, clock))
    clock.advance(30)
    manager.verify(totp_code(rotation.secret, clock))
    with pytest.raises(MfaInvalidCodeError):
        manager.verify(totp_code(old_secret, clock, offset_steps=1))


def test_forced_rotation_and_reset(tmp_path: Path, clock: FakeClock) -> None:
    manager = make_manager(tmp_path, clock)
    enroll(manager, clock)
    assert manager.begin_enrollment(force=True).rotation
    manager.reset()
    assert not manager.status().configured
    assert not manager.status().enrollment_pending
    with pytest.raises(MfaNotConfiguredError):
        manager.verify("123456")


def test_state_is_shared_between_instances(tmp_path: Path, clock: FakeClock) -> None:
    service = make_manager(tmp_path, clock)
    admin = make_manager(tmp_path, clock)
    secret = enroll(service, clock)
    code = totp_code(secret, clock)
    admin.verify(code)
    with pytest.raises(MfaCodeReusedError):
        service.verify(code)
    admin.reset()
    assert not service.is_configured()


def test_corrupted_state_file_is_reported(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "state" / "mfa.json"
    path.parent.mkdir(mode=0o700)
    path.write_text("[]")
    with pytest.raises(ValueError, match="corrupted"):
        make_manager(tmp_path, clock).status()
