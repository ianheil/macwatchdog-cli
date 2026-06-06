import os
import stat

from macwatchdog.audit.permissions import is_world_writable


def test_is_world_writable_true_for_o_plus_w(tmp_path):
    target = tmp_path / "f"
    target.write_text("x")
    os.chmod(target, 0o666)
    assert is_world_writable(target)


def test_is_world_writable_false_for_o_minus_w(tmp_path):
    target = tmp_path / "f"
    target.write_text("x")
    os.chmod(target, 0o644)
    assert not is_world_writable(target)


def test_is_world_writable_respects_mode_not_euid(tmp_path):
    target = tmp_path / "f"
    target.write_text("x")
    os.chmod(target, 0o600)  # user-writable but not world-writable
    assert not is_world_writable(target)


def test_is_world_writable_handles_missing_path(tmp_path):
    assert not is_world_writable(tmp_path / "nope")
