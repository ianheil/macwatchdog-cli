"""Filesystem permission checks."""

from __future__ import annotations

import os
from pathlib import Path

from ..result import CheckResult
from ..severity import Severity

SENSITIVE_PATHS: tuple[str, ...] = (
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    os.path.expanduser("~/Library/LaunchAgents"),
    "/etc",
    "/usr/local/bin",
    "/usr/local/sbin",
)


def is_world_writable(path: str | os.PathLike[str]) -> bool:
    """Return ``True`` if the ``other`` write bit (``0o002``) is set on ``path``.

    Returns ``False`` for paths that don't exist or can't be stat'd.
    """
    try:
        return bool(os.stat(path).st_mode & 0o002)
    except OSError:
        return False


def check_world_writable() -> CheckResult:
    """Flag world-writable files in sensitive locations."""
    suspicious: list[str] = []
    for path in SENSITIVE_PATHS:
        if not os.path.exists(path):
            continue
        try:
            entries = os.listdir(path)
        except PermissionError:
            continue
        for entry in entries:
            full = os.path.join(path, entry)
            if is_world_writable(full):
                suspicious.append(full)

    if suspicious:
        return CheckResult(
            label="World-writable/Suspicious Files",
            status="ALERT",
            severity=Severity.HIGH,
            info=suspicious,
            tip="World-writable files in sensitive locations can be abused by malware. Remove or restrict permissions with 'chmod o-w <path>'.",
        )
    return CheckResult(
        label="World-writable/Suspicious Files",
        status="OK",
        severity=Severity.OK,
        info="none found",
    )
