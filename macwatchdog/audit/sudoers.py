"""Sudoers configuration audit.

Parses /etc/sudoers and all files under /etc/sudoers.d/ for NOPASSWD entries,
which allow privilege escalation without a password prompt.

Requires root — returns UNKNOWN if run as a standard user.
"""

from __future__ import annotations

from pathlib import Path

from ..result import CheckResult
from ..severity import Severity

_SUDOERS_FILE = Path("/etc/sudoers")
_SUDOERS_D = Path("/etc/sudoers.d")


def _parse_nopasswd(path: Path) -> list[str]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except (PermissionError, OSError):
        raise
    entries: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "NOPASSWD" in stripped:
            entries.append(f"{path.name}: {stripped}")
    return entries


def check_sudoers() -> CheckResult:
    targets: list[Path] = []
    if _SUDOERS_FILE.exists():
        targets.append(_SUDOERS_FILE)
    if _SUDOERS_D.is_dir():
        targets.extend(sorted(_SUDOERS_D.iterdir()))

    if not targets:
        return CheckResult(
            "Sudoers Configuration", "SKIPPED",
            info="No sudoers files found.",
        )

    nopasswd: list[str] = []
    for path in targets:
        try:
            nopasswd.extend(_parse_nopasswd(path))
        except (PermissionError, OSError):
            # Either access denied or I/O error — treat as unreadable.
            # Return immediately; remaining files in the loop are also likely
            # unreadable so we'd just accumulate the same UNKNOWN verdict.
            return CheckResult(
                label="Sudoers Configuration",
                status="UNKNOWN",
                severity=Severity.INFO,
                info="Cannot read sudoers — requires root.",
                tip="Run as root ('sudo macwatchdog') for a complete sudoers check.",
            )

    if nopasswd:
        return CheckResult(
            label="Sudoers Configuration",
            status="ALERT",
            severity=Severity.HIGH,
            info=nopasswd,
            tip="NOPASSWD entries let a user run commands as root without a password. Remove any you don't explicitly intend.",
        )

    return CheckResult(
        label="Sudoers Configuration",
        status="OK",
        info=f"no NOPASSWD entries  ({len(targets)} file(s) checked)",
    )
