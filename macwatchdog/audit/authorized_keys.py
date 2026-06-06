"""SSH authorized_keys audit.

Checks ~/.ssh/authorized_keys for the current user, root (/var/root on macOS),
and all accounts under /Users/. Any populated authorized_keys file grants
passwordless SSH access and is a high-priority finding.
"""

from __future__ import annotations

from pathlib import Path

from ..result import CheckResult
from ..severity import Severity


def _home_dirs() -> list[Path]:
    candidates: list[Path] = [
        Path.home(),
        Path("/var/root"),          # root on macOS (not /root)
    ]
    users = Path("/Users")
    if users.is_dir():
        for d in sorted(users.iterdir()):
            if d.is_dir() and not d.name.startswith(".") and d not in candidates:
                candidates.append(d)
    return candidates


def _read_keys(ak_path: Path) -> list[str]:
    try:
        return [
            ln.strip() for ln in ak_path.read_text(errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    except (PermissionError, OSError):
        return []


def check_authorized_keys() -> CheckResult:
    findings: list[str] = []

    for home in _home_dirs():
        ak = home / ".ssh" / "authorized_keys"
        if not ak.exists():
            continue
        keys = _read_keys(ak)
        if not keys:
            continue
        findings.append(f"{ak}  [{len(keys)} key(s)]")
        for key in keys[:3]:
            preview = key[:100] + ("…" if len(key) > 100 else "")
            findings.append(f"  {preview}")
        if len(keys) > 3:
            findings.append(f"  … and {len(keys) - 3} more")

    if findings:
        return CheckResult(
            label="SSH Authorized Keys",
            status="ALERT",
            severity=Severity.HIGH,
            info=findings,
            tip="Each key in authorized_keys grants passwordless SSH login. Remove any you don't recognise.",
        )

    return CheckResult(
        label="SSH Authorized Keys",
        status="OK",
        info="none found",
    )
