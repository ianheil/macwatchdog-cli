"""Remote login (SSH) check."""

from __future__ import annotations

from ..proc import run
from ..result import CheckResult
from ..severity import Severity


def check_remote_management() -> CheckResult:
    result = run(["systemsetup", "-getremotelogin"], timeout=10)
    if result.missing:
        return CheckResult(
            label="Remote Login (SSH)",
            status="UNKNOWN",
            severity=Severity.INFO,
            info=["`systemsetup` binary not found."],
        )
    output = (result.stdout or "").strip()
    # systemsetup prints an admin-error to stdout on some macOS versions even with exit 0
    if not output or "administrator access" in output.lower() or "exiting" in output.lower():
        return CheckResult(
            label="Remote Login (SSH)",
            status="UNKNOWN",
            severity=Severity.INFO,
            tip="Run as root ('sudo macwatchdog') to check SSH remote login state.",
        )
    enabled = output.lower().rstrip(".").endswith("on")
    return CheckResult(
        label="Remote Login (SSH)",
        status="ALERT" if enabled else "OK",
        severity=Severity.MEDIUM if enabled else Severity.OK,
        info="enabled" if enabled else "disabled",
        tip="SSH should only be enabled when you actively use it." if enabled else "",
    )
