"""MDM and DEP enrollment check."""

from __future__ import annotations

import os

from ..proc import run
from ..result import CheckResult
from ..severity import Severity


def check_mdm_and_dep() -> CheckResult:
    cmd = ["profiles", "status", "-type", "enrollment"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd

    result = run(cmd, timeout=10)

    if result.missing:
        return CheckResult(
            label="MDM & DEP Enrollment",
            status="UNKNOWN",
            severity=Severity.INFO,
            info="`profiles` binary not found on this system.",
        )

    # sudo -n fails with a password prompt message — surface as UNKNOWN, not OK
    stderr_lower = result.stderr.lower()
    if not result.ok or "a password is required" in stderr_lower or "sudo" in stderr_lower:
        return CheckResult(
            label="MDM & DEP Enrollment",
            status="UNKNOWN",
            severity=Severity.INFO,
            tip="Run as root ('sudo macwatchdog') for accurate MDM/DEP enrollment status.",
        )

    output = result.stdout.strip()
    enrolled = "MDM enrollment: Yes" in output
    dep = "Enrolled via DEP: Yes" in output
    info = [line.strip() for line in output.splitlines() if "MDM enrollment:" in line or "Enrolled via DEP:" in line]

    return CheckResult(
        label="MDM & DEP Enrollment",
        status="ALERT" if enrolled else "OK",
        severity=Severity.MEDIUM if enrolled else Severity.OK,
        info=info if info else "",
        extras={"dep_enrolled": dep, "mdm_enrolled": enrolled},
    )
