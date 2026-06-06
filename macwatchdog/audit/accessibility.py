"""Apps with Accessibility or Full Disk Access.

This is a focused view of the TCC data; see :mod:`.tcc` for the general case.
"""

from __future__ import annotations

from ..result import CheckResult
from ..severity import Severity
from .tcc import SYSTEM_DB, USER_DB, _query_allowed


def check_accessibility_apps() -> CheckResult:
    services = [
        ("Accessibility", "kTCCServiceAccessibility"),
        ("Full Disk Access", "kTCCServiceSystemPolicyAllFiles"),
    ]

    fda_denied = False
    findings: list[str] = []
    any_data = False

    for label, service in services:
        user_clients, user_err = _query_allowed(USER_DB, service)
        system_clients, system_err = _query_allowed(SYSTEM_DB, service)
        if "fda-denied" in (user_err, system_err):
            fda_denied = True
        if user_err != "missing" or system_err != "missing":
            any_data = True
        clients = sorted(set(user_clients + system_clients))
        if clients:
            findings.append(f"{label}: {', '.join(clients)}")

    if fda_denied:
        return CheckResult(
            label="Accessibility/Full Disk Access",
            status="SKIPPED",
            severity=Severity.INFO,
            tip="Grant Full Disk Access to terminal in System Settings > Privacy & Security.",
        )
    if not any_data:
        return CheckResult(
            label="Accessibility/Full Disk Access",
            status="OK",
            severity=Severity.OK,
            info=["TCC.db not available on this machine."],
        )
    if not findings:
        return CheckResult(
            label="Accessibility/Full Disk Access",
            status="OK",
            severity=Severity.OK,
            info=["No apps with Accessibility or Full Disk Access found."],
        )
    return CheckResult(
        label="Accessibility/Full Disk Access",
        status="INFO",
        severity=Severity.INFO,
        info=findings,
        tip="Only trusted apps should hold Accessibility or Full Disk Access.",
    )
