"""TCC (privacy) permissions audit.

Queries both the user and system ``TCC.db`` via the stdlib :mod:`sqlite3`
module with parameterised statements and returns the list of clients granted
each sensitive service.

Reading either database requires Full Disk Access for the invoking process.
When access is denied the check returns ``SKIPPED`` and points at the FDA-free
``App Privacy Capabilities`` check instead of demanding the user grant FDA
to their terminal.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from ..result import CheckResult
from ..severity import Severity

USER_DB = Path(os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db"))
SYSTEM_DB = Path("/Library/Application Support/com.apple.TCC/TCC.db")

SENSITIVE_SERVICES: list[tuple[str, str]] = [
    ("Screen Recording", "kTCCServiceScreenCapture"),
    ("Input Monitoring", "kTCCServiceListenEvent"),
    ("Camera", "kTCCServiceCamera"),
    ("Microphone", "kTCCServiceMicrophone"),
    ("Location", "kTCCServiceLocation"),
    ("Full Disk Access", "kTCCServiceSystemPolicyAllFiles"),
    ("Automation", "kTCCServiceAppleEvents"),
    ("Accessibility", "kTCCServiceAccessibility"),
]


def _query_allowed(db: Path, service: str) -> tuple[list[str], str | None]:
    """Return ``(clients, error)`` for ``service`` in ``db``.

    ``error`` is ``None`` on success or one of ``"missing"`` (DB absent),
    ``"fda-denied"`` (OS refused the open), or ``f"error: {exc}"``.
    """
    if not db.exists():
        return [], "missing"
    try:
        uri = f"file:{db}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2.0) as conn:
            # ``auth_value`` is used on 10.15+; fall back to ``allowed``.
            try:
                rows = conn.execute(
                    "SELECT client FROM access WHERE service = ? AND auth_value >= 2",
                    (service,),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute(
                    "SELECT client FROM access WHERE service = ? AND allowed = 1",
                    (service,),
                ).fetchall()
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if "authorization denied" in message or "unable to open" in message:
            return [], "fda-denied"
        return [], f"error: {exc}"
    except sqlite3.DatabaseError as exc:
        return [], f"error: {exc}"

    return sorted({row[0] for row in rows if row and row[0]}), None


def check_tcc_permissions() -> CheckResult:
    denied = False
    missing = True
    findings: list[str] = []

    for label, service in SENSITIVE_SERVICES:
        user_clients, user_err = _query_allowed(USER_DB, service)
        system_clients, system_err = _query_allowed(SYSTEM_DB, service)
        if user_err != "missing" or system_err != "missing":
            missing = False
        if user_err == "fda-denied" or system_err == "fda-denied":
            denied = True
        clients = sorted(set(user_clients + system_clients))
        if clients:
            findings.append(f"{label}: {', '.join(clients)}")

    if denied:
        return CheckResult(
            label="TCC Privacy Permissions",
            status="SKIPPED",
            severity=Severity.INFO,
            tip="Grant Full Disk Access to macWatchdog in System Settings > Privacy & Security.",
        )

    if missing:
        return CheckResult(
            label="TCC Privacy Permissions",
            status="UNKNOWN",
            severity=Severity.INFO,
            info=["Neither user nor system TCC.db is present on this machine."],
        )

    if not findings:
        return CheckResult(
            label="TCC Privacy Permissions",
            status="OK",
            severity=Severity.OK,
            info="",
        )

    return CheckResult(
        label="TCC Privacy Permissions",
        status="INFO",
        severity=Severity.INFO,
        info=findings,
        tip="Review which apps have sensitive permissions and revoke any you don't recognise in System Settings > Privacy & Security.",
    )
