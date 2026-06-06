"""Cron job and periodic script audit.

Checks the current user's crontab, /etc/periodic/ scripts, and at-job queue
for unexpected scheduled tasks — a classic persistence mechanism.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..proc import run
from ..result import CheckResult
from ..severity import Severity

_PERIODIC_DIRS = (
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
)

# Apple's default periodic script prefixes (numeric-named system scripts)
_APPLE_NUMERIC = frozenset({
    "100", "110", "130", "140", "150", "160", "170", "199",
    "200", "250", "300", "400", "450", "500", "600", "700", "800", "999",
})


def _user_crontab() -> CheckResult:
    result = run(["crontab", "-l"], timeout=10)
    if result.missing:
        return CheckResult("User Crontab", "SKIPPED", info="crontab not available.")
    if not result.ok:
        # Exit 1 = no crontab for user
        return CheckResult("User Crontab", "OK", info="no entries")

    entries = [
        ln for ln in result.stdout.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not entries:
        return CheckResult("User Crontab", "OK", info="no entries")

    return CheckResult(
        label="User Crontab",
        status="ALERT",
        severity=Severity.MEDIUM,
        info=entries,
        tip="Crontab entries run on a schedule. Remove any you don't recognise — they're a common persistence mechanism.",
    )


def _system_crontabs() -> CheckResult | None:
    """Check /var/at/tabs for other users' crontabs (requires root)."""
    at_tabs = Path("/private/var/at/tabs")
    if not at_tabs.exists():
        return None
    try:
        tabs = [t for t in at_tabs.iterdir() if t.is_file() and t.stat().st_size > 0]
    except PermissionError:
        return CheckResult(
            "System Crontabs",
            "UNKNOWN",
            severity=Severity.LOW,
            info="Cannot read /var/at/tabs — requires root.",
        )
    if not tabs:
        return CheckResult("System Crontabs", "OK", info="no entries")
    return CheckResult(
        label="System Crontabs",
        status="ALERT",
        severity=Severity.MEDIUM,
        info=[str(t) for t in tabs],
        tip="Crontab files found for system users. Review for unexpected scheduled tasks.",
    )


def _at_jobs() -> CheckResult | None:
    result = run(["atq"], timeout=10)
    if result.missing:
        return None
    jobs = [ln for ln in result.stdout.splitlines() if ln.strip()]
    if not jobs:
        return CheckResult("At Jobs", "OK", info="none queued")
    return CheckResult(
        label="At Jobs",
        status="ALERT",
        severity=Severity.MEDIUM,
        info=jobs,
        tip="at-jobs are one-shot scheduled tasks. Remove unknown jobs with 'atrm <job#>'.",
    )


def _periodic_scripts() -> CheckResult:
    non_system: list[str] = []
    for pdir in _PERIODIC_DIRS:
        p = Path(pdir)
        if not p.exists():
            continue
        for script in sorted(p.iterdir()):
            if not script.is_file():
                continue
            prefix = script.name.split(".")[0]
            if prefix not in _APPLE_NUMERIC and not script.name.startswith("com.apple."):
                non_system.append(str(script))

    if non_system:
        return CheckResult(
            label="Periodic Scripts",
            status="ALERT",
            severity=Severity.MEDIUM,
            info=non_system,
            tip="Non-standard scripts in /etc/periodic/ run as root on a schedule. Verify these are expected.",
        )
    return CheckResult("Periodic Scripts", "OK", info="clean")


def check_cron_jobs() -> list[CheckResult]:
    results: list[CheckResult] = [
        _user_crontab(),
        _periodic_scripts(),
    ]
    sys_cron = _system_crontabs()
    if sys_cron is not None:
        results.append(sys_cron)
    at = _at_jobs()
    if at is not None:
        results.append(at)
    return results
