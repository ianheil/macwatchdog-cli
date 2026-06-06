"""Admin user / group check.

Lists non-system members of the ``admin`` group. Admin membership is
reported as ``INFO``; the result is escalated to ``ALERT`` only when an
entry looks genuinely unusual (service-style ``_foo`` accounts or
``Guest``).
"""

from __future__ import annotations

from ..proc import run
from ..result import CheckResult
from ..severity import Severity

SYSTEM_USERS: frozenset[str] = frozenset(
    {"root", "_mbsetupuser", "daemon", "nobody"}
)


def _admin_members() -> list[str]:
    result = run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], timeout=10)
    if not result.ok:
        return []
    output = result.stdout.strip()
    # Format: "GroupMembership: user1 user2 user3"
    if ":" in output:
        _, _, members = output.partition(":")
        return [u for u in members.split() if u]
    return output.split()[1:] if output else []


def check_admin_users() -> CheckResult:
    members = [m for m in _admin_members() if m not in SYSTEM_USERS]
    if not members:
        return CheckResult(
            label="Admin Users/Groups",
            status="OK",
            severity=Severity.OK,
            info=["No non-system admin accounts found."],
        )

    unusual = [m for m in members if m.startswith("_") or m == "Guest"]
    info = [f"Admin members: {', '.join(sorted(members))}"]
    if unusual:
        info.append(f"Unusual entries: {', '.join(unusual)}")
        return CheckResult(
            label="Admin Users/Groups",
            status="ALERT",
            severity=Severity.MEDIUM,
            info=info,
            tip="Remove unexpected service-style accounts from the admin group with 'dseditgroup'.",
        )

    return CheckResult(
        label="Admin Users/Groups",
        status="INFO",
        severity=Severity.INFO,
        info=info,
        tip="Only trusted accounts should have admin privileges.",
    )
