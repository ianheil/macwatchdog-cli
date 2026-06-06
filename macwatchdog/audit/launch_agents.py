"""Launch agent/daemon audit.

Scans ``/Library/LaunchAgents``, ``/Library/LaunchDaemons``, and
``~/Library/LaunchAgents``. An entry is considered suspicious if its plist
file is world-writable, the executable it launches is not code-signed (for
non-Apple agents), or its filename contains an obvious red-flag keyword.
"""

from __future__ import annotations

import os
import plistlib
from pathlib import Path

from ..proc import run
from ..result import CheckResult
from ..severity import Severity
from .permissions import is_world_writable

AGENT_PATHS: tuple[str, ...] = (
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    os.path.expanduser("~/Library/LaunchAgents"),
)

SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "backdoor",
    "rat",
    "keylog",
    "spyware",
    "spy",
    "hack",
)


def _plist_executable(plist_path: str | os.PathLike[str]) -> str | None:
    """Resolve the executable referenced by a launchd plist.

    Returns ``None`` if the plist is unreadable or doesn't declare a program.
    """
    try:
        with open(plist_path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return None
    program = data.get("Program")
    if isinstance(program, str) and program:
        return program
    args = data.get("ProgramArguments")
    if isinstance(args, list) and args and isinstance(args[0], str):
        return args[0]
    return None


def is_unsigned(path: str | os.PathLike[str]) -> bool:
    """Return True if the executable referenced by ``path`` is not code-signed.

    When ``path`` is a launchd ``.plist`` the executable it launches is
    resolved from its ``Program`` / ``ProgramArguments`` keys before
    verification. Returns ``False`` if the executable can't be located or if
    ``codesign`` is unavailable.
    """
    target = path
    if str(path).endswith(".plist"):
        resolved = _plist_executable(path)
        if not resolved:
            return False
        target = resolved

    if not os.path.exists(str(target)):
        return False

    result = run(["codesign", "--verify", "--deep", str(target)], timeout=10)
    if result.missing or result.timed_out:
        return False
    return result.returncode != 0


def _is_apple_agent(filename: str) -> bool:
    return filename.startswith("com.apple.")


def find_unsigned_agents() -> list[str]:
    """Return absolute paths of unsigned (non-Apple) launch agents/daemons."""
    unsigned: list[str] = []
    for path in AGENT_PATHS:
        if not os.path.exists(path):
            continue
        for entry in sorted(os.listdir(path)):
            full = os.path.join(path, entry)
            if _is_apple_agent(entry):
                continue
            if is_unsigned(full):
                unsigned.append(full)
    return unsigned


def list_all_agents() -> list[dict]:
    """Return all non-Apple third-party launch agents with basic metadata."""
    agents = []
    for path_str in AGENT_PATHS:
        if not os.path.exists(path_str):
            continue
        for entry in sorted(os.listdir(path_str)):
            if not entry.endswith(".plist"):
                continue
            if _is_apple_agent(entry):
                continue
            full = os.path.join(path_str, entry)
            agents.append({
                "path": full,
                "name": os.path.splitext(entry)[0],
                "directory": os.path.basename(path_str),
                "unsigned": is_unsigned(full),
            })
    return agents


def check_launch_agents() -> CheckResult:
    """Return suspicious launch agents/daemons.

    A file is flagged when any of the following apply:
      * it is world-writable;
      * its target executable is unsigned and the plist is not a
        ``com.apple.*`` agent;
      * its filename contains an obvious red-flag keyword.
    """
    findings: list[str] = []
    seen: set[str] = set()

    for path in AGENT_PATHS:
        if not os.path.exists(path):
            continue
        for entry in sorted(os.listdir(path)):
            full = os.path.join(path, entry)
            reasons: list[str] = []
            if is_world_writable(full):
                reasons.append("world-writable")
            if not _is_apple_agent(entry) and is_unsigned(full):
                reasons.append("unsigned")
            lower = entry.lower()
            if any(keyword in lower for keyword in SUSPICIOUS_KEYWORDS):
                reasons.append("suspicious keyword")
            if reasons and full not in seen:
                findings.append(f"{full} ({', '.join(reasons)})")
                seen.add(full)

    if findings:
        return CheckResult(
            label="Suspicious Launch Agents/Daemons",
            status="ALERT",
            severity=Severity.HIGH,
            info=findings,
            tip="Review anything you don't recognise; macwatchdog can quarantine items under 'Manage unsigned launch agents/daemons'.",
        )

    return CheckResult(
        label="Suspicious Launch Agents/Daemons",
        status="OK",
        severity=Severity.OK,
        info="none found",
    )
