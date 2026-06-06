"""Quarantine attribute audit.

Scans ~/Downloads for installer and executable files that are missing the
com.apple.quarantine extended attribute. Files downloaded via a browser or
App Store should carry this attribute — its absence on an installer means
Gatekeeper won't run its check, which is a known macOS malware delivery
technique (the attribute can be stripped with xattr -d).

Focuses on high-risk file types: .app, .pkg, .dmg, .sh, .command, .tool.
Skips files older than 90 days (low relevance) and files under 1 KB.
"""

from __future__ import annotations

import time
from pathlib import Path

from ..proc import run
from ..result import CheckResult
from ..severity import Severity

_DOWNLOADS = Path.home() / "Downloads"
_RISKY_EXTENSIONS = frozenset({".app", ".pkg", ".dmg", ".sh", ".command", ".tool"})
_MAX_AGE_DAYS = 90
_MIN_SIZE_BYTES = 1024


def _has_quarantine(path: Path) -> bool:
    """Return True if com.apple.quarantine xattr is present."""
    result = run(["xattr", "-p", "com.apple.quarantine", str(path)], timeout=3)
    return result.ok


def _is_recent(path: Path) -> bool:
    """Return True if the file was modified within MAX_AGE_DAYS."""
    try:
        age_secs = time.time() - path.stat().st_mtime
        return age_secs < _MAX_AGE_DAYS * 86400
    except OSError:
        return False


def _is_worth_checking(path: Path) -> bool:
    if path.suffix.lower() not in _RISKY_EXTENSIONS:
        return False
    try:
        # .app bundles are directories — stat().st_size on a directory returns
        # only the inode size (~96 bytes), not bundle contents. Use is_dir()
        # as the size proxy for bundles; use actual file size for flat files.
        if path.is_dir():
            return True  # any .app directory bundle is worth checking
        return path.stat().st_size >= _MIN_SIZE_BYTES
    except OSError:
        return False


def check_quarantine_attributes() -> CheckResult:
    if not _DOWNLOADS.is_dir():
        return CheckResult(
            label="Quarantine Attributes",
            status="SKIPPED",
            severity=Severity.INFO,
            info="~/Downloads not found.",
        )

    missing: list[str] = []
    verified: int = 0

    try:
        candidates = [p for p in _DOWNLOADS.iterdir() if _is_worth_checking(p) and _is_recent(p)]
    except PermissionError:
        return CheckResult(
            label="Quarantine Attributes",
            status="UNKNOWN",
            severity=Severity.LOW,
            info="Cannot read ~/Downloads.",
        )

    for path in sorted(candidates):
        if _has_quarantine(path):
            verified += 1
        else:
            missing.append(path.name)

    if not candidates:
        return CheckResult(
            label="Quarantine Attributes",
            status="OK",
            info="no recent installer/script files in ~/Downloads",
        )

    if not missing:
        return CheckResult(
            label="Quarantine Attributes",
            status="OK",
            info=f"all {verified} recent file(s) carry quarantine attribute",
        )

    info: list[str] = [
        f"# Missing quarantine attribute  [{len(missing)}]  —  Gatekeeper bypass risk",
    ]
    for name in missing:
        info.append(f"  {name}")
    if verified:
        info.append(f"# Quarantine-verified  [{verified}]")

    return CheckResult(
        label="Quarantine Attributes",
        status="ALERT",
        severity=Severity.HIGH,
        info=info,
        tip=(
            "The quarantine attribute triggers Gatekeeper on first launch. "
            "Its absence on an installer may mean it was stripped with 'xattr -d' — "
            "a common technique to bypass macOS security checks. Inspect before running."
        ),
    )
