"""Login items / Background Items audit.

macOS exposes two "things that run at login" surfaces:

- Classic login items (``System Settings > General > Login Items > Open at
  Login``), queryable via AppleScript.
- Background Items / SMAppService agents registered by apps themselves,
  reported by ``btmutil dump`` (Ventura+) or ``sfltool dumpbtm`` (Monterey).

This module returns both kinds, each tagged with its ``source``. AppleScript
calls pass arguments through ``osascript``'s ``argv`` so item names are
never interpolated into the script source.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable

from ..applescript import osascript
from ..proc import run
from ..result import CheckResult
from ..severity import Severity


@dataclass
class LoginItem:
    name: str
    path: str | None
    source: str  # "classic" or "background"
    kind: str = "unknown"

    @property
    def display(self) -> str:
        # AppleScript returns "(null)" for unresolved paths — treat as absent
        path = self.path if self.path and self.path != "(null)" else None
        if path:
            return f"{self.name}  —  {path}"
        return self.name


def _classic_login_items() -> list[LoginItem]:
    names = osascript(
        'tell application "System Events" to get the name of every login item',
        timeout=10,
    )
    paths = osascript(
        'tell application "System Events" to get the path of every login item',
        timeout=10,
    )
    if not names.ok:
        return []
    name_list = [n.strip() for n in names.stdout.strip().split(", ") if n.strip()]
    path_list = [p.strip() for p in paths.stdout.strip().split(", ") if p.strip()] if paths.ok else []
    items: list[LoginItem] = []
    for i, name in enumerate(name_list):
        path = path_list[i] if i < len(path_list) else None
        kind = "Application" if path and path.endswith(".app") else "Script"
        items.append(LoginItem(name=name, path=path, source="classic", kind=kind))
    return items


def _background_items() -> list[LoginItem]:
    """Parse output from sfltool/btmutil — requires root on modern macOS.

    Both tools trigger an admin password prompt when run as a standard user,
    so we skip them entirely unless already elevated.
    """
    if os.geteuid() != 0:
        return []
    for cmd in (["sfltool", "dumpbtm"], ["btmutil", "dump"]):
        result = run(cmd, timeout=15)
        if not result.ok or not result.stdout.strip():
            continue
        return _parse_btm(result.stdout)
    return []


_NAME_RE = re.compile(r"\s*Name:\s*(.+?)\s*$", re.MULTILINE)
_URL_RE = re.compile(r"\s*(?:URL|Executable Path|Path):\s*(.+?)\s*$", re.MULTILINE)
_KIND_RE = re.compile(r"\s*(?:Type|Item type):\s*(.+?)\s*$", re.MULTILINE)


def _parse_btm(output: str) -> list[LoginItem]:
    entries: list[LoginItem] = []
    for block in re.split(r"\n\s*Record(?:\s+#\d+)?\s*:?\n", output):
        block = block.strip()
        if not block:
            continue
        name_match = _NAME_RE.search(block)
        if not name_match:
            continue
        url_match = _URL_RE.search(block)
        kind_match = _KIND_RE.search(block)
        entries.append(
            LoginItem(
                name=name_match.group(1).strip(),
                path=url_match.group(1).strip() if url_match else None,
                source="background",
                kind=kind_match.group(1).strip() if kind_match else "background",
            )
        )
    return entries


def get_login_items() -> list[LoginItem]:
    seen: set[tuple[str, str | None, str]] = set()
    items: list[LoginItem] = []
    for item in _classic_login_items() + _background_items():
        key = (item.name, item.path, item.source)
        if key in seen:
            continue
        seen.add(key)
        items.append(item)
    return items


def check_login_items() -> CheckResult:
    items = get_login_items()
    if not items:
        return CheckResult(
            label="Login Items",
            status="OK",
            severity=Severity.OK,
        )
    return CheckResult(
        label="Login Items",
        status="INFO",
        severity=Severity.INFO,
        info=[i.display for i in items],
        tip="Review items you don't recognise. Classic items can be removed via 'macwatchdog'; background items must be removed from the app that installed them.",
        extras={"items": [vars(i) for i in items]},
    )
