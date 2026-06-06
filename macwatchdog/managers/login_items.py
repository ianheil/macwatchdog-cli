"""Login item backup/remove/restore.

Each operation creates a JSON backup under ``paths.login_items_quarantine_dir()``
before mutating state. AppleScript invocations pass the item name/path via
``osascript``'s ``argv`` and reference them as ``item 1 of argv`` inside an
``on run argv`` handler.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import paths
from ..applescript import osascript
from ..audit.login_items import LoginItem, get_login_items
from ..timeline import log_event


_REMOVE_SCRIPT = (
    'on run argv\n'
    '    tell application "System Events"\n'
    '        delete (every login item whose name is (item 1 of argv))\n'
    '    end tell\n'
    'end run'
)

_ADD_SCRIPT = (
    'on run argv\n'
    '    tell application "System Events"\n'
    '        make new login item at end with properties {path:(item 1 of argv), hidden:false}\n'
    '    end tell\n'
    'end run'
)


def list_login_items() -> list[LoginItem]:
    return [i for i in get_login_items() if i.source == "classic"]


def backup_login_item(item: LoginItem) -> tuple[bool, str]:
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = paths.login_items_quarantine_dir() / f"login_item_backup_{timestamp}.json"
        backup_path.write_text(json.dumps(asdict(item), indent=2), encoding="utf-8")
        log_event("login_item.backup", name=item.name, path=item.path)
        return True, str(backup_path)
    except Exception as exc:
        return False, str(exc)


def remove_login_item(name: str) -> tuple[bool, str]:
    items = list_login_items()
    item = next((i for i in items if i.name == name), None)
    if not item:
        return False, f"Login item not found: {name}"

    success, backup_result = backup_login_item(item)
    if not success:
        return False, f"Backup failed: {backup_result}"

    result = osascript(_REMOVE_SCRIPT, args=[name], timeout=10)
    if result.ok:
        log_event("login_item.removed", name=name, backup=backup_result)
        return True, f"Removed '{name}' (backup at {backup_result})"
    return False, result.stderr.strip() or result.stdout.strip() or "osascript failed"


def restore_login_item(backup_file: str | Path) -> tuple[bool, str]:
    try:
        data: dict[str, Any] = json.loads(Path(backup_file).read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Could not read backup: {exc}"

    path = data.get("path")
    if not path:
        return False, "Backup has no path recorded; cannot restore."

    result = osascript(_ADD_SCRIPT, args=[path], timeout=10)
    if result.ok:
        log_event("login_item.restored", name=data.get("name"), path=path)
        return True, f"Restored login item {data.get('name')}"
    return False, result.stderr.strip() or result.stdout.strip() or "osascript failed"


def list_backups() -> list[Path]:
    return sorted(paths.login_items_quarantine_dir().glob("login_item_backup_*.json"), reverse=True)
