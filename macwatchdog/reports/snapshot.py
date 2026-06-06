"""Snapshots capture the output of every registered check as a single JSON
file under ``paths.snapshots_dir()`` so two snapshots can be diffed later."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import paths
from ..audit import CHECKS
from ..result import CheckResult, ensure_dict
from ..timeline import log_event


def _run_all() -> dict[str, list[Any]]:
    snapshot: dict[str, list[Any]] = {}
    for check in CHECKS:
        try:
            outcome = check.function()
        except Exception as exc:  # noqa: BLE001
            outcome = CheckResult(label=check.name, status="ERROR", info=str(exc))
        snapshot.setdefault(check.category, []).append(ensure_dict(outcome))
    return snapshot


def create_snapshot() -> Path:
    path = paths.snapshots_dir() / f"snapshot_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    data = {
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "checks": _run_all(),
    }
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log_event("snapshot.created", path=str(path))
    return path


def list_snapshots() -> list[Path]:
    return sorted(paths.snapshots_dir().glob("snapshot_*.json"))


def _profile_identifiers(snapshot: dict[str, Any]) -> set[str]:
    identifiers: set[str] = set()
    checks = snapshot.get("checks") if "checks" in snapshot else snapshot
    if not isinstance(checks, dict):
        return identifiers
    for items in checks.values():
        for item in items:
            if isinstance(item, dict) and item.get("label", "").startswith("Configuration Profiles"):
                for p in item.get("profiles", []) or []:
                    ident = p.get("profileIdentifier")
                    if ident:
                        identifiers.add(ident)
    return identifiers


def compare_snapshots(a: Path, b: Path) -> dict[str, list[str]]:
    first = json.loads(a.read_text(encoding="utf-8"))
    second = json.loads(b.read_text(encoding="utf-8"))
    first_ids = _profile_identifiers(first)
    second_ids = _profile_identifiers(second)
    result = {
        "added": sorted(second_ids - first_ids),
        "removed": sorted(first_ids - second_ids),
    }
    log_event("snapshot.compared", first=str(a), second=str(b), **result)
    return result
