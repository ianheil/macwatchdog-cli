"""Snapshots capture the output of every registered check as a single JSON
file under ``paths.snapshots_dir()`` so two snapshots can be diffed later."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
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


def create_snapshot(scan_id: str | None = None) -> Path:
    sid = scan_id or str(uuid.uuid4())
    path = paths.snapshots_dir() / f"snapshot_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    data = {
        "scan_id": sid,
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "checks": _run_all(),
    }
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log_event("snapshot.created", path=str(path), scan_id=sid)
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


def write_scan_history(summary: dict[str, Any]) -> None:
    """Append a scan summary to the lightweight history index.

    Keeps the last 100 entries. The GUI reads this file to populate its
    history sidebar without loading full snapshot blobs.
    """
    history_path = paths.scan_history_file()
    history: list[dict[str, Any]] = []
    if history_path.exists():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    entry: dict[str, Any] = {
        "scan_id": summary.get("scan_id", str(uuid.uuid4())),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score": summary.get("score"),
        "band": summary.get("band"),
        "ceiling_reason": summary.get("ceiling_reason"),
        "counts": summary.get("counts", {}),
        "elapsed": summary.get("elapsed"),
    }
    history.append(entry)
    history = history[-100:]
    try:
        history_path.write_text(json.dumps(history, indent=2, default=str), encoding="utf-8")
        log_event("scan.recorded", scan_id=entry["scan_id"], score=entry["score"])
    except OSError:
        pass


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
