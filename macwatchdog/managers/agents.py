"""Quarantine / restore of unsigned launch agents."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from .. import paths
from ..audit.launch_agents import find_unsigned_agents
from ..timeline import log_event


def quarantine_agents(selected: list[str]) -> tuple[Path, list[str], list[str]]:
    """Move ``selected`` paths into a fresh backup subdirectory.

    Returns ``(backup_dir, moved, failed)``.
    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = paths.agents_quarantine_dir() / f"backup_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    moved: list[str] = []
    failed: list[str] = []
    for src in selected:
        try:
            dest = backup_dir / Path(src).name
            shutil.move(src, dest)
            # Write original path so restore doesn't have to guess
            meta = dest.with_suffix(dest.suffix + ".meta")
            meta.write_text(json.dumps({"original_path": src}), encoding="utf-8")
            moved.append(str(dest))
            log_event("agent.quarantined", source=src, destination=str(dest))
        except Exception as exc:
            failed.append(f"{src}: {exc}")
            log_event("agent.quarantine.failed", source=src, error=str(exc))
    return backup_dir, moved, failed


def list_quarantined() -> list[Path]:
    root = paths.agents_quarantine_dir()
    items: list[Path] = []
    for backup in sorted(root.iterdir(), reverse=True):
        if not backup.is_dir():
            continue
        items.extend(sorted(backup.iterdir()))
    return items


def restore_agents(selected: list[Path]) -> tuple[list[str], list[str]]:
    """Restore quarantined files. Returns ``(restored, failed)``."""
    restored: list[str] = []
    failed: list[str] = []
    for src in selected:
        try:
            target = _original_path(src)
            shutil.move(str(src), target)
            # Clean up the .meta sidecar if present
            meta = src.with_suffix(src.suffix + ".meta")
            if meta.exists():
                meta.unlink(missing_ok=True)
            restored.append(str(target))
            log_event("agent.restored", source=str(src), destination=str(target))
        except Exception as exc:
            failed.append(f"{src}: {exc}")
            log_event("agent.restore.failed", source=str(src), error=str(exc))
    return restored, failed


def _original_path(quarantined: Path) -> Path:
    """Resolve the original path for a quarantined agent.

    Reads the .meta sidecar written at quarantine time. Falls back to
    reconstructing from the filename if the sidecar is missing (legacy backups).
    """
    meta = quarantined.with_suffix(quarantined.suffix + ".meta")
    if meta.exists():
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            return Path(data["original_path"])
        except (json.JSONDecodeError, KeyError, OSError):
            pass
    # Legacy fallback: best-guess from the directory name in the quarantine path
    src_str = str(quarantined)
    if "LaunchDaemons" in src_str:
        return Path("/Library/LaunchDaemons") / quarantined.name
    if "~/Library" in src_str or str(Path.home()) in src_str:
        return Path.home() / "Library" / "LaunchAgents" / quarantined.name
    return Path("/Library/LaunchAgents") / quarantined.name


def purge_quarantine() -> int:
    """Permanently delete all quarantined items."""
    root = paths.agents_quarantine_dir()
    count = 0
    for backup in sorted(root.iterdir()):
        if backup.is_dir():
            for file in backup.iterdir():
                try:
                    file.unlink()
                    count += 1
                except OSError:
                    pass
            try:
                backup.rmdir()
            except OSError:
                pass
    log_event("agent.quarantine.purged", deleted=count)
    return count


def currently_unsigned() -> list[str]:
    return find_unsigned_agents()
