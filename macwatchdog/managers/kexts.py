"""Quarantine and restore of kernel extensions from /Library/Extensions/.

Removal requires root — the directory is system-owned.
Each quarantined kext gets a .meta sidecar recording its original path,
consistent with how agents.py handles launch agent quarantine.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from .. import paths
from ..audit.kernel_extensions import KextEntry, _installed_kexts, _loaded_bundle_ids
from ..timeline import log_event

_KEXT_DIR = Path("/Library/Extensions")


def list_installed() -> list[KextEntry]:
    """Return all third-party kexts in /Library/Extensions/ with enrichment."""
    loaded_ids = _loaded_bundle_ids()
    return _installed_kexts(loaded_ids)


def quarantine_kexts(selected: list[Path]) -> tuple[Path, list[str], list[str]]:
    """Move selected kext paths to quarantine. Returns (backup_dir, moved, failed).

    Requires root — /Library/Extensions/ is not user-writable.
    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = paths.kexts_quarantine_dir() / f"backup_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    moved: list[str] = []
    failed: list[str] = []
    for src in selected:
        try:
            dest = backup_dir / src.name
            shutil.move(str(src), str(dest))
            meta = dest.with_suffix(dest.suffix + ".meta")
            meta.write_text(json.dumps({"original_path": str(src)}), encoding="utf-8")
            moved.append(str(dest))
            log_event("kext.quarantined", source=str(src), destination=str(dest))
        except Exception as exc:
            failed.append(f"{src.name}: {exc}")
            log_event("kext.quarantine.failed", source=str(src), error=str(exc))
    return backup_dir, moved, failed


def list_quarantined() -> list[Path]:
    root = paths.kexts_quarantine_dir()
    items: list[Path] = []
    try:
        for backup in sorted(root.iterdir(), reverse=True):
            if not backup.is_dir():
                continue
            for f in sorted(backup.iterdir()):
                # Skip .meta sidecars — only show the actual kext bundles
                if not f.suffix.endswith(".meta"):
                    items.append(f)
    except OSError:
        pass
    return items


def restore_kexts(selected: list[Path]) -> tuple[list[str], list[str]]:
    """Restore quarantined kexts to their original location. Requires root."""
    restored: list[str] = []
    failed: list[str] = []
    for src in selected:
        try:
            meta = src.with_suffix(src.suffix + ".meta")
            if meta.exists():
                data = json.loads(meta.read_text(encoding="utf-8"))
                target = Path(data["original_path"])
            else:
                target = _KEXT_DIR / src.name
            shutil.move(str(src), str(target))
            if meta.exists():
                meta.unlink(missing_ok=True)
            restored.append(str(target))
            log_event("kext.restored", source=str(src), destination=str(target))
        except Exception as exc:
            failed.append(f"{src.name}: {exc}")
            log_event("kext.restore.failed", source=str(src), error=str(exc))
    return restored, failed


def purge_quarantine() -> int:
    """Permanently delete all quarantined kexts."""
    root = paths.kexts_quarantine_dir()
    count = 0
    try:
        for backup in sorted(root.iterdir()):
            if backup.is_dir():
                shutil.rmtree(backup, ignore_errors=True)
                count += 1
    except OSError:
        pass
    log_event("kext.quarantine.purged", deleted=count)
    return count
