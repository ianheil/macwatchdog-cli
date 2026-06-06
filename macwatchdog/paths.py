"""Filesystem paths used by macWatchdog.

Runtime data (quarantine backups, snapshots, timeline log, MDM state) is stored
under macOS's Application Support directory by default so the source tree stays
clean and the data survives reinstalls.

Tests or users who want to override the location can set the
``MACWATCHDOG_DATA_DIR`` environment variable to any writable directory.
"""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the root directory for persistent macWatchdog data.

    Precedence:
        1. ``MACWATCHDOG_DATA_DIR`` environment variable
        2. ``~/Library/Application Support/macwatchdog``
    The directory is created on first access.
    """
    override = os.environ.get("MACWATCHDOG_DATA_DIR")
    if override:
        base = Path(override).expanduser()
    else:
        base = Path.home() / "Library" / "Application Support" / "macwatchdog"
    base.mkdir(parents=True, exist_ok=True)
    return base


def quarantine_dir() -> Path:
    path = data_dir() / "quarantine"
    path.mkdir(parents=True, exist_ok=True)
    return path


def agents_quarantine_dir() -> Path:
    path = quarantine_dir() / "agents"
    path.mkdir(parents=True, exist_ok=True)
    return path


def login_items_quarantine_dir() -> Path:
    path = quarantine_dir() / "login_items"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ports_quarantine_dir() -> Path:
    path = quarantine_dir() / "ports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def kexts_quarantine_dir() -> Path:
    path = quarantine_dir() / "kexts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def snapshots_dir() -> Path:
    path = data_dir() / "snapshots"
    path.mkdir(parents=True, exist_ok=True)
    return path


def timeline_log() -> Path:
    return data_dir() / "timeline.jsonl"


def mdm_state_file() -> Path:
    return data_dir() / "mdm_state.json"


def watchlist_file() -> Path:
    return data_dir() / "auto_remove_watchlist.json"


def scan_history_file() -> Path:
    return data_dir() / "scan_history.json"
