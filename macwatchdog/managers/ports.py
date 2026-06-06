"""Port management: snapshot current listeners, gracefully close a
listener, and diff a saved snapshot against the live state.
"""

from __future__ import annotations

import json
import os
import signal
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import paths
from ..audit.network_listeners import Listener, list_listeners
from ..timeline import log_event


def backup_port_state(listeners: list[Listener] | None = None) -> tuple[bool, str]:
    """Snapshot the current listeners to a JSON file.

    An empty listener list is a valid snapshot; only filesystem errors cause
    this function to return ``(False, reason)``.
    """
    listeners = listeners if listeners is not None else list_listeners()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = paths.ports_quarantine_dir() / f"ports_backup_{timestamp}.json"
    try:
        backup_path.write_text(
            json.dumps([l.as_dict() for l in listeners], indent=2),
            encoding="utf-8",
        )
        log_event("ports.snapshot", path=str(backup_path), listener_count=len(listeners))
        return True, str(backup_path)
    except Exception as exc:
        return False, str(exc)


def list_backups() -> list[Path]:
    return sorted(paths.ports_quarantine_dir().glob("ports_backup_*.json"), reverse=True)


def close_port(port: str, *, grace_seconds: float = 3.0) -> tuple[bool, str]:
    """Close the first process listening on ``port``.

    Sends ``SIGTERM``, waits up to ``grace_seconds``, then escalates to
    ``SIGKILL`` only if the process is still alive. An advisory snapshot is
    taken first; its failure does not prevent the close.
    """
    listener = next((l for l in list_listeners() if l.port.endswith(f":{port}")), None)
    if not listener:
        return False, f"No listening process found on port {port}"

    snapshot_ok, snapshot_msg = backup_port_state()
    try:
        pid = int(listener.pid)
    except ValueError:
        return False, f"Invalid PID {listener.pid!r}"

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        log_event("ports.closed", port=port, pid=pid, method="already-dead")
        return True, f"Process {pid} already exited."
    except PermissionError:
        return False, f"Permission denied sending SIGTERM to PID {pid}. Try running with sudo."

    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            log_event("ports.closed", port=port, pid=pid, method="sigterm")
            return True, f"Closed {listener.process} on port {port} (SIGTERM)."
        time.sleep(0.1)

    try:
        os.kill(pid, signal.SIGKILL)
        log_event("ports.closed", port=port, pid=pid, method="sigkill")
        return True, f"Closed {listener.process} on port {port} (SIGKILL after grace period)."
    except PermissionError:
        return False, f"Permission denied sending SIGKILL to PID {pid}. Try running with sudo."
    except ProcessLookupError:
        return True, f"Process {pid} exited during grace period."


def diff_snapshot(backup_file: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compare a saved port snapshot against the current state.

    Returns ``(gone, appeared)`` where each is a list of listener dicts.
    """
    saved = json.loads(Path(backup_file).read_text(encoding="utf-8"))
    current = [l.as_dict() for l in list_listeners()]

    def key(entry: dict[str, Any]) -> tuple[str, str]:
        return entry.get("process", ""), entry.get("port", "")

    saved_keys = {key(e) for e in saved}
    current_keys = {key(e) for e in current}

    gone = [e for e in saved if key(e) not in current_keys]
    appeared = [e for e in current if key(e) not in saved_keys]
    return gone, appeared
