"""Structured timeline log.

Each call to :func:`log_event` appends one JSON object per line (JSON Lines)
to ``paths.timeline_log()``. :func:`read_events` parses the file back into a
list of dicts; :func:`format_events` renders them for display.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from . import paths


def log_event(event: str, **fields: Any) -> None:
    """Append a structured event to the timeline.

    Example::

        log_event("snapshot.created", path=str(fname))
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        **fields,
    }
    log_path = paths.timeline_log()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")


def read_events() -> list[dict[str, Any]]:
    log_path = paths.timeline_log()
    if not log_path.exists():
        return []
    events: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"timestamp": "?", "event": "invalid-log-line", "raw": line})
    return events


def format_events(events: Iterable[dict[str, Any]]) -> str:
    lines = []
    for event in events:
        ts = event.get("timestamp", "?")
        name = event.get("event", "?")
        extras = {k: v for k, v in event.items() if k not in {"timestamp", "event"}}
        extra_str = " ".join(f"{k}={v}" for k, v in extras.items())
        line = f"[{ts}] {name}"
        if extra_str:
            line += f" {extra_str}"
        lines.append(line)
    return "\n".join(lines)


def clear() -> None:
    log_path = paths.timeline_log()
    if log_path.exists():
        log_path.unlink()
