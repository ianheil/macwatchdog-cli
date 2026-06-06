"""Severity tiers for audit findings.

``Status`` strings are the stable machine value surfaced by checks. Each one
maps to a :class:`Severity` which drives display colour and the
``--min-severity`` filter.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Final


class Severity(IntEnum):
    """Ordered severity tiers. Higher value == more attention needed."""

    OK = 0
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50
    ERROR = 60  # tool-level failure, distinct from a finding

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return _SEVERITY_COLORS[self]


_SEVERITY_COLORS: Final[dict[Severity, str]] = {
    Severity.OK: "green",
    Severity.INFO: "cyan",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
    Severity.ERROR: "magenta",
}


STATUS_SEVERITY: Final[dict[str, Severity]] = {
    "OK": Severity.OK,
    "INFO": Severity.INFO,
    "SKIPPED": Severity.INFO,
    "SUGGESTION": Severity.LOW,
    "UNKNOWN": Severity.LOW,
    "ALERT": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.ERROR,
}


def severity_for(status: str) -> Severity:
    return STATUS_SEVERITY.get(status.upper(), Severity.INFO)
