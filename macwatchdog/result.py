"""Shared data shapes for audit findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .severity import Severity, severity_for


@dataclass
class CheckResult:
    """Structured output of a single check.

    :meth:`to_dict` renders the result into the ``{label, status, info, tip,
    severity, ...}`` shape used by exporters and the JSON CLI output.
    """

    label: str
    status: str = "OK"
    info: Any = ""
    tip: str = ""
    category: str = ""
    severity: Severity | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def resolved_severity(self) -> Severity:
        return self.severity if self.severity is not None else severity_for(self.status)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "label": self.label,
            "status": self.status,
            "info": self.info,
            "tip": self.tip,
            "severity": self.resolved_severity().label,
        }
        if self.category:
            data["category"] = self.category
        data.update(self.extras)
        return data


def ensure_dict(result: "CheckResult | dict[str, Any] | list[Any]") -> Any:
    """Normalise a ``CheckResult``, dict, or list of either into
    JSON-serialisable data."""
    if isinstance(result, CheckResult):
        return result.to_dict()
    if isinstance(result, list):
        return [ensure_dict(r) for r in result]
    return result
