"""Report serialisation helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ..result import CheckResult, ensure_dict


def _coerce(report: dict[str, list[Any]]) -> dict[str, list[Any]]:
    return {category: [ensure_dict(item) for item in items] for category, items in report.items()}


def export_report(report: dict[str, list[Any]], destination: str | Path, *, as_json: bool = False) -> Path:
    path = Path(destination)
    coerced = _coerce(report)
    if as_json:
        path.write_text(json.dumps(coerced, indent=2, default=str), encoding="utf-8")
    else:
        with path.open("w", encoding="utf-8") as fh:
            for category, items in coerced.items():
                fh.write(f"== {category} ==\n")
                for item in _flatten(items):
                    label = item.get("label", "")
                    status = item.get("status", "")
                    info = item.get("info", "")
                    if isinstance(info, list):
                        info = " | ".join(str(i) for i in info)
                    fh.write(f"{label}: {status} {info}\n")
                fh.write("\n")
    return path


def _flatten(items: Iterable[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, list):
            out.extend(_flatten(item))
        elif isinstance(item, dict):
            out.append(item)
        elif isinstance(item, CheckResult):
            out.append(item.to_dict())
    return out
