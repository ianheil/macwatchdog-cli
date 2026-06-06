"""macWatchdog: privacy-focused macOS security and privacy auditor."""

from pathlib import Path


def _read_version() -> str:
    candidates = [
        Path(__file__).with_name("VERSION"),
        Path(__file__).resolve().parent.parent / "VERSION",
    ]
    for candidate in candidates:
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return "0.0.0"


__version__ = _read_version()
__all__ = ["__version__"]
