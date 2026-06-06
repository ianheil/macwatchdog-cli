"""Script entry point that delegates to :mod:`macwatchdog.cli`.

Supports ``python3 main.py`` launches; the installed console script
``macwatchdog`` (from ``pyproject.toml``) invokes the same ``app``.
"""

from __future__ import annotations

from macwatchdog.cli import app


if __name__ == "__main__":
    app()
