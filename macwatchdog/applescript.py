"""Helpers for safely invoking AppleScript.

AppleScript string literals only accept two escapes: ``\\\\`` for backslash
and ``\\"`` for double quote. Use :func:`quote` for simple literal
construction; prefer :func:`osascript` with an ``argv`` list so user input is
referenced via ``item 1 of argv`` inside an ``on run argv`` handler and never
reaches the AppleScript lexer.
"""

from __future__ import annotations

from typing import Iterable

from .proc import ProcResult, run


def quote(value: str) -> str:
    """Return ``value`` safely quoted for inclusion in an AppleScript literal.

    >>> quote('Greg\\'s "App"')
    '"Greg\\'s \\\\"App\\\\""'
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def osascript(script: str, *, args: Iterable[str] = (), timeout: float = 15.0) -> ProcResult:
    """Run an AppleScript source string with optional argv values.

    ``args`` are passed to ``osascript`` after ``--`` and become ``argv``
    inside an ``on run argv`` handler, keeping user-provided values outside
    of the AppleScript source.
    """
    cmd = ["osascript", "-e", script, "--"] + list(args)
    return run(cmd, timeout=timeout)
