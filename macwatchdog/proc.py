"""Subprocess helpers with a default timeout and graceful error handling.

:func:`run` wraps :func:`subprocess.run` to enforce a timeout, detect missing
binaries, and return a :class:`ProcResult` so callers don't need repetitive
``try/except`` blocks around every shell-out.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

DEFAULT_TIMEOUT = 15.0


@dataclass
class ProcResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing


def run(
    cmd: Sequence[str],
    *,
    timeout: float | None = DEFAULT_TIMEOUT,
    check: bool = False,
) -> ProcResult:
    """Run ``cmd`` and return a :class:`ProcResult`.

    If the binary is not on ``PATH`` the result has ``missing=True`` instead
    of raising ``FileNotFoundError``. If execution exceeds ``timeout`` the
    result has ``timed_out=True``.
    """
    if not cmd:
        raise ValueError("run() requires a non-empty command")

    if shutil.which(cmd[0]) is None and not cmd[0].startswith("/"):
        return ProcResult(returncode=127, stdout="", stderr="", missing=True)

    try:
        completed = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return ProcResult(returncode=-1, stdout=stdout, stderr=stderr, timed_out=True)
    except FileNotFoundError:
        return ProcResult(returncode=127, stdout="", stderr="", missing=True)

    result = ProcResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if check and not result.ok:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result
