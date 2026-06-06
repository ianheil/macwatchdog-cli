"""Security score calculation.

A single 0–100 score derived from severity-weighted deductions plus hard
ceilings that enforce meaningful bands regardless of total finding count.

Design principles:
  - Pure addition (weights) handles the baseline: more problems = lower score.
  - Hard ceilings handle the structural constraint: a machine with any HIGH
    finding cannot score GOOD, and a CRITICAL finding locks you into VULNERABLE.
    This prevents "mostly clean but FileVault is off" from scoring GOOD.
  - UNKNOWN (root-required checks run as standard user) maps to LOW (weight 3)
    as a small incentive to run with sudo — not a penalty for being clean.
  - ERROR reflects tool failure, not a security finding — weight 1.
  - SKIPPED and INFO both carry weight 0; they inform but don't penalise.
"""

from __future__ import annotations

from collections import Counter
from typing import Final

from .result import CheckResult
from .severity import Severity

SCORE_WEIGHTS: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 25,
    Severity.HIGH:     15,
    Severity.MEDIUM:   10,
    Severity.LOW:       3,   # UNKNOWN maps here — small root incentive
    Severity.INFO:      0,
    Severity.OK:        0,
    Severity.ERROR:     1,   # tool failure ≠ security risk
}

# Hard ceilings: a machine with any finding at or above the threshold
# severity cannot score above the ceiling, regardless of other results.
# Checked in order — first match wins.
_CEILINGS: Final[tuple[tuple[Severity, int], ...]] = (
    (Severity.CRITICAL, 35),   # CRITICAL present → VULNERABLE at best
    (Severity.HIGH,     65),   # HIGH present → AT RISK at best
)

# (min_score, label, rich_style)
_BANDS: Final[tuple[tuple[int, str, str], ...]] = (
    (90, "SECURE",     "bold bright_green"),
    (75, "GOOD",       "bold green"),
    (50, "AT RISK",    "bold yellow"),
    (25, "VULNERABLE", "bold red"),
    ( 0, "CRITICAL",   "bold red on dark_red"),
)


def compute_score(report: dict[str, list[CheckResult]]) -> tuple[int, str | None]:
    """Return (score, ceiling_reason) where ceiling_reason is set if a hard
    ceiling was applied (e.g. 'HIGH finding' or 'CRITICAL finding').
    """
    all_results = [r for items in report.values() for r in items]
    counts: Counter[Severity] = Counter(r.resolved_severity() for r in all_results)

    deductions = sum(SCORE_WEIGHTS.get(sev, 0) * n for sev, n in counts.items())
    raw = max(0, 100 - deductions)

    for threshold, ceiling in _CEILINGS:
        if counts.get(threshold, 0) > 0:
            return min(raw, ceiling), f"{threshold.name} finding"

    return raw, None


def score_band(score: int) -> tuple[str, str]:
    """Return (label, rich_style) for a score."""
    for minimum, label, style in _BANDS:
        if score >= minimum:
            return label, style
    return "CRITICAL", "bold red"
