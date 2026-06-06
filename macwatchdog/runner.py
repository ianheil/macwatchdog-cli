"""Execute registered checks and render their output."""

from __future__ import annotations

import sys
from collections import Counter
from typing import Iterable

from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from .audit import CHECKS, RegisteredCheck
from .result import CheckResult, ensure_dict
from .severity import Severity, severity_for
from .ui import console, print_category, print_result, print_rule, print_tip


def _as_results(raw: object, category: str) -> list[CheckResult]:
    if isinstance(raw, list):
        return [r for r in (_coerce(item, category) for item in raw) if r is not None]
    coerced = _coerce(raw, category)
    return [coerced] if coerced is not None else []


def _coerce(item: object, category: str) -> CheckResult | None:
    if isinstance(item, CheckResult):
        if not item.category:
            item.category = category
        return item
    if isinstance(item, dict):
        return CheckResult(
            label=item.get("label", "(unnamed)"),
            status=item.get("status", "OK"),
            info=item.get("info", ""),
            tip=item.get("tip", ""),
            category=category,
            extras={k: v for k, v in item.items() if k not in {"label", "status", "info", "tip"}},
        )
    return None


def run_checks(
    checks: Iterable[RegisteredCheck] = CHECKS,
    *,
    show_progress: bool | None = None,
) -> dict[str, list[CheckResult]]:
    """Run ``checks`` and return results grouped by category.

    A Rich progress bar is shown when attached to a TTY (controlled by
    ``show_progress``). Set ``show_progress=False`` for script-friendly
    output.
    """
    items = list(checks)
    if show_progress is None:
        show_progress = sys.stdout.isatty()

    report: dict[str, list[CheckResult]] = {}
    if show_progress and items:
        with Progress(
            TextColumn("[bold green][ SCANNING ][/bold green]"),
            TextColumn("[green]{task.description}[/green]"),
            BarColumn(bar_width=20, style="dark_green", complete_style="bright_green"),
            TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
            TimeElapsedColumn(),
            transient=True,
            console=console,
            expand=False,
        ) as progress:
            task = progress.add_task("", total=len(items))
            for check in items:
                progress.update(task, description=check.name)
                _execute(check, report)
                progress.advance(task)
    else:
        for check in items:
            _execute(check, report)
    return report


def _execute(check: RegisteredCheck, report: dict[str, list[CheckResult]]) -> None:
    try:
        outcome = check.function()
    except Exception as exc:  # noqa: BLE001
        outcome = CheckResult(
            label=check.name,
            status="ERROR",
            info=f"{type(exc).__name__}: {exc}",
            category=check.category,
        )
    for result in _as_results(outcome, check.category):
        report.setdefault(check.category, []).append(result)


def render_report(report: dict[str, list[CheckResult]], *, min_severity: Severity = Severity.OK) -> None:
    for category, items in report.items():
        visible = [item for item in items if item.resolved_severity() >= min_severity]
        if not visible:
            continue
        print_category(category)
        for item in visible:
            sev = item.resolved_severity()

            if item.status == "SKIPPED":
                # Compact: one badge line + tip as the reason
                print_result(item.label, item.status, severity=sev)
                if item.tip:
                    print_tip(item.tip)
                continue

            # Always show info — security facts matter even on OK results.
            # Specific checks return empty info when there's genuinely nothing to say.
            print_result(item.label, item.status, item.info, severity=sev)
            # Tips only for actionable findings (LOW and above)
            if sev >= Severity.LOW:
                print_tip(item.tip)
            # Breathing room after any result that expanded beyond a single line
            has_expanded = bool(item.info and not (isinstance(item.info, str) and len(item.info) <= 72))
            has_tip = sev >= Severity.LOW and bool(item.tip)
            if has_expanded or has_tip:
                console.print()


def report_to_dict(report: dict[str, list[CheckResult]]) -> dict[str, list[dict]]:
    return {category: [ensure_dict(item) for item in items] for category, items in report.items()}


def flatten(report: dict[str, list[CheckResult]]) -> list[CheckResult]:
    return [item for items in report.values() for item in items]


def render_summary(report: dict[str, list[CheckResult]], *, elapsed: float | None = None) -> None:
    from .scoring import compute_score, score_band

    all_results = flatten(report)
    if not all_results:
        return

    counts: Counter[Severity] = Counter(r.resolved_severity() for r in all_results)
    total = len(all_results)
    elapsed_str = f"  ·  {elapsed:.1f}s" if elapsed is not None else ""

    score, ceiling_reason = compute_score(report)
    label, style = score_band(score)

    ceiling_str = f"  [dim]· capped by {ceiling_reason}[/dim]" if ceiling_reason else ""
    print_rule()
    console.print(
        f"  [bold bright_green]AUDIT COMPLETE[/bold bright_green]"
        f"[dim]  ·  {total} checks{elapsed_str}[/dim]"
        f"    SCORE  [{style}]{score:>3}/100  {label}[/{style}]{ceiling_str}"
    )
    print_rule()

    pairs = [
        (Severity.OK,   Severity.MEDIUM),
        (Severity.INFO, Severity.HIGH),
        (Severity.LOW,  Severity.CRITICAL),
    ]

    def _fmt(sev: Severity) -> str:
        count = counts.get(sev, 0)
        style = f"sev.{sev.name.lower()}"
        return f"[{style}]{sev.name:<8}[/{style}]  [bold]{count:>3}[/bold]"

    for left, right in pairs:
        console.print(f"    {_fmt(left)}        {_fmt(right)}")

    print_rule()
    console.print()
