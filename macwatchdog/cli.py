"""Typer entry points for macWatchdog.

Running ``macwatchdog`` with no subcommand drops into the interactive menu.
All other subcommands are designed to be script-friendly (non-interactive,
exit codes, optional ``--format json``).
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Optional

import typer

from . import __version__, ui
from .audit import CHECKS
from .logo import print_logo
from .managers import ports as ports_manager
from .managers.login_items import remove_login_item as _remove_login_item
from .reports import export_report
from .runner import flatten, render_report, render_summary, report_to_dict, run_checks
from .scoring import compute_score, score_band
from .severity import Severity

app = typer.Typer(add_completion=True, invoke_without_command=True, no_args_is_help=False)


def _apply_global_flags(no_color: bool, min_severity: str | None) -> Severity:
    if no_color:
        ui.set_no_color(True)
    if min_severity:
        try:
            return Severity[min_severity.upper()]
        except KeyError:
            typer.echo(
                f"Unknown severity {min_severity!r}. Valid values: "
                + ", ".join(name for name in Severity.__members__),
                err=True,
            )
            raise typer.Exit(2)
    return Severity.OK


@app.callback()
def main(
    ctx: typer.Context,
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output."),
    min_severity: Optional[str] = typer.Option(
        None,
        "--min-severity",
        help="Filter output to findings at or above this severity (INFO, LOW, MEDIUM, HIGH, CRITICAL).",
    ),
    show_version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
) -> None:
    severity = _apply_global_flags(no_color, min_severity)
    ctx.obj = {"min_severity": severity}
    if show_version:
        ui.console.print(f"macWatchdog [bold green]{__version__}[/bold green]")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        from .menus.main import run as run_menu

        run_menu()


@app.command()
def version() -> None:
    """Show the current macWatchdog version."""
    ui.console.print(f"macWatchdog [bold green]{__version__}[/bold green]")


@app.command("list-checks")
def list_checks() -> None:
    """Print all checks with descriptions and privilege requirements."""
    root_count = sum(1 for c in CHECKS if c.requires_root)
    ui.console.print(f"[dim]{len(CHECKS)} checks  ·  {root_count} require root (*)[/dim]\n")
    for idx, check in enumerate(CHECKS, 1):
        root_tag = "  [dim]*[/dim]" if check.requires_root else ""
        desc = f"  [dim]{check.description}[/dim]" if check.description else ""
        ui.console.print(f"  [cyan]{idx:>2}.[/cyan]  {check.name}{root_tag}{desc}")


@app.command()
def check(
    ctx: typer.Context,
    all_: bool = typer.Option(False, "--all", help="Run every registered check."),
    checks: Optional[str] = typer.Option(None, "--checks", help="Comma-separated check numbers."),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Run checks non-interactively."""
    severity = ctx.obj["min_severity"] if ctx.obj else Severity.OK

    if not all_ and not checks:
        typer.echo("Use --all or --checks <numbers>. See 'macwatchdog list-checks'.", err=True)
        raise typer.Exit(2)

    if all_:
        selection = list(CHECKS)
    else:
        assert checks is not None
        numbers = [int(t) for t in checks.split(",") if t.strip().isdigit()]
        selection = [CHECKS[i - 1] for i in numbers if 1 <= i <= len(CHECKS)]
        if not selection:
            typer.echo("No valid check numbers given.", err=True)
            raise typer.Exit(2)

    if output_format == "text" and sys.stdout.isatty():
        root_count = sum(1 for c in CHECKS if c.requires_root)
        print_logo()
        ui.print_system_info(root_check_count=root_count)

    start = time.monotonic()
    report = run_checks(selection)
    elapsed = time.monotonic() - start

    if output_format == "json":
        typer.echo(json.dumps(report_to_dict(report), indent=2, default=str))
        return
    if output_format != "text":
        typer.echo(f"Unknown --format {output_format!r} (expected text or json).", err=True)
        raise typer.Exit(2)

    render_report(report, min_severity=severity)
    render_summary(report, elapsed=elapsed)


@app.command()
def export(
    filename: str = typer.Argument(..., help="Destination file (.txt / .json)."),
) -> None:
    """Run all checks and export the report to a file."""
    report = run_checks()
    as_json = filename.endswith(".json")
    path = export_report(report_to_dict(report), filename, as_json=as_json)
    ui.console.print(f"[green]Report exported to {path}[/green]")


@app.command("remove-login-item")
def remove_login_item(name: str) -> None:
    """Remove a classic login item by name (creates a backup first)."""
    ok, message = _remove_login_item(name)
    ui.console.print(("[green]" if ok else "[red]") + message + "[/]")
    if not ok:
        raise typer.Exit(1)


@app.command("backup-ports")
def backup_ports() -> None:
    """Snapshot the current port state."""
    ok, message = ports_manager.backup_port_state()
    ui.console.print(("[green]" if ok else "[red]") + message + "[/]")
    if not ok:
        raise typer.Exit(1)


@app.command("close-port")
def close_port(port: str) -> None:
    """Close a port by gracefully terminating the owning process."""
    ok, message = ports_manager.close_port(port)
    ui.console.print(("[green]" if ok else "[red]") + message + "[/]")
    if not ok:
        raise typer.Exit(1)


@app.command()
def scan(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Run all checks. Shorthand for 'check --all'."""
    severity = ctx.obj["min_severity"] if ctx.obj else Severity.OK
    if output_format == "text" and sys.stdout.isatty():
        root_count = sum(1 for c in CHECKS if c.requires_root)
        print_logo()
        ui.print_system_info(root_check_count=root_count)

    start = time.monotonic()
    report = run_checks()
    elapsed = time.monotonic() - start

    if output_format == "json":
        typer.echo(json.dumps(report_to_dict(report), indent=2, default=str))
        return

    render_report(report, min_severity=severity)
    render_summary(report, elapsed=elapsed)


@app.command()
def status() -> None:
    """Quick security posture: score and top findings only."""
    if sys.stdout.isatty():
        root_count = sum(1 for c in CHECKS if c.requires_root)
        print_logo()
        ui.print_system_info(root_check_count=root_count)

    ui.console.print("[dim]Running quick status scan…[/dim]")
    start = time.monotonic()
    report = run_checks(show_progress=sys.stdout.isatty())
    elapsed = time.monotonic() - start

    score, ceiling_reason = compute_score(report)
    label, style = score_band(score)
    ceiling_str = f"  [dim]· capped by {ceiling_reason}[/dim]" if ceiling_reason else ""

    ui.print_rule()
    ui.console.print(
        f"  [{style}]{score}/100  {label}[/{style}]"
        f"[dim]  ·  {elapsed:.1f}s[/dim]{ceiling_str}"
    )
    ui.print_rule()

    high_priority = sorted(
        [r for r in flatten(report) if r.resolved_severity() >= Severity.MEDIUM],
        key=lambda x: x.resolved_severity(),
        reverse=True,
    )
    if high_priority:
        ui.console.print(f"  [bold]Top findings[/bold]  [dim]({len(high_priority)} issues ≥ MEDIUM)[/dim]")
        for r in high_priority[:10]:
            sev = r.resolved_severity()
            badge = ui._SEVERITY_BADGES[sev]
            ui.console.print(f"  [{ui.sev_style(sev)}][{badge}][/{ui.sev_style(sev)}]  {r.label}: [dim]{r.status}[/dim]")
    else:
        ui.console.print("  [green]No issues at MEDIUM or above.[/green]")
    ui.print_rule()
    ui.console.print()


@app.command()
def timeline(limit: int = typer.Option(50, help="Number of most-recent events to show.")) -> None:
    """View recent events from the structured JSONL timeline."""
    from . import timeline as timeline_module

    events = timeline_module.read_events()[-limit:]
    if not events:
        ui.console.print("[yellow]Timeline is empty.[/yellow]")
        return
    ui.console.print(timeline_module.format_events(events))


if __name__ == "__main__":
    app()
