"""Top-level interactive menu."""

from __future__ import annotations

import os
import time
from pathlib import Path

from .. import __version__, ui
from ..audit import CHECKS
from ..logo import print_logo
from ..reports import export_report
from ..runner import flatten, render_report, render_summary, run_checks
from ..scoring import compute_score, score_band
from ..severity import Severity
from . import agents, forensics, kexts, login_items, ports, profiles, search


def _select_checks() -> list | None:
    ui.print_rule(" SELECT CHECKS ")
    for idx, check in enumerate(CHECKS, 1):
        root_tag = "[dim] *[/dim]" if check.requires_root else ""
        ui.console.print(f"  [medium_purple1]{idx:>2}.[/medium_purple1]  {check.name}{root_tag}")
    ui.console.print()
    ui.console.print("  [dim]* requires root   |   blank = all   |   m = back[/dim]")
    raw = ui.prompt("Selection", default="").strip()
    if raw.lower() == "m":
        return None
    if not raw:
        return list(CHECKS)
    numbers = [int(t.strip()) for t in raw.split(",") if t.strip().isdigit()]
    selected = [CHECKS[i - 1] for i in numbers if 1 <= i <= len(CHECKS)]
    if not selected:
        ui.console.print("[yellow]No valid checks selected.[/yellow]")
        return []
    return selected


def _run_timed(checks=None) -> tuple[dict, float]:
    start = time.monotonic()
    report = run_checks(checks) if checks is not None else run_checks()
    return report, time.monotonic() - start


def _post_scan_hints(report: dict) -> None:
    """After a scan, surface remediable findings with direct action prompts."""
    all_results = flatten(report)
    actionable = [
        r for r in all_results
        if r.resolved_severity() >= Severity.MEDIUM
        and r.category in ("Launch Agents/Daemons", "Login Items", "Network Listeners", "Kernel Extensions")
    ]
    if not actionable:
        return
    ui.console.print(f"\n  [bold yellow]{len(actionable)} finding(s) have remediation available:[/bold yellow]")
    for r in actionable:
        category_hint = {
            "Launch Agents/Daemons": "→ Manage agents  [menu 3]",
            "Login Items":           "→ Manage login items  [menu 4]",
            "Network Listeners":     "→ Manage open ports  [menu 5]",
            "Kernel Extensions":     "→ Manage kexts  [menu 6]",
        }.get(r.category, "")
        sev = r.resolved_severity()
        badge = ui._SEVERITY_BADGES[sev]
        ui.console.print(
            f"  [{ui.sev_style(sev)}][{badge}][/{ui.sev_style(sev)}]"
            f"  {r.label}  [dim]{category_hint}[/dim]"
        )


def run() -> None:
    root_count = sum(1 for c in CHECKS if c.requires_root)
    print_logo()
    ui.print_system_info(root_check_count=root_count)

    last_report: dict | None = None

    while True:
        # Show score from last scan if available
        score_line = ""
        if last_report is not None:
            score, ceiling_reason = compute_score(last_report)
            label, style = score_band(score)
            ceiling_note = f"  [dim]· {ceiling_reason} caps score[/dim]" if ceiling_reason else ""
            score_line = f"  Last scan score: [{style}]{score}/100 {label}[/{style}]{ceiling_note}"

        ui.console.print()
        ui.print_rule()
        if score_line:
            ui.console.print(score_line)

        # --- SCAN ---
        ui.console.print("\n  [bold]SCAN[/bold]")
        ui.print_menu([
            ("1", "Full audit  — all checks"),
            ("2", "Select checks to run"),
        ], title=None)

        # --- MANAGE ---
        ui.console.print("\n  [bold]MANAGE[/bold]")
        ui.print_menu([
            ("3", "Launch agents / daemons"),
            ("4", "Login items"),
            ("5", "Open ports"),
            ("6", "Kernel extensions"),
        ], title=None)

        # --- INVESTIGATE ---
        ui.console.print("\n  [bold]INVESTIGATE[/bold]")
        ui.print_menu([
            ("7", "Search agents, profiles, login items"),
            ("8", "MDM / profiles"),
            ("9", "Forensics & timeline"),
        ], title=None)

        # --- SESSION ---
        ui.console.print("\n  [bold]SESSION[/bold]")
        ui.print_menu([
            ("10", "Export last report"),
            ("11", "Help"),
            ("q",  "Quit"),
        ], title=None)

        ui.console.print()
        action = ui.prompt("Selection", default="1").strip().lower()

        if action == "1":
            report, elapsed = _run_timed()
            render_report(report)
            render_summary(report, elapsed=elapsed)
            _post_scan_hints(report)
            last_report = report

        elif action == "2":
            selection = _select_checks()
            if selection is None:
                continue
            if selection:
                report, elapsed = _run_timed(selection)
                render_report(report)
                render_summary(report, elapsed=elapsed)
                _post_scan_hints(report)
                last_report = report

        elif action == "3":
            agents.run()
        elif action == "4":
            login_items.run()
        elif action == "5":
            ports.run()
        elif action == "6":
            kexts.run()
        elif action == "7":
            search.run()
        elif action == "8":
            profiles.run()
        elif action == "9":
            forensics.run()

        elif action == "10":
            if not last_report:
                ui.console.print("[yellow]Run a scan first.[/yellow]")
                continue
            filename = ui.prompt("Filename (.json for JSON format)", default="report.txt")
            path = export_report(
                {cat: [r.to_dict() for r in items] for cat, items in last_report.items()},
                filename,
                as_json=filename.endswith(".json"),
            )
            ui.console.print(f"[green]Exported to {path}[/green]")

        elif action == "11":
            _help()

        elif action in ("q", "12"):
            ui.console.print("[bold green]Bark! Bark! Bark![/bold green]")
            return

        else:
            ui.console.print("[red]Invalid selection.[/red]")

        ui.console.input("\n[dim]Press Enter to continue...[/dim]")


def _help() -> None:
    root_count = sum(1 for c in CHECKS if c.requires_root)
    ui.panel(
        f"macWatchdog v{__version__} — privacy-first macOS security auditor\n\n"
        f"  {len(CHECKS)} registered checks across persistence, privilege escalation,\n"
        "  privacy, network, hardening, and filesystem categories.\n\n"
        f"  {root_count} checks require root for full results.\n"
        "  Run 'sudo macwatchdog' for a complete audit.\n\n"
        "Checks that may trigger macOS Privacy prompts:\n"
        "  TCC, Login Items, Accessibility — this is expected behaviour.\n\n"
        "Timeline log:  ~/Library/Application Support/macwatchdog/timeline.jsonl\n"
        "Snapshots:     ~/Library/Application Support/macwatchdog/snapshots/\n"
        "Quarantine:    ~/Library/Application Support/macwatchdog/quarantine/",
        title=" Help ",
    )
