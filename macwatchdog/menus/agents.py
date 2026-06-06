"""Unsigned launch-agent management menu."""

from __future__ import annotations

import os

from .. import ui
from ..managers import agents as manager


def _selection(prompt: str, choices: list, allow_all: bool = True) -> list:
    raw = ui.prompt(
        f"{prompt} (comma-separated numbers{', or \"a\" for all' if allow_all else ''}, blank to cancel)",
        default="",
    ).strip()
    if not raw:
        return []
    if allow_all and raw.lower() == "a":
        return list(choices)
    picked: list = []
    for token in raw.split(","):
        if token.strip().isdigit():
            index = int(token.strip()) - 1
            if 0 <= index < len(choices):
                picked.append(choices[index])
    return picked


def run() -> None:
    if os.geteuid() != 0:
        ui.console.print("[yellow]This menu requires administrator privileges; run with sudo.[/yellow]")
        return
    while True:
        unsigned = manager.currently_unsigned()
        quarantined = manager.list_quarantined()
        ui.panel("Unsigned Launch Agents/Daemons Management")
        if unsigned:
            ui.console.print("[bold green]Currently on system:[/bold green]")
            for idx, path in enumerate(unsigned, 1):
                ui.console.print(f"[bold medium_purple1]{idx}.[/bold medium_purple1] {path}")
        else:
            ui.console.print("[green]No unsigned launch agents/daemons found.[/green]")

        if quarantined:
            ui.console.print("\n[bold yellow]Quarantined:[/bold yellow]")
            for idx, path in enumerate(quarantined, 1):
                ui.console.print(f"[magenta]{idx}.[/magenta] {path}")

        ui.print_menu(
            [
                ("q", "Quarantine unsigned agents/daemons"),
                ("r", "Restore from quarantine"),
                ("p", "Purge all quarantined items"),
                ("m", "Return to main menu"),
            ]
        )
        action = ui.prompt("Selection", default="m").strip().lower()
        if action == "q" and unsigned:
            picks = _selection("Numbers to quarantine", unsigned)
            if picks:
                backup_dir, moved, failed = manager.quarantine_agents(picks)
                ui.console.print(f"[green]Quarantined {len(moved)} file(s) to {backup_dir}[/green]")
                for fail in failed:
                    ui.console.print(f"[red]{fail}[/red]")
        elif action == "r" and quarantined:
            picks = _selection("Numbers to restore", quarantined)
            if picks:
                restored, failed = manager.restore_agents(picks)
                for path in restored:
                    ui.console.print(f"[green]Restored {path}[/green]")
                for fail in failed:
                    ui.console.print(f"[red]{fail}[/red]")
        elif action == "p":
            if ui.confirm("Permanently delete all quarantined items?", default=False):
                count = manager.purge_quarantine()
                ui.console.print(f"[green]Purged {count} file(s).[/green]")
        elif action == "m":
            return
        else:
            ui.console.print("[yellow]Nothing to do for that choice.[/yellow]")
