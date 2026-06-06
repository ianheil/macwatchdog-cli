"""Kernel extension management menu."""

from __future__ import annotations

import os
from pathlib import Path

from .. import ui
from ..managers import kexts as manager


def _selection(prompt: str, choices: list, allow_all: bool = True) -> list:
    raw = ui.prompt(
        f"{prompt} (numbers{', \"a\" for all' if allow_all else ''}, blank to cancel)",
        default="",
    ).strip()
    if not raw:
        return []
    if allow_all and raw.lower() == "a":
        return list(choices)
    picked: list = []
    for token in raw.split(","):
        if token.strip().isdigit():
            idx = int(token.strip()) - 1
            if 0 <= idx < len(choices):
                picked.append(choices[idx])
    return picked


def run() -> None:
    if os.geteuid() != 0:
        ui.console.print(
            "[yellow]Kernel extension management requires root. Run as sudo.[/yellow]"
        )
        return

    while True:
        installed = manager.list_installed()
        quarantined = manager.list_quarantined()

        ui.panel("Kernel Extension Management")

        if installed:
            ui.console.print("[bold green]Installed in /Library/Extensions:[/bold green]")
            for idx, k in enumerate(installed, 1):
                parts = []
                if k.loaded:
                    parts.append("[yellow]loaded[/yellow]")
                else:
                    import platform
                    if platform.machine() == "arm64":
                        parts.append("[dim]inert on Apple Silicon[/dim]")
                    else:
                        parts.append("[dim]not loaded[/dim]")
                if k.signed is True:
                    parts.append("[green]signed[/green]")
                elif k.signed is False:
                    parts.append("[bold red]UNSIGNED[/bold red]")
                status = "  ·  ".join(parts) if parts else ""
                ui.console.print(f"  [medium_purple1]{idx}.[/medium_purple1]  {k.name}  {status}")
        else:
            ui.console.print("[green]No third-party kexts in /Library/Extensions.[/green]")

        if quarantined:
            ui.console.print("\n[bold yellow]Quarantined:[/bold yellow]")
            for idx, p in enumerate(quarantined, 1):
                ui.console.print(f"  [dim]{idx}.[/dim]  {p.name}  [dim]← {p.parent.name}[/dim]")

        options = []
        if installed:
            options.append(("q", "Quarantine (remove) selected kext(s)"))
        if quarantined:
            options.append(("r", "Restore from quarantine"))
            options.append(("p", "Purge all quarantined kexts"))
        options.append(("m", "Return to main menu"))
        ui.print_menu(options)

        action = ui.prompt("Selection", default="m").strip().lower()

        if action == "q" and installed:
            picks = _selection("Numbers to quarantine", installed)
            if picks:
                paths_to_quarantine = [k.path for k in picks]
                _, moved, failed = manager.quarantine_kexts(paths_to_quarantine)
                for p in moved:
                    ui.console.print(f"[green]Quarantined {Path(p).name}[/green]")
                for f in failed:
                    ui.console.print(f"[red]{f}[/red]")
                if moved:
                    ui.console.print(
                        "[dim]Kext removed. A reboot may be needed to fully unload if it was previously active.[/dim]"
                    )

        elif action == "r" and quarantined:
            picks = _selection("Numbers to restore", quarantined)
            if picks:
                restored, failed = manager.restore_kexts(picks)
                for p in restored:
                    ui.console.print(f"[green]Restored {Path(p).name}[/green]")
                for f in failed:
                    ui.console.print(f"[red]{f}[/red]")

        elif action == "p":
            if ui.confirm("Permanently delete all quarantined kexts?", default=False):
                count = manager.purge_quarantine()
                ui.console.print(f"[green]Purged {count} backup(s).[/green]")

        elif action == "m":
            return

        else:
            ui.console.print("[yellow]Nothing to do.[/yellow]")

        ui.console.input("\n[dim]Press Enter to continue...[/dim]")
