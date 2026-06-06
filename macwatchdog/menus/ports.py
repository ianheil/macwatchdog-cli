"""Open-ports management menu."""

from __future__ import annotations

import json

from .. import ui
from ..managers import ports as manager
from ..audit.network_listeners import list_listeners


def _ask_index(prompt: str, count: int) -> int | None:
    raw = ui.prompt(prompt, default="").strip()
    if not raw.isdigit():
        return None
    idx = int(raw)
    return idx - 1 if 1 <= idx <= count else None


def run() -> None:
    while True:
        listeners = list_listeners()
        backups = manager.list_backups()
        ui.panel("Open Ports Management")

        if listeners:
            ui.console.print("[bold green]Current listeners:[/bold green]")
            for idx, l in enumerate(listeners, 1):
                ui.console.print(f"[medium_purple1]{idx}.[/medium_purple1] {l.process} (PID {l.pid}) {l.port}")
        else:
            ui.console.print("[green]No listening sockets found.[/green]")

        if backups:
            ui.console.print("\n[bold yellow]Backups:[/bold yellow]")
            for idx, b in enumerate(backups, 1):
                ui.console.print(f"[magenta]{idx}.[/magenta] {b.name}")

        options: list[tuple[str, str]] = [("b", "Back up current port state")]
        if listeners:
            options.append(("c", "Close a port (SIGTERM then SIGKILL)"))
        if backups:
            options.append(("v", "View a backup"))
            options.append(("x", "Diff backup vs. current state"))
            options.append(("d", "Delete a backup"))
        options.append(("m", "Return to main menu"))
        ui.print_menu(options)
        action = ui.prompt("Selection", default="m").strip().lower()

        if action == "b":
            ok, msg = manager.backup_port_state(listeners)
            ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
        elif action == "c" and listeners:
            idx = _ask_index("Number of listener to close", len(listeners))
            if idx is not None:
                listener = listeners[idx]
                port = listener.port.rsplit(":", 1)[-1]
                if ui.confirm(f"Close {listener.process} on port {port}?", default=False):
                    ok, msg = manager.close_port(port)
                    ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
        elif action == "v" and backups:
            idx = _ask_index("Number of backup to view", len(backups))
            if idx is not None:
                data = json.loads(backups[idx].read_text(encoding="utf-8"))
                for entry in data:
                    ui.console.print(
                        f"{entry.get('process')} (PID {entry.get('pid')}) {entry.get('port')}"
                    )
        elif action == "x" and backups:
            idx = _ask_index("Number of backup to diff against current state", len(backups))
            if idx is not None:
                gone, appeared = manager.diff_snapshot(backups[idx])
                if gone:
                    ui.console.print("[red]No longer listening:[/red]")
                    for entry in gone:
                        ui.console.print(f"  - {entry}")
                if appeared:
                    ui.console.print("[yellow]New since backup:[/yellow]")
                    for entry in appeared:
                        ui.console.print(f"  + {entry}")
                if not gone and not appeared:
                    ui.console.print("[green]Backup matches current state.[/green]")
        elif action == "d" and backups:
            idx = _ask_index("Number of backup to delete", len(backups))
            if idx is not None and ui.confirm("Delete backup?", default=False):
                backups[idx].unlink(missing_ok=True)
                ui.console.print("[green]Deleted.[/green]")
        elif action == "m":
            return
        else:
            ui.console.print("[yellow]Nothing to do for that choice.[/yellow]")
