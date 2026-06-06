"""Login items management menu."""

from __future__ import annotations

import json
from pathlib import Path

from .. import ui
from ..managers import login_items as manager


def _ask_index(prompt: str, count: int) -> int | None:
    raw = ui.prompt(prompt, default="").strip()
    if not raw.isdigit():
        return None
    idx = int(raw)
    return idx - 1 if 1 <= idx <= count else None


def run() -> None:
    while True:
        items = manager.list_login_items()
        backups = manager.list_backups()
        ui.panel("Login Items Management (classic items only)")

        if items:
            ui.console.print("[bold green]Current login items:[/bold green]")
            for idx, item in enumerate(items, 1):
                ui.console.print(f"[medium_purple1]{idx}.[/medium_purple1] {item.display}")
        else:
            ui.console.print("[green]No classic login items found.[/green]")

        if backups:
            ui.console.print("\n[bold yellow]Backups:[/bold yellow]")
            for idx, backup in enumerate(backups, 1):
                try:
                    data = json.loads(backup.read_text(encoding="utf-8"))
                    label = data.get("name", backup.name)
                except Exception:
                    label = backup.name
                ui.console.print(f"[magenta]{idx}.[/magenta] {label}  [{backup.name}]")

        options: list[tuple[str, str]] = [("b", "Back up a login item")]
        if items:
            options.append(("r", "Remove a login item (auto-backup first)"))
        if backups:
            options.append(("s", "Restore a login item from backup"))
            options.append(("d", "Delete a backup"))
        options.append(("m", "Return to main menu"))
        ui.print_menu(options)
        action = ui.prompt("Selection", default="m").strip().lower()

        if action == "b" and items:
            idx = _ask_index("Number of login item to back up", len(items))
            if idx is not None:
                ok, msg = manager.backup_login_item(items[idx])
                ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
        elif action == "r" and items:
            idx = _ask_index("Number of login item to remove", len(items))
            if idx is not None:
                item = items[idx]
                if ui.confirm(f"Remove '{item.name}' (backup will be created)?", default=False):
                    ok, msg = manager.remove_login_item(item.name)
                    ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
        elif action == "s" and backups:
            idx = _ask_index("Number of backup to restore", len(backups))
            if idx is not None:
                ok, msg = manager.restore_login_item(backups[idx])
                ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
        elif action == "d" and backups:
            idx = _ask_index("Number of backup to delete", len(backups))
            if idx is not None and ui.confirm("Delete selected backup?", default=False):
                Path(backups[idx]).unlink(missing_ok=True)
                ui.console.print("[green]Backup deleted.[/green]")
        elif action == "m":
            return
        else:
            ui.console.print("[yellow]Nothing to do for that choice.[/yellow]")
