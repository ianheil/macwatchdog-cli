"""Forensics / reporting menu."""

from __future__ import annotations

from .. import paths, timeline, ui
from ..reports import compare_snapshots, create_snapshot, list_snapshots


def _ask_index(prompt: str, count: int) -> int | None:
    raw = ui.prompt(prompt, default="").strip()
    if not raw.isdigit():
        return None
    idx = int(raw)
    return idx - 1 if 1 <= idx <= count else None


def run() -> None:
    while True:
        ui.panel("Forensics & Reporting")
        options: list[tuple[str, str]] = [
            ("s", "Create snapshot"),
            ("c", "Compare two snapshots"),
            ("t", "View timeline"),
        ]
        if paths.timeline_log().exists():
            options.append(("x", "Clear timeline"))
        if list_snapshots():
            options.append(("d", "Delete all snapshots"))
        options.append(("m", "Return to main menu"))
        ui.print_menu(options)
        action = ui.prompt("Selection", default="m").strip().lower()
        if action == "s":
            path = create_snapshot()
            ui.console.print(f"[green]Snapshot saved to {path}[/green]")
        elif action == "c":
            snaps = list_snapshots()
            if len(snaps) < 2:
                ui.console.print("[yellow]Need at least two snapshots to compare.[/yellow]")
                continue
            for i, snap in enumerate(snaps, 1):
                ui.console.print(f"[cyan]{i}.[/cyan] {snap.name}")
            a = _ask_index("First snapshot", len(snaps))
            b = _ask_index("Second snapshot", len(snaps))
            if a is None or b is None:
                continue
            diff = compare_snapshots(snaps[a], snaps[b])
            if diff["added"]:
                ui.console.print("[green]Profiles added:[/green] " + ", ".join(diff["added"]))
            if diff["removed"]:
                ui.console.print("[red]Profiles removed:[/red] " + ", ".join(diff["removed"]))
            if not diff["added"] and not diff["removed"]:
                ui.console.print("[green]No profile changes between snapshots.[/green]")
        elif action == "t":
            events = timeline.read_events()
            if not events:
                ui.console.print("[yellow]Timeline is empty.[/yellow]")
            else:
                ui.panel(timeline.format_events(events), title="Timeline")
        elif action == "x":
            if ui.confirm("Clear the timeline?", default=False):
                timeline.clear()
                ui.console.print("[green]Timeline cleared.[/green]")
        elif action == "d":
            if ui.confirm("Delete all snapshots?", default=False):
                for snap in list_snapshots():
                    snap.unlink(missing_ok=True)
                ui.console.print("[green]Snapshots deleted.[/green]")
        elif action == "m":
            return
        else:
            ui.console.print("[yellow]Invalid selection.[/yellow]")
