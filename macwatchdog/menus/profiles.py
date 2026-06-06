"""Profile / MDM management menu."""

from __future__ import annotations

import json

from .. import paths, ui
from ..audit.profiles import check_profiles, get_mdm_info, remove_profile
from ..timeline import log_event


def _ask_index(prompt: str, count: int) -> int | None:
    raw = ui.prompt(prompt, default="").strip()
    if not raw.isdigit():
        return None
    idx = int(raw)
    return idx - 1 if 1 <= idx <= count else None


def run() -> None:
    current_mdm = get_mdm_info()
    state_file = paths.mdm_state_file()
    last = state_file.read_text(encoding="utf-8").strip() if state_file.exists() else None

    if last is None:
        state_file.write_text(current_mdm, encoding="utf-8")
        ui.console.print(f"[green]MDM status recorded:[/green] {current_mdm}")
    elif last != current_mdm:
        ui.console.print(
            f"[yellow]MDM status changed.[/yellow]\nPrevious: {last}\nCurrent: {current_mdm}"
        )
        state_file.write_text(current_mdm, encoding="utf-8")
        log_event("mdm.state.changed", previous=last, current=current_mdm)
    else:
        ui.console.print(f"[green]MDM status unchanged.[/green] {current_mdm}")

    report = check_profiles()
    profiles = report.extras.get("profiles", [])
    if not profiles:
        ui.console.print("[green]No configuration profiles installed.[/green]")
        return

    ui.console.print("\n[bold magenta]Configuration Profiles:[/bold magenta]")
    for idx, profile in enumerate(profiles, 1):
        badges = []
        if profile.get("mdm"):
            badges.append("[yellow]MDM[/yellow]")
        if not profile.get("removable", True):
            badges.append("[red]LOCKED[/red]")
        if profile.get("risk"):
            badges.append("[red]risk=" + "/".join(profile["risk"]) + "[/red]")
        ui.console.print(
            f"[medium_purple1]{idx}.[/medium_purple1] {profile.get('profileDisplayName') or profile.get('profileIdentifier')} ({profile.get('profileIdentifier', 'N/A')}) "
            + " ".join(badges)
        )

    ui.print_menu(
        [
            ("r", "Remove a profile"),
            ("m", "Add a profile to the auto-remove watchlist"),
            ("q", "Return to main menu"),
        ]
    )
    action = ui.prompt("Selection", default="q")
    if action.lower() == "r":
        idx = _ask_index("Number of profile to remove", len(profiles))
        if idx is None:
            return
        profile = profiles[idx]
        if not profile.get("removable", True):
            ui.console.print("[red]This profile is locked and cannot be removed.[/red]")
            return
        if profile.get("mdm") and not ui.confirm(
            "This is an MDM profile; removing it may cause management issues. Continue?",
            default=False,
        ):
            return
        ok, msg = remove_profile(profile.get("profileIdentifier", ""))
        ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
    elif action.lower() == "m":
        idx = _ask_index("Number of profile to monitor", len(profiles))
        if idx is None:
            return
        profile = profiles[idx]
        if profile.get("mdm") or not profile.get("removable", True):
            ui.console.print("[yellow]Only non-MDM, removable profiles can be auto-removed.[/yellow]")
            return
        identifier = profile.get("profileIdentifier", "")
        watchlist_file = paths.watchlist_file()
        watchlist = []
        if watchlist_file.exists():
            try:
                watchlist = json.loads(watchlist_file.read_text(encoding="utf-8"))
            except Exception:
                watchlist = []
        if identifier not in watchlist:
            watchlist.append(identifier)
            watchlist_file.write_text(json.dumps(watchlist, indent=2), encoding="utf-8")
        ok, msg = remove_profile(identifier)
        ui.console.print(f"[{'green' if ok else 'red'}]{msg}[/]")
        log_event("profile.watchlist.added", identifier=identifier)
