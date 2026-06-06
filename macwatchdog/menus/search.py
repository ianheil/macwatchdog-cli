"""Unified keyword search across agents, profiles, login items, and backups."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .. import paths, ui
from ..audit.login_items import get_login_items
from ..audit.profiles import parse_profiles
from ..managers import agents as agents_manager


@dataclass
class SearchResult:
    kind: str
    label: str
    detail: str = ""


def _launch_agent_matches(keyword: str) -> list[SearchResult]:
    matches: list[SearchResult] = []
    locations = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        os.path.expanduser("~/Library/LaunchAgents"),
    ]
    for location in locations:
        if not os.path.isdir(location):
            continue
        for entry in sorted(os.listdir(location)):
            if keyword in entry.lower():
                matches.append(SearchResult("Agent/Daemon", os.path.join(location, entry)))
    return matches


def _profile_matches(keyword: str) -> list[SearchResult]:
    results: list[SearchResult] = []
    for profile in parse_profiles():
        haystack = " ".join(
            str(profile.get(k, "")) for k in ("profileIdentifier", "profileDisplayName", "profileOrganization")
        ).lower()
        if keyword in haystack:
            results.append(
                SearchResult(
                    "Profile",
                    profile.get("profileDisplayName") or profile.get("profileIdentifier") or "",
                    detail=profile.get("profileIdentifier", ""),
                )
            )
    return results


def _login_item_matches(keyword: str) -> list[SearchResult]:
    results: list[SearchResult] = []
    for item in get_login_items():
        hay = f"{item.name} {item.path or ''}".lower()
        if keyword in hay:
            results.append(SearchResult(f"Login Item ({item.source})", item.name, detail=item.path or ""))
    return results


def _quarantine_matches(keyword: str) -> list[SearchResult]:
    results: list[SearchResult] = []
    quarantine_root = paths.quarantine_dir()
    for path in quarantine_root.rglob("*"):
        if path.is_file() and keyword in path.name.lower():
            results.append(SearchResult("Quarantined", str(path)))
    return results


def run() -> None:
    keyword = ui.prompt("Keyword to search (case-insensitive)", default="").strip().lower()
    if not keyword:
        ui.console.print("[yellow]No keyword entered.[/yellow]")
        return

    results = (
        _launch_agent_matches(keyword)
        + _profile_matches(keyword)
        + _login_item_matches(keyword)
        + _quarantine_matches(keyword)
    )

    if not results:
        ui.console.print("[green]No matches found.[/green]")
        return

    for idx, r in enumerate(results, 1):
        extra = f" — {r.detail}" if r.detail else ""
        ui.console.print(f"[medium_purple1]{idx}.[/medium_purple1] [{r.kind}] {r.label}{extra}")

    action = ui.prompt(
        "Number to view details, 'd' to quarantine an agent/daemon, or blank to return",
        default="",
    ).strip().lower()

    if not action:
        return
    if action.isdigit():
        idx = int(action) - 1
        if 0 <= idx < len(results):
            r = results[idx]
            ui.panel(f"{r.kind}\nLabel: {r.label}\nDetail: {r.detail or '(n/a)'}", title="Details")
        return
    if action == "d":
        pick = ui.prompt("Number of agent/daemon to quarantine", default="").strip()
        if pick.isdigit():
            idx = int(pick) - 1
            if 0 <= idx < len(results) and results[idx].kind == "Agent/Daemon":
                backup_dir, moved, failed = agents_manager.quarantine_agents([results[idx].label])
                for path in moved:
                    ui.console.print(f"[green]Quarantined {path}[/green]")
                for fail in failed:
                    ui.console.print(f"[red]{fail}[/red]")
