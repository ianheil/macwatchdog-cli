"""Rich-based UI layer shared by the CLI and all interactive menus.

Provides the themed :class:`~rich.console.Console` singleton, helpers for
printing categorised findings, and small wrappers around prompts, tables,
and panels. Honours ``NO_COLOR`` / ``MACWATCHDOG_NO_COLOR`` and the global
``--no-color`` flag via :func:`set_no_color`.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
from datetime import datetime
from typing import Any, Final, Iterable, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .result import CheckResult
from .severity import Severity, severity_for

_THEME = Theme(
    {
        "category":     "bold green",
        "sev.ok":       "green",
        "sev.info":     "medium_purple1",   # purple replaces cyan for info/skipped
        "sev.low":      "steel_blue1",      # softer blue for low-priority suggestions
        "sev.medium":   "yellow",
        "sev.high":     "red",
        "sev.critical": "bold red",
        "sev.error":    "bright_red",       # distinct from purple info
        "tip":          "dim",              # unused directly; kept for safety
        "bullet":       "green",
        "tier":         "orchid1",          # tier/section headers inside info blocks
    }
)

_MACOS_NAMES: Final[dict[str, str]] = {
    "15": "Sequoia",
    "14": "Sonoma",
    "13": "Ventura",
    "12": "Monterey",
    "11": "Big Sur",
    "10.15": "Catalina",
    "10.14": "Mojave",
    "10.13": "High Sierra",
}

_SEVERITY_BADGES: Final[dict[Severity, str]] = {
    Severity.OK:       "OK",
    Severity.INFO:     "INFO",
    Severity.LOW:      "LOW",
    Severity.MEDIUM:   "MED",
    Severity.HIGH:     "HIGH",
    Severity.CRITICAL: "CRIT",
    Severity.ERROR:    "ERR",
}


def _no_color_requested() -> bool:
    return bool(os.environ.get("NO_COLOR")) or os.environ.get("MACWATCHDOG_NO_COLOR") == "1"


console = Console(theme=_THEME, no_color=_no_color_requested(), highlight=False)


def set_no_color(value: bool) -> None:
    """Toggle colour output at runtime (used by ``--no-color``)."""
    global console
    console = Console(theme=_THEME, no_color=value, highlight=False)


def _macos_name(version: str) -> str:
    major = version.split(".")[0]
    minor_key = ".".join(version.split(".")[:2])
    return _MACOS_NAMES.get(major) or _MACOS_NAMES.get(minor_key) or ""


def print_system_info(root_check_count: int = 0) -> None:
    ver = platform.mac_ver()[0]
    name = _macos_name(ver)
    os_str = f"macOS {name} {ver}" if name else f"macOS {ver}"
    hostname = socket.gethostname()
    user = getpass.getuser()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    if os.geteuid() == 0:
        mode_str = "[bold bright_green]root  \\[ elevated — all checks available ][/bold bright_green]"
    elif root_check_count:
        mode_str = f"[yellow]standard user  \\[ {root_check_count} checks need sudo for full results ][/yellow]"
    else:
        mode_str = "[yellow]standard user[/yellow]"

    console.print(f"  [dim]HOST[/dim]  {hostname}")
    console.print(f"  [dim]OS  [/dim]  {os_str}")
    console.print(f"  [dim]USER[/dim]  {user}")
    console.print(f"  [dim]TIME[/dim]  {now}")
    console.print(f"  [dim]MODE[/dim]  {mode_str}")
    console.print()


def print_rule(title: str = "", *, style: str = "green") -> None:
    if title:
        console.print(Rule(f" {title} ", style=style))
    else:
        console.print(Rule(style=style))


def print_category(title: str) -> None:
    console.print(Rule(f" {title} ", style="category"))


def sev_style(severity: Severity) -> str:
    return f"sev.{severity.name.lower()}"


# Keep internal alias for modules that already use it
_sev_style = sev_style


# Statuses that carry meaning beyond the badge colour and should be shown in text
_VERBOSE_STATUSES: frozenset[str] = frozenset(
    {"ALERT", "UNKNOWN", "ERROR", "SKIPPED", "HIGH", "CRITICAL", "SUGGESTION"}
)

# Maximum length for info to be rendered inline rather than as bullets below
_INLINE_INFO_MAX = 72


def print_result(label: str, status: str, info: Any = "", severity: Severity | None = None) -> None:
    sev = severity or severity_for(status)
    style = _sev_style(sev)
    badge = _SEVERITY_BADGES[sev]

    # Status text only when it adds meaning the badge doesn't already give
    status_str = f" [dim]{status}[/dim]" if status.upper() in _VERBOSE_STATUSES else ""

    # Bold label for visual distinction from the badge
    label_str = f"[bold]{label}[/bold]"

    badge_str = f"[bold][{style}][ {badge} ][/{style}][/bold]"

    # Short string → inline after an em-dash; list or long string → bullets below
    if isinstance(info, str) and info and len(info) <= _INLINE_INFO_MAX:
        console.print(f"{badge_str}  {label_str}{status_str}[dim]  —  {info}[/dim]")
    else:
        console.print(f"{badge_str}  {label_str}{status_str}")
        _print_info(info)


def _print_info(info: Any) -> None:
    if not info:
        return
    if isinstance(info, list):
        for item in info:
            if not isinstance(item, str):
                console.print(f"    [bullet]•[/bullet] [dim]{item}[/dim]")
            elif item.startswith("# "):
                # Tier/section header — orchid with ▸ marker, no bullet
                console.print(f"    [tier]▸  {item[2:]}[/tier]")
            elif item.startswith("  "):
                # Sub-item under a tier — deeper indent, dim
                console.print(f"         [dim]{item.strip()}[/dim]")
            else:
                console.print(f"    [bullet]•[/bullet] [dim]{item}[/dim]")
    else:
        for line in str(info).splitlines():
            console.print(f"    [dim]{line}[/dim]")


def print_tip(tip: str) -> None:
    # Arrow in brand green, text in dim — clearly secondary to findings
    if tip:
        console.print(f"  [green]→[/green]  [dim]{tip}[/dim]")


def panel(content: str, *, title: str | None = None) -> None:
    console.print(Panel(content, title=title))


def prompt(message: str, *, default: str = "") -> str:
    from rich.prompt import Prompt

    return Prompt.ask(message, default=default)


def confirm(message: str, *, default: bool = False) -> bool:
    from rich.prompt import Confirm

    return Confirm.ask(message, default=default)


def findings_table(results: Sequence[CheckResult | dict[str, Any]]) -> Table:
    table = Table(show_header=True, header_style="bold magenta", show_lines=False)
    table.add_column("Severity", width=9)
    table.add_column("Check", overflow="fold")
    table.add_column("Status", width=10)

    for item in results:
        if isinstance(item, CheckResult):
            sev = item.resolved_severity()
            label = item.label
            status = item.status
        else:
            sev = severity_for(item.get("status", "OK"))
            label = item.get("label", "")
            status = item.get("status", "")
        table.add_row(
            f"[{_sev_style(sev)}]{sev.label}[/{_sev_style(sev)}]",
            label,
            status,
        )
    return table


def print_menu(
    options: Iterable[tuple[str, str]],
    *,
    title: str | None = "Actions",
) -> None:
    """Render a key/label action menu with a clear visual break.

    A blank line always precedes the menu so it cannot visually run into a
    preceding numbered list, and keys are shown as ``[key]`` to distinguish
    them from item numbers like ``1.``.
    """

    console.print()
    if title:
        console.print(f"[bold magenta]{title}[/bold magenta]")
    for key, description in options:
        console.print(f"  [bold medium_purple1]\\[{key}][/bold medium_purple1] {description}")
