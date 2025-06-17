import argparse
import os
import sys
import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from utils.ascii_art import print_logo
from utils.output import print_category, print_result, export_report, print_tip
from audit.mdm import check_mdm_and_dep
from audit.remote import check_remote_management
from audit.launch_agents import check_launch_agents, is_unsigned
from audit.profiles import check_profiles, remove_profile, get_mdm_info
from audit.usb import check_usb
from audit.network import check_network
from audit.permissions import check_world_writable
from audit.users import check_admin_users
from audit.login_items import check_login_items, remove_login_item, get_login_items, restore_login_item, get_quarantine_dir
from audit.network_listeners import check_network_listeners, backup_port_state, close_port_process, restore_port_state
from audit.accessibility import check_accessibility_apps
from audit.tcc import check_tcc_permissions
from audit.hardening import (
    check_sip, check_gatekeeper, check_xprotect, check_firewall, check_bluetooth, check_firmware_password,
    check_firewall_stealth, check_guest_account, check_remote_apple_events, check_screen_sharing, check_automatic_updates, check_filevault
)
import shutil
import time
from pathlib import Path
import stat
import subprocess
import json
from datetime import datetime

# Read version from VERSION file
VERSION = "unknown"
try:
    # Try same directory as main.py
    version_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
    if not os.path.isfile(version_path):
        # Try parent directory (project root)
        version_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION")
    with open(version_path) as vf:
        VERSION = vf.read().strip()
except Exception:
    pass

app = typer.Typer(add_completion=False, invoke_without_command=True)
console = Console()

CHECKS = [
    ("MDM Enrollment", check_mdm_and_dep, "MDM"),
    ("Remote Access", check_remote_management, "Remote Access"),
    ("Launch Agents/Daemons", check_launch_agents, "Launch Agents/Daemons"),
    ("Configuration Profiles (All, with Risk Analysis)", check_profiles, "Profiles"),
    ("USB Devices", check_usb, "USB"),
    ("Network Interfaces & Connections", check_network, "Network"),
    ("World-writable/Suspicious Files", check_world_writable, "Permissions"),
    ("Admin Users/Groups", check_admin_users, "Users"),
    ("Login Items", check_login_items, "Login Items"),
    ("Network Listeners (Open Ports)", check_network_listeners, "Network Listeners"),
    ("Accessibility/Full Disk Access", check_accessibility_apps, "Accessibility"),
    ("TCC Privacy Permissions", check_tcc_permissions, "TCC Privacy"),
    ("System Integrity Protection (SIP)", check_sip, "System Hardening & Security"),
    ("Gatekeeper", check_gatekeeper, "System Hardening & Security"),
    ("XProtect", check_xprotect, "System Hardening & Security"),
    ("Firewall & Stealth Mode", lambda: [check_firewall(), check_firewall_stealth()], "System Hardening & Security"),
    ("Bluetooth", check_bluetooth, "System Hardening & Security"),
    ("Guest Account", check_guest_account, "System Hardening & Security"),
    ("Remote Apple Events", check_remote_apple_events, "System Hardening & Security"),
    ("Screen Sharing", check_screen_sharing, "System Hardening & Security"),
    ("Automatic Software Updates", check_automatic_updates, "System Hardening & Security"),
    ("FileVault", check_filevault, "System Hardening & Security"),
    ("Firmware Password", check_firmware_password, "System Hardening & Security"),
]

MANUAL_HARDENING_TIPS = [
    "[Manual] Review your AirDrop status in Control Center or System Preferences > General > AirDrop & Handoff. Set to 'Contacts Only' or 'No One' for better privacy.",
    # Add more manual tips here as needed
]

# Quarantine folder (could be renamed to 'dog_house' for fun, but using 'quarantine' for clarity)
QUARANTINE_DIR = Path(__file__).parent / "quarantine"
SNAPSHOT_DIR = QUARANTINE_DIR / "snapshots"
LOG_FILE = QUARANTINE_DIR / "watchdog_timeline.log"

def run_all_checks():
    report = {}
    for name, func, cat in CHECKS:
        result = func()
        # If the result is a list (e.g., firewall & stealth), flatten into the category
        if isinstance(result, list):
            for r in result:
                report.setdefault(cat, []).append(r)
        else:
            report.setdefault(cat, []).append(result)
    return report

def print_report(report):
    # Only show AirDrop tip if relevant checks are present
    manual_tips = []
    relevant_labels = set()
    for results in report.values():
        for item in results:
            if isinstance(item, list):
                for subitem in item:
                    relevant_labels.add(subitem.get("label", ""))
            else:
                relevant_labels.add(item.get("label", ""))
    AIRDROP_RELEVANT_LABELS = {"Bluetooth", "Network Interfaces & Connections", "Screen Sharing", "Remote Apple Events"}
    if relevant_labels & AIRDROP_RELEVANT_LABELS:
        manual_tips.append({
            "title": "AirDrop & Handoff",
            "bullets": [
                "Review your AirDrop status in Control Center or System Settings > General > AirDrop & Handoff. Set to 'Contacts Only' or 'No One' for better privacy.",
                "Consider turning off 'Allow Handoff between this Mac and your iCloud devices' in System Settings > General > AirDrop & Handoff if you do not use this feature."
            ]
        })
    grouped_manuals = []
    firmware_pw_block = []
    for category, results in report.items():
        print_category(category)
        for item in results:
            items_to_process = item if isinstance(item, list) else [item]
            for subitem in items_to_process:
                # Special handling for firmware password SUGGESTION
                if subitem["label"].startswith("Firmware Password") and subitem.get("status") == "SUGGESTION":
                    block = []
                    if subitem.get("info"):
                        if isinstance(subitem["info"], list):
                            for line in subitem["info"]:
                                block.append(line)
                        else:
                            block.append(subitem['info'])
                    if subitem.get("tip"):
                        block.append(subitem['tip'])
                    if block:
                        firmware_pw_block.append({
                            "title": "Firmware Password",
                            "bullets": block
                        })
                    continue
                # Special handling for automatic updates UNKNOWN
                if subitem["label"] == "Automatic Software Updates" and subitem.get("status") == "UNKNOWN":
                    block = []
                    for line in subitem.get("info", []):
                        if line.startswith("[Manual]"):
                            block.append(line[8:].strip())
                        else:
                            if "System Settings > General > Software Update" in line:
                                line = line.replace(
                                    "System Settings > General > Software Update > (i) Automatic Updates",
                                    "System Settings > General > Software Update > Automatic Updates"
                                )
                            block.append(line.strip())
                    grouped_manuals.append({
                        "title": "Automatic Updates",
                        "bullets": block
                    })
                    continue
                print_result(subitem["label"], subitem["status"], subitem.get("info", ""))
                # --- DEP/MDM Note ---
                if subitem["label"] == "MDM & DEP Enrollment" and not subitem.get("dep_enrolled", True):
                    print_tip("Note: If you see a system notification to Enroll in Remote Management, this Mac is assigned to DEP but not yet enrolled. DEP status may not be reported until enrollment is complete.")
                if "tip" in subitem and subitem["tip"]:
                    print_tip(subitem["tip"])
    # Manual hardening tips
    if manual_tips or grouped_manuals or firmware_pw_block:
        print_category("Manual Hardening Suggestions")
        from rich.console import Console
        console = Console()
        # Print AirDrop and other manual tips as blocks
        for block in manual_tips:
            console.print(f"[bold]{block['title']}[/bold]")
            for bullet in block['bullets']:
                console.print(f"  [cyan]•[/cyan] {bullet}")
        for block in grouped_manuals:
            console.print(f"[bold]{block['title']}[/bold]")
            for bullet in block['bullets']:
                console.print(f"  [cyan]•[/cyan] {bullet}")
        for fw_block in firmware_pw_block:
            console.print(f"[bold]{fw_block['title']}[/bold]")
            for bullet in fw_block['bullets']:
                console.print(f"  [cyan]•[/cyan] {bullet}")

def select_checks_menu():
    while True:
        console.print(Panel("[bold magenta]Select checks to run (comma separated numbers, e.g. 1,3,5, or 'm' to return to main menu):[/bold magenta]"))
        for idx, (name, _, _) in enumerate(CHECKS, 1):
            console.print(f"[bold cyan]{idx}.[/bold cyan] {name}")
        console.print("[bold cyan]m.[/bold cyan] Return to main menu")
        raw = Prompt.ask("Selection", default="1")
        if raw.strip().lower() == 'm':
            return None  # Signal to return to main menu
        try:
            nums = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
            selected = [CHECKS[i-1][0] for i in nums if 1 <= i <= len(CHECKS)]
            if not selected:
                console.print("[yellow]No checks selected. Please select at least one check or 'm' to return to the main menu.[/yellow]")
                continue
            report = {}
            for name, func, cat in CHECKS:
                if name in selected:
                    result = func()
                    report.setdefault(cat, []).append(result)
            print_report(report)
            input("\nPress Enter to return to the select checks menu...")
        except Exception as e:
            console.print(f"[red]Invalid input:[/red] {e}")
            continue

def find_unsigned_agents():
    suspicious = []
    paths = [
        "/Library/LaunchAgents", "/Library/LaunchDaemons",
        os.path.expanduser("~/Library/LaunchAgents")
    ]
    for path in paths:
        if os.path.exists(path):
            for f in os.listdir(path):
                full_path = os.path.join(path, f)
                if is_unsigned(full_path):
                    suspicious.append(full_path)
    return suspicious

def quarantine_agents(selected_files):
    QUARANTINE_DIR.mkdir(exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = QUARANTINE_DIR / f"backup_{timestamp}"
    backup_dir.mkdir()
    for file_path in selected_files:
        try:
            shutil.move(file_path, backup_dir)
            console.print(f"[green]Quarantined:[/green] {file_path} -> {backup_dir}")
        except Exception as e:
            console.print(f"[red]Failed to quarantine {file_path}: {e}[/red]")
    return backup_dir

def restore_agents(backup_dir):
    for file_path in Path(backup_dir).iterdir():
        try:
            dest = Path("/Library/LaunchAgents") if "LaunchAgents" in str(file_path) else Path("/Library/LaunchDaemons")
            shutil.move(str(file_path), dest)
            console.print(f"[green]Restored:[/green] {file_path} -> {dest}")
        except Exception as e:
            console.print(f"[red]Failed to restore {file_path}: {e}[/red]")

def search_items():
    print_logo()
    console.print(Panel("[bold magenta]Search for agents, profiles, login items, or files by keyword[/bold magenta]"))
    keyword = Prompt.ask("Enter keyword to search for (case-insensitive)").strip().lower()
    if not keyword:
        console.print("[yellow]No keyword entered. Returning to menu.[/yellow]")
        return
    # Gather all items
    results = []
    # Launch agents/daemons
    for path in ["/Library/LaunchAgents", "/Library/LaunchDaemons", os.path.expanduser("~/Library/LaunchAgents")]:
        if os.path.exists(path):
            for f in os.listdir(path):
                if keyword in f.lower():
                    results.append(("Agent/Daemon", os.path.join(path, f), None))
    # Profiles (search lines for keyword)
    try:
        result = subprocess.run(["profiles", "list", "-all"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if keyword in line.lower():
                results.append(("Profile", line.strip(), None))
    except Exception:
        pass
    # Login items (search name and path for keyword)
    try:
        result = subprocess.run([
            'osascript', '-e', 'tell application "System Events" to get the name of every login item'
        ], capture_output=True, text=True)
        path_result = subprocess.run([
            'osascript', '-e', 'tell application "System Events" to get the path of every login item'
        ], capture_output=True, text=True)
        items = [i.strip() for i in result.stdout.strip().split(',') if i.strip()]
        paths = [p.strip() for p in path_result.stdout.strip().split(',') if p.strip()]
        for i, item in enumerate(items):
            path = paths[i] if i < len(paths) else None
            # Only add if keyword matches name or path
            if keyword in item.lower() or (path and keyword in path.lower()):
                results.append(("Login Item", item, path))
    except Exception:
        pass
    # Quarantine (search filename for keyword)
    if QUARANTINE_DIR.exists():
        for backup_dir in QUARANTINE_DIR.iterdir():
            if backup_dir.is_dir():
                for f in backup_dir.iterdir():
                    if keyword in f.name.lower():
                        results.append(("Quarantined", str(f), None))
    if not results:
        console.print("[green]No matches found for that keyword.[/green]")
        return
    console.print(Panel(f"[bold green]Search results for '{keyword}':[/bold green]"))
    for idx, item in enumerate(results, 1):
        typ, val, *extra = item
        typ, val = item[0], item[1]
        console.print(f"[bold cyan]{idx}.[/bold cyan] [{typ}] {val}")
    # Only show d/r if any Agent/Daemon or Quarantined in results
    show_dr = any(typ in ("Agent/Daemon", "Quarantined") for typ, *_ in results)
    prompt_msg = "Enter number to view details"
    if show_dr:
        prompt_msg += ", 'd' to disable/quarantine, 'r' to restore"
    prompt_msg += ", or blank to return"
    raw = Prompt.ask(prompt_msg, default="")
    if not raw:
        return
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(results):
            typ, val, *extra = results[idx-1]
            if typ == "Agent/Daemon" or typ == "Quarantined":
                try:
                    st = os.stat(val)
                    perms = stat.filemode(st.st_mode)
                    with open(val, "r", errors="ignore") as f:
                        content = f.read(500)
                    console.print(Panel(f"Path: {val}\nPermissions: {perms}\nFirst 500 chars:\n{content}", title="Details"))
                except Exception as e:
                    console.print(f"[red]Could not read file: {e}[/red]")
            elif typ == "Login Item":
                path = extra[0] if extra else None
                details = f"Login Item: {val}\n"
                if path:
                    details += f"Path: {path}"
                else:
                    details += "No additional details available."
                console.print(Panel(details, title="Details"))
            else:
                details = f"{typ}: {val}\nNo additional details available."
                console.print(Panel(details, title="Details"))
            return  # Only one input pause, then return to menu
    elif show_dr and raw.lower() == 'd':
        # Disable/quarantine
        idx = Prompt.ask("Enter number to disable/quarantine", default="")
        if idx.isdigit():
            idx = int(idx)
            if 1 <= idx <= len(results):
                typ, val, *_ = results[idx-1]
                if typ == "Agent/Daemon":
                    backup_dir = quarantine_agents([val])
                    console.print(f"[green]Quarantined {val} to {backup_dir}[/green]")
                else:
                    console.print("[yellow]Can only quarantine agents/daemons from here.[/yellow]")
        return  # Only one input pause, then return to menu
    elif show_dr and raw.lower() == 'r':
        idx = Prompt.ask("Enter number to restore from quarantine", default="")
        if idx.isdigit():
            idx = int(idx)
            if 1 <= idx <= len(results):
                typ, val, *_ = results[idx-1]
                if typ == "Quarantined":
                    try:
                        dest = Path("/Library/LaunchAgents") if "LaunchAgents" in str(val) else Path("/Library/LaunchDaemons")
                        shutil.move(str(val), dest)
                        console.print(f"[green]Restored:[/green] {val} -> {dest}")
                    except Exception as e:
                        console.print(f"[red]Failed to restore {val}: {e}[/red]")
                else:
                    console.print("[yellow]Can only restore quarantined items from here.[/yellow]")
        return  # Only one input pause, then return to menu

@app.command()
def version():
    """Show the current version of macWatchdog."""
    console.print(f"macWatchdog version: [bold green]{VERSION}[/bold green]")

@app.command()
def menu():
    print_logo()
    console.print(f"[dim]macWatchdog version {VERSION}[/dim]")
    if os.geteuid() != 0:
        console.print("[yellow]Warning: Some checks may require administrator (sudo) privileges for full results. Run with 'sudo' if you want a complete audit.[/yellow]")
    last_report = None
    while True:
        console.print(Panel("[bold green]Growls..macWatchdog is on duty. What's your move?[/bold green]"))
        console.print("[bold cyan]1.[/bold cyan] Run all checks")
        console.print("[bold cyan]2.[/bold cyan] Select checks to run")
        console.print("[bold cyan]3.[/bold cyan] Manage unsigned launch agents/daemons")
        console.print("[bold cyan]4.[/bold cyan] Manage login items")
        console.print("[bold cyan]5.[/bold cyan] Manage open ports")
        console.print("[bold cyan]6.[/bold cyan] Search agents/profiles/login items")
        console.print("[bold cyan]7.[/bold cyan] Profile/MDM Management")
        console.print("[bold cyan]8.[/bold cyan] Forensics/Reporting")
        console.print("[bold cyan]9.[/bold cyan] Help/About")
        console.print("[bold cyan]10.[/bold cyan] View README")
        console.print("[bold cyan]11.[/bold cyan] Export last report")
        console.print("[bold cyan]12.[/bold cyan] Quit")
        action = Prompt.ask("Selection", default="1")
        if action == "1":
            if os.geteuid() != 0:
                console.print("[yellow]Warning: Some checks may require administrator (sudo) privileges for full results.[/yellow]")
            report = run_all_checks()
            print_report(report)
            last_report = report
            input("\nPress Enter to return to the menu...")
        elif action == "2":
            if os.geteuid() != 0:
                console.print("[yellow]Warning: Some checks may require administrator (sudo) privileges for full results.[/yellow]")
            while True:
                result = select_checks_menu()
                if result is None:
                    break  # Return to main menu
            input("\nPress Enter to return to the menu...")
        elif action == "3":
            manage_unsigned()
            input("\nPress Enter to return to the menu...")
        elif action == "4":
            manage_login_items()
            input("\nPress Enter to return to the menu...")
        elif action == "5":
            manage_ports()
            input("\nPress Enter to return to the menu...")
        elif action == "6":
            search_items()
            input("\nPress Enter to return to the menu...")
        elif action == "7":
            profile_mdm_menu()
        elif action == "8":
            forensics_menu()
        elif action == "9":
            console.print(Panel("[bold magenta]macWatchdog Help/About[/bold magenta]\n\n"
                "- Audit MDM enrollment, remote access, launch agents/daemons, configuration profiles, USB devices, network interfaces, and more\n"
                "- Unsigned Launch Agents/Daemons Management: Detect, quarantine, restore, or purge unsigned launch agents/daemons with automatic backup creation\n"
                "- Login Items Management: View, backup, remove, and restore login items with automatic backup creation\n"
                "- Port Management: Monitor open ports, create backups of port state, and safely close ports with automatic backup creation\n"
                "- Search Functionality: Find agents, profiles, login items, or files by keyword across multiple locations\n"
                "- Detect world-writable/suspicious files, unknown admin users, login items, open network listeners, and apps with Accessibility/Full Disk Access\n"
                "- Profile/MDM Deep Dive: List, flag, and remove user-removable configuration profiles; alert on MDM changes\n"
                "- Forensics & Reporting: Export system snapshots, compare snapshots, view a timeline/log of changes\n"
                "- Export reports to text or JSON\n"
                "- Modular, open source, and privacy-first\n\n"
                "[yellow]Note: Some checks may trigger macOS privacy popups (TCC) for full access. See the README for details.[/yellow]"
            ))
            input("\nPress Enter to return to the menu...")
        elif action == "10":
            try:
                readme_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md")
                with open(readme_path, "r") as f:
                    content = f.read()
                console.print(Panel(content, title="README.md", expand=False))
            except Exception as e:
                console.print(f"[red]Could not open README.md: {e}[/red]")
            input("\nPress Enter to return to the menu...")
        elif action == "11":
            if not last_report:
                console.print("[yellow]No report to export. Run a check first.[/yellow]")
                input("\nPress Enter to return to the menu...")
                continue
            filename = Prompt.ask("Enter filename (e.g. report.json or report.txt)", default="report.txt")
            as_json = filename.endswith(".json")
            export_report(last_report, filename, as_json=as_json)
            console.print(f"\n[green]Report exported to {filename}[/green]")
            input("\nPress Enter to return to the menu...")
        elif action == "12":
            console.print("[bold magenta]Bark! Bark! Bark![/bold magenta]")
            break
        else:
            console.print("[red]Invalid selection. Please enter a valid number.[/red]")

@app.command()
def check(
    all: bool = typer.Option(False, "--all", help="Run all checks"),
    checks: str = typer.Option("", "--checks", help="Comma separated check numbers to run (e.g. 1,3,5)")
):
    print_logo()
    if os.geteuid() != 0:
        console.print("[yellow]Warning: Some checks may require administrator (sudo) privileges for full results. Run with 'sudo' if you want a complete audit.[/yellow]")
    if all:
        report = run_all_checks()
        print_report(report)
    elif checks:
        nums = [int(x.strip()) for x in checks.split(",") if x.strip().isdigit()]
        selected = [CHECKS[i-1][0] for i in nums if 1 <= i <= len(CHECKS)]
        report = {}
        for name, func, cat in CHECKS:
            if name in selected:
                result = func()
                report.setdefault(cat, []).append(result)
        print_report(report)
    else:
        console.print("[yellow]No checks specified. Use --all or --checks.[/yellow]")

@app.command()
def manage_unsigned():
    """Manage unsigned launch agents/daemons."""
    print_logo()
    if os.geteuid() != 0:
        console.print("[yellow]Warning: This feature requires administrator (sudo) privileges![/yellow]")
        return
    while True:
        agents = find_unsigned_agents()
        quarantined = []
        agents_dir = QUARANTINE_DIR / "agents"
        if agents_dir.exists():
            for backup_dir in sorted(agents_dir.iterdir(), reverse=True):
                if backup_dir.is_dir():
                    for f in backup_dir.iterdir():
                        quarantined.append(str(f))
        console.print(Panel("[bold magenta]Unsigned Launch Agents/Daemons Management[/bold magenta]"))
        if agents:
            console.print("[bold green]Unsigned agents/daemons currently on system:[/bold green]")
            for idx, path in enumerate(agents, 1):
                console.print(f"[bold cyan]{idx}.[/bold cyan] {path}")
        else:
            console.print("[green]No unsigned launch agents/daemons found on system![green]")
        if quarantined:
            console.print("\n[bold yellow]Quarantined agents/daemons:[/bold yellow]")
            for idx, path in enumerate(quarantined, 1):
                console.print(f"[bold magenta]{idx}.[/bold magenta] {path}")
        else:
            console.print("[green]No quarantined agents/daemons found![green]")
        console.print("\n[bold cyan]1.[/bold cyan] Quarantine unsigned agents/daemons")
        console.print("[bold cyan]2.[/bold cyan] Restore from quarantine")
        console.print("[bold cyan]3.[/bold cyan] Purge all quarantined items")
        console.print("[bold cyan]4.[/bold cyan] Return to main menu")
        action = Prompt.ask("Selection", default="4")
        if action == "1" and agents:
            raw = Prompt.ask("Enter numbers to quarantine (comma separated, or 'a' for all, or leave blank to cancel)", default="")
            if not raw:
                console.print("[yellow]No files selected. Returning to manage menu.[/yellow]")
                continue
            if raw.strip().lower() == 'a':
                selected = agents
            else:
                try:
                    nums = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
                    selected = [agents[i-1] for i in nums if 1 <= i <= len(agents)]
                except Exception as e:
                    console.print(f"[red]Invalid input: {e}[/red]")
                    continue
            backup_dir = quarantine_agents(selected)
            console.print(f"[green]Quarantined files are in: {backup_dir}[green]")
        elif action == "2" and quarantined:
            raw = Prompt.ask("Enter numbers to restore (comma separated, or 'a' for all, or leave blank to cancel)", default="")
            if not raw:
                console.print("[yellow]No files selected. Returning to manage menu.[/yellow]")
                continue
            if raw.strip().lower() == 'a':
                selected = quarantined
            else:
                try:
                    nums = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
                    selected = [quarantined[i-1] for i in nums if 1 <= i <= len(quarantined)]
                except Exception as e:
                    console.print(f"[red]Invalid input: {e}[/red]")
                    continue
            for file_path in selected:
                try:
                    dest = Path("/Library/LaunchAgents") if "LaunchAgents" in str(file_path) else Path("/Library/LaunchDaemons")
                    shutil.move(str(file_path), dest)
                    console.print(f"[green]Restored:[/green] {file_path} -> {dest}")
                except Exception as e:
                    console.print(f"[red]Failed to restore {file_path}: {e}[/red]")
        elif action == "3":
            confirm = Prompt.ask("Are you sure you want to purge all quarantined items? (y/n)", default="n")
            if confirm.lower() == "y":
                if agents_dir.exists():
                    for backup_dir in agents_dir.iterdir():
                        if backup_dir.is_dir():
                            for f in backup_dir.iterdir():
                                f.unlink()
                            backup_dir.rmdir()
                console.print("[green]All quarantined items purged.[/green]")
            else:
                console.print("[yellow]Purge cancelled.[/yellow]")
        elif action == "4":
            break
        else:
            console.print("[yellow]Invalid selection or no items available for that action.[/yellow]")

@app.command()
def remove_login_item_cmd(name: str):
    """Remove a login item by name."""
    success, message = remove_login_item(name)
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")

@app.command()
def backup_ports():
    """Create a backup of current port state."""
    success, message = backup_port_state()
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")

@app.command()
def close_port(port: str):
    """Close a specific port by killing the process using it."""
    success, message = close_port_process(port)
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")

@app.command()
def restore_ports(backup_file: str):
    """Restore port state from a backup file."""
    success, message = restore_port_state(backup_file)
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")

@app.callback()
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        menu()

# --- Profile/MDM Management Menu ---
def profile_mdm_menu():
    """Manage configuration profiles and MDM status."""
    print_logo()
    current_mdm = get_mdm_info()
    last_mdm = None
    mdm_state_file = QUARANTINE_DIR / "mdm_state.json"
    if mdm_state_file.exists():
        with open(mdm_state_file, "r") as f:
            last_mdm = f.read()
    if last_mdm is None:
        with open(mdm_state_file, "w") as f:
            f.write(current_mdm)
        console.print(f"[green]MDM status: {current_mdm}[/green]")
    elif last_mdm != current_mdm:
        console.print(f"[yellow]MDM status has changed![/yellow]\n[bold]Previous:[/bold] {last_mdm}\n[bold]Current:[/bold] {current_mdm}")
        with open(mdm_state_file, "w") as f:
            f.write(current_mdm)
    else:
        console.print(f"[green]MDM status unchanged.[/green] Current: {current_mdm}")
    result = check_profiles()
    profiles = result.get("profiles", [])
    if not profiles:
        console.print("[green]No configuration profiles found.[/green]")
        input("\nPress Enter to return to the menu...")
        return
    console.print("\n[bold magenta]Configuration Profiles:[/bold magenta]")
    for idx, p in enumerate(profiles, 1):
        risk = ", ".join(p["risk"]) if p["risk"] else "None"
        mdm_label = " [MDM]" if p.get("mdm") else ""
        removable_label = " [LOCKED]" if not p.get("removable", True) else ""
        console.print(f"[bold cyan]{idx}.[/bold cyan] Identifier: {p.get('profileIdentifier', 'N/A')} | Name: {p.get('profileDisplayName', 'N/A')} | Risk: {risk}{mdm_label}{removable_label}")
    console.print("\n[bold cyan]r.[/bold cyan] Remove a profile")
    console.print("[bold cyan]m.[/bold cyan] Monitor and auto-remove a profile (non-MDM, removable only)")
    console.print("[bold cyan]s.[/bold cyan] Restore a profile (if backup exists)")
    console.print("[bold cyan]q.[/bold cyan] Return to main menu")
    action = Prompt.ask("Selection", default="q")
    if action.lower() == "r":
        idx = Prompt.ask("Enter number of profile to remove", default="")
        if idx.isdigit():
            idx = int(idx)
            if 1 <= idx <= len(profiles):
                p = profiles[idx-1]
                identifier = p.get("profileIdentifier")
                mdm = p.get("mdm")
                removable = p.get("removable", True)
                risk = ", ".join(p["risk"]) if p["risk"] else "None"
                warn = ""
                if mdm:
                    warn += "[yellow]Warning: This is an MDM profile. Removing it may cause device management issues and it may be reinstalled by your organization.[/yellow]\n"
                if not removable:
                    warn += "[red]This profile is locked and cannot be removed (PayloadRemovalDisallowed).[/red]\n"
                if warn:
                    console.print(warn)
                if not removable:
                    input("\nPress Enter to return to the menu...")
                    return
                confirm = Prompt.ask(f"Are you sure you want to remove profile '{p.get('profileDisplayName', 'N/A')}' (Risk: {risk})? (y/n)", default="n")
                if confirm.lower() == "y":
                    success, msg = remove_profile(identifier)
                    if success:
                        console.print(f"[green]Profile removed successfully: {msg}[/green]")
                    else:
                        console.print(f"[red]Failed to remove profile: {msg}[/red]")
            else:
                console.print("[red]Invalid selection.[/red]")
        input("\nPress Enter to return to the menu...")
    elif action.lower() == "m":
        idx = Prompt.ask("Enter number of profile to monitor and auto-remove", default="")
        if idx.isdigit():
            idx = int(idx)
            if 1 <= idx <= len(profiles):
                p = profiles[idx-1]
                identifier = p.get("profileIdentifier")
                mdm = p.get("mdm")
                removable = p.get("removable", True)
                if mdm or not removable:
                    console.print("[yellow]Can only auto-remove non-MDM, removable profiles.[/yellow]")
                else:
                    console.print(f"[green]Will monitor and auto-remove profile: {identifier} (run this tool in the background to keep removing it if it reappears).[/green]")
                    # Simple implementation: remove now, and add to a watchlist file
                    success, msg = remove_profile(identifier)
                    if success:
                        console.print(f"[green]Profile removed successfully: {msg}[/green]")
                        # Add to watchlist
                        watchlist_file = QUARANTINE_DIR / "auto_remove_watchlist.json"
                        try:
                            if watchlist_file.exists():
                                with open(watchlist_file, "r") as f:
                                    watchlist = json.load(f)
                            else:
                                watchlist = []
                            if identifier not in watchlist:
                                watchlist.append(identifier)
                                with open(watchlist_file, "w") as f:
                                    json.dump(watchlist, f)
                        except Exception as e:
                            console.print(f"[yellow]Could not update watchlist: {e}[/yellow]")
                    else:
                        console.print(f"[red]Failed to remove profile: {msg}[/red]")
            else:
                console.print("[red]Invalid selection.[/red]")
        input("\nPress Enter to return to the menu...")
    elif action.lower() == "s":
        console.print("[yellow]Restore is not natively supported. If you have a backup of the profile (.mobileconfig), you can re-import it using 'profiles install -type configuration -path <file>'.[/yellow]")
        input("\nPress Enter to return to the menu...")
    # else just return

# --- Forensics/Reporting Menu ---
def forensics_menu():
    while True:
        print_logo()
        console.print("[bold magenta]Forensics & Reporting[/bold magenta]\n")
        console.print("[bold cyan]1.[/bold cyan] Export snapshot")
        console.print("[bold cyan]2.[/bold cyan] Compare snapshots")
        console.print("[bold cyan]3.[/bold cyan] View timeline/log")
        if LOG_FILE.exists():
            console.print("[bold cyan]4.[/bold cyan] Clear timeline/log")
        if SNAPSHOT_DIR.exists() and any(SNAPSHOT_DIR.glob("snapshot_*.json")):
            console.print("[bold cyan]5.[/bold cyan] Clear all snapshots")
        console.print("[bold cyan]q.[/bold cyan] Return to main menu")
        action = Prompt.ask("Selection", default="q")
        if action == "1":
            SNAPSHOT_DIR.mkdir(exist_ok=True)
            from datetime import datetime
            snap = {
                "profiles": check_profiles(),
                "mdm": get_mdm_info(),
                # Add more as needed (TCC, agents, etc.)
            }
            fname = SNAPSHOT_DIR / f"snapshot_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            with open(fname, "w") as f:
                json.dump(snap, f, indent=2)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(LOG_FILE, "a") as log:
                log.write(f"[{timestamp}] Snapshot exported: {fname}\n")
            console.print(f"[green]Snapshot exported to {fname}[/green]")
            input("\nPress Enter to return to the menu...")
        elif action == "2":
            files = sorted(SNAPSHOT_DIR.glob("snapshot_*.json"))
            if len(files) < 2:
                console.print("[yellow]At least two snapshots are required to compare.[/yellow]")
                input("\nPress Enter to return to the menu...")
                continue
            for i, f in enumerate(files, 1):
                console.print(f"[bold cyan]{i}.[/bold cyan] {f.name}")
            idx1 = Prompt.ask("Enter number of first snapshot", default="1")
            idx2 = Prompt.ask("Enter number of second snapshot", default="2")
            try:
                idx1, idx2 = int(idx1)-1, int(idx2)-1
                if not (0 <= idx1 < len(files)) or not (0 <= idx2 < len(files)):
                    raise IndexError("Snapshot number out of range.")
                with open(files[idx1]) as f1, open(files[idx2]) as f2:
                    snap1, snap2 = json.load(f1), json.load(f2)
                profs1 = {p.get('profileIdentifier') for p in snap1['profiles'].get('profiles', []) if p.get('profileIdentifier')}
                profs2 = {p.get('profileIdentifier') for p in snap2['profiles'].get('profiles', []) if p.get('profileIdentifier')}
                added = profs2 - profs1
                removed = profs1 - profs2
                timestamp = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_entry = f"[{timestamp}] Compared snapshots: {files[idx1].name} vs {files[idx2].name}\n"
                if added:
                    console.print(f"[green]Profiles added: {', '.join(added)}[/green]")
                    log_entry += f"  Profiles added: {', '.join(added)}\n"
                if removed:
                    console.print(f"[red]Profiles removed: {', '.join(removed)}[/red]")
                    log_entry += f"  Profiles removed: {', '.join(removed)}\n"
                if not added and not removed:
                    console.print("[cyan]No profile changes detected between snapshots.[/cyan]")
                    log_entry += "  No profile changes detected between snapshots.\n"
                with open(LOG_FILE, "a") as log:
                    log.write(log_entry)
                input("\nPress Enter to return to the menu...")
            except Exception as e:
                console.print(f"[red]Error comparing snapshots: {e}[/red]")
                input("\nPress Enter to return to the menu...")
        elif action == "3":
            if not LOG_FILE.exists():
                console.print("[yellow]No timeline/log file found yet.[/yellow]")
            else:
                with open(LOG_FILE) as log:
                    content = log.read()
                if not content.strip():
                    console.print("[yellow]Timeline/log is empty.[/yellow]")
                else:
                    console.print(Panel(content, title="Timeline/Log"))
            input("\nPress Enter to return to the menu...")
        elif action == "4" and LOG_FILE.exists():
            confirm = Prompt.ask("Are you sure you want to clear the timeline/log? (y/n)", default="n")
            if confirm.lower() == "y":
                LOG_FILE.unlink()
                console.print("[green]Timeline/log cleared.[/green]")
            else:
                console.print("[yellow]Timeline/log not cleared.[/yellow]")
            input("\nPress Enter to return to the menu...")
        elif action == "5" and SNAPSHOT_DIR.exists() and any(SNAPSHOT_DIR.glob("snapshot_*.json")):
            confirm = Prompt.ask("Are you sure you want to delete all snapshots? (y/n)", default="n")
            if confirm.lower() == "y":
                for f in SNAPSHOT_DIR.glob("snapshot_*.json"):
                    f.unlink()
                console.print("[green]All snapshots deleted.[/green]")
            else:
                console.print("[yellow]Snapshots not deleted.[/yellow]")
            input("\nPress Enter to return to the menu...")
        elif action.lower() == "q":
            break

def manage_login_items():
    """Manage login items with a menu-driven interface."""
    print_logo()
    while True:
        items = get_login_items()
        console.print(Panel("[bold magenta]Login Items Management[/bold magenta]"))
        
        if items:
            console.print("[bold green]Current login items:[/bold green]")
            for idx, item in enumerate(items, 1):
                formatted = f"{item['display_name']}"
                if 'path' in item:
                    formatted += f" ({item['path']})"
                if 'kind' in item:
                    formatted += f" [{item['kind']}]"
                console.print(f"[bold cyan]{idx}.[/bold cyan] {formatted}")
        else:
            console.print("[green]No login items found![green]")
            
        # Check for backups
        login_items_dir = Path(__file__).parent / "quarantine" / "login_items"
        backup_files = sorted(login_items_dir.glob("login_item_backup_*.json"), reverse=True) if login_items_dir.exists() else []
        
        if backup_files:
            console.print("\n[bold yellow]Quarantined login items:[/bold yellow]")
            for idx, backup in enumerate(backup_files, 1):
                try:
                    with open(backup, 'r') as f:
                        item = json.load(f)
                    # Extract timestamp from filename
                    timestamp = backup.stem.split('_')[-2] + ' ' + backup.stem.split('_')[-1]
                    formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[9:11]}:{timestamp[11:13]}:{timestamp[13:15]}"
                    console.print(f"[bold magenta]{idx}.[/bold magenta] {item['display_name']} (Backup: {formatted_time})")
                except Exception:
                    console.print(f"[bold magenta]{idx}.[/bold magenta] {backup.name}")
        
        console.print("\n[bold cyan]1.[/bold cyan] Create backup of login item")
        console.print("[bold cyan]2.[/bold cyan] Remove login item (creates backup automatically)")
        if backup_files:
            console.print("[bold cyan]3.[/bold cyan] Restore from backup")
            console.print("[bold cyan]4.[/bold cyan] Delete backup")
        console.print("[bold cyan]5.[/bold cyan] Return to main menu")
        
        action = Prompt.ask("Selection", default="5")
        
        if action == "1" and items:
            idx = Prompt.ask("Enter number of login item to backup", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(items):
                    item = items[idx-1]
                    success, backup_path = backup_login_item(item)
                    if success:
                        console.print(f"[green]✓[/green] Created backup: {backup_path}")
                    else:
                        console.print(f"[red]✗[/red] Failed to create backup: {backup_path}")
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action == "2" and items:
            idx = Prompt.ask("Enter number of login item to remove", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(items):
                    item = items[idx-1]
                    confirm = Prompt.ask(f"Are you sure you want to remove '{item['display_name']}'? (A backup will be created automatically) (y/n)", default="n")
                    if confirm.lower() == "y":
                        success, message = remove_login_item(item['name'])
                        if success:
                            console.print(f"[green]✓[/green] {message}")
                        else:
                            console.print(f"[red]✗[/red] {message}")
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action == "3" and backup_files:
            idx = Prompt.ask("Enter number of backup to restore", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(backup_files):
                    backup = backup_files[idx-1]
                    try:
                        with open(backup, 'r') as f:
                            item = json.load(f)
                        confirm = Prompt.ask(f"Are you sure you want to restore '{item['display_name']}'? (y/n)", default="n")
                        if confirm.lower() == "y":
                            success, message = restore_login_item(str(backup))
                            if success:
                                console.print(f"[green]✓[/green] {message}")
                            else:
                                console.print(f"[red]✗[/red] {message}")
                    except Exception as e:
                        console.print(f"[red]Error reading backup: {e}[/red]")
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action == "4" and backup_files:
            idx = Prompt.ask("Enter number of backup to delete", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(backup_files):
                    backup = backup_files[idx-1]
                    try:
                        with open(backup, 'r') as f:
                            item = json.load(f)
                        confirm = Prompt.ask(f"Are you sure you want to delete backup of '{item['display_name']}'? (y/n)", default="n")
                        if confirm.lower() == "y":
                            backup.unlink()
                            console.print(f"[green]✓[/green] Backup deleted successfully")
                    except Exception as e:
                        console.print(f"[red]Error deleting backup: {e}[/red]")
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action == "5":
            break
        else:
            console.print("[yellow]Invalid selection or no items available for that action.[/yellow]")

def cleanup_all_data():
    """Clean up all quarantined items, logs, and snapshots."""
    try:
        if QUARANTINE_DIR.exists():
            shutil.rmtree(QUARANTINE_DIR)
            print(f"Cleaned up quarantine directory: {QUARANTINE_DIR}")
    except Exception as e:
        print(f"Error during cleanup: {e}")

def manage_ports():
    """Manage open ports with a menu-driven interface."""
    print_logo()
    while True:
        result = check_network_listeners()
        listeners = result.get("listeners", [])
        
        console.print(Panel("[bold magenta]Open Ports Management[/bold magenta]"))
        
        if listeners:
            console.print("[bold green]Current open ports:[/bold green]")
            for idx, listener in enumerate(listeners, 1):
                console.print(f"[bold cyan]{idx}.[/bold cyan] {listener['process']} {listener['port']} (PID: {listener['pid']})")
        else:
            console.print("[green]No open ports found![green]")
            
        # Check for backups in the correct directory
        ports_dir = Path(__file__).parent / "quarantine" / "ports"
        backup_files = sorted(ports_dir.glob("ports_backup_*.json"), reverse=True) if ports_dir.exists() else []
        
        if backup_files:
            console.print("\n[bold yellow]Port state backups:[/bold yellow]")
            for idx, backup in enumerate(backup_files, 1):
                # Extract timestamp from filename (format: ports_backup_YYYYMMDD_HHMMSS.json)
                timestamp = backup.stem.split('_')[-2] + ' ' + backup.stem.split('_')[-1]
                formatted_time = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]} {timestamp[9:11]}:{timestamp[11:13]}:{timestamp[13:15]}"
                console.print(f"[bold magenta]{idx}.[/bold magenta] {backup.name} ({formatted_time})")
        
        # Add spacing before menu options
        console.print("")
        
        # Build menu options
        menu_options = [
            ("1", "Create backup of current port state"),
            ("2", "Close a port")
        ]
        
        # Add backup management options if backups exist
        if backup_files:
            menu_options.extend([
                ("3", "View backup details"),
                ("4", "Delete backup")
            ])
            
        # Add return to main menu option
        menu_options.append(("m", "Return to main menu"))
        
        # Print menu options
        for key, desc in menu_options:
            console.print(f"[bold cyan]{key}.[/bold cyan] {desc}")
        
        action = Prompt.ask("Selection", default="m")
        
        if action == "1":
            success, message = backup_port_state()
            if success:
                console.print(f"[green]✓[/green] {message}")
                # Refresh the menu to show the new backup
                continue
            else:
                console.print(f"[red]✗[/red] {message}")
                
        elif action == "2" and listeners:
            idx = Prompt.ask("Enter number of port to close", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(listeners):
                    listener = listeners[idx-1]
                    port = listener['port'].split(':')[-1]  # Extract port number
                    confirm = Prompt.ask(f"Are you sure you want to close port {port} used by {listener['process']}? (y/n)", default="n")
                    if confirm.lower() == "y":
                        success, message = close_port_process(port)
                        if success:
                            console.print(f"[green]✓[/green] {message}")
                            # Refresh the menu to show the new backup
                            continue
                        else:
                            console.print(f"[red]✗[/red] {message}")
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action == "3" and backup_files:
            idx = Prompt.ask("Enter number to view backup details", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(backup_files):
                    try:
                        with open(backup_files[idx-1], 'r') as f:
                            backup = json.load(f)
                        console.print("\n[bold green]Backup details:[/bold green]")
                        for item in backup:
                            console.print(f"Process: {item['process']}")
                            console.print(f"Port: {item['port']}")
                            console.print(f"PID: {item['pid']}")
                            console.print("---")
                    except Exception as e:
                        console.print(f"[red]Error reading backup: {e}[/red]")
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action == "4" and backup_files:
            idx = Prompt.ask("Enter number of backup to delete", default="")
            if idx.isdigit():
                idx = int(idx)
                if 1 <= idx <= len(backup_files):
                    backup = backup_files[idx-1]
                    confirm = Prompt.ask(f"Are you sure you want to delete backup {backup.name}? (y/n)", default="n")
                    if confirm.lower() == "y":
                        backup.unlink()
                        console.print(f"[green]✓[/green] Backup deleted successfully")
                        # Refresh the menu after deletion
                        continue
                else:
                    console.print("[red]Invalid selection.[/red]")
                    
        elif action.lower() == "m":
            break
        else:
            console.print("[yellow]Invalid selection or no items available for that action.[/yellow]")

@app.command()
def uninstall():
    """Uninstall macWatchdog and clean up all data."""
    confirm = Prompt.ask("Are you sure you want to uninstall macWatchdog? This will remove all quarantined items, logs, and snapshots. (y/n)", default="n")
    if confirm.lower() == "y":
        cleanup_all_data()
        console.print("[green]✓[/green] macWatchdog uninstalled and all data cleaned up.")
    else:
        console.print("[yellow]Uninstall cancelled.[/yellow]")

def backup_login_item(item):
    """Create a backup of a login item."""
    try:
        login_items_dir = QUARANTINE_DIR / "login_items"
        login_items_dir.mkdir(parents=True, exist_ok=True)
        
        # Create backup with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = login_items_dir / f"login_item_backup_{timestamp}.json"
        
        # Save the item details
        with open(backup_file, 'w') as f:
            json.dump(item, f, indent=2)
            
        return True, str(backup_file)
    except Exception as e:
        return False, str(e)

if __name__ == "__main__":
    app() 