"""Audit checks.

Each check returns a :class:`~macwatchdog.result.CheckResult` (or a list of
them, for checks that are really several related probes). The :data:`CHECKS`
registry drives the menu and the ``check`` CLI command.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..result import CheckResult
from .accessibility import check_accessibility_apps
from .app_entitlements import check_app_privacy_capabilities
from .authorized_keys import check_authorized_keys
from .cron import check_cron_jobs
from .quarantine import check_quarantine_attributes
from .hardening import (
    check_automatic_updates,
    check_bluetooth,
    check_filevault,
    check_firewall,
    check_firewall_stealth,
    check_firmware_password,
    check_gatekeeper,
    check_guest_account,
    check_remote_apple_events,
    check_screen_sharing,
    check_sip,
    check_xprotect,
)
from .kernel_extensions import check_kernel_extensions
from .launch_agents import check_launch_agents
from .login_items import check_login_items
from .mdm import check_mdm_and_dep
from .network import check_network
from .network_listeners import check_network_listeners
from .permissions import check_world_writable
from .profiles import check_profiles
from .remote import check_remote_management
from .sudoers import check_sudoers
from .tcc import check_tcc_permissions
from .usb import check_usb
from .users import check_admin_users


CheckFn = Callable[[], "CheckResult | list[CheckResult]"]


@dataclass(frozen=True)
class RegisteredCheck:
    name: str
    function: CheckFn
    category: str
    description: str = ""
    requires_root: bool = False
    slow: bool = False


CHECKS: tuple[RegisteredCheck, ...] = (
    # --- Identity & Enrollment -------------------------------------------------
    RegisteredCheck("MDM Enrollment", check_mdm_and_dep, "MDM",
        description="MDM/DEP enrollment and management profile state",
        requires_root=True),
    RegisteredCheck("Remote Access", check_remote_management, "Remote Access",
        description="SSH remote login status",
        requires_root=True),
    RegisteredCheck("Admin Users/Groups", check_admin_users, "Users",
        description="Local admin group membership — unexpected accounts"),

    # --- Persistence -----------------------------------------------------------
    RegisteredCheck("Launch Agents/Daemons", check_launch_agents, "Launch Agents/Daemons",
        description="Unsigned or suspicious launchd agents and daemons"),
    RegisteredCheck("Login Items", check_login_items, "Login Items",
        description="Applications and daemons launching at login"),
    RegisteredCheck("Cron Jobs & Periodic Scripts", check_cron_jobs, "Persistence",
        description="User crontab and /etc/periodic script audit"),
    RegisteredCheck("SSH Authorized Keys", check_authorized_keys, "Persistence",
        description="SSH authorized_keys files — backdoor access vectors",
        requires_root=True),
    RegisteredCheck("Quarantine Attributes", check_quarantine_attributes, "Persistence",
        description="~/Downloads files missing Gatekeeper quarantine xattr"),

    # --- Privilege Escalation --------------------------------------------------
    RegisteredCheck("Sudoers Configuration", check_sudoers, "Privilege Escalation",
        description="NOPASSWD entries and unusual sudo rules",
        requires_root=True),

    # --- Privacy & Access Control ---------------------------------------------
    RegisteredCheck("TCC Privacy Permissions", check_tcc_permissions, "TCC Privacy",
        description="Camera, mic, screen recording, full disk access grants"),
    RegisteredCheck("Accessibility/Full Disk Access", check_accessibility_apps, "Accessibility",
        description="Apps with accessibility or full disk access"),
    RegisteredCheck("App Privacy Capabilities", check_app_privacy_capabilities, "App Privacy",
        description="Apps declaring sensitive privacy capabilities on disk",
        slow=True),
    RegisteredCheck("Configuration Profiles", check_profiles, "Profiles",
        description="Installed configuration profiles and MDM policies",
        requires_root=True),

    # --- Network ---------------------------------------------------------------
    RegisteredCheck("Network Listeners (Open Ports)", check_network_listeners, "Network Listeners",
        description="Processes listening on network ports"),
    RegisteredCheck("Network Interfaces & Connections", check_network, "Network",
        description="Active interfaces and established connections"),

    # --- Hardware --------------------------------------------------------------
    RegisteredCheck("USB Devices", check_usb, "USB",
        description="Connected USB device inventory"),
    RegisteredCheck("Kernel Extensions", check_kernel_extensions, "Kernel Extensions",
        description="Third-party kernel and system extensions"),

    # --- System Hardening ------------------------------------------------------
    RegisteredCheck("System Integrity Protection (SIP)", check_sip, "System Hardening",
        description="SIP enabled/disabled status"),
    RegisteredCheck("Gatekeeper", check_gatekeeper, "System Hardening",
        description="Gatekeeper app verification enforcement"),
    RegisteredCheck("XProtect", check_xprotect, "System Hardening",
        description="XProtect malware signature version"),
    RegisteredCheck("Firewall & Stealth Mode",
        lambda: [check_firewall(), check_firewall_stealth()],
        "System Hardening",
        description="Application firewall and stealth mode state"),
    RegisteredCheck("FileVault", check_filevault, "System Hardening",
        description="Full-disk encryption status"),
    RegisteredCheck("Automatic Software Updates", check_automatic_updates, "System Hardening",
        description="Automatic update settings — security patches"),
    RegisteredCheck("Remote Apple Events", check_remote_apple_events, "System Hardening",
        description="Remote Apple Events — remote script execution vector",
        requires_root=True),
    RegisteredCheck("Screen Sharing", check_screen_sharing, "System Hardening",
        description="Screen sharing service state"),
    RegisteredCheck("Guest Account", check_guest_account, "System Hardening",
        description="Guest account enabled/disabled"),
    RegisteredCheck("Bluetooth", check_bluetooth, "System Hardening",
        description="Bluetooth radio state and connected devices",
        slow=True),
    RegisteredCheck("Firmware Password", check_firmware_password, "System Hardening",
        description="Firmware/startup security password (Intel) or Secure Enclave note"),

    # --- Filesystem ------------------------------------------------------------
    RegisteredCheck("World-writable/Suspicious Files", check_world_writable, "Permissions",
        description="World-writable files in sensitive system directories"),
)


__all__ = ["CHECKS", "RegisteredCheck", "CheckFn"]
