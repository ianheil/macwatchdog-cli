"""System hardening checks: SIP, Gatekeeper, XProtect, firewall + stealth,
Bluetooth, guest account, Remote Apple Events, Screen Sharing, automatic
software updates, FileVault, and firmware password.

Each check is a top-level function that returns a :class:`CheckResult`.
Firmware-password status is architecture-aware: Apple Silicon Macs are
reported with a note that firmware passwords do not apply.
"""

from __future__ import annotations

import os
import platform
import plistlib
from pathlib import Path

from ..proc import run
from ..result import CheckResult
from ..severity import Severity


HARDENING_CATEGORY = "System Hardening & Security"


# -- SIP ---------------------------------------------------------------------

def check_sip() -> CheckResult:
    result = run(["csrutil", "status"], timeout=5)
    if not result.ok:
        return CheckResult("System Integrity Protection (SIP)", "ERROR", info="Unable to check SIP status.")
    enabled = "enabled" in result.stdout.lower() and "disabled" not in result.stdout.lower()
    return CheckResult(
        label="System Integrity Protection (SIP)",
        status="OK" if enabled else "ALERT",
        severity=Severity.OK if enabled else Severity.HIGH,
        info="enabled" if enabled else result.stdout.strip(),
        tip="" if enabled else "SIP should be enabled (boot to Recovery to toggle).",
    )


# -- Gatekeeper --------------------------------------------------------------

def check_gatekeeper() -> CheckResult:
    result = run(["spctl", "--status"], timeout=5)
    if not result.ok:
        return CheckResult("Gatekeeper", "ERROR", info="Unable to check Gatekeeper status.")
    enabled = "assessments enabled" in result.stdout.lower()
    return CheckResult(
        label="Gatekeeper",
        status="OK" if enabled else "ALERT",
        severity=Severity.OK if enabled else Severity.MEDIUM,
        info="enabled" if enabled else result.stdout.strip(),
        tip="" if enabled else "Gatekeeper helps protect against untrusted binaries; enable with 'sudo spctl --master-enable'.",
    )


# -- XProtect ----------------------------------------------------------------

def check_xprotect() -> CheckResult:
    plist_path = Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist")
    if not plist_path.exists():
        return CheckResult(
            label="XProtect",
            status="ALERT",
            severity=Severity.HIGH,
            info="XProtect bundle not found.",
            tip="XProtect is shipped with macOS; its absence is highly unusual.",
        )
    try:
        with plist_path.open("rb") as fh:
            info = plistlib.load(fh)
    except Exception as exc:
        return CheckResult("XProtect", "ERROR", info=f"Could not read XProtect plist: {exc}")
    return CheckResult(
        label="XProtect",
        status="OK",
        severity=Severity.OK,
        info=f"version {info.get('CFBundleShortVersionString', 'unknown')}",
    )


# -- Firewall ----------------------------------------------------------------

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def _firewall_enabled() -> bool | None:
    result = run([_SOCKETFILTERFW, "--getglobalstate"], timeout=5)
    if not result.ok:
        return None
    text = result.stdout.strip().lower()
    # Typical output: "Firewall is enabled. (State = 1)" / "Firewall is disabled. (State = 0)"
    if "disabled" in text or "state = 0" in text:
        return False
    if "enabled" in text or "state = 1" in text:
        return True
    return None


def check_firewall() -> CheckResult:
    state = _firewall_enabled()
    if state is None:
        return CheckResult("Firewall", "ERROR", info="Unable to determine firewall status.")
    return CheckResult(
        label="Firewall",
        status="OK" if state else "ALERT",
        severity=Severity.OK if state else Severity.MEDIUM,
        info="enabled" if state else "disabled",
        tip="" if state else "Enable the application firewall in System Settings > Network > Firewall.",
    )


def check_firewall_stealth() -> CheckResult:
    state = _firewall_enabled()
    if state is False:
        return CheckResult(
            label="Firewall Stealth Mode",
            status="SUGGESTION",
            severity=Severity.LOW,
            info="Stealth mode requires the firewall to be enabled first.",
            tip="Enable the firewall, then turn on stealth mode in System Settings > Network > Firewall > Options.",
        )

    result = run([_SOCKETFILTERFW, "--getstealthmode"], timeout=5)
    if not result.ok:
        return CheckResult("Firewall Stealth Mode", "ERROR", info="Unable to check stealth mode.")
    text = result.stdout.strip().rstrip(".").lower()
    # Typical output: "Stealth mode enabled" / "Stealth mode disabled" / "... is on/off"
    if "disabled" in text or text.endswith("off") or "state = 0" in text:
        enabled = False
    elif "enabled" in text or text.endswith("on") or "state = 1" in text:
        enabled = True
    else:
        return CheckResult("Firewall Stealth Mode", "ERROR", info=f"Could not parse output: {result.stdout!r}")
    return CheckResult(
        label="Firewall Stealth Mode",
        status="OK" if enabled else "ALERT",
        severity=Severity.OK if enabled else Severity.LOW,
        info="enabled" if enabled else "disabled",
        tip="" if enabled else "Stealth mode hides your Mac from unsolicited network probes.",
    )


# -- Bluetooth ---------------------------------------------------------------

def check_bluetooth() -> CheckResult:
    result = run(["system_profiler", "SPBluetoothDataType"], timeout=15)
    if not result.ok:
        return CheckResult("Bluetooth", "ERROR", info="Unable to check Bluetooth status.")
    text = result.stdout.lower()
    powered_on = "state: on" in text or "bluetooth power: on" in text
    has_connected_input = any(line.strip() for line in result.stdout.splitlines() if "Connected:" in line and "Yes" in line)

    if not powered_on:
        return CheckResult(
            label="Bluetooth",
            status="OK",
            severity=Severity.OK,
            info="off",
        )
    info = "on — connected devices detected" if has_connected_input else "on"
    return CheckResult(
        label="Bluetooth",
        status="INFO",
        severity=Severity.INFO,
        info=info,
        tip="Disable Bluetooth when unused if you're not relying on wireless input devices.",
    )


# -- Guest Account ------------------------------------------------------------

def check_guest_account() -> CheckResult:
    result = run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], timeout=5)
    if not result.ok:
        # macOS usually treats "key not set" as an error; the account is off.
        return CheckResult(
            label="Guest Account",
            status="OK",
            severity=Severity.OK,
            info="Guest account key not set (treated as disabled).",
        )
    enabled = result.stdout.strip() == "1"
    return CheckResult(
        label="Guest Account",
        status="ALERT" if enabled else "OK",
        severity=Severity.MEDIUM if enabled else Severity.OK,
        info="enabled" if enabled else "disabled",
        tip="" if not enabled else "Disable the guest account in System Settings > Users & Groups.",
    )


# -- Remote Apple Events ------------------------------------------------------

def check_remote_apple_events() -> CheckResult:
    result = run(["systemsetup", "-getremoteappleevents"], timeout=10)
    stdout = result.stdout.strip()
    # systemsetup prints an admin-error message to stdout on some macOS versions
    # even when the exit code is 0 — detect and surface as UNKNOWN
    if not result.ok or "administrator access" in stdout.lower() or "exiting" in stdout.lower():
        return CheckResult(
            label="Remote Apple Events",
            status="UNKNOWN",
            severity=Severity.INFO,
            tip="Run as root ('sudo macwatchdog') to check Remote Apple Events state.",
        )
    enabled = stdout.lower().endswith("on")
    return CheckResult(
        label="Remote Apple Events",
        status="ALERT" if enabled else "OK",
        severity=Severity.MEDIUM if enabled else Severity.OK,
        info=stdout if enabled else "",
    )


# -- Screen Sharing -----------------------------------------------------------

def check_screen_sharing() -> CheckResult:
    result = run(["launchctl", "list"], timeout=10)
    if not result.ok:
        return CheckResult("Screen Sharing", "ERROR", info="Unable to query launchctl.")
    # launchctl list columns: PID  Status  Label
    # A dash ("-") in column 0 means the service is registered but not running.
    # Only flag if the PID is a real number (service is actively running).
    running = False
    for line in result.stdout.splitlines():
        if "com.apple.screensharing" not in line:
            continue
        parts = line.split()
        if parts and parts[0] != "-":
            running = True
        break
    return CheckResult(
        label="Screen Sharing",
        status="ALERT" if running else "OK",
        severity=Severity.MEDIUM if running else Severity.OK,
        info="service running" if running else "not running",
        tip="" if not running else "Disable in System Settings > General > Sharing unless actively needed.",
    )


# -- Automatic software updates ----------------------------------------------

def check_automatic_updates() -> CheckResult:
    sys_su = Path("/Library/Preferences/com.apple.SoftwareUpdate")
    user_su = Path.home() / "Library/Preferences/com.apple.SoftwareUpdate.plist"
    sys_commerce = Path("/Library/Preferences/com.apple.commerce")
    user_commerce = Path.home() / "Library/Preferences/com.apple.commerce.plist"

    def read_key(domain: os.PathLike, key: str) -> str | None:
        result = run(["defaults", "read", str(domain), key], timeout=5)
        return result.stdout.strip() if result.ok else None

    def read_first(*pairs: tuple[os.PathLike, str]) -> str | None:
        """Try each (domain, key) pair and return the first hit."""
        for domain, key in pairs:
            val = read_key(domain, key)
            if val is not None:
                return val
        return None

    def on(val: str | None) -> bool:
        return val is not None and val.strip() == "1"

    def fmt(val: str | None, label: str) -> str:
        if val is None:
            return f"{label}: Unknown"
        return f"{label}: {'Enabled' if on(val) else 'Disabled'}"

    # Download: AutomaticDownload (macOS 15+/26+) or AutomaticCheckEnabled (legacy)
    download = read_first(
        (sys_su, "AutomaticDownload"),
        (sys_su, "AutomaticCheckEnabled"),
        (user_su, "AutomaticDownload"),
        (user_su, "AutomaticCheckEnabled"),
    )

    # Security responses: SplatEnabled (macOS 26+ — SPLAT = Security Patches,
    # Latest Assistants, and Tools) or CriticalUpdateInstall (macOS 12–14)
    security = read_first(
        (sys_su, "SplatEnabled"),
        (sys_su, "CriticalUpdateInstall"),
        (user_su, "SplatEnabled"),
        (user_su, "CriticalUpdateInstall"),
    )

    # macOS auto-install: legacy boolean key first; macOS 26+ uses
    # AutoInstallProductKeys (non-empty array = auto-install on)
    macos = read_first(
        (sys_su, "AutomaticallyInstallMacOSUpdates"),
        (user_su, "AutomaticallyInstallMacOSUpdates"),
    )
    if macos is None:
        keys_val = read_first((sys_su, "AutoInstallProductKeys"))
        if keys_val is not None:
            # "(\n)" or "()" = empty array = off; anything else = entries present = on
            has_entries = bool(keys_val.strip().strip("()").strip())
            macos = "1" if has_entries else "0"

    # App Store auto-updates live in com.apple.commerce, a separate
    # preference domain not shown alongside Software Update settings.
    # Omitted here to avoid misleading "Disabled" on machines where
    # the commerce plist doesn't exist or the setting is in App Store prefs.

    if all(x is None for x in (download, security, macos)):
        return CheckResult(
            label="Automatic Software Updates",
            status="UNKNOWN",
            severity=Severity.LOW,
            info="Could not read update settings — check System Settings > General > Software Update.",
        )

    info = [
        fmt(download, "Download new updates when available"),
        fmt(security, "Install security responses and system files"),
        fmt(macos,    "Install macOS updates automatically"),
    ]

    # Only flag as problematic if we can CONFIRM a critical setting is off.
    # Unknown (key missing on this macOS version) is not the same as Disabled.
    download_off = download is not None and not on(download)
    security_off = security is not None and not on(security)

    if download_off and security_off:
        # Both confirmed off — genuine HIGH exposure
        severity, status = Severity.HIGH, "ALERT"
        tip = "Enable security patch install and auto-download in System Settings > General > Software Update."
    elif download_off or security_off:
        # One confirmed off
        severity, status = Severity.MEDIUM, "ALERT"
        tip = "Enable security patch install and auto-download in System Settings > General > Software Update."
    else:
        severity, status = Severity.OK, "OK"
        tip = ""

    return CheckResult(
        label="Automatic Software Updates",
        status=status,
        severity=severity,
        info=info,
        tip=tip,
    )


# -- FileVault ---------------------------------------------------------------

def check_filevault() -> CheckResult:
    result = run(["fdesetup", "status"], timeout=5)
    if not result.ok:
        return CheckResult("FileVault", "ERROR", info="Unable to check FileVault status.")
    enabled = "filevault is on" in result.stdout.lower()
    return CheckResult(
        label="FileVault",
        status="OK" if enabled else "ALERT",
        severity=Severity.OK if enabled else Severity.HIGH,
        info="encrypted" if enabled else result.stdout.strip(),
        tip="" if enabled else "Enable FileVault in System Settings > Privacy & Security > FileVault to encrypt the disk.",
    )


# -- Firmware password -------------------------------------------------------

def check_firmware_password() -> CheckResult:
    if platform.machine() == "arm64":
        # Firmware passwords don't apply to Apple Silicon — the Secure Enclave
        # provides equivalent startup security. Not a finding.
        return CheckResult(
            label="Firmware Password",
            status="OK",
            severity=Severity.OK,
            info="N/A — Secure Enclave provides startup security on Apple Silicon",
        )

    result = run(["firmwarepasswd", "-check"], timeout=5)
    if result.missing:
        return CheckResult(
            label="Firmware Password",
            status="SUGGESTION",
            severity=Severity.LOW,
            info="firmwarepasswd not available on this system.",
        )
    output = result.stdout.strip()
    if "Password Enabled: Yes" in output:
        return CheckResult(
            label="Firmware Password",
            status="OK",
            severity=Severity.OK,
            info="Firmware password is set.",
        )
    if "Password Enabled: No" in output:
        return CheckResult(
            label="Firmware Password",
            status="ALERT",
            severity=Severity.LOW,
            info="Firmware password is NOT set.",
            tip="A firmware password prevents someone from booting alternate media. Set one via Recovery > Utilities > Startup Security Utility.",
        )
    return CheckResult(
        label="Firmware Password",
        status="SUGGESTION",
        severity=Severity.LOW,
        info="Unable to determine firmware password status.",
    )
