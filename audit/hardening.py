import subprocess
import plistlib
import os
from pathlib import Path

def check_sip():
    """Check System Integrity Protection (SIP) status."""
    try:
        result = subprocess.run(["csrutil", "status"], capture_output=True, text=True)
        enabled = "enabled" in result.stdout.lower()
        tip = "Tip: SIP should be enabled for maximum system protection."
        return {
            "label": "System Integrity Protection (SIP)",
            "status": "OK" if enabled else "ALERT",
            "info": result.stdout.strip(),
            "tip": tip if not enabled else ""
        }
    except Exception:
        return {"label": "System Integrity Protection (SIP)", "status": "ERROR", "info": "Unable to check SIP status.", "tip": ""}

def check_gatekeeper():
    """Check Gatekeeper status."""
    try:
        result = subprocess.run(["spctl", "--status"], capture_output=True, text=True)
        enabled = "assessments enabled" in result.stdout.lower()
        tip = "Tip: Gatekeeper helps protect your Mac from untrusted apps."
        return {
            "label": "Gatekeeper",
            "status": "OK" if enabled else "ALERT",
            "info": result.stdout.strip(),
            "tip": tip if not enabled else ""
        }
    except Exception:
        return {"label": "Gatekeeper", "status": "ERROR", "info": "Unable to check Gatekeeper status.", "tip": ""}

def check_xprotect():
    """Check if XProtect (Apple's built-in malware scanner) is present."""
    try:
        xprotect_path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        if os.path.exists(xprotect_path):
            with open(xprotect_path, "rb") as f:
                info = plistlib.load(f)
            version = info.get("CFBundleShortVersionString", "Unknown")
            return {
                "label": "XProtect",
                "status": "OK",
                "info": f"XProtect version: {version}",
                "tip": ""
            }
        else:
            return {
                "label": "XProtect",
                "status": "ALERT",
                "info": "XProtect not found!",
                "tip": "Tip: XProtect is a built-in malware scanner. It should be present on all modern Macs."
            }
    except Exception:
        return {"label": "XProtect", "status": "ERROR", "info": "Unable to check XProtect status.", "tip": ""}

def check_firewall():
    """Check if the macOS Application Firewall is enabled."""
    try:
        result = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True)
        output = result.stdout.strip().lower()
        if "enabled" in output:
            enabled = True
        elif "disabled" in output:
            enabled = False
        elif "state = 1" in output:
            enabled = True
        elif "state = 0" in output:
            enabled = False
        else:
            return {"label": "Firewall", "status": "ERROR", "info": "Unable to determine firewall status.", "tip": ""}
        tip = "Tip: The firewall helps block unwanted incoming connections. Enable it in System Settings > Network > Firewall."
        return {
            "label": "Firewall",
            "status": "OK" if enabled else "ALERT",
            "info": "Firewall is enabled." if enabled else "Firewall is disabled.",
            "tip": tip if not enabled else ""
        }
    except Exception:
        return {"label": "Firewall", "status": "ERROR", "info": "Unable to check firewall status.", "tip": ""}

def check_firewall_stealth():
    """Check if firewall stealth mode is enabled. Stealth mode requires the firewall to be enabled."""
    try:
        # First, check if firewall is enabled
        fw_result = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True)
        fw_output = fw_result.stdout.strip().lower()
        fw_enabled = ("enabled" in fw_output) or ("state = 1" in fw_output)
        if not fw_enabled:
            return {
                "label": "Firewall Stealth Mode",
                "status": "SUGGESTION",
                "info": "Stealth mode requires the firewall to be enabled. Enable the firewall first in System Settings > Network > Firewall.",
                "tip": "Tip: The firewall must be enabled before you can enable stealth mode."
            }
        result = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"], capture_output=True, text=True)
        output = result.stdout.strip().lower()
        # Robust detection for stealth mode
        enabled = (
            "enabled" in output or
            "state = 1" in output or
            "stealth mode is on" in output or
            "firewall stealth mode is on" in output
        )
        tip = "Tip: Stealth mode makes your Mac ignore unsolicited network probes. Enable it in System Settings > Network > Firewall > Options."
        return {
            "label": "Firewall Stealth Mode",
            "status": "OK" if enabled else "ALERT",
            "info": "Stealth mode is enabled." if enabled else "Stealth mode is disabled.",
            "tip": tip if not enabled else ""
        }
    except Exception:
        return {"label": "Firewall Stealth Mode", "status": "ERROR", "info": "Unable to check firewall stealth mode.", "tip": ""}

def check_bluetooth():
    """Check if Bluetooth is enabled."""
    try:
        result = subprocess.run(["system_profiler", "SPBluetoothDataType"], capture_output=True, text=True)
        output = result.stdout
        enabled = False
        for line in output.splitlines():
            if "bluetooth power: on" in line.lower() or "state: on" in line.lower():
                enabled = True
                break
        if not enabled and "Connected: Yes" in output:
            enabled = True
        tip = "Tip: Disable Bluetooth when not in use to reduce attack surface."
        return {
            "label": "Bluetooth",
            "status": "ALERT" if enabled else "OK",
            "info": "Bluetooth is ON" if enabled else "Bluetooth is OFF",
            "tip": tip if enabled else ""
        }
    except Exception:
        return {"label": "Bluetooth", "status": "ERROR", "info": "Unable to check Bluetooth status.", "tip": ""}

def check_guest_account():
    """Check if the guest account is enabled."""
    try:
        result = subprocess.run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], capture_output=True, text=True)
        enabled = result.stdout.strip() == "1"
        tip = "Tip: Disable the guest account for better security."
        return {
            "label": "Guest Account",
            "status": "ALERT" if enabled else "OK",
            "info": "Guest account is enabled." if enabled else "Guest account is disabled.",
            "tip": tip if enabled else ""
        }
    except Exception:
        return {"label": "Guest Account", "status": "ERROR", "info": "Unable to check guest account status.", "tip": ""}

def check_remote_apple_events():
    """Check if remote Apple Events are enabled."""
    try:
        result = subprocess.run(["systemsetup", "-getremoteappleevents"], capture_output=True, text=True)
        enabled = "on" in result.stdout.lower()
        tip = "Tip: Remote Apple Events should be off unless specifically needed."
        return {
            "label": "Remote Apple Events",
            "status": "ALERT" if enabled else "OK",
            "info": result.stdout.strip(),
            "tip": tip if enabled else ""
        }
    except Exception:
        return {"label": "Remote Apple Events", "status": "ERROR", "info": "Unable to check remote Apple Events status.", "tip": ""}

def check_screen_sharing():
    """Check if screen sharing is enabled."""
    try:
        result = subprocess.run(["launchctl", "print-disabled", "system"], capture_output=True, text=True)
        output = result.stdout
        enabled = False
        for line in output.splitlines():
            if "com.apple.screensharing" in line:
                if " = false" in line.replace(' ', ''):
                    enabled = True
                break
        tip = "Tip: Disable screen sharing unless you need it."
        return {
            "label": "Screen Sharing",
            "status": "ALERT" if enabled else "OK",
            "info": "Screen sharing is enabled." if enabled else "Screen sharing is disabled.",
            "tip": tip if enabled else ""
        }
    except Exception:
        return {"label": "Screen Sharing", "status": "ERROR", "info": "Unable to check screen sharing status.", "tip": ""}

def check_automatic_updates():
    """Check if automatic software updates are enabled, and distinguish between download, system/security, and app/macOS updates. If settings cannot be detected, return UNKNOWN and add a manual suggestion."""
    try:
        user_su = Path.home() / "Library/Preferences/com.apple.SoftwareUpdate.plist"
        user_commerce = Path.home() / "Library/Preferences/com.apple.commerce.plist"
        sys_su = Path("/Library/Preferences/com.apple.SoftwareUpdate")
        sys_commerce = Path("/Library/Preferences/com.apple.commerce")
        def read_key(domain, key):
            try:
                result = subprocess.run(["defaults", "read", str(domain), key], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass
            return None
        download = read_key(user_su, "AutomaticCheckEnabled") or read_key(sys_su, "AutomaticCheckEnabled")
        security = read_key(user_su, "CriticalUpdateInstall") or read_key(sys_su, "CriticalUpdateInstall")
        macos = read_key(user_su, "AutomaticallyInstallMacOSUpdates") or read_key(sys_su, "AutomaticallyInstallMacOSUpdates")
        app = read_key(user_commerce, "AutoUpdate") or read_key(sys_commerce, "AutoUpdate")
        if all(x is None for x in [download, security, macos, app]):
            return {
                "label": "Automatic Software Updates",
                "status": "UNKNOWN",
                "info": [
                    "Automatic update settings could not be detected programmatically on this macOS version.",
                    "Please review your settings in System Settings > General > Software Update > Automatic Updates.",
                    "[Manual] It is recommended to enable 'Install Security Responses and system files' and 'Download new updates when available'. General users should also enable 'Install macOS updates' and 'Install application updates from the App Store'. Developers may wish to leave those off for manual control.",
                    "Note: On managed Macs, your organization may enforce update settings via MDM. Local tools cannot always detect these settings on modern macOS."
                ],
                "tip": ""
            }
        def enabled(val):
            return str(val).strip() == "1"
        info = []
        info.append(f"Download new updates when available: {'Enabled' if enabled(download) else 'Disabled'}")
        info.append(f"Install system data files and security updates: {'Enabled' if enabled(security) else 'Disabled'}")
        info.append(f"Install macOS updates automatically: {'Enabled' if enabled(macos) else 'Disabled'}")
        info.append(f"Install app updates automatically: {'Enabled' if enabled(app) else 'Disabled'}")
        status = "OK" if enabled(download) and enabled(security) else "ALERT"
        tip = ("Tip: It is recommended to enable 'Install Security Responses and system files' and 'Download new updates when available'. "
               "General users should also enable 'Install macOS updates' and 'Install application updates from the App Store'. "
               "Developers may wish to leave those off for manual control.")
        return {
            "label": "Automatic Software Updates",
            "status": status,
            "info": info,
            "tip": tip if status == "ALERT" else ""
        }
    except Exception:
        return {
            "label": "Automatic Software Updates",
            "status": "ERROR",
            "info": "Unable to check automatic update status.",
            "tip": ""
        }

def check_filevault():
    """Check if FileVault disk encryption is enabled."""
    try:
        result = subprocess.run(["fdesetup", "status"], capture_output=True, text=True)
        enabled = "filevault is on" in result.stdout.lower()
        tip = "Tip: Enable FileVault to encrypt your disk and protect your data."
        return {
            "label": "FileVault",
            "status": "OK" if enabled else "ALERT",
            "info": result.stdout.strip(),
            "tip": tip if not enabled else ""
        }
    except Exception:
        return {"label": "FileVault", "status": "ERROR", "info": "Unable to check FileVault status.", "tip": ""}

def check_firmware_password():
    """Check if a firmware password is set (returns a tip if not)."""
    try:
        result = subprocess.run(["firmwarepasswd", "-check"], capture_output=True, text=True)
        output = result.stdout.strip()
        if "Password Enabled: Yes" in output:
            enabled = True
        elif "Password Enabled: No" in output:
            enabled = False
        elif "No such file or directory" in output or "command not found" in output or "usage" in output.lower():
            return {
                "label": "Firmware Password",
                "status": "SUGGESTION",
                "info": "Unable to check firmware password status. This feature may not be supported on your Mac (common on T2/Apple Silicon Macs).",
                "tip": "Tip: Set a firmware password to prevent unauthorized changes to startup disks."
            }
        else:
            return {
                "label": "Firmware Password",
                "status": "SUGGESTION",
                "info": "Unable to determine firmware password status. You can check manually in Recovery Mode.",
                "tip": "Tip: Set a firmware password to prevent unauthorized changes to startup disks."
            }
        tip = "Tip: Set a firmware password to prevent unauthorized changes to startup disks."
        return {
            "label": "Firmware Password",
            "status": "OK" if enabled else "ALERT",
            "info": "Firmware password is set." if enabled else "Firmware password is NOT set.",
            "tip": tip if not enabled else ""
        }
    except Exception:
        return {
            "label": "Firmware Password",
            "status": "SUGGESTION",
            "info": "Unable to check firmware password status. This feature may not be supported on your Mac (common on T2/Apple Silicon Macs).",
            "tip": "Tip: Set a firmware password to prevent unauthorized changes to startup disks."
        } 