"""App privacy-capability scan.

Reads every installed ``.app`` bundle's ``Info.plist`` and reports which
apps declare ``NS*UsageDescription`` keys. Apple requires these keys for any
app that wants to request Camera, Microphone, Location, Automation, etc.,
so the presence of a key means "this app is *built* to ask for X", not that
the user has granted it.

This check runs without Full Disk Access and is the FDA-free counterpart to
:mod:`macwatchdog.audit.tcc`.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

from ..result import CheckResult
from ..severity import Severity

APP_ROOTS: tuple[Path, ...] = (
    Path("/Applications"),
    Path("/Applications/Utilities"),
    Path.home() / "Applications",
    Path("/System/Applications"),
)

USAGE_KEYS: dict[str, str] = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSLocationUsageDescription": "Location",
    "NSLocationWhenInUseUsageDescription": "Location",
    "NSLocationAlwaysUsageDescription": "Location",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location",
    "NSContactsUsageDescription": "Contacts",
    "NSCalendarsUsageDescription": "Calendar",
    "NSRemindersUsageDescription": "Reminders",
    "NSPhotoLibraryUsageDescription": "Photos",
    "NSPhotoLibraryAddUsageDescription": "Photos",
    "NSAppleEventsUsageDescription": "Automation (Apple Events)",
    "NSSystemAdministrationUsageDescription": "System Administration",
    "NSAccessibilityUsageDescription": "Accessibility",
    "NSInputMonitoringUsageDescription": "Input Monitoring",
    "NSScreenCaptureUsageDescription": "Screen Recording",
    "NSFullDiskAccessUsageDescription": "Full Disk Access",
    "NSDesktopFolderUsageDescription": "Desktop folder",
    "NSDocumentsFolderUsageDescription": "Documents folder",
    "NSDownloadsFolderUsageDescription": "Downloads folder",
    "NSRemovableVolumesUsageDescription": "Removable volumes",
    "NSNetworkVolumesUsageDescription": "Network volumes",
    "NSMotionUsageDescription": "Motion",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSBluetoothPeripheralUsageDescription": "Bluetooth",
    "NSHomeKitUsageDescription": "HomeKit",
    "NSHealthShareUsageDescription": "Health",
    "NSHealthUpdateUsageDescription": "Health",
    "NSSpeechRecognitionUsageDescription": "Speech recognition",
    "NSSiriUsageDescription": "Siri",
    "NSFocusStatusUsageDescription": "Focus",
    "NSUserTrackingUsageDescription": "Tracking",
}

SENSITIVE_CAPABILITIES: frozenset[str] = frozenset(
    {
        "Camera",
        "Microphone",
        "Screen Recording",
        "Input Monitoring",
        "Full Disk Access",
        "Accessibility",
        "Automation (Apple Events)",
        "Location",
    }
)


def _scan_app(app: Path) -> tuple[str, list[str]] | None:
    """Return ``(bundle_name, sorted_capabilities)`` or ``None`` if nothing found."""

    info_plist = app / "Contents" / "Info.plist"
    try:
        with info_plist.open("rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None

    capabilities: set[str] = set()
    for key, label in USAGE_KEYS.items():
        if key in data:
            capabilities.add(label)
    if not capabilities:
        return None

    name = data.get("CFBundleDisplayName") or data.get("CFBundleName") or app.stem
    return str(name), sorted(capabilities)


def scan_apps(
    roots: tuple[Path, ...] | None = None,
) -> list[tuple[str, list[str], Path]]:
    """Scan ``roots`` (or :data:`APP_ROOTS` when omitted) for ``.app`` bundles
    declaring sensitive usage keys."""

    if roots is None:
        roots = APP_ROOTS

    findings: list[tuple[str, list[str], Path]] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        try:
            apps = sorted(root.glob("*.app"))
        except OSError:
            continue
        for app in apps:
            resolved = app.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            result = _scan_app(app)
            if result:
                name, capabilities = result
                findings.append((name, capabilities, app))
    findings.sort(key=lambda entry: entry[0].casefold())
    return findings


_CRITICAL_CAPS: frozenset[str] = frozenset({
    "Screen Recording", "Input Monitoring", "Full Disk Access",
    "Accessibility", "System Administration",
})
_HIGH_CAPS: frozenset[str] = frozenset({"Automation (Apple Events)"})
_SENSOR_CAPS: frozenset[str] = frozenset({"Camera", "Microphone"})


def _chunk_apps(apps: list[str], max_width: int = 62) -> list[str]:
    """Split an app list into sub-item lines that fit within max_width chars."""
    lines: list[str] = []
    current: list[str] = []
    current_len = 0
    sep = "  ·  "
    for app in apps:
        needed = len(app) + (len(sep) if current else 0)
        if current_len + needed > max_width and current:
            lines.append("  " + sep.join(current))
            current = []
            current_len = 0
        current.append(app)
        current_len += needed
    if current:
        lines.append("  " + sep.join(current))
    return lines


def _group_apps(findings: list[tuple[str, list[str], object]]) -> list[str]:
    """Format findings grouped by sensitivity tier with two-level indentation."""
    critical: list[str] = []
    high: list[str] = []
    sensors: list[str] = []
    location: list[str] = []

    for name, caps, _ in findings:
        cap_set = set(caps)
        if cap_set & _CRITICAL_CAPS:
            critical.append(f"{name}  [{', '.join(sorted(cap_set & _CRITICAL_CAPS))}]")
        elif cap_set & _HIGH_CAPS:
            high.append(name)
        elif cap_set & {"Camera", "Microphone"}:
            sensors.append(name)
        elif "Location" in cap_set:
            location.append(name)

    lines: list[str] = []
    if critical:
        # "# " prefix → rendered as styled tier header by _print_info
        lines.append(f"# Screen Recording / Input Monitoring / FDA / Accessibility  [{len(critical)}]")
        for app in critical:
            lines.append(f"  {app}")
    if high:
        lines.append(f"# Automation (Apple Events)  [{len(high)}]")
        lines.extend(_chunk_apps(high))
    if sensors:
        lines.append(f"# Camera / Microphone  [{len(sensors)}]")
        lines.extend(_chunk_apps(sensors))
    if location:
        lines.append(f"# Location  [{len(location)}]")
        lines.extend(_chunk_apps(location))

    other = len(findings) - len(critical) - len(high) - len(sensors) - len(location)
    lines.append(f"{len(findings)} apps scanned  ·  {other} with low-sensitivity caps only")
    return lines


def check_app_privacy_capabilities() -> CheckResult:
    """Summarise which installed apps declare privacy-sensitive usage keys."""

    findings = scan_apps()
    if not findings:
        return CheckResult(
            label="App Privacy Capabilities",
            status="OK",
            severity=Severity.OK,
            category="App Privacy",
        )

    sensitive_hits = sum(
        1 for _, caps, _ in findings
        if any(cap in SENSITIVE_CAPABILITIES for cap in caps)
    )

    return CheckResult(
        label="App Privacy Capabilities",
        status="INFO",
        severity=Severity.INFO,
        info=_group_apps(findings),
        tip="These are capabilities apps are built to request — not necessarily granted. Review unfamiliar apps in System Settings > Privacy & Security.",
        category="App Privacy",
        extras={"app_count": len(findings), "sensitive_count": sensitive_hits},
    )
