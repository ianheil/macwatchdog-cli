"""Connected USB device inventory.

Parses ``system_profiler SPUSBDataType`` output block-by-block using its
indentation structure. Devices carrying a ``Built-in: Yes`` marker are
excluded; the remaining external devices are reported with vendor/product
identifiers.
"""

from __future__ import annotations

from ..proc import run
from ..result import CheckResult
from ..severity import Severity


def _parse_devices(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip())
        if not stripped:
            continue

        if stripped.endswith(":") and indent <= 6 and "Product ID" not in stripped and ":" in stripped:
            # A device header like "    USB3.0 Hub:"
            if current and current.get("Product ID"):
                devices.append(current)
            current = {"Name": stripped.rstrip(":")}
            continue

        if ":" in stripped and current is not None:
            key, _, value = stripped.partition(":")
            current[key.strip()] = value.strip()

    if current and current.get("Product ID"):
        devices.append(current)

    return devices


def _format(device: dict[str, str]) -> str:
    parts = [device.get("Name", "Unknown Device")]
    for key in ("Product ID", "Vendor ID", "Manufacturer", "Serial Number"):
        if device.get(key):
            parts.append(f"{key}: {device[key]}")
    return " | ".join(parts)


def check_usb() -> CheckResult:
    result = run(["system_profiler", "SPUSBDataType"], timeout=20)
    if result.missing:
        return CheckResult(
            label="Connected USB Devices",
            status="UNKNOWN",
            severity=Severity.LOW,
            info=["`system_profiler` not available."],
        )
    if result.timed_out:
        return CheckResult(
            label="Connected USB Devices",
            status="UNKNOWN",
            severity=Severity.LOW,
            info=["system_profiler timed out; a USB device may be misbehaving."],
        )

    parsed = _parse_devices(result.stdout)
    external = [d for d in parsed if d.get("Built-in", "No").lower() != "yes"]
    external = [d for d in external if not (d.get("Serial Number", "").strip("0") == "")]

    if not external:
        return CheckResult(
            label="Connected USB Devices",
            status="OK",
            severity=Severity.OK,
            info="no external devices",
        )

    return CheckResult(
        label="Connected USB Devices",
        status="INFO",
        severity=Severity.INFO,
        info=[_format(d) for d in external],
        tip="Only trusted USB devices should be connected. Unknown devices could be data-exfiltration hardware.",
    )
