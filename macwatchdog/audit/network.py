"""Network interfaces and active connections check.

Reports the list of interfaces from ``ifconfig`` and the number of
ESTABLISHED connections from ``netstat -an`` as an ``INFO`` finding.
"""

from __future__ import annotations

from ..proc import run
from ..result import CheckResult
from ..severity import Severity


def _parse_interfaces(ifconfig_out: str) -> list[str]:
    names = []
    for line in ifconfig_out.splitlines():
        if line and not line.startswith((" ", "\t")):
            name = line.split(":", 1)[0]
            if name:
                names.append(name)
    return names


def _summarise_interfaces(names: list[str]) -> list[str]:
    """Return a human-useful summary of interfaces.

    Shows physical/ethernet (en*), loopback (lo0), and VPN tunnels (utun*)
    separately. Virtual bridges and Apple-internal interfaces are collapsed
    into a count.
    """
    physical = [n for n in names if n.startswith("en")]
    tunnels = [n for n in names if n.startswith("utun")]
    loopback = [n for n in names if n == "lo0"]
    other_count = len(names) - len(physical) - len(tunnels) - len(loopback)

    lines = []
    if loopback:
        lines.append(f"Loopback: lo0")
    if physical:
        lines.append(f"Physical / Ethernet: {', '.join(physical)}")
    if tunnels:
        lines.append(f"VPN tunnels: {', '.join(tunnels)}")
    if other_count:
        lines.append(f"Other (virtual, bridge, AWDL, etc.): {other_count}")
    return lines


def check_network() -> CheckResult:
    ifconfig_result = run(["ifconfig"], timeout=5)
    netstat_result = run(["netstat", "-an"], timeout=10)

    if ifconfig_result.missing or netstat_result.missing:
        missing = [t for t, r in [("ifconfig", ifconfig_result), ("netstat", netstat_result)] if r.missing]
        return CheckResult(
            label="Network Interfaces & Connections",
            status="UNKNOWN",
            severity=Severity.LOW,
            info=f"Missing tool(s): {', '.join(missing)}",
        )

    interfaces = _parse_interfaces(ifconfig_result.stdout)
    established = sum(1 for line in netstat_result.stdout.splitlines() if "ESTABLISHED" in line)

    info = _summarise_interfaces(interfaces)
    info.append(f"Established connections: {established}")
    return CheckResult(
        label="Network Interfaces & Connections",
        status="INFO",
        severity=Severity.INFO,
        info=info,
        tip="Use 'lsof -i -P -n | grep ESTABLISHED' to inspect individual connections.",
    )
