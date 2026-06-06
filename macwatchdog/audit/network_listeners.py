"""Network listener / open-port audit.

Distinguishes between listeners exposed to all interfaces (0.0.0.0, *, ::)
and those bound to localhost only (127.x.x.x, ::1). Exposed listeners are
flagged at MEDIUM — they're reachable by anything on the local network.
Localhost-only listeners are INFO.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..proc import run
from ..result import CheckResult
from ..severity import Severity

_LOCALHOST_PREFIXES = ("127.", "::1", "[::1]")
_EXPOSED_ADDRS = {"0.0.0.0", "*", "::", "[::]"}


@dataclass
class Listener:
    process: str
    pid: str
    port: str        # full "addr:port" string from lsof
    exposed: bool    # True = bound to all interfaces; False = localhost only

    @property
    def display(self) -> str:
        tag = "[dim]all interfaces[/dim]" if self.exposed else "[dim]localhost[/dim]"
        return f"{self.process}  (PID {self.pid})  {self.port}  {tag}"

    def as_dict(self) -> dict[str, str]:
        return {
            "process": self.process,
            "pid": self.pid,
            "port": self.port,
            "exposed": str(self.exposed),
        }


def _is_exposed(port_field: str) -> bool:
    """Return True if the listener is bound to all interfaces."""
    addr = port_field.rsplit(":", 1)[0] if ":" in port_field else port_field
    if addr in _EXPOSED_ADDRS:
        return True
    if any(port_field.startswith(p) for p in _LOCALHOST_PREFIXES):
        return False
    # IPv4 private/specific address → not exposed via all-interface binding
    return False


def list_listeners() -> list[Listener]:
    result = run(["lsof", "-i", "-n", "-P"], timeout=15)
    if not result.ok:
        return []
    listeners: list[Listener] = []
    for line in result.stdout.splitlines():
        if "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        process = parts[0].replace("\\x20", " ")
        port_field = parts[8]
        listeners.append(Listener(
            process=process,
            pid=parts[1],
            port=port_field,
            exposed=_is_exposed(port_field),
        ))
    return listeners


def check_network_listeners() -> CheckResult:
    listeners = list_listeners()
    if not listeners:
        return CheckResult(
            label="Network Listeners (Open Ports)",
            status="OK",
            info="no listening sockets",
        )

    exposed = [l for l in listeners if l.exposed]
    local_only = [l for l in listeners if not l.exposed]

    info: list[str] = []
    if exposed:
        info.append(f"# Exposed — all interfaces  [{len(exposed)}]")
        for l in exposed:
            info.append(f"  {l.process}  (PID {l.pid})  {l.port}")
    if local_only:
        info.append(f"# Localhost only  [{len(local_only)}]")
        for l in local_only:
            info.append(f"  {l.process}  (PID {l.pid})  {l.port}")

    severity = Severity.MEDIUM if exposed else Severity.INFO
    tip = (
        f"{len(exposed)} listener(s) bound to all interfaces are reachable from the network — verify each is intentional."
        if exposed else
        "All listeners are localhost-only. Close any you don't recognise via 'macwatchdog close-port'."
    )

    return CheckResult(
        label="Network Listeners (Open Ports)",
        status="ALERT" if exposed else "INFO",
        severity=severity,
        info=info,
        tip=tip if (exposed or local_only) else "",
        extras={"listeners": [l.as_dict() for l in listeners]},
    )
