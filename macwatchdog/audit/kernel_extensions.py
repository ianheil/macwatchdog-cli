"""Kernel and system extension audit.

Inventories third-party kernel extensions (kextstat + /Library/Extensions/) and
system extensions (/Library/SystemExtensions/). For each installed kext reports:
  - load state (loaded vs on-disk-only)
  - codesign validity
  - Apple Silicon inert flag (kexts cannot load on AS)

Severity logic (from the security community consensus):
  loaded + present                 → INFO  (benign, worth noting)
  on-disk + not loaded + unsigned  → HIGH  (kext with no valid sig is a red flag)
  on-disk + not loaded + signed    → INFO  (orphan candidate; review vendor)
  on-disk + Apple Silicon          → INFO  (inert, but good hygiene to remove)
"""

from __future__ import annotations

import platform
import plistlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..proc import run
from ..result import CheckResult
from ..severity import Severity

_BUNDLE_RE = re.compile(r"\s([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9_-]+){2,})\s+\(")
_KEXT_DIR = Path("/Library/Extensions")
_SEXT_DIR = Path("/Library/SystemExtensions")


@dataclass
class KextEntry:
    name: str
    path: Path
    loaded: bool
    signed: bool | None   # None = codesign not available or check skipped
    bundle_id: str = ""


def _loaded_bundle_ids() -> set[str]:
    result = run(["kextstat", "-l"], timeout=15)
    if result.missing or not result.ok:
        return set()
    ids: set[str] = set()
    for line in result.stdout.splitlines()[1:]:
        m = _BUNDLE_RE.search(line)
        if m:
            b = m.group(1)
            if not b.startswith("com.apple."):
                ids.add(b)
    return ids


def _read_bundle_id(kext_path: Path) -> str:
    plist = kext_path / "Contents" / "Info.plist"
    try:
        with plist.open("rb") as fh:
            data = plistlib.load(fh)
        return data.get("CFBundleIdentifier", "")
    except Exception:
        return ""


def _verify_signature(path: Path) -> bool | None:
    result = run(["codesign", "-v", str(path)], timeout=10)
    if result.missing:
        return None
    return result.ok


def _installed_kexts(loaded_ids: set[str]) -> list[KextEntry]:
    if not _KEXT_DIR.is_dir():
        return []
    entries: list[KextEntry] = []
    for kext_path in sorted(_KEXT_DIR.iterdir()):
        if kext_path.suffix != ".kext":
            continue
        bundle_id = _read_bundle_id(kext_path)
        loaded = bundle_id in loaded_ids if bundle_id else False
        signed = _verify_signature(kext_path)
        entries.append(KextEntry(kext_path.name, kext_path, loaded, signed, bundle_id))
    return entries


def _system_extensions() -> list[str]:
    if not _SEXT_DIR.is_dir():
        return []
    found: list[str] = []
    for uuid_dir in sorted(_SEXT_DIR.iterdir()):
        if not uuid_dir.is_dir():
            continue
        for ext in sorted(uuid_dir.iterdir()):
            if ext.suffix == ".systemextension":
                found.append(ext.name)
    return list(dict.fromkeys(found))


def check_kernel_extensions() -> CheckResult:
    is_as = platform.machine() == "arm64"
    loaded_ids = _loaded_bundle_ids()
    kexts = _installed_kexts(loaded_ids)
    sext_names = _system_extensions()

    if not kexts and not sext_names:
        return CheckResult(
            label="Kernel Extensions",
            status="OK",
            info="none found",
        )

    info: list[str] = []
    worst_sev = Severity.INFO
    unsigned_count = 0
    loaded_count = 0

    if kexts:
        info.append(f"# Installed kexts  [{len(kexts)}]  —  run 'Manage > Kernel Extensions' to remove")
        for k in kexts:
            parts = [k.name]
            if k.loaded:
                parts.append("loaded")
                loaded_count += 1
            elif is_as:
                parts.append("inert on Apple Silicon")
            else:
                parts.append("not loaded")
            if k.signed is True:
                parts.append("signed")
            elif k.signed is False:
                parts.append("UNSIGNED ⚠")
                unsigned_count += 1
                worst_sev = max(worst_sev, Severity.HIGH)
            info.append(f"  {k.name}  ·  {'  ·  '.join(parts[1:])}")

    if sext_names:
        info.append(f"# System extensions  [{len(sext_names)}]")
        for s in sext_names:
            info.append(f"  {s}")

    total = len(kexts) + len(sext_names)
    tip = (
        f"{total} third-party extension(s). "
        + ("Unsigned kexts are high risk — remove via the management menu. " if unsigned_count else "")
        + ("Kexts on Apple Silicon are inert but removing orphans is good hygiene." if is_as and kexts and not all(k.loaded for k in kexts) else "Verify each is from a known vendor.")
    )

    return CheckResult(
        label="Kernel Extensions",
        status="INFO",
        severity=worst_sev,
        info=info,
        tip=tip,
        extras={"kext_count": len(kexts), "sext_count": len(sext_names), "unsigned": unsigned_count},
    )
