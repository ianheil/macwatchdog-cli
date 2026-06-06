"""Configuration profile audit.

Invokes ``profiles -P -o stdout-xml`` and parses the result with
:mod:`plistlib`. Each profile is normalised into a dict with identifier,
scope, MDM flag, removable flag, and a list of risk tags derived from its
payloads.
"""

from __future__ import annotations

import os
import plistlib
import re
from typing import Any

from ..proc import run
from ..result import CheckResult
from ..severity import Severity


ROOT_CERT_RE = re.compile(r"root", re.IGNORECASE)
VPN_RE = re.compile(r"vpn", re.IGNORECASE)


def _profiles_xml() -> dict[str, Any] | None:
    """Return the ``profiles -P -o stdout-xml`` payload as a dict, or None."""
    cmd = ["profiles", "-P", "-o", "stdout-xml"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    result = run(cmd, timeout=15)
    if not result.ok or not result.stdout:
        return None
    try:
        xml_start = result.stdout.index("<?xml")
    except ValueError:
        return None
    try:
        return plistlib.loads(result.stdout[xml_start:].encode("utf-8"))
    except Exception:
        return None


def _payload_items(entry: Any) -> list[dict[str, Any]]:
    if isinstance(entry, list):
        return [x for x in entry if isinstance(x, dict)]
    if isinstance(entry, dict):
        return [entry]
    return []


def _risk_flags(payloads: list[dict[str, Any]]) -> list[str]:
    risks: list[str] = []
    cert_markers = ("rootca", "certificate", "pkcs12", "pkcs1", "security.scep")
    for payload in payloads:
        payload_type = str(payload.get("PayloadType", "")).lower()
        if any(marker in payload_type for marker in cert_markers):
            risks.append("Certificate payload")
        if "vpn" in payload_type:
            risks.append("VPN")
        for value in payload.values():
            text = str(value)
            if ROOT_CERT_RE.search(text) and "Root certificate" not in risks:
                risks.append("Root certificate")
                break
    # dedupe preserving order
    deduped: list[str] = []
    for r in risks:
        if r not in deduped:
            deduped.append(r)
    return deduped


def parse_profiles() -> list[dict[str, Any]]:
    """Return a list of normalised profile descriptors."""
    data = _profiles_xml()
    if not data:
        return []

    profiles: list[dict[str, Any]] = []
    # The payload key is either "_computerlevel" or a user-level key.
    for key, entries in data.items():
        for entry in _payload_items(entries):
            payload_items = _payload_items(entry.get("ProfileItems"))
            removable = True
            removal_disallowed = entry.get("PayloadRemovalDisallowed")
            if isinstance(removal_disallowed, bool):
                removable = not removal_disallowed
            elif isinstance(removal_disallowed, str):
                removable = removal_disallowed.lower() not in ("yes", "true", "1")

            payload_types = [str(p.get("PayloadType", "")).lower() for p in payload_items]
            identifier = str(entry.get("ProfileIdentifier") or entry.get("PayloadIdentifier") or "").strip()
            is_mdm = any("mdm" in t for t in payload_types) or "mdm" in identifier.lower()

            profiles.append(
                {
                    "profileIdentifier": identifier,
                    "profileDisplayName": entry.get("ProfileDisplayName") or entry.get("PayloadDisplayName") or "",
                    "profileOrganization": entry.get("ProfileOrganization") or entry.get("PayloadOrganization") or "",
                    "scope": key,
                    "mdm": is_mdm,
                    "removable": removable,
                    "risk": _risk_flags(payload_items),
                    "payloadTypes": payload_types,
                }
            )
    return profiles


def check_profiles() -> CheckResult:
    profiles = parse_profiles()
    if not profiles:
        return CheckResult(
            label="Configuration Profiles",
            status="OK",
            severity=Severity.OK,
            info="none installed",
        )

    risky = [p for p in profiles if p["risk"]]
    info = [_format_profile(p) for p in profiles]
    extras = {"profiles": profiles}
    if risky:
        return CheckResult(
            label="Configuration Profiles",
            status="ALERT",
            severity=Severity.MEDIUM,
            info=info,
            tip="Review profiles marked with Risk tags. Root certificates and VPN payloads deserve extra scrutiny.",
            extras=extras,
        )
    return CheckResult(
        label="Configuration Profiles",
        status="INFO",
        severity=Severity.INFO,
        info=info,
        tip="No high-risk payloads detected, but review any profile you didn't install intentionally.",
        extras=extras,
    )


def _format_profile(p: dict[str, Any]) -> str:
    parts = [p.get("profileDisplayName") or p.get("profileIdentifier") or "(unnamed)"]
    parts.append(f"id={p.get('profileIdentifier', 'N/A')}")
    if p.get("mdm"):
        parts.append("MDM")
    if not p.get("removable", True):
        parts.append("LOCKED")
    if p.get("risk"):
        parts.append("risk=" + "/".join(p["risk"]))
    return " | ".join(parts)


def remove_profile(identifier: str) -> tuple[bool, str]:
    """Remove a configuration profile by identifier."""
    if not identifier or not re.fullmatch(r"[A-Za-z0-9._\-]+", identifier):
        return False, "Refusing to remove profile: identifier contains unexpected characters."

    result = run(["sudo", "-n", "profiles", "remove", "-identifier", identifier], timeout=15)
    if result.ok:
        return True, result.stdout.strip() or f"Removed {identifier}."
    return False, (result.stderr or result.stdout).strip() or f"Failed to remove {identifier}."


def get_mdm_info() -> str:
    result = run(["profiles", "status", "-type", "enrollment"], timeout=10)
    if result.missing:
        return "profiles binary not available"
    return (result.stdout or result.stderr).strip()
