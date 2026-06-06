"""Tests for the FDA-free App Privacy Capabilities check."""

from __future__ import annotations

import plistlib
from pathlib import Path

from macwatchdog.audit import app_entitlements


def _make_app(root: Path, name: str, **keys: object) -> Path:
    app = root / f"{name}.app"
    contents = app / "Contents"
    contents.mkdir(parents=True, exist_ok=True)
    info = contents / "Info.plist"
    data: dict[str, object] = {"CFBundleName": name, **keys}
    with info.open("wb") as handle:
        plistlib.dump(data, handle)
    return app


def test_scan_apps_finds_declared_capabilities(tmp_path):
    _make_app(
        tmp_path,
        "CamApp",
        NSCameraUsageDescription="We need the camera",
        NSMicrophoneUsageDescription="And the mic",
    )
    _make_app(tmp_path, "BoringApp")  # no usage keys, should be ignored
    _make_app(
        tmp_path,
        "AutoApp",
        NSAppleEventsUsageDescription="Automate other apps",
    )

    findings = app_entitlements.scan_apps((tmp_path,))
    names = {name for name, _caps, _path in findings}

    assert "CamApp" in names
    assert "AutoApp" in names
    assert "BoringApp" not in names

    cam_caps = next(caps for name, caps, _ in findings if name == "CamApp")
    assert "Camera" in cam_caps
    assert "Microphone" in cam_caps


def test_scan_apps_handles_missing_info_plist(tmp_path):
    app = tmp_path / "Broken.app"
    (app / "Contents").mkdir(parents=True)
    # No Info.plist intentionally

    assert app_entitlements.scan_apps((tmp_path,)) == []


def test_check_app_privacy_capabilities_ok_when_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(app_entitlements, "APP_ROOTS", (tmp_path,))
    result = app_entitlements.check_app_privacy_capabilities()
    assert result.status == "OK"


def test_check_app_privacy_capabilities_reports_sensitive(tmp_path, monkeypatch):
    _make_app(
        tmp_path,
        "Screenshot Pro",
        NSScreenCaptureUsageDescription="Capture the screen",
        NSAccessibilityUsageDescription="Control the UI",
    )
    monkeypatch.setattr(app_entitlements, "APP_ROOTS", (tmp_path,))

    result = app_entitlements.check_app_privacy_capabilities()

    assert result.status == "INFO"
    joined = " ".join(result.info)
    assert "Screenshot Pro" in joined
    assert "Screen Recording" in joined
    assert "Accessibility" in joined
    assert result.extras.get("sensitive_count", 0) >= 1
