import json
from pathlib import Path

from macwatchdog.result import CheckResult
from macwatchdog.reports.export import export_report


def _sample_report():
    return {
        "MDM": [
            CheckResult(label="MDM & DEP Enrollment", status="OK", info="MDM enrollment: No"),
        ],
        "USB": [
            CheckResult(label="Connected USB Devices", status="INFO", info=["Device A"]),
        ],
    }


def test_export_text(tmp_path: Path):
    path = export_report(_sample_report(), tmp_path / "out.txt", as_json=False)
    content = path.read_text(encoding="utf-8")
    assert "== MDM ==" in content
    assert "MDM & DEP Enrollment: OK" in content
    assert "Connected USB Devices: INFO" in content


def test_export_json(tmp_path: Path):
    path = export_report(_sample_report(), tmp_path / "out.json", as_json=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "MDM" in data and "USB" in data
    assert data["MDM"][0]["label"] == "MDM & DEP Enrollment"
    assert data["USB"][0]["severity"] == "INFO"
