import os
from pathlib import Path

from macwatchdog import paths


def test_data_dir_respects_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MACWATCHDOG_DATA_DIR", str(tmp_path / "custom"))
    result = paths.data_dir()
    assert result == tmp_path / "custom"
    assert result.exists()


def test_subdirectories_are_created(tmp_path, monkeypatch):
    monkeypatch.setenv("MACWATCHDOG_DATA_DIR", str(tmp_path))
    assert paths.quarantine_dir().exists()
    assert paths.agents_quarantine_dir().exists()
    assert paths.login_items_quarantine_dir().exists()
    assert paths.ports_quarantine_dir().exists()
    assert paths.snapshots_dir().exists()


def test_non_dir_helpers_return_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("MACWATCHDOG_DATA_DIR", str(tmp_path))
    assert isinstance(paths.timeline_log(), Path)
    assert isinstance(paths.mdm_state_file(), Path)
    assert isinstance(paths.watchlist_file(), Path)
