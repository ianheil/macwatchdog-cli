"""Pytest fixtures.

We point ``MACWATCHDOG_DATA_DIR`` at a tmp path per test so nothing writes
into ``~/Library/Application Support`` during the run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("MACWATCHDOG_DATA_DIR", str(tmp_path))
    yield
