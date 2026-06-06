#!/usr/bin/env bash
# Build a sdist + wheel for macWatchdog.

set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf dist build *.egg-info
python3 -m pip install --quiet --upgrade build
python3 -m build

echo "Artifacts:"
ls -1 dist/
