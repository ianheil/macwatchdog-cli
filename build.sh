#!/bin/bash
# Build script for macWatchdog
# Packages the CLI directory and necessary files for distribution

set -e

cd "$(dirname "$0")"

ARCHIVE_NAME="macwatchdog-$(cat VERSION).zip"

# Exclude patterns
EXCLUDES=(
  "venv"
  "__pycache__"
  "*.pyc"
  "quarantine"
  "snapshots"
  "watchdog_timeline.log"
  "mdm_state.json"
  "report.txt"
  ".DS_Store"
)

# Create the zip archive from within CLI
zip -r "$ARCHIVE_NAME" . -x ${EXCLUDES[@]}

echo "Build complete: $ARCHIVE_NAME" 