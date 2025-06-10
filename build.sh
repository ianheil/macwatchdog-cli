#!/bin/bash
# Build script for macWatchdog
# Packages the CLI directory and necessary files for distribution

set -e

cd "$(dirname "$0")"

ARCHIVE_NAME="macwatchdog-$(cat VERSION).zip"

# Build the list of files to include
find . \
  -path './venv' -prune -o \
  -path './.git' -prune -o \
  -path './__pycache__' -prune -o \
  -path './quarantine' -prune -o \
  -path './snapshots' -prune -o \
  -path './screenshots' -prune -o \
  -name '*.pyc' -prune -o \
  -name 'watchdog_timeline.log' -prune -o \
  -name 'mdm_state.json' -prune -o \
  -name 'report.txt' -prune -o \
  -name '.DS_Store' -prune -o \
  -name '*.zip' -prune -o \
  -name '.filelist.txt' -prune -o \
  -type f -print > .filelist.txt

zip "$ARCHIVE_NAME" -@ < .filelist.txt
rm .filelist.txt

echo "Build complete: $ARCHIVE_NAME" 