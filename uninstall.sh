#!/bin/bash
# Uninstall script for macWatchdog
# Removes all files, virtual environment, and shell alias

set -e

INSTALL_DIR="$HOME/macwatchdog"
ALIAS_NAME="macwatchdog"
SHELL_RC="$HOME/.zshrc"
if [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

# Remove the install directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
else
    echo "$INSTALL_DIR not found."
fi

# Remove the alias from shell rc file
if grep -q "$ALIAS_NAME" "$SHELL_RC"; then
    echo "Removing alias from $SHELL_RC..."
    sed -i.bak "/alias $ALIAS_NAME=/d" "$SHELL_RC"
    echo "Alias removed. (Backup saved as $SHELL_RC.bak)"
else
    echo "Alias not found in $SHELL_RC."
fi

# Remove any remaining logs, quarantine, or snapshots in CLI if run from source
SCRIPT_DIR="$(dirname "$0")"
for f in "quarantine" "snapshots" "watchdog_timeline.log" "mdm_state.json" "report.txt"; do
    if [ -e "$SCRIPT_DIR/$f" ]; then
        echo "Removing $SCRIPT_DIR/$f..."
        rm -rf "$SCRIPT_DIR/$f"
    fi

done

echo "Uninstall complete. You may want to restart your terminal session." 