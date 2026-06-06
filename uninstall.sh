#!/usr/bin/env bash
# macWatchdog uninstaller.

set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '%s\n' "$*"; }

info "Removing macWatchdog..."

if command -v pipx >/dev/null 2>&1 && pipx list 2>/dev/null | grep -q macwatchdog; then
    pipx uninstall macwatchdog
fi

SYMLINK="/usr/local/bin/macwatchdog"
if [[ -L "$SYMLINK" ]]; then
    if [[ -w "$SYMLINK" ]]; then
        rm -f "$SYMLINK"
    else
        sudo rm -f "$SYMLINK"
    fi
    info "Removed $SYMLINK"
fi

if [[ -d "$SCRIPT_DIR/venv" ]]; then
    rm -rf "$SCRIPT_DIR/venv"
    info "Removed $SCRIPT_DIR/venv"
fi

DATA_DIR="${MACWATCHDOG_DATA_DIR:-$HOME/Library/Application Support/macwatchdog}"
if [[ -d "$DATA_DIR" ]]; then
    read -r -p "Also delete runtime data in '$DATA_DIR'? [y/N] " answer
    case "$answer" in
        y|Y|yes|YES)
            rm -rf "$DATA_DIR"
            info "Removed $DATA_DIR"
            ;;
        *)
            info "Leaving data dir in place."
            ;;
    esac
fi

# Clean any legacy in-tree data too.
for f in quarantine snapshots watchdog_timeline.log timeline.jsonl mdm_state.json report.txt report.json auto_remove_watchlist.json; do
    target="$SCRIPT_DIR/$f"
    if [[ -e "$target" ]]; then
        if [[ -w "$target" ]]; then
            rm -rf "$target"
        else
            sudo rm -rf "$target"
        fi
        info "Removed $target"
    fi
done

info "Uninstall complete."
