#!/usr/bin/env bash
# macWatchdog installer.
# Prefers pipx (isolated per-tool venv, globally callable); falls back to
# a project-local venv + /usr/local/bin symlink for folks without pipx.

set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
    RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
    CYAN="$(tput setaf 6)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; RESET=""
fi

info()  { printf '%s%s%s\n' "$CYAN" "$*" "$RESET"; }
ok()    { printf '%s%s%s\n' "$GREEN" "$*" "$RESET"; }
warn()  { printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"; }
die()   { printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

info "macWatchdog installer"

# --- Xcode CLT ---------------------------------------------------------------
if ! xcode-select -p >/dev/null 2>&1; then
    warn "Xcode Command Line Tools not found. Starting install (accept the GUI prompt)."
    xcode-select --install || true
    info "Waiting for Command Line Tools to install..."
    until xcode-select -p >/dev/null 2>&1; do sleep 5; done
    ok "Xcode Command Line Tools installed."
fi

install_with_pipx() {
    info "Installing macWatchdog via pipx..."
    pipx install --force "$SCRIPT_DIR"
    ok "Installed. Run 'macwatchdog' from any terminal."
}

install_with_venv() {
    info "pipx not available; falling back to project-local venv."
    VENV_DIR="$SCRIPT_DIR/venv"
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi
    "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
    "$VENV_DIR/bin/python" -m pip install "$SCRIPT_DIR"
    local target="/usr/local/bin/macwatchdog"
    if [[ -w /usr/local/bin ]] || sudo -n true 2>/dev/null; then
        sudo ln -sf "$VENV_DIR/bin/macwatchdog" "$target"
        ok "Symlinked $target -> $VENV_DIR/bin/macwatchdog"
    else
        warn "Could not symlink to /usr/local/bin. Add this to your shell profile:"
        printf '  export PATH=%q:$PATH\n' "$VENV_DIR/bin"
    fi
}

if command -v pipx >/dev/null 2>&1; then
    install_with_pipx
else
    install_with_venv
fi

ok "All done. Launch the interactive menu with 'macwatchdog' or list checks with 'macwatchdog list-checks'."
