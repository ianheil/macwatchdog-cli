#!/bin/bash
# Install script for macWatchdog
# Installs dependencies in a virtual environment and sets up a shortcut

set -e

# Color functions for feedback
if command -v tput >/dev/null 2>&1; then
    RED="$(tput setaf 1)"
    GREEN="$(tput setaf 2)"
    YELLOW="$(tput setaf 3)"
    CYAN="$(tput setaf 6)"
    RESET="$(tput sgr0)"
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

echo "${CYAN}== macWatchdog Installer ==${RESET}"

# Check for Xcode Command Line Tools
echo "${CYAN}Checking for Xcode Command Line Tools...${RESET}"
if ! xcode-select -p >/dev/null 2>&1; then
    echo "${YELLOW}Xcode Command Line Tools are not installed.${RESET}"
    echo "Please install them (click 'Install' on the popup, or run 'xcode-select --install')."
    echo "After installation completes, this script will resume."
    xcode-select --install || true
    echo "Waiting for Xcode Command Line Tools to finish installing..."
    until xcode-select -p >/dev/null 2>&1; do
        sleep 5
    done
    echo "${GREEN}Xcode Command Line Tools installed. Resuming setup...${RESET}"
    exec "$0" "$@"
fi

# Set up correct paths with no spaces
INSTALL_DIR="$(pwd)"
VENV_DIR="${INSTALL_DIR}/venv"
VENV_PY="${INSTALL_DIR}/venv/bin/python3"
ALIAS_NAME="macwatchdog"

# Read and sanitize version string if VERSION file exists
VERSION="unknown"
if [ -f "VERSION" ]; then
    VERSION=$(cat VERSION | tr -d '\n' | sed 's/^ *//;s/ *$//')
    if [[ "$VERSION" =~ [[:space:]] ]]; then
        echo "${YELLOW}Warning: The VERSION file contains spaces or non-printing characters. This can break path and alias logic!${RESET}"
        echo "Sanitizing version string: '$VERSION'"
        VERSION=$(echo "$VERSION" | tr -d '[:space:]')
        echo "Using sanitized version: '$VERSION'"
    fi
fi

# Detect and select the correct Python 3 interpreter
PYTHON3_PATH="$(command -v python3 2>/dev/null || true)"
if [ "$PYTHON3_PATH" = "/Library/Developer/CommandLineTools/usr/bin/python3" ]; then
    echo "${RED}[ERROR] Detected python3 is the Xcode Command Line Tools stub: $PYTHON3_PATH${RESET}"
    echo "This Python cannot be used to create a working virtual environment."
    # Try Homebrew Python (Intel and Apple Silicon)
    if [ -x "/usr/local/bin/python3" ]; then
        PYTHON3_PATH="/usr/local/bin/python3"
        echo "${GREEN}Using Homebrew Python at $PYTHON3_PATH${RESET}"
    elif [ -x "/opt/homebrew/bin/python3" ]; then
        PYTHON3_PATH="/opt/homebrew/bin/python3"
        echo "${GREEN}Using Homebrew Python at $PYTHON3_PATH${RESET}"
    else
        echo "${YELLOW}Homebrew Python not found. Attempting to install Homebrew and Python...${RESET}"
        # Install Homebrew if not present
        if ! command -v brew >/dev/null 2>&1; then
            echo "${YELLOW}Homebrew is not installed. Installing Homebrew...${RESET}"
            NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            # Source Homebrew shellenv for current session
            if [ -f "/opt/homebrew/bin/brew" ]; then
                eval "$('/opt/homebrew/bin/brew' shellenv)"
            elif [ -f "/usr/local/bin/brew" ]; then
                eval "$('/usr/local/bin/brew' shellenv)"
            fi
        fi
        # Re-check for brew
        if ! command -v brew >/dev/null 2>&1; then
            echo "${RED}Homebrew installation failed or brew not found in PATH. Please install Homebrew manually and re-run this script.${RESET}"
            exit 1
        fi
        echo "${GREEN}Homebrew installed successfully.${RESET}"
        echo "${CYAN}Installing Python 3 with Homebrew...${RESET}"
        brew install python
        # Source Homebrew shellenv again in case Python was just added
        if [ -f "/opt/homebrew/bin/brew" ]; then
            eval "$('/opt/homebrew/bin/brew' shellenv)"
        elif [ -f "/usr/local/bin/brew" ]; then
            eval "$('/usr/local/bin/brew' shellenv)"
        fi
        # Try again
        if [ -x "/usr/local/bin/python3" ]; then
            PYTHON3_PATH="/usr/local/bin/python3"
        elif [ -x "/opt/homebrew/bin/python3" ]; then
            PYTHON3_PATH="/opt/homebrew/bin/python3"
        else
            echo "${RED}Failed to find a suitable Python 3 after Homebrew install. Please check your Homebrew installation and try again.${RESET}"
            exit 1
        fi
        echo "${GREEN}Using Homebrew Python at $PYTHON3_PATH${RESET}"
        echo "${GREEN}Re-running install script with correct Python...${RESET}"
        exec "$0" "$@"
    fi
fi

# Final check: refuse to proceed if still using Xcode CLT Python
if [ "$PYTHON3_PATH" = "/Library/Developer/CommandLineTools/usr/bin/python3" ]; then
    echo "${RED}No suitable Python 3 found. Please ensure Homebrew and Python 3 are installed and in your PATH, then re-run this script.${RESET}"
    exit 1
fi

# Check for architecture mismatch (Intel vs Apple Silicon)
PYTHON_ARCH=$("$PYTHON3_PATH" -c "import platform; print(platform.machine())" 2>/dev/null || echo unknown)
SYSTEM_ARCH=$(uname -m)
if [ "$PYTHON_ARCH" != "$SYSTEM_ARCH" ]; then
    echo "${YELLOW}[WARNING] Python architecture ($PYTHON_ARCH) does not match your system architecture ($SYSTEM_ARCH).${RESET}"
    echo "You may encounter 'bad CPU type in executable' errors."
    echo "Proceeding anyway, but if you see errors, ensure you are using the correct Python for your Mac."
fi

# Check for multiple venv directories and warn
VENV_COUNT=$(find . -type d -name venv | wc -l | tr -d ' ')
if [ "$VENV_COUNT" -gt 1 ]; then
    echo "${YELLOW}Warning: Multiple 'venv' directories found in your project. This can cause path issues. Please ensure only one venv exists at the project root.${RESET}"
    find . -type d -name venv
fi

echo "${CYAN}Setting up virtual environment...${RESET}"
# Create Python virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON3_PATH" -m venv "$VENV_DIR"
    echo "${GREEN}Virtual environment created at $VENV_DIR${RESET}"
else
    echo "${YELLOW}Virtual environment already exists at $VENV_DIR${RESET}"
fi

# Ensure pip is installed in the venv
echo "${CYAN}Ensuring pip is available in the virtual environment...${RESET}"
"$VENV_PY" -m ensurepip --upgrade

# Activate venv and install dependencies
echo "${CYAN}Installing Python dependencies...${RESET}"
source "$VENV_DIR/bin/activate"
"$VENV_PY" -m pip install --upgrade pip
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$VENV_PY" -m pip install -r "$INSTALL_DIR/requirements.txt"
    echo "${GREEN}Dependencies installed from requirements.txt${RESET}"
else
    echo "${YELLOW}No requirements.txt found. Skipping dependency install.${RESET}"
fi

deactivate

echo "${CYAN}Setting up macwatchdog executable...${RESET}"
LAUNCHER_PATH="${VENV_DIR}/bin/macwatchdog"
cat > "$LAUNCHER_PATH" <<'EOF'
#!/bin/bash
# Resolve the real path to this script, following all symlinks
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
  done
# Project root is always two levels up from venv/bin
DIR="$(cd -P "$(dirname "$SOURCE")/../.." && pwd)"
PYTHON="$DIR/venv/bin/python3"
MAIN="$DIR/main.py"
if [ ! -x "$PYTHON" ]; then
  echo "[ERROR] Python binary not found at $PYTHON" >&2
  exit 1
fi
if [ ! -f "$MAIN" ]; then
  echo "[ERROR] main.py not found at $MAIN" >&2
  exit 1
fi
exec "$PYTHON" "$MAIN" "$@"
EOF
chmod +x "$LAUNCHER_PATH"
echo "${GREEN}Executable created at $LAUNCHER_PATH${RESET}"

# Offer to symlink to /usr/local/bin for global access
if [ ! -d /usr/local/bin ]; then
    echo "${YELLOW}/usr/local/bin does not exist. Creating it with sudo...${RESET}"
    sudo mkdir -p /usr/local/bin
fi
if [ -w /usr/local/bin ]; then
    ln -sf "$LAUNCHER_PATH" /usr/local/bin/macwatchdog
    echo "${GREEN}Symlinked macwatchdog to /usr/local/bin/macwatchdog${RESET}"
    # Verify the symlink
    SYMLINK_TARGET=$(readlink /usr/local/bin/macwatchdog)
    echo "${CYAN}Symlink target: $SYMLINK_TARGET${RESET}"
    if [ "$SYMLINK_TARGET" != "$LAUNCHER_PATH" ]; then
        echo "${YELLOW}Warning: /usr/local/bin/macwatchdog does not point to the current venv/bin/macwatchdog!${RESET}"
        echo "It points to: $SYMLINK_TARGET"
        echo "If you moved or renamed your project directory, re-run the install script and re-create the symlink."
    fi
else
    echo "${YELLOW}To make macwatchdog available everywhere (including with sudo), run:${RESET}"
    echo "  sudo ln -sf '$LAUNCHER_PATH' /usr/local/bin/macwatchdog"
    echo "If you move or rename your project directory, re-run the install script and re-create the symlink."
fi

echo "${GREEN}Install complete. Run 'macwatchdog' to start the menu (with or without sudo).${RESET}" 