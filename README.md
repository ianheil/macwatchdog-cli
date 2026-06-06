# macWatchdog

Privacy-focused macOS security auditor. Scans your system for persistence mechanisms, privilege escalation paths, privacy exposure, network exposure, and hardening gaps — then gives you a 0–100 security score and direct remediation for what it finds.

[MIT License](./LICENSE) · Python 3.10+ · macOS Monterey – Sequoia · [Audit coverage](./AUDIT.md) · [Changelog](./CHANGELOG.md)

---

## What it checks

28 checks across 8 categories:

| Category | Checks |
|---|---|
| **Identity & Enrollment** | MDM/DEP enrollment, SSH remote login, local admin group |
| **Persistence** | Launch agents/daemons, login items, cron jobs, SSH authorized_keys |
| **Privilege Escalation** | Sudoers NOPASSWD entries |
| **Privacy & TCC** | TCC grants (camera, mic, screen recording, FDA), app privacy capabilities |
| **Network** | Open ports/listeners, network interfaces |
| **Hardware** | USB devices, kernel & system extensions |
| **System Hardening** | SIP, Gatekeeper, XProtect, firewall + stealth, FileVault, auto-updates, screen sharing, remote Apple Events, guest account, Bluetooth, firmware password |
| **Filesystem** | World-writable files in sensitive directories |

Some checks need root for complete results. Run `sudo macwatchdog scan` for a full audit.

---

## Highlights

- **Security score** — a 0–100 score after every scan. SECURE / GOOD / AT RISK / VULNERABLE / CRITICAL bands.
- **Inline format** — clean results like `[ OK ]  FileVault  —  encrypted`. Findings expand with detail bullets and actionable tips.
- **Safe remediation with backups** — quarantine unsigned launch agents, remove login items, close open ports (SIGTERM → SIGKILL). Every action creates a backup you can restore.
- **Forensics** — JSON snapshots of every check, diff between two snapshots, structured JSONL timeline of all actions taken.
- **Machine-readable** — `macwatchdog scan --format json` and `macwatchdog export report.json` for pipelines and SIEM ingestion.
- **Privacy-first** — no network requests, no telemetry. All data lives under `~/Library/Application Support/macwatchdog/`.

---

## macOS permission prompts

Some checks (TCC privacy, login items, MDM) access system services via AppleScript or read system databases. macOS will prompt for **Automation** or **Full Disk Access** the first time. Click **Allow** for the most complete results. If denied, those checks degrade to `SKIPPED` or `UNKNOWN` and the rest of the tool keeps working.

---

## Install

### One-liner (pipx — recommended)

```sh
pipx install git+https://github.com/ianheil/macwatchdog-cli.git
```

Requires [pipx](https://pipx.pypa.io). If you don't have it:

```sh
brew install pipx && pipx ensurepath
```

### Clone and install

```sh
git clone https://github.com/ianheil/macwatchdog-cli.git
cd macwatchdog-cli
./install.sh        # uses pipx if available, otherwise venv + symlink
```

### Uninstall

```sh
pipx uninstall macwatchdog
# or from the cloned directory:
./uninstall.sh
```

Uninstalling preserves `~/Library/Application Support/macwatchdog/` — your quarantine backups, snapshots, and timeline are kept unless you explicitly choose to delete them.

---

## Usage

### Interactive menu

```sh
macwatchdog            # standard user
sudo macwatchdog       # elevated — all checks available
```

The interactive menu opens on launch. Navigation:

| Section | Options |
|---|---|
| **SCAN** | Full audit, select checks |
| **MANAGE** | Launch agents/daemons, login items, open ports |
| **INVESTIGATE** | Keyword search, MDM/profiles, forensics & timeline |
| **SESSION** | Export report, help, quit |

After each scan the menu shows your last score and flags any findings with direct remediation links.

### CLI — non-interactive

```sh
macwatchdog scan                          # full audit, human output
macwatchdog scan --format json            # full audit, JSON output
macwatchdog status                        # quick score + top findings only
macwatchdog check --checks 1,3,5,17      # run a specific subset
macwatchdog list-checks                   # numbered list with descriptions
macwatchdog export report.txt             # run all checks, write text file
macwatchdog export report.json            # run all checks, write JSON file
macwatchdog --min-severity MEDIUM scan    # only show MEDIUM and above
macwatchdog --no-color scan               # disable colour output
macwatchdog timeline --limit 100          # view forensic event log
macwatchdog close-port 8080               # graceful shutdown (SIGTERM → SIGKILL)
macwatchdog backup-ports                  # snapshot current listeners to JSON
macwatchdog remove-login-item "App Name"  # remove a classic login item
```

**Environment variables:**

- `MACWATCHDOG_DATA_DIR` — override the default data directory
- `NO_COLOR` / `MACWATCHDOG_NO_COLOR=1` — disable colour output

### Severity tiers

| Badge | Level | Meaning |
|---|---|---|
| `[ OK ]` | OK | Checked and clean |
| `[ INFO ]` | INFO | Informational — review at your leisure |
| `[ LOW ]` | LOW | Hardening suggestion |
| `[ MED ]` | MEDIUM | Likely needs attention |
| `[ HIGH ]` | HIGH | Act soon |
| `[ CRIT ]` | CRITICAL | Immediate action recommended |
| `[ ERR ]` | ERROR | Tool-level failure |

Use `--min-severity MEDIUM` to filter to actionable findings only.

---

## Requirements

- Python 3.10+
- macOS Monterey (12), Ventura (13), Sonoma (14), or Sequoia (15)
- Some checks require `sudo` — see `macwatchdog list-checks` for which ones

---

## Development

```sh
git clone https://github.com/ianheil/macwatchdog-cli.git
cd macwatchdog-cli
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest
```

See [AUDIT.md](./AUDIT.md) for the full check catalogue — what each check inspects, its blind spots, and required privileges.

---

## License

MIT — see [LICENSE](./LICENSE).
