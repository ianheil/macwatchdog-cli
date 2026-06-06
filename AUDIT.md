# macWatchdog audit coverage

Every check macWatchdog runs, what it inspects, its blind spots, and required privileges.

Run `macwatchdog list-checks` for the numbered list that matches the CLI.

---

## Legend

| Status | Meaning |
|---|---|
| OK | Inspected and clean |
| INFO | Informational — nothing immediately concerning |
| LOW | Hardening suggestion |
| MEDIUM | Likely needs attention |
| HIGH | Strong signal, act soon |
| CRITICAL | Immediate action recommended |
| UNKNOWN | Could not inspect — usually missing privilege or tool |
| SKIPPED | Intentionally skipped — reason shown with tip |
| ERROR | Tool-level failure |

---

## Identity & Enrollment

### MDM & DEP Enrollment
- **Source:** `profiles status -type enrollment`
- Reports MDM management state and DEP enrollment.
- Requires root for reliable output; returns UNKNOWN without it.
- MEDIUM when MDM-enrolled (not inherently bad — just worth knowing).

### Remote Login (SSH)
- **Source:** `systemsetup -getremotelogin`
- MEDIUM when SSH is enabled.
- Requires root; returns UNKNOWN without it.

### Admin Users/Groups
- **Source:** `dscl . -read /Groups/admin GroupMembership`
- Lists all members of the local `admin` group.
- Escalates from INFO to ALERT when service accounts (`_foo`) or `Guest` appear.
- Blind spot: accounts with admin via sudo rules rather than group membership.

---

## Persistence

### Launch Agents/Daemons
- **Scans:** `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents`
- Flags: world-writable plist files, executables that fail `codesign --verify`, filenames containing red-flag keywords (backdoor, rat, keylog, etc.).
- **Blind spots:** signed-but-malicious agents (stolen/purchased developer cert), agents outside the three standard paths.

### Login Items
- **Sources:**
  - Classic items via AppleScript (`System Events`)
  - Background Items via `sfltool dumpbtm` / `btmutil dump` — **requires root** on Ventura+; skipped otherwise to avoid system auth prompts
- AppleScript calls use `osascript` argv to avoid injection.
- Classic items can be removed/restored via the management menu. Background items must be removed through System Settings or the owning app.

### Cron Jobs & Periodic Scripts
- **User crontab:** `crontab -l` for the current user
- **System crontabs:** `/private/var/at/tabs/` — requires root
- **Periodic scripts:** `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly` — flags non-standard scripts (anything not matching Apple's numeric prefix scheme)
- **At jobs:** `atq` for one-shot scheduled tasks
- MEDIUM for any active entries; crontab is a classic persistence mechanism.

### SSH Authorized Keys
- Scans `~/.ssh/authorized_keys`, `/var/root/.ssh/authorized_keys`, and all home directories under `/Users/`
- Requires root to read other users' SSH directories; checks current user without it.
- HIGH for any populated `authorized_keys` — each key grants passwordless SSH access.

---

## Privilege Escalation

### Sudoers Configuration
- **Sources:** `/etc/sudoers` and all files in `/etc/sudoers.d/`
- Parses for `NOPASSWD` entries that allow privilege escalation without a password.
- **Requires root** to read sudoers files; returns UNKNOWN without it.
- HIGH for any NOPASSWD entries.

---

## Privacy & Access Control

### TCC Privacy Permissions
- **Source:** SQLite queries against user and system `TCC.db`
- Reports which apps hold grants for: Screen Recording, Input Monitoring, Camera, Microphone, Location, Full Disk Access, Automation, Accessibility.
- Returns SKIPPED (with tip) when Full Disk Access has not been granted — avoids demanding FDA from the user's terminal. Grant FDA in System Settings > Privacy & Security to enable this check.
- Uses parameterised queries against read-only URI connections; no writes to TCC.db.

### Accessibility / Full Disk Access
- Focused subset of the TCC check: Accessibility and Full Disk Access grants only.
- Same SKIPPED behaviour when FDA is absent.
- Only trusted tools (security software, automation) should hold these grants.

### App Privacy Capabilities
- **Source:** `Contents/Info.plist` of every `.app` in `/Applications`, `/Applications/Utilities`, `~/Applications`, `/System/Applications`
- Reports which apps declare `NS*UsageDescription` keys — i.e., apps that are *built to request* Camera, Microphone, Location, Automation, Screen Recording, FDA, etc.
- Does **not** require Full Disk Access — this is the FDA-free alternative to the TCC checks above.
- Results are grouped by sensitivity tier: Critical (Screen Recording, Input Monitoring, FDA, Accessibility), Automation, Camera/Microphone, Location.
- Blind spot: what's been granted vs what the app can request are different things. Use the TCC check (with FDA) for live grant state.

### Configuration Profiles
- **Source:** `profiles -P -o stdout-xml` parsed via `plistlib`
- Reports identifier, display name, organisation, MDM flag, `PayloadRemovalDisallowed` (locked), and per-profile risk tags (root cert, VPN, certificate payload).
- Requires root to enumerate computer-level profiles.

---

## Network

### Network Listeners (Open Ports)
- **Source:** `lsof -i -n -P` filtered on LISTEN
- Reports process name, PID, and listening address/port.
- Use `macwatchdog close-port <port>` to gracefully shut down a listener: SIGTERM first, 3-second grace, then SIGKILL.

### Network Interfaces & Connections
- Interface list from `ifconfig`, ESTABLISHED connection count from `netstat -an`.
- Always INFO — a running Mac has many legitimate connections. Use `lsof -i -P -n` to investigate specific connections.

---

## Hardware

### USB Devices
- **Source:** `system_profiler SPUSBDataType`
- Lists external devices with name, vendor ID, product ID, and serial number.
- Built-in devices and devices with default (all-zero) serials are filtered.

### Kernel Extensions
- **Source:** `kextstat -l` (loaded kexts), `/Library/Extensions/` (installed kexts), `/Library/SystemExtensions/` (system extensions)
- Filters out all `com.apple.*` entries — third-party only.
- Kernel and system extensions run with elevated trust; any unexpected entry is worth investigating.
- `kextstat` is deprecated on Apple Silicon; on those machines only the `/Library/` directories are checked.

---

## System Hardening

### System Integrity Protection (SIP)
- **Source:** `csrutil status`
- HIGH when disabled.

### Gatekeeper
- **Source:** `spctl --status`
- MEDIUM when disabled.

### XProtect
- **Source:** `Contents/Info.plist` of the XProtect bundle
- Reports the current signature version. No severity — absence of the bundle is HIGH.

### Firewall & Stealth Mode
- **Source:** `/usr/libexec/ApplicationFirewall/socketfilterfw`
- Output parsing is anchored on the trailing `on`/`off` token to avoid false positives.
- MEDIUM for firewall disabled; LOW for stealth mode off.

### FileVault
- **Source:** `fdesetup status`
- HIGH when disabled.

### Automatic Software Updates
- Reads four `defaults` keys across user and system domains covering download, security patch install, macOS update, and app update settings.
- MEDIUM when download and security-patch install are both off — missing security patches is a real exposure.

### Remote Apple Events
- **Source:** `systemsetup -getremoteappleevents`
- MEDIUM when enabled — allows remote script execution.
- Requires root; returns UNKNOWN without it.

### Screen Sharing
- **Source:** `launchctl list | grep com.apple.screensharing`
- MEDIUM when the service is loaded.

### Guest Account
- **Source:** `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled`
- MEDIUM when enabled.

### Bluetooth
- **Source:** `system_profiler SPBluetoothDataType`
- INFO when on — most Macs legitimately use Bluetooth input devices.

### Firmware Password
- Apple Silicon: returns a LOW SUGGESTION explaining protection is provided by the Secure Enclave; firmware passwords don't apply.
- Intel: `firmwarepasswd -check`. LOW when not set.

---

## Filesystem

### World-writable / Suspicious Files
- Scans `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents`, `/etc`, `/usr/local/bin`, `/usr/local/sbin`
- Flags any file with the `other-writable` bit set (mode `0o002`).
- HIGH when found — world-writable files in these locations can be hijacked by any local process.

---

## Privacy notes

- macWatchdog makes no network requests and sends no telemetry.
- Runtime data lives under `$MACWATCHDOG_DATA_DIR` (default: `~/Library/Application Support/macwatchdog/`) and never in the source tree.
- The structured timeline (`timeline.jsonl`) records user-initiated actions (quarantine, remove, close) and their outcomes — not audit findings.
- Quarantine backups, snapshots, and the timeline are preserved on uninstall unless you explicitly choose to delete them.

---

## Known limitations

- **Signature verification** uses `codesign --verify --deep`; a signed-but-malicious launch agent with a legitimate developer certificate will not be flagged.
- **Profile contents** depend on `profiles` honouring your request — MDM-enforced profiles may conceal payload details.
- **Background items** (sfltool/btmutil) require root on Ventura+. Without root only classic login items are visible.
- **TCC live state** requires Full Disk Access on the terminal process. The App Privacy Capabilities check is the FDA-free alternative.
- **Cron on modern macOS** — Apple deprecated cron in favour of launchd. On Sequoia the cron daemon may be disabled entirely; `crontab` still exists but may do nothing.
