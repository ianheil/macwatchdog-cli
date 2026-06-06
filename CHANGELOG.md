# Changelog

## 2.2.0 — 2026-06-05

### New checks

- **Quarantine Attributes** — scans `~/Downloads` for installer and script files missing the `com.apple.quarantine` xattr. HIGH when found — its absence on an installer is a known Gatekeeper bypass technique.
- **Network Listeners: exposed vs localhost** — distinguishes listeners bound to all interfaces (`0.0.0.0`, `*`, `::`) from localhost-only. Exposed listeners flagged at MEDIUM.
- **Kernel Extensions enriched** — each kext now shows load state (loaded / not loaded), codesign validity, and Apple Silicon inert flag. Management menu added (quarantine/restore from `/Library/Extensions/`).

### Scoring

- Hard severity ceilings: any HIGH finding caps score at AT RISK (65); any CRITICAL caps at VULNERABLE (35). Prevents "mostly clean but FileVault is off" from scoring GOOD.
- MEDIUM weight raised from 8 → 10.
- ERROR weight reduced to 1 (tool failure ≠ security risk).
- Ceiling reason surfaced in the summary line when triggered.

### Bug fixes

- **Auto-updates check rewritten for macOS 26 Tahoe**: reads `SplatEnabled` (security responses), `AutomaticDownload`, and `AutoInstallProductKeys` (macOS auto-install). Shows `Unknown` rather than `Disabled` for keys absent on newer macOS versions. Only fires ALERT when a critical setting is confirmed off.
- **Firmware Password on Apple Silicon** returns `[ OK ]` with a Secure Enclave note instead of a LOW/SUGGESTION — there's no action to take.
- **App updates** removed from the auto-updates check — it lives in App Store preferences, not Software Update, and was showing a false "Disabled" on macOS 26.
- **`.app` bundles now included in quarantine scan** — `stat().st_size` on a directory returns the inode size (~96 bytes), not bundle contents. Fixed to use `is_dir()` for bundles.
- **authorized_keys unreadable files** now surface as UNKNOWN rather than silently returning empty (which hid root's keys when running as a standard user).
- **sudoers** now catches `OSError` in addition to `PermissionError` so an I/O error mid-read doesn't abort the remaining file loop silently.
- **kexts restore path traversal** fixed: `original_path` from the `.meta` sidecar is now validated to `/Library/Extensions/` before a root-privileged `shutil.move()`.
- **IPv4-mapped all-interface addresses** (`[::ffff:0.0.0.0]`) now correctly classified as exposed rather than localhost-only.

---

## 2.1.0 — 2026-06-03

### New checks

- **Cron Jobs & Periodic Scripts** — scans user crontab, `/etc/periodic/` scripts, system crontab files (root), and at-job queue. MEDIUM for any active entries.
- **SSH Authorized Keys** — checks `~/.ssh/authorized_keys`, `/var/root/.ssh/authorized_keys`, and all user home directories. HIGH for any populated file.
- **Sudoers Configuration** — parses `/etc/sudoers` and `/etc/sudoers.d/` for `NOPASSWD` entries. HIGH when found; requires root.
- **Kernel Extensions** — inventories loaded kexts (`kextstat`), `/Library/Extensions/`, and `/Library/SystemExtensions/`, filtered to third-party only. Deduplicates system extension entries.

### New commands

- **`macwatchdog scan`** — full audit shorthand; equivalent to `check --all` with the logo/system-info header.
- **`macwatchdog status`** — quick security posture: score, band, and top findings at MEDIUM or above only. No full report output.
- **`macwatchdog list-checks`** — now shows descriptions and root-required markers (`*`) for each check.

### Security score

- Post-audit summary now shows a **0–100 security score** with a severity-weighted deduction model.
- Score bands: SECURE (90+), GOOD (75+), AT RISK (50+), VULNERABLE (25+), CRITICAL (<25).
- Score visible in the interactive menu header between sessions.

### UI overhaul

- **System info splash** — shows HOST, OS, USER, TIME, and privilege level on launch. When running as standard user, shows how many checks require root.
- **Severity badges** — `[ OK ]`, `[MED ]`, `[CRIT]`, etc. replace plain status text.
- **Rule-based category headers** — full-width dividers with centred title replace manual `==` lines.
- **Inline brief info** — short OK/INFO values (e.g. `— enabled`, `— none found`, `— encrypted`) render on the same line as the badge. Lists and longer details expand below as bullets.
- **Status text suppressed for OK/INFO** — the badge already communicates the level; status text is shown only for ALERT, UNKNOWN, ERROR, SKIPPED, SUGGESTION.
- **Tips use `→` prefix** and appear only for LOW and above (not on informational results).
- **Progress bar** — styled `[ SCANNING ]` prefix with green fill.
- **Post-audit summary** — finding counts by severity plus score and elapsed time.
- **Post-scan remediation hints** — after a scan the menu surfaces any MEDIUM+ findings that have direct remediation (agents, login items, ports) with the menu shortcut.

### Bug fixes

- **`restore_agents` path reconstruction** was guessing the original path from the quarantine filename, incorrectly restoring `~/Library/LaunchAgents` items to `/Library/LaunchAgents`. Fixed: quarantine now writes a `.meta` sidecar with the original path; restore reads it.
- **MDM check** was showing raw `sudo: a password is required` stderr as info on an OK result. Fixed: sudo failure now returns UNKNOWN cleanly.
- **Remote Login (SSH) and Remote Apple Events** were echoing `You need administrator access to run this tool... exiting!` as info on OK results. Fixed: admin-error text detected and converted to UNKNOWN.
- **`sfltool dumpbtm`** triggered an admin password popup on every scan for standard users. Fixed: background items check now skips sfltool/btmutil when not running as root.
- **Login item display** was silently swallowing `[classic]`/`[background]` source tags — Rich was treating them as markup. Fixed: tags removed from the display string; format is now `Name  —  /path/to.app`.
- **Network listener process names** with `\x20` escape sequences (Adobe) now decoded to spaces.
- **Kernel extension parser** was reading the `<linked against>` ref column (`3>`, `5>`) instead of bundle IDs. Fixed: regex anchored to the bundle ID before the version `(x.y)`.
- **Duplicate system extensions** (LuLu appearing twice) now deduplicated.
- **Circular import** between `scoring.py` and `runner.py` resolved by inlining the flatten logic in `scoring.py`.

### Architecture

- `RegisteredCheck` gains `description`, `requires_root`, and `slow` metadata fields used throughout the UI and CLI.
- New checks' imports moved to top of `audit/__init__.py` with all other imports.
- Menu restructured into labelled sections: SCAN / MANAGE / INVESTIGATE / SESSION.
- `render_report` handles SKIPPED as a special compact case (tip as one-liner, no bullets).
- `_print_info` switched from `[sev.info]` cyan to `[dim]` for info bullets — reduces visual noise on purely informational results.
- Automatic Software Updates severity raised from LOW to MEDIUM — disabled security patches is a real exposure.

---

## 2.0.1 — 2026-04-23

### Added

- **`App Privacy Capabilities` check** — scans every installed `.app`'s `Info.plist` for `NS*UsageDescription` keys. FDA-free alternative to the TCC.db checks.

### Changed

- TCC.db checks return `SKIPPED` (INFO) when Full Disk Access is not granted, pointing at `App Privacy Capabilities` instead of demanding FDA from the terminal.
- Interactive action menus no longer collide with numbered item lists — action keys are single letters with a clear visual break.

---

## 2.0.0 — 2026-04-23

Ground-up rewrite addressing correctness and security issues in 1.1.0.

### Security

- AppleScript injection in login-item add/remove fixed — item names/paths now pass through `osascript` argv instead of string interpolation.
- `is_world_writable` no longer uses `os.access` (effective-UID based; misreported files).
- `restore_port_state` removed — previous behaviour launched substitute processes from backup data.
- `close_port` now sends SIGTERM before escalating to SIGKILL.
- TCC queries use parameterised `sqlite3` statements against read-only URI connections.

### Correctness

- Firewall stealth mode parsing anchored on trailing `on`/`off`.
- Network check reports INFO not ALERT for connections.
- Admin users check only escalates for service accounts or Guest.
- Profiles parsed via `plistlib` instead of brittle colon-split.
- Bluetooth reported as INFO with context; not flagged for every Bluetooth keyboard user.
- Firmware password check detects Apple Silicon and explains Secure Enclave.
- Login items now includes `sfltool`/`btmutil` Background Items in addition to classic items.

### UX and packaging

- Rich-based output with themed severity, `NO_COLOR` support, `--min-severity` filtering.
- Runtime data moved to `~/Library/Application Support/macwatchdog`.
- Structured JSONL timeline replaces free-form text log.
- New CLI: `list-checks`, `timeline`, `export`, `backup-ports`, `close-port`, `remove-login-item`, `check --format json`.
- `pipx`-based installer with `console_scripts` entry point.
