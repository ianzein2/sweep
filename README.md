# sweep

A macOS security scanner that detects spyware, keyloggers, and surveillance software. Available as a CLI tool and a native macOS app. Runs 14 security scans in parallel, scores your Mac's security posture, and can auto-fix common issues.

## Download

Grab the latest `.dmg` from [**Releases**](https://github.com/ianzein2/sweep/releases), open it, and drag **Sweep.app** to your Applications folder. No terminal required.

> **First launch:** macOS will warn the app is from an "unidentified developer" since it's not notarized. Right-click the app and select **Open**, then click **Open** in the dialog to bypass the warning. You only need to do this once.

## Build from source

Requires **macOS 13+** and **Swift 5.9+**.

```bash
git clone https://github.com/ianzein2/sweep.git
cd sweep
```

### macOS app

```bash
make app                    # builds to build/Sweep.app
sudo make install-app       # copies to /Applications
make dmg                    # creates build/Sweep.dmg for distribution
```

Double-click **Sweep.app** to launch. Click **Scan** for a user-level scan, or **Scan as Admin** for a full scan with the native macOS password prompt.

### Command-line

```bash
make build                  # builds CLI binary
sudo make install           # installs to /usr/local/bin
```

## Usage (CLI)

```bash
# Full scan (run as root for complete results)
sudo sweep

# Run a specific scanner
sudo sweep --only hardening

# Verbose output (show per-scanner details)
sudo sweep --verbose

# Auto-fix safe issues (enable firewall, remove orphaned plists, etc.)
sudo sweep --fix

# Preview what --fix would do without changing anything
sudo sweep --dry-run

# Save a baseline for future comparison
sudo sweep --save-baseline

# Compare current scan against saved baseline
sudo sweep --diff

# JSON output (for piping to other tools)
sudo sweep --json
```

### Available scanners

`process`, `permission`, `persistence`, `evidence`, `eventtap`, `device`, `kernel`, `integrity`, `network`, `profile`, `browser`, `deep`, `hardening`, `supplychain`

## What it checks

| Scanner | What it does |
|---------|-------------|
| **Process** | Matches running processes against known spyware signatures, flags unsigned binaries, enumerates loaded dylibs for injection, detects orphan processes, flags cryptominers (xmrig, ethminer, etc.) |
| **Permission** | Audits TCC grants (Accessibility, Screen Recording, Input Monitoring), detects stale/suspicious permissions |
| **Persistence** | Scans LaunchAgents, LaunchDaemons, login items, StartupItems, rc scripts, shell configs, cron jobs, login/logout hooks, periodic scripts, Folder Actions, Automator workflows |
| **Evidence** | Looks for stored screenshots, keystroke logs, and recording artifacts on disk; detects ClickFix-style quarantine-stripped downloads in ~/Downloads |
| **Event Tap** | Detects active keyboard/mouse event taps (how keyloggers capture input) |
| **Device** | Checks for USB/Bluetooth monitoring hardware |
| **Kernel** | Lists kernel extensions and system extensions, flags non-Apple entries |
| **System Integrity** | Verifies SIP, Gatekeeper, XProtect health, Full Disk Access grants |
| **Network** | Analyzes active connections, suspicious ports, /etc/hosts tampering |
| **Profile** | Detects MDM enrollment and configuration profiles with surveillance payloads |
| **Browser** | Audits Chrome/Brave/Edge/Firefox/Safari extensions for dangerous permissions |
| **Deep Inspection** | Behavioral checks — root CA certificates, DNS hijacking, hidden files, ownership anomalies, DYLD environment abuse |
| **Hardening** | CIS benchmark checks — firewall, FileVault, auto-login, screen lock, SSH, sharing services, software updates, Apple Silicon boot security (bputil), iCloud Private Relay, web content filter profiles |
| **Supply Chain** | Developer-environment attacks — malicious npm packages, non-standard package indexes, weaponized git hooks (`core.hooksPath`), compromised Homebrew taps, SSH `ProxyCommand` droppers, DPRK ContagiousInterview (BeaverTail/InvisibleFerret) IOCs |

After all scanners run, the **Threat Correlator** cross-references findings to escalate patterns (e.g., unsigned process + persistence + network activity = HIGH threat).

## Security score

Every scan produces a score from 0-100 (grade A-F). HIGH findings deduct 15 points, MEDIUM deducts 5, LOW deducts 1. The score gives you a quick read on your Mac's overall security posture.

## Baseline & diff

Save a scan as a baseline, then compare future scans against it to see what changed:

```bash
sudo sweep --save-baseline    # saves to ~/.sweep/baseline.json
# ... time passes ...
sudo sweep --diff              # shows new, resolved, and unchanged findings
```

## Understanding results

Findings are rated by severity:

- **HIGH** — strong indicator of spyware or system compromise. Investigate immediately.
- **MEDIUM** — suspicious but could be legitimate. Verify the software is expected.
- **LOW** — informational. Orphaned files, known security tools, minor anomalies.

## Troubleshooting

**Scan hangs or takes too long** — Some scanners (particularly Process) inspect every running process, which can be slow on busy systems. The app has a 60-second timeout and will show partial results if a scanner hangs.

**"Scan as Admin" shows a password prompt** — This is macOS asking you to authorize elevated scanning. Entering your password lets sweep inspect protected system areas (TCC database, kernel extensions, etc.) that aren't readable as a regular user.

**Results differ between user and admin scans** — Expected. Many system files are only readable as root. Run `sudo sweep` or use **Scan as Admin** in the app for the most complete results.

## Scope

sweep is a point-in-time security audit — it tells you what's wrong *right now*, not a resident antivirus.

- **Snapshot, not shield** — scans current state but doesn't block or monitor in real-time
- **Built-in signatures** — the spyware database ships with the binary, no update feed
- **Complements, not replaces** — pairs well with real-time tools like [LuLu](https://objective-see.org/products/lulu.html) (firewall) and [BlockBlock](https://objective-see.org/products/blockblock.html) (persistence monitor)

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No HIGH findings |
| 1 | HIGH findings detected |
| 2 | Scan errors, no findings |

## License

MIT
