# anti-spy

A macOS command-line tool that detects spyware, keyloggers, and surveillance software. Runs 12 security scans and cross-correlates findings to surface threats that individual checks would miss.

## What it checks

| Scanner | What it does |
|---------|-------------|
| **Process** | Matches running processes against known spyware signatures, flags unsigned binaries |
| **Permission** | Audits TCC grants (Accessibility, Screen Recording, Input Monitoring), detects stale/suspicious permissions |
| **Persistence** | Scans LaunchAgents, LaunchDaemons, login items, legacy StartupItems, rc scripts |
| **Evidence** | Looks for stored screenshots, keystroke logs, and recording artifacts on disk |
| **Event Tap** | Detects active keyboard/mouse event taps (how keyloggers capture input) |
| **Device** | Checks for USB/Bluetooth monitoring hardware |
| **Kernel** | Lists kernel extensions and system extensions, flags non-Apple entries |
| **System Integrity** | Verifies SIP, Gatekeeper, XProtect health, Full Disk Access grants |
| **Network** | Analyzes active connections, suspicious ports, /etc/hosts tampering |
| **Profile** | Detects MDM enrollment and configuration profiles with surveillance payloads |
| **Browser** | Audits Chrome/Brave/Edge/Firefox/Safari extensions for dangerous permissions |
| **Deep Inspection** | Behavioral checks — dylib injection, root CA certificates, DNS hijacking, hidden files, DYLD environment abuse |

After all scanners run, the **Threat Correlator** cross-references findings to escalate patterns (e.g., unsigned process + persistence + network activity = HIGH threat).

## Install

Requires **macOS 13+** and **Swift 5.9+**.

```bash
git clone https://github.com/YOUR_USERNAME/anti-spy.git
cd anti-spy
swift build -c release
```

The binary will be at `.build/release/anti-spy`.

## Usage

```bash
# Full scan (recommended — run as root for complete results)
sudo .build/release/anti-spy

# Run a specific scanner
sudo .build/release/anti-spy --only deep

# JSON output (for piping to other tools)
sudo .build/release/anti-spy --json

# Verbose mode
sudo .build/release/anti-spy --verbose
```

### Available scanners

`process`, `permission`, `persistence`, `evidence`, `eventtap`, `device`, `kernel`, `integrity`, `network`, `profile`, `browser`, `deep`

## Understanding results

Findings are rated by severity:

- **HIGH** — strong indicator of spyware or system compromise. Investigate immediately.
- **MEDIUM** — suspicious but could be legitimate. Verify the software is expected.
- **LOW** — informational. Orphaned files, known security tools, minor anomalies.

## What it does NOT do

This is a health check, not an antivirus. Be aware of its limits:

- **No real-time protection** — it scans the current state, it doesn't block anything
- **No signature updates** — the spyware database is built-in and static
- **Won't catch state-level threats** — firmware implants, zero-day exploits, and kernel rootkits are beyond its scope
- **Not a replacement** for tools like [Objective-See](https://objective-see.org) (KnockKnock, LuLu, BlockBlock) or commercial endpoint security

Think of it as a quick second opinion on your Mac's security posture.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No HIGH findings |
| 1 | HIGH findings detected |
| 2 | Scan errors, no findings |

## License

MIT
