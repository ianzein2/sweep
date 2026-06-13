import Foundation

/// Checks macOS security hardening settings against CIS benchmark recommendations.
public final class HardeningScanner: Scanner {
    public let name = "Hardening Check"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking firewall")
        checkFirewall(findings: &findings, errors: &errors)

        progress?.update("checking FileVault")
        checkFileVault(findings: &findings, errors: &errors)

        progress?.update("checking auto-login")
        checkAutoLogin(findings: &findings, errors: &errors)

        progress?.update("checking screen lock")
        checkScreenLock(findings: &findings, errors: &errors)

        progress?.update("checking remote access")
        checkRemoteAccess(findings: &findings, errors: &errors)

        progress?.update("checking sharing services")
        checkSharingServices(findings: &findings, errors: &errors)

        progress?.update("checking software updates")
        checkSoftwareUpdates(findings: &findings, errors: &errors)

        progress?.update("checking guest account")
        checkGuestAccount(findings: &findings, errors: &errors)

        progress?.update("checking AirDrop")
        checkAirDrop(findings: &findings, errors: &errors)

        progress?.update("checking password hints")
        checkPasswordHints(findings: &findings, errors: &errors)

        progress?.update("checking password-after-sleep")
        checkPasswordAfterSleep(findings: &findings, errors: &errors)

        progress?.update("checking Internet Sharing")
        checkInternetSharing(findings: &findings, errors: &errors)

        progress?.update("checking printer / media / content sharing")
        checkExtraSharingServices(findings: &findings, errors: &errors)

        progress?.update("checking Lockdown Mode")
        checkLockdownMode(findings: &findings, errors: &errors)

        progress?.update("checking Rapid Security Response")
        checkRapidSecurityResponse(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking Wi-Fi auto-join")
        checkWiFiAutoJoin(findings: &findings, errors: &errors)

        progress?.update("checking verbose boot / boot-args")
        checkBootArgs(findings: &findings, errors: &errors)

        progress?.update("checking hot corners")
        checkHotCorners(findings: &findings, errors: &errors)

        progress?.update("checking Bluetooth state")
        checkBluetoothDiscoverable(findings: &findings, errors: &errors)

        progress?.update("checking encrypted DNS")
        checkEncryptedDNS(findings: &findings, errors: &errors)

        progress?.update("checking sudo configuration")
        checkSudoTimeout(findings: &findings, errors: &errors)

        progress?.update("checking signed system volume")
        checkSignedSystemVolume(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Firewall

    private func checkFirewall(findings: inout [Finding], errors: inout [String]) {
        // Check firewall state
        let result = ShellRunner.run("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                     arguments: ["--getglobalstate"], timeout: 5)
        if result.success {
            if result.stdout.lowercased().contains("disabled") {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "macOS firewall is disabled",
                    detail: "The built-in application firewall is not running",
                    path: nil,
                    remediation: "Enable: System Settings > Network > Firewall, or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
                ))
            }
        }

        // Check stealth mode
        let stealth = ShellRunner.run("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                      arguments: ["--getstealthmode"], timeout: 5)
        if stealth.success {
            if stealth.stdout.lowercased().contains("disabled") {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Firewall stealth mode is disabled",
                    detail: "Mac responds to ICMP probes and port scans, making it discoverable on the network",
                    path: nil,
                    remediation: "Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
                ))
            }
        }
    }

    // MARK: - FileVault

    private func checkFileVault(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/fdesetup", arguments: ["status"], timeout: 5)
        if result.success {
            if result.stdout.contains("FileVault is Off") {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "FileVault disk encryption is disabled",
                    detail: "Disk is not encrypted — data is accessible if Mac is stolen or physically accessed",
                    path: nil,
                    remediation: "Enable: System Settings > Privacy & Security > FileVault"
                ))
            }
        }
    }

    // MARK: - Auto-Login

    private func checkAutoLogin(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"
        ], timeout: 5)
        // If the key exists (exit 0), auto-login is enabled
        if result.success && !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let user = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Auto-login is enabled",
                detail: "User '\(user)' logs in automatically — anyone with physical access has full access",
                path: nil,
                remediation: "Disable: System Settings > Users & Groups > Automatic login: Off"
            ))
        }
    }

    // MARK: - Screen Lock

    private func checkScreenLock(findings: inout [Finding], errors: inout [String]) {
        // Check screen saver idle time
        let idleResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "-currentHost", "read", "com.apple.screensaver", "idleTime"
        ], timeout: 5)
        if idleResult.success {
            if let idleTime = Int(idleResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) {
                if idleTime == 0 {
                    findings.append(Finding(
                        severity: .medium, category: .hardening,
                        title: "Screen saver is disabled",
                        detail: "Screen saver never activates — screen stays unlocked indefinitely when idle",
                        path: nil,
                        remediation: "Set: System Settings > Lock Screen > Start Screen Saver when inactive"
                    ))
                } else if idleTime > 600 {
                    findings.append(Finding(
                        severity: .low, category: .hardening,
                        title: "Screen saver timeout is long (\(idleTime / 60) minutes)",
                        detail: "Screen locks after \(idleTime / 60) minutes of inactivity",
                        path: nil,
                        remediation: "Consider reducing to 5 minutes: System Settings > Lock Screen"
                    ))
                }
            }
        }
    }

    // MARK: - Remote Access

    private func checkRemoteAccess(findings: inout [Finding], errors: inout [String]) {
        // Check Remote Login (SSH)
        let sshResult = ShellRunner.run("/usr/sbin/systemsetup",
                                        arguments: ["-getremotelogin"], timeout: 5)
        if sshResult.success && sshResult.stdout.lowercased().contains(": on") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Remote Login (SSH) is enabled",
                detail: "SSH access is open — attackers can attempt brute-force login",
                path: nil,
                remediation: "Disable if not needed: System Settings > General > Sharing > Remote Login"
            ))
        }

        // Check Remote Management (ARD)
        let ardResult = ShellRunner.run("/bin/ps", arguments: ["-ax", "-o", "comm"], timeout: 5)
        if ardResult.success && ardResult.stdout.contains("ARDAgent") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Remote Management (ARD) is enabled",
                detail: "Apple Remote Desktop agent is running — allows remote control of this Mac",
                path: nil,
                remediation: "Disable if not needed: System Settings > General > Sharing > Remote Management"
            ))
        }
    }

    // MARK: - Sharing Services

    private func checkSharingServices(findings: inout [Finding], errors: inout [String]) {
        let services: [(label: String, name: String)] = [
            ("com.apple.smbd", "File Sharing (SMB)"),
            ("com.apple.screensharing", "Screen Sharing"),
        ]

        for service in services {
            let result = ShellRunner.run("/bin/launchctl", arguments: ["list"], timeout: 5)
            if result.success && result.stdout.contains(service.label) {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "\(service.name) is enabled",
                    detail: "Sharing service is active and accepting connections",
                    path: nil,
                    remediation: "Disable if not needed: System Settings > General > Sharing"
                ))
            }
        }
    }

    // MARK: - Software Updates

    private func checkSoftwareUpdates(findings: inout [Finding], errors: inout [String]) {
        let autoCheck = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"
        ], timeout: 5)
        if autoCheck.success {
            let value = autoCheck.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Automatic software update checks are disabled",
                    detail: "Mac won't check for security updates automatically",
                    path: nil,
                    remediation: "Enable: System Settings > General > Software Update > Automatic Updates"
                ))
            }
        }

        let autoDownload = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"
        ], timeout: 5)
        if autoDownload.success {
            let value = autoDownload.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Automatic software update download is disabled",
                    detail: "Updates are checked but not downloaded automatically",
                    path: nil,
                    remediation: "Enable: System Settings > General > Software Update > Download new updates when available"
                ))
            }
        }
    }

    // MARK: - Guest Account

    private func checkGuestAccount(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Guest account is enabled",
                    detail: "Anyone can use this Mac without a password via the guest account",
                    path: nil,
                    remediation: "Disable: System Settings > Users & Groups > Guest User"
                ))
            }
        }
    }

    // MARK: - AirDrop

    private func checkAirDrop(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.sharingd", "DiscoverableMode"
        ], timeout: 5)
        if result.success {
            let mode = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if mode == "Everyone" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "AirDrop is set to 'Everyone'",
                    detail: "Anyone nearby can send files to this Mac via AirDrop",
                    path: nil,
                    remediation: "Change to 'Contacts Only': System Settings > General > AirDrop & Handoff"
                ))
            }
        }
    }

    // MARK: - Password Hints

    private func checkPasswordHints(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if let retries = Int(value), retries > 0 {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Password hints are shown at login",
                    detail: "After \(retries) failed attempt(s), login screen shows password hint",
                    path: nil,
                    remediation: "Disable: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0"
                ))
            }
        }
    }

    // MARK: - Password Required After Sleep / Screensaver

    private func checkPasswordAfterSleep(findings: inout [Finding], errors: inout [String]) {
        // The askForPassword and askForPasswordDelay settings control whether a password
        // is required when the Mac wakes from sleep or screensaver — a critical lock-screen control.
        let askResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.screensaver", "askForPassword"
        ], timeout: 5)

        if askResult.success {
            let value = askResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "No password required after sleep or screen saver",
                    detail: "Anyone who wakes the Mac can access your session without a password",
                    path: nil,
                    remediation: "Enable: System Settings > Lock Screen > Require password after screen saver begins"
                ))
                return
            }
        }

        // Delay: 0 = immediate; values above 60s are risky. Touch ID/Apple Watch users may keep this short intentionally.
        let delayResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.screensaver", "askForPasswordDelay"
        ], timeout: 5)
        if delayResult.success,
           let seconds = Int(delayResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)),
           seconds > 60 {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Password grace period after sleep is long (\(seconds)s)",
                detail: "Mac waits \(seconds) seconds after sleep/screensaver before requiring a password",
                path: nil,
                remediation: "Reduce to Immediately or 5 seconds: System Settings > Lock Screen"
            ))
        }
    }

    // MARK: - Internet Sharing

    private func checkInternetSharing(findings: inout [Finding], errors: inout [String]) {
        // Internet Sharing turns the Mac into a router/hotspot — a high-risk sharing service.
        // Driven by /Library/Preferences/SystemConfiguration/com.apple.nat.plist
        let natPlist = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
        guard let data = FileManager.default.contents(atPath: natPlist),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let nat = plist["NAT"] as? [String: Any] else { return }

        let enabled = (nat["Enabled"] as? Int ?? 0) == 1 ||
                      (nat["Enabled"] as? Bool ?? false)
        if enabled {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Internet Sharing is enabled",
                detail: "Mac is sharing its internet connection — other devices can route through this machine",
                path: natPlist,
                remediation: "Disable: System Settings > General > Sharing > Internet Sharing"
            ))
        }
    }

    // MARK: - Additional Sharing Services

    private func checkExtraSharingServices(findings: inout [Finding], errors: inout [String]) {
        // Listing launchctl once and reusing the output is faster than repeated spawns.
        let launchctl = ShellRunner.run("/bin/launchctl", arguments: ["list"], timeout: 5)
        let launchList = launchctl.success ? launchctl.stdout : ""

        let extras: [(label: String, name: String, detail: String, severity: Severity)] = [
            ("com.apple.AssetCacheLocatorService",
             "Content Caching",
             "Content Caching shares Apple software updates/iCloud data to LAN devices",
             .medium),
            ("com.apple.amp.mediasharingd",
             "Media Sharing",
             "Music/Photos libraries are being shared with nearby devices or Home Sharing",
             .low),
            ("com.apple.printtool.daemon",
             "Printer Sharing",
             "Printer Sharing is active — printers attached to this Mac are network-accessible",
             .medium),
            ("org.cups.cupsd",
             "CUPS print service",
             "CUPS is running — printer sharing may be exposed on the network",
             .low),
        ]

        for service in extras where launchList.contains(service.label) {
            findings.append(Finding(
                severity: service.severity, category: .hardening,
                title: "\(service.name) is active",
                detail: service.detail,
                path: nil,
                remediation: "Disable if not needed: System Settings > General > Sharing"
            ))
        }

        // Bluetooth Sharing is controlled by a preference, not launchd service name
        let btShareResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.Bluetooth", "PANServices"
        ], timeout: 5)
        if btShareResult.success &&
           btShareResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Bluetooth Sharing (PAN) is enabled",
                detail: "Personal Area Network via Bluetooth is active — nearby devices may route through this Mac",
                path: nil,
                remediation: "Disable: System Settings > General > Sharing > Bluetooth Sharing"
            ))
        }
    }

    // MARK: - Lockdown Mode

    private func checkLockdownMode(findings: inout [Finding], errors: inout [String]) {
        // Lockdown Mode is an opt-in hardening feature for users at high risk of targeted
        // attacks (journalists, activists, executives). We don't penalize its absence — most users
        // don't need it — but we surface its state as informational.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.security.LockdownMode", "LDMGlobalEnabled"
        ], timeout: 5)

        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Lockdown Mode is enabled",
                    detail: "Lockdown Mode restricts many features to defend against targeted attacks — expect some apps and websites to work differently",
                    path: nil,
                    remediation: "No action needed. Disable only if you no longer need maximum protection."
                ))
            }
        }
    }

    // MARK: - Rapid Security Response

    private func checkRapidSecurityResponse(findings: inout [Finding], errors: inout [String]) {
        // macOS Ventura+ supports Rapid Security Responses (RSRs) — out-of-band patches for
        // actively exploited bugs. If automatic install is disabled, the Mac may miss emergency fixes.
        let rsrInstall = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"
        ], timeout: 5)
        if rsrInstall.success {
            let value = rsrInstall.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Automatic install of security responses is disabled",
                    detail: "Rapid Security Responses (RSRs) patch actively exploited bugs — leaving this off delays urgent fixes",
                    path: nil,
                    remediation: "Enable: System Settings > General > Software Update > (i) > Install Security Responses and system files"
                ))
            }
        }
    }

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac is the macOS counterpart to Activation Lock — it enables remote lock/wipe
        // if the Mac is stolen. Its absence is one of the most-overlooked theft-protection gaps.
        let result = ShellRunner.run("/usr/sbin/nvram", arguments: ["-x", "fmm-mobileme-token-FMM"], timeout: 5)
        // Exit 0 + non-empty payload = enabled. Otherwise nvram errors with "Error getting variable".
        let combined = (result.stdout + result.stderr).lowercased()
        let isEnabled = result.success && !result.stdout.isEmpty &&
            !combined.contains("error getting variable")
        if !isEnabled {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is not enabled",
                detail: "If this Mac is lost or stolen you cannot remotely lock, locate, or wipe it",
                path: nil,
                remediation: "Enable: System Settings > [Your Name] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Wi-Fi Auto-Join

    private func checkWiFiAutoJoin(findings: inout [Finding], errors: inout [String]) {
        // "Ask to join networks" — when set to "Off" the Mac will silently join any open
        // network with a remembered SSID, which is a classic Wi-Fi pineapple / KARMA vector.
        let services = ShellRunner.run("/usr/sbin/networksetup",
                                       arguments: ["-listallhardwareports"], timeout: 5)
        guard services.success else { return }

        // Find the Wi-Fi adapter (usually en0 on M-series, en1 on Intel)
        var wifiInterface: String?
        let lines = services.stdout.split(separator: "\n").map(String.init)
        for (i, line) in lines.enumerated() {
            if line.contains("Wi-Fi") || line.contains("AirPort") {
                // Next "Device: enX" line is the interface
                for j in (i + 1)..<min(i + 4, lines.count) {
                    if let r = lines[j].range(of: "Device: ") {
                        wifiInterface = String(lines[j][r.upperBound...])
                            .trimmingCharacters(in: .whitespaces)
                        break
                    }
                }
                break
            }
        }

        guard let iface = wifiInterface else { return }

        // -getnetworkserviceenabled / airport are deprecated; use defaults to read the pref
        let prefPath = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
        guard let data = FileManager.default.contents(atPath: prefPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return
        }

        if let joinMode = plist["JoinMode"] as? String, joinMode == "Automatic" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Wi-Fi auto-join is set to 'Automatic'",
                detail: "Interface \(iface) silently joins any known network — enables rogue-AP / Wi-Fi pineapple impersonation",
                path: prefPath,
                remediation: "Set: System Settings > Wi-Fi > Ask to join networks → 'Ask' or 'Notify'"
            ))
        }
    }

    // MARK: - Boot Args

    private func checkBootArgs(findings: inout [Finding], errors: inout [String]) {
        // Custom boot-args (verbose, single-user, debug, -no_compat_check) often reveal
        // tampering or weaken kernel hardening (e.g., disabling kext signature enforcement).
        let result = ShellRunner.run("/usr/sbin/nvram", arguments: ["boot-args"], timeout: 5)
        // Default state: nvram returns non-zero with "Error getting variable"
        guard result.success else { return }

        let args = result.stdout
            .replacingOccurrences(of: "boot-args", with: "")
            .replacingOccurrences(of: "\t", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        if args.isEmpty { return }

        let dangerous: [(needle: String, why: String)] = [
            ("-v",                  "verbose boot — exposes startup output, often left on after recovery exploits"),
            ("-s",                  "single-user mode — boots straight to a root shell"),
            ("-x",                  "safe mode persistence — kexts and login items skipped on every boot"),
            ("debug=",              "kernel debugger enabled — allows live kernel modification"),
            ("kcsuffix=development", "development kernel selected — extra debug surface, less hardened"),
            ("amfi_get_out_of_my_way", "AMFI (code-signing enforcement) disabled — unsigned binaries can run"),
            ("amfi=",               "AMFI flags overridden — reduces code-signing enforcement"),
            ("rootless=0",          "SIP disabled at the kernel level — full root tampering allowed"),
            ("kext-dev-mode",       "kext signature checks disabled — unsigned kernel extensions allowed"),
        ]

        for entry in dangerous where args.lowercased().contains(entry.needle.lowercased()) {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Custom kernel boot-args weaken hardening",
                detail: "boot-args contains \"\(entry.needle)\" — \(entry.why). Full: \(args)",
                path: nil,
                remediation: "Clear (requires CSR disabled if SIP is on): sudo nvram -d boot-args"
            ))
        }
    }

    // MARK: - Hot Corners

    private func checkHotCorners(findings: inout [Finding], errors: inout [String]) {
        // "Disable Screen Saver" hot corner (value 6) lets anyone with physical access wave the
        // pointer to the corner and prevent the lock screen — a common bypass in shared offices.
        let corners = [
            ("wvous-tl-corner", "top-left"),
            ("wvous-tr-corner", "top-right"),
            ("wvous-bl-corner", "bottom-left"),
            ("wvous-br-corner", "bottom-right"),
        ]
        for (key, label) in corners {
            let result = ShellRunner.run("/usr/bin/defaults", arguments: [
                "read", "com.apple.dock", key
            ], timeout: 5)
            guard result.success else { continue }
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "6" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Hot corner set to 'Disable Screen Saver' (\(label))",
                    detail: "Anyone with physical access can prevent the screen lock by parking the pointer in the \(label) corner",
                    path: nil,
                    remediation: "Change: System Settings > Desktop & Dock > Hot Corners — set \(label) to anything except 'Disable Screen Saver'"
                ))
            }
        }
    }

    // MARK: - Bluetooth State

    private func checkBluetoothDiscoverable(findings: inout [Finding], errors: inout [String]) {
        // Discoverable Bluetooth on a Mac with no paired devices is a real attack surface
        // (BlueBorne-class bugs are rediscovered every couple of years). We avoid flagging users
        // who actually use Bluetooth.
        let prefPath = "/Library/Preferences/com.apple.Bluetooth.plist"
        guard let data = FileManager.default.contents(atPath: prefPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return
        }

        let isOn = (plist["ControllerPowerState"] as? Int ?? 1) == 1
        guard isOn else { return }

        // Count paired devices — if none and Bluetooth is on, surface as low.
        let paired = plist["PairedDevices"] as? [Any] ?? []
        let cache = plist["DeviceCache"] as? [String: Any] ?? [:]
        if paired.isEmpty && cache.isEmpty {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Bluetooth is on but no devices are paired",
                detail: "Bluetooth radio is active without any paired device — turning it off removes a wireless attack surface",
                path: prefPath,
                remediation: "Turn off: Control Center > Bluetooth, or System Settings > Bluetooth"
            ))
        }
    }

    // MARK: - Encrypted DNS (DoH / DoT)

    private func checkEncryptedDNS(findings: inout [Finding], errors: inout [String]) {
        // Encrypted DNS (Sonoma+) prevents on-path DNS sniffing and pharming. The presence of
        // *any* "dns" payload-type configuration profile is the simplest signal that it's set up.
        // Absence is informational — we don't penalize users on private/ISP DNS.
        let result = ShellRunner.run("/usr/bin/profiles", arguments: ["show"], timeout: 5)
        if !result.success { return }

        let hasEncryptedDNS = result.stdout.lowercased().contains("com.apple.dnssettings.managed") ||
            result.stdout.lowercased().contains("dnsprotocol") ||
            result.stdout.lowercased().contains("encrypted-dns")
        if !hasEncryptedDNS {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Encrypted DNS is not configured",
                detail: "macOS Sonoma+ supports DNS-over-HTTPS / DNS-over-TLS via configuration profile — without it, DNS queries are visible to any on-path observer",
                path: nil,
                remediation: "Install an encrypted DNS profile (Cloudflare, Quad9, NextDNS) from your DNS provider"
            ))
        }
    }

    // MARK: - sudo Timeout

    private func checkSudoTimeout(findings: inout [Finding], errors: inout [String]) {
        // Default macOS sudo timestamp_timeout is 5 minutes. Values above 15 leave the door
        // open for malware that runs in the same TTY to escalate without prompting again.
        guard let content = try? String(contentsOfFile: "/etc/sudoers", encoding: .utf8) else { return }

        for raw in content.split(separator: "\n") {
            let line = String(raw).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard line.lowercased().contains("timestamp_timeout") else { continue }

            // Parse `Defaults timestamp_timeout = NN` — split on '=' and take first token after
            let parts = line.components(separatedBy: "=")
            guard parts.count >= 2 else { continue }
            let after = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
            let token = after.components(separatedBy: .whitespaces).first ?? after
            guard let val = Int(token) else { continue }

            if val < 0 || val > 15 {
                let label = val < 0 ? "never expires" : "\(val) minutes"
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "sudo authentication timeout is permissive (\(label))",
                    detail: "A long sudo grace period lets any program in the same terminal session re-run sudo without your password",
                    path: "/etc/sudoers",
                    remediation: "Edit: sudo visudo — set Defaults timestamp_timeout=5 (or omit for default)"
                ))
            }
        }
    }

    // MARK: - Signed System Volume (SSV)

    private func checkSignedSystemVolume(findings: inout [Finding], errors: inout [String]) {
        // macOS Big Sur+ seals the system volume with a cryptographic hash (SSV). If SSV is
        // disabled (typically to load 3rd-party kexts) the OS becomes mutable and is no longer
        // tamper-evident on boot.
        let result = ShellRunner.run("/usr/sbin/diskutil", arguments: ["apfs", "list"], timeout: 10)
        guard result.success else { return }

        let lower = result.stdout.lowercased()
        // Look for the system volume entry and check whether it is "Sealed: Yes" vs "Sealed: Broken/No"
        let hasSealedYes = lower.contains("sealed:        yes") ||
            lower.contains("snapshot:      yes") ||
            (lower.contains("sealed") && lower.contains("yes"))
        let hasSealedBroken = lower.contains("sealed:        broken") || lower.contains("sealed: broken")
        let hasSealedNo = lower.contains("sealed:        no") || lower.contains("sealed: no")

        if hasSealedBroken || (hasSealedNo && !hasSealedYes) {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Signed System Volume seal is broken",
                detail: "The cryptographic seal that protects /System has been broken or disabled — the OS is mutable and no longer tamper-evident on boot",
                path: nil,
                remediation: "Boot into recovery and reinstall macOS to restore the SSV seal — common cause is third-party kext or rootless mount"
            ))
        }
    }
}
