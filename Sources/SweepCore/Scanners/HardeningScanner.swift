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

        progress?.update("checking Time Machine encryption")
        checkTimeMachineEncryption(findings: &findings, errors: &errors)

        progress?.update("checking Terminal secure keyboard entry")
        checkSecureKeyboardEntry(findings: &findings, errors: &errors)

        progress?.update("checking Wi-Fi auto-join open networks")
        checkOpenNetworkAutoJoin(findings: &findings, errors: &errors)

        progress?.update("checking sudo timeout")
        checkSudoTimestampTimeout(findings: &findings, errors: &errors)

        progress?.update("checking firewall logging")
        checkFirewallLogging(findings: &findings, errors: &errors)

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

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac is the principal recovery channel for stolen devices and the gating
        // factor for Activation Lock. Without it, a thief can wipe the disk, reinstall macOS,
        // and resell the Mac. The token lives in a SystemConfiguration plist when active.
        let plistPath = "/Library/Preferences/com.apple.FindMyMac.plist"
        let exists = FileManager.default.fileExists(atPath: plistPath)
        if !exists {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is not enabled",
                detail: "Without Find My Mac, the Mac cannot be remotely located, locked, or wiped if stolen, and Activation Lock is disabled",
                path: nil,
                remediation: "Enable: System Settings > [Your Name] > iCloud > Find My Mac"
            ))
            return
        }

        // The plist exists but check for the actual FMMToken key
        if let data = FileManager.default.contents(atPath: plistPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           plist["FMMToken"] == nil && plist["Token"] == nil {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is configured but inactive",
                detail: "The Find My Mac preference exists but has no auth token — feature is not actively enrolled",
                path: plistPath,
                remediation: "Re-enable: System Settings > [Your Name] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Time Machine Encryption

    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        // Time Machine backups can contain everything FileVault protects on disk, including
        // keychain items, mail, and documents. An unencrypted external Time Machine drive
        // defeats FileVault — a thief who steals the drive gets the data.
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // Output blocks are separated by "====". For each destination, look for "Encryption: Off"
        let blocks = result.stdout.components(separatedBy: "====")
        for block in blocks {
            let lines = block.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }

            // Only care about destinations actually configured (Name + ID present)
            guard lines.contains(where: { $0.hasPrefix("Name") }) else { continue }

            let nameLine = lines.first { $0.hasPrefix("Name") } ?? ""
            let name = nameLine.replacingOccurrences(of: "Name", with: "")
                .trimmingCharacters(in: CharacterSet(charactersIn: " :")).trimmingCharacters(in: .whitespaces)

            // tmutil reports "Encryption: Off" or "Encryption: On" (older macOS uses "Encrypted: Yes/No")
            let encryptionOff = lines.contains { $0.contains("Encryption") && $0.lowercased().contains(" off") } ||
                                lines.contains { $0.contains("Encrypted") && $0.lowercased().contains(": no") }
            if encryptionOff {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Time Machine destination is unencrypted",
                    detail: "Backup destination \"\(name)\" stores backups without encryption — anyone with physical access to the drive can read your data, defeating FileVault",
                    path: nil,
                    remediation: "Re-add the destination as encrypted: System Settings > General > Time Machine > Add Backup Disk > Encrypt Backup"
                ))
            }
        }
    }

    // MARK: - Terminal Secure Keyboard Entry

    private func checkSecureKeyboardEntry(findings: inout [Finding], errors: inout [String]) {
        // Terminal.app and iTerm2 ship a "Secure Keyboard Entry" mode that prevents other
        // processes (including event-tap based keyloggers) from reading keystrokes typed
        // into the terminal. It's off by default. Enabling it dramatically reduces the
        // impact of a stealth keylogger sitting in the user session.
        let terminals: [(label: String, domain: String, key: String, defaultOn: Bool)] = [
            ("Terminal", "com.apple.Terminal", "SecureKeyboardEntry", false),
            ("iTerm2", "com.googlecode.iterm2", "Secure Input", false),
        ]

        let fm = FileManager.default
        let home = ShellRunner.realUserHome

        for term in terminals {
            // Only check apps the user actually has installed
            let plistPath = "\(home)/Library/Preferences/\(term.domain).plist"
            guard fm.fileExists(atPath: plistPath) else { continue }

            let result = ShellRunner.run("/usr/bin/defaults",
                                         arguments: ["read", term.domain, term.key], timeout: 5)
            // If the key is missing or set to 0, secure entry is disabled
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let enabled = result.success && (value == "1" || value.uppercased() == "YES" || value.uppercased() == "TRUE")
            if !enabled {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "\(term.label) Secure Keyboard Entry is disabled",
                    detail: "Without Secure Keyboard Entry, processes with Input Monitoring or active event taps can capture keys typed into \(term.label) — including passwords typed into sudo and ssh prompts",
                    path: nil,
                    remediation: term.label == "Terminal"
                        ? "Enable: Terminal > Secure Keyboard Entry (menu bar)"
                        : "Enable: iTerm2 > Secure Keyboard Entry (menu bar)"
                ))
            }
        }
    }

    // MARK: - Wi-Fi Auto-Join Open Networks

    private func checkOpenNetworkAutoJoin(findings: inout [Finding], errors: inout [String]) {
        // macOS can be configured to auto-join *unsecured* (open) Wi-Fi networks without
        // prompting. This is a classic eavesdropping / SSID-spoofing vector — an attacker
        // can set up an open AP with a popular SSID name and the Mac silently joins.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/SystemConfiguration/com.apple.wifi.message-tracer", "JoinModeFallback"
        ], timeout: 5)

        // The user-facing setting lives in com.apple.wifi.airport-prefs but key naming
        // varies between macOS versions; the most reliable cross-version check is via
        // `networksetup -getairportnetwork` plus the airport-prefs domain.
        let prefs = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.wifi.plist"
        ], timeout: 5)

        // Pattern: "JoinModeFallback = ... DoNotJoin" or "Prompt" → safe.
        // "JoinModeFallback = JoinOpen" or absent on a stricter OS → unsafe.
        let combined = (result.stdout + "\n" + prefs.stdout).lowercased()
        if combined.contains("joinopen") || combined.contains("auto-join open") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Wi-Fi is set to auto-join open networks",
                detail: "Mac will silently connect to unencrypted Wi-Fi networks — a common phishing/eavesdropping vector (rogue APs with familiar SSIDs)",
                path: nil,
                remediation: "Disable: System Settings > Wi-Fi > Advanced > Ask to join networks > Ask, and turn off \"Auto-Join Hotspot\" for unknown networks"
            ))
        }
    }

    // MARK: - Sudo Timestamp Timeout

    private func checkSudoTimestampTimeout(findings: inout [Finding], errors: inout [String]) {
        // After running sudo once, macOS caches the auth for `timestamp_timeout` minutes
        // (default 5). Some users disable this entirely with `Defaults timestamp_timeout=-1`,
        // which means once they sudo once in a terminal, that terminal can run sudo forever
        // without a password — a major risk if any local malware can spawn into that session.
        let sudoersPaths = ["/etc/sudoers"]
        var paths = sudoersPaths
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") {
            for entry in dropIns where !entry.hasPrefix(".") && entry != "README" {
                paths.append("/etc/sudoers.d/\(entry)")
            }
        }

        for path in paths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            for line in content.split(separator: "\n") {
                let trimmed = String(line).trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                // Catch both "timestamp_timeout=-1" and "timestamp_timeout = -1"
                let normalized = trimmed.replacingOccurrences(of: " ", with: "")
                if normalized.contains("timestamp_timeout=-1") {
                    findings.append(Finding(
                        severity: .high, category: .hardening,
                        title: "sudo timestamp_timeout is set to -1 (never expires)",
                        detail: "Once you authenticate with sudo, the credential cache never expires — local malware spawning into your shell could escalate to root without prompting",
                        path: path,
                        remediation: "Edit with: sudo visudo -f \(path) — set timestamp_timeout to 5 (default) or remove the line"
                    ))
                } else if let range = normalized.range(of: "timestamp_timeout=") {
                    let valueStr = String(normalized[range.upperBound...]
                        .prefix(while: { $0.isNumber || $0 == "-" }))
                    if let v = Int(valueStr), v > 15 {
                        findings.append(Finding(
                            severity: .medium, category: .hardening,
                            title: "sudo timestamp_timeout is unusually long (\(v) minutes)",
                            detail: "Long sudo grace windows widen the blast radius of any local code that runs in your shell session",
                            path: path,
                            remediation: "Edit with: sudo visudo -f \(path) — reduce timestamp_timeout to 5 or 15"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Firewall Logging

    private func checkFirewallLogging(findings: inout [Finding], errors: inout [String]) {
        // Firewall logging records blocked/allowed connection attempts. Without it, you have
        // no after-the-fact record of network activity if an investigation is needed.
        let result = ShellRunner.run("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                     arguments: ["--getloggingmode"], timeout: 5)
        if result.success && result.stdout.lowercased().contains("disabled") {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Firewall logging is disabled",
                detail: "macOS firewall is not recording connection events — limits forensic visibility if you suspect an intrusion",
                path: nil,
                remediation: "Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on"
            ))
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
}
