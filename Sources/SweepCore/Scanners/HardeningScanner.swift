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

        progress?.update("checking Wake-on-LAN / Wake for Network Access")
        checkWakeOnNetwork(findings: &findings, errors: &errors)

        progress?.update("checking diagnostic data sharing")
        checkDiagnosticDataSharing(findings: &findings, errors: &errors)

        progress?.update("checking Private Wi-Fi Address")
        checkPrivateWiFiAddress(findings: &findings, errors: &errors)

        progress?.update("checking hidden file extensions")
        checkHiddenFileExtensions(findings: &findings, errors: &errors)

        progress?.update("checking SSH config hardening")
        checkSSHDConfig(findings: &findings, errors: &errors)

        progress?.update("checking SMB signing / SMB1")
        checkSMBSigning(findings: &findings, errors: &errors)

        progress?.update("checking IPv6 privacy extensions")
        checkIPv6Privacy(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine encryption")
        checkTimeMachineEncryption(findings: &findings, errors: &errors)

        progress?.update("checking Gatekeeper assessment")
        checkGatekeeperAssessment(findings: &findings, errors: &errors)

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

    // MARK: - Wake for Network Access

    private func checkWakeOnNetwork(findings: inout [Finding], errors: inout [String]) {
        // Wake-on-LAN "womp" lets remote hosts wake this Mac from sleep with a magic packet.
        // On a hostile network it's an amplification / lateral-movement vector.
        let result = ShellRunner.run("/usr/bin/pmset", arguments: ["-g", "custom"], timeout: 5)
        guard result.success else { return }

        var current: String?
        for line in result.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "AC Power" || trimmed == "Battery Power" {
                current = trimmed
                continue
            }
            if trimmed.hasPrefix("womp") {
                let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
                if let value = parts.last, value == "1", current == "AC Power" {
                    findings.append(Finding(
                        severity: .low, category: .hardening,
                        title: "Wake for Network Access (magic packet) is enabled on AC",
                        detail: "Remote hosts on your LAN can wake this Mac while it's plugged in — useful for admins, risky on untrusted networks (cafes, airports)",
                        path: nil,
                        remediation: "Disable if not needed: System Settings > Battery > Options > Wake for network access, or: sudo pmset -a womp 0"
                    ))
                }
            }
        }
    }

    // MARK: - Diagnostic Data Sharing

    private func checkDiagnosticDataSharing(findings: inout [Finding], errors: inout [String]) {
        // Apple's diagnostic submissions include crash reports which may contain memory
        // contents. Third-party diagnostic sharing forwards these to app developers.
        let thirdParty = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory",
            "ThirdPartyDataSubmit"
        ], timeout: 5)
        if thirdParty.success {
            let v = thirdParty.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if v == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Sharing analytics with third-party developers is enabled",
                    detail: "Crash reports and diagnostic data are forwarded to app developers — may contain memory dumps",
                    path: nil,
                    remediation: "Disable: System Settings > Privacy & Security > Analytics & Improvements > Share With App Developers"
                ))
            }
        }
    }

    // MARK: - Private Wi-Fi Address (MAC randomization)

    private func checkPrivateWiFiAddress(findings: inout [Finding], errors: inout [String]) {
        // Private Wi-Fi Address (macOS 15+/iOS 14+) randomizes the Wi-Fi MAC per network to
        // prevent cross-network tracking. If disabled globally, this Mac is trackable across
        // hotspots by its real hardware address.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.wifi.settings", "PrivateMACAddress"
        ], timeout: 5)
        if result.success {
            let v = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if v == "0" || v.lowercased().contains("false") {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Private Wi-Fi Address is disabled",
                    detail: "Real Wi-Fi MAC address is broadcast to every network — enables cross-hotspot tracking",
                    path: nil,
                    remediation: "Enable per-network: System Settings > Wi-Fi > (i) > Private Wi-Fi Address = Rotating"
                ))
            }
        }
    }

    // MARK: - Show File Extensions

    private func checkHiddenFileExtensions(findings: inout [Finding], errors: inout [String]) {
        // Hidden file extensions are a classic phishing trick: "invoice.pdf.dmg" appears as
        // "invoice.pdf" in Finder when extensions are hidden.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "NSGlobalDomain", "AppleShowAllExtensions"
        ], timeout: 5)
        if result.success {
            let v = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if v == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "File extensions are hidden in Finder",
                    detail: "Files like \"invoice.pdf.dmg\" appear as \"invoice.pdf\" — a common social-engineering technique",
                    path: nil,
                    remediation: "Enable: Finder > Settings > Advanced > Show all filename extensions"
                ))
            }
        } else {
            // Key not present means default (hidden) — same effective state
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "File extensions are hidden in Finder (default)",
                detail: "AppleShowAllExtensions is not set — Finder hides extensions like .dmg / .command / .app.zip",
                path: nil,
                remediation: "Enable: Finder > Settings > Advanced > Show all filename extensions"
            ))
        }
    }

    // MARK: - SSH Daemon Configuration

    private func checkSSHDConfig(findings: inout [Finding], errors: inout [String]) {
        // Only check if SSH is actually enabled — otherwise config doesn't matter
        let sshEnabled = ShellRunner.run("/usr/sbin/systemsetup",
                                        arguments: ["-getremotelogin"], timeout: 5)
        guard sshEnabled.success && sshEnabled.stdout.lowercased().contains(": on") else { return }

        // Prefer the effective merged config from sshd -T; fall back to /etc/ssh/sshd_config
        var config = ""
        let effective = ShellRunner.run("/usr/sbin/sshd", arguments: ["-T"], timeout: 5)
        if effective.success && !effective.stdout.isEmpty {
            config = effective.stdout.lowercased()
        } else if let text = try? String(contentsOfFile: "/etc/ssh/sshd_config", encoding: .utf8) {
            // Strip commented-out directives so we don't misread them as active
            config = text
                .components(separatedBy: "\n")
                .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }
                .joined(separator: "\n")
                .lowercased()
        }
        guard !config.isEmpty else { return }

        if config.contains("permitrootlogin yes") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH daemon allows root login",
                detail: "PermitRootLogin is set to yes — attackers who guess the root password gain immediate root",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd"
            ))
        }
        if config.contains("passwordauthentication yes") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SSH daemon accepts password authentication",
                detail: "Password auth is enabled — vulnerable to brute-force. Key auth is safer.",
                path: "/etc/ssh/sshd_config",
                remediation: "Configure SSH keys, then set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
            ))
        }
        if config.contains("permitemptypasswords yes") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH daemon allows empty passwords",
                detail: "PermitEmptyPasswords yes — accounts without passwords can log in over SSH",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
            ))
        }
        if config.contains("protocol 1") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH v1 protocol enabled",
                detail: "SSH protocol 1 has known cryptographic weaknesses and is broken.",
                path: "/etc/ssh/sshd_config",
                remediation: "Remove 'Protocol 1' — SSHv2 is the only safe choice"
            ))
        }
    }

    // MARK: - SMB Signing / Legacy SMB

    private func checkSMBSigning(findings: inout [Finding], errors: inout [String]) {
        // Legacy SMB1 has RCE-class bugs (EternalBlue lineage). SMB signing prevents MitM
        // downgrade and packet-injection attacks against file sharing.
        let smb1 = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "SMB1Enabled"
        ], timeout: 5)
        if smb1.success && smb1.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Legacy SMB1 protocol is enabled",
                detail: "SMB1 has severe cryptographic and protocol flaws (EternalBlue-class) — disable unless required for a specific legacy device",
                path: nil,
                remediation: "Disable: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server SMB1Enabled -bool false"
            ))
        }

        let signing = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "SigningEnabled"
        ], timeout: 5)
        if signing.success && signing.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "0" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SMB packet signing is disabled",
                detail: "Without SMB signing, an attacker on the same network can inject packets or replay traffic against your file shares",
                path: nil,
                remediation: "Enable: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server SigningEnabled -bool true"
            ))
        }
    }

    // MARK: - IPv6 Privacy Extensions

    private func checkIPv6Privacy(findings: inout [Finding], errors: inout [String]) {
        // IPv6 privacy extensions (RFC 4941) rotate the interface identifier so servers
        // can't track a laptop by its hard-coded MAC-derived IPv6 address.
        let result = ShellRunner.run("/usr/sbin/sysctl", arguments: [
            "-n", "net.inet6.ip6.use_tempaddr"
        ], timeout: 5)
        if result.success {
            let v = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if v == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "IPv6 privacy extensions are disabled",
                    detail: "IPv6 address is derived from a stable interface identifier — trackable across networks",
                    path: nil,
                    remediation: "Enable temporary IPv6 addresses: sudo sysctl -w net.inet6.ip6.use_tempaddr=1"
                ))
            }
        }
    }

    // MARK: - Time Machine Encryption

    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        // Time Machine destinations that aren't encrypted contain a plaintext copy of every
        // file the user has ever backed up — a much softer target than the encrypted internal disk.
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 10)
        guard result.success && !result.stdout.isEmpty else { return }

        // Output: "Name : name\nKind : Local\nMount Point : /path\nID : uuid\n..."
        // We report per destination; a "yes" for LastDestination and no "yes" under "Encrypted"
        // heuristically indicates a plaintext backup destination.
        let sections = result.stdout.components(separatedBy: "====")
        for section in sections {
            let lines = section.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }
            let name = lines.first { $0.hasPrefix("Name") }?
                .replacingOccurrences(of: "Name", with: "")
                .replacingOccurrences(of: ":", with: "")
                .trimmingCharacters(in: .whitespaces) ?? ""
            let encryptedLine = lines.first { $0.hasPrefix("Encrypted") }
            let kindLine = lines.first { $0.hasPrefix("Kind") }
            guard !name.isEmpty, let kind = kindLine, !kind.contains("Network") else { continue }

            let isEncrypted = encryptedLine?.lowercased().contains("yes") == true
            if !isEncrypted && encryptedLine != nil {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Time Machine backup destination is not encrypted",
                    detail: "Destination: \(name) — anyone with the disk can read every backed-up file",
                    path: nil,
                    remediation: "Erase and re-add the destination with encryption: System Settings > Time Machine"
                ))
            }
        }
    }

    // MARK: - Gatekeeper Assessment

    private func checkGatekeeperAssessment(findings: inout [Finding], errors: inout [String]) {
        // `spctl --status` reports whether Gatekeeper assessment is running for apps launched
        // from Finder — the last line of defense against unsigned/notarized apps. Users sometimes
        // disable this with `spctl --master-disable` for troubleshooting and forget to re-enable.
        let result = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status"], timeout: 5)
        if result.success {
            let output = result.stdout.lowercased()
            if output.contains("assessments disabled") {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "Gatekeeper assessment is disabled",
                    detail: "spctl --master-disable was run — macOS no longer blocks unsigned or un-notarized apps",
                    path: nil,
                    remediation: "Re-enable: sudo spctl --master-enable"
                ))
            }
        }
    }
}
