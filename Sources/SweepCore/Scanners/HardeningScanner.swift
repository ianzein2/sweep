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

        progress?.update("checking Gatekeeper assessment policy")
        checkGatekeeperAssessment(findings: &findings, errors: &errors)

        progress?.update("checking automatic install of macOS updates")
        checkAutoInstallUpdates(findings: &findings, errors: &errors)

        progress?.update("checking sudo Touch ID")
        checkSudoTouchID(findings: &findings, errors: &errors)

        progress?.update("checking AirPlay Receiver")
        checkAirPlayReceiver(findings: &findings, errors: &errors)

        progress?.update("checking Wi-Fi MAC randomization")
        checkWifiMacRandomization(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

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

    // MARK: - Gatekeeper Assessment Policy

    private func checkGatekeeperAssessment(findings: inout [Finding], errors: inout [String]) {
        // `spctl --status` reports the master enable/disable; `--test-devid-status` and
        // `--assess` reveal whether the assessment policy still trusts developer IDs.
        // Setting "Allow apps from: Anywhere" (silently re-enabled with `sudo spctl --master-disable`)
        // is a strong indicator that the user (or attacker) bypassed Apple's notarization gate.
        let assessmentMaster = ShellRunner.run("/usr/sbin/spctl",
                                               arguments: ["--status", "--verbose"], timeout: 5)
        let output = assessmentMaster.stdout + assessmentMaster.stderr
        if output.lowercased().contains("assessments disabled") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Gatekeeper assessments are disabled",
                detail: "spctl reports assessments disabled — any unsigned or unnotarized app can launch without warning",
                path: nil,
                remediation: "Re-enable: sudo spctl --master-enable"
            ))
            return
        }

        // Newer macOS releases hide the "Anywhere" option from System Settings, but it can still be
        // enabled via the command line. Even with master assessments on, an empty policy means
        // unsigned apps from /Applications run without prompt.
        let policy = ShellRunner.run("/usr/sbin/spctl",
                                     arguments: ["--list", "--type", "execute"], timeout: 5)
        if policy.success && policy.stdout.lowercased().contains("disabled") &&
           policy.stdout.contains("Notarized Developer ID") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Gatekeeper notarization rule is disabled",
                detail: "The 'Notarized Developer ID' assessment rule is off — apps notarized by Apple aren't enforced",
                path: nil,
                remediation: "Restore the default rule: sudo spctl --enable --label \"Notarized Developer ID\""
            ))
        }
    }

    // MARK: - Automatic Install of macOS Updates

    private func checkAutoInstallUpdates(findings: inout [Finding], errors: inout [String]) {
        // AutomaticallyInstallMacOSUpdates controls whether the major-version security updates
        // (e.g., 14.x → 14.y) install on their own. Even with auto-check on, an attacker who can
        // socially-engineer a user away from updating still wins — this setting closes that gap.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Automatic install of macOS updates is disabled",
                    detail: "macOS security updates are downloaded but require manual install — delaying patches for actively exploited bugs",
                    path: nil,
                    remediation: "Enable: System Settings > General > Software Update > (i) > Install macOS updates"
                ))
            }
        }
    }

    // MARK: - Sudo Touch ID

    private func checkSudoTouchID(findings: inout [Finding], errors: inout [String]) {
        // Apple Silicon supports pam_tid for sudo as of macOS Sonoma+ (and via custom edit prior).
        // /etc/pam.d/sudo_local is the recommended override — it survives system updates that
        // overwrite /etc/pam.d/sudo. A configured sudo_local is a positive hardening signal.
        let localPath = "/etc/pam.d/sudo_local"
        let sudoPath = "/etc/pam.d/sudo"
        let fm = FileManager.default

        let hasLocalTid: Bool = {
            guard let content = try? String(contentsOfFile: localPath, encoding: .utf8) else { return false }
            return content.split(separator: "\n").contains { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return !trimmed.hasPrefix("#") && trimmed.contains("pam_tid.so")
            }
        }()

        let hasSudoTid: Bool = {
            guard let content = try? String(contentsOfFile: sudoPath, encoding: .utf8) else { return false }
            return content.split(separator: "\n").contains { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return !trimmed.hasPrefix("#") && trimmed.contains("pam_tid.so")
            }
        }()

        if !hasLocalTid && !hasSudoTid && fm.fileExists(atPath: "/usr/bin/bioutil") {
            // Only suggest on machines that actually have biometrics available.
            let bioCheck = ShellRunner.run("/usr/bin/bioutil", arguments: ["-r"], timeout: 5)
            let hasTouchID = bioCheck.success && bioCheck.stdout.lowercased().contains("touch id")
            if hasTouchID {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Sudo Touch ID is not configured",
                    detail: "sudo still requires typing your password — Touch ID can replace it on Apple Silicon for faster, phishing-resistant auth",
                    path: nil,
                    remediation: "Enable: echo 'auth sufficient pam_tid.so' | sudo tee /etc/pam.d/sudo_local"
                ))
            }
        }
    }

    // MARK: - AirPlay Receiver

    private func checkAirPlayReceiver(findings: inout [Finding], errors: inout [String]) {
        // AirPlay Receiver lets nearby Apple devices send screens / audio TO this Mac. On a hostile
        // network (cafés, hotels, conferences) it widens the attack surface — CVE-2025-31200 was
        // an AirPlay-derived zero-click. Disable when not actively presenting.
        let plist = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.controlcenter", "AirplayRecieverEnabled"
        ], timeout: 5)
        let altPlist = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.RemoteDesktop", "AirplayRecieverEnabled"
        ], timeout: 5)

        let value = plist.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let altValue = altPlist.stdout.trimmingCharacters(in: .whitespacesAndNewlines)

        if value == "1" || altValue == "1" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "AirPlay Receiver is enabled",
                detail: "Other devices can stream to this Mac — exposes an additional network listener. Past AirPlay parsing bugs have allowed RCE.",
                path: nil,
                remediation: "Disable when not in use: System Settings > General > AirDrop & Handoff > AirPlay Receiver"
            ))
        }
    }

    // MARK: - Wi-Fi MAC Randomization

    private func checkWifiMacRandomization(findings: inout [Finding], errors: inout [String]) {
        // Disabling private Wi-Fi address makes the Mac trackable across networks. This is mostly
        // a privacy concern, not a compromise indicator, so we keep it low severity.
        let result = ShellRunner.run("/usr/sbin/networksetup",
                                     arguments: ["-listpreferredwirelessnetworks", "en0"], timeout: 5)
        guard result.success else { return }

        // PrivateMACAddressMode is per-network and lives in
        // /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist.
        let plistPath = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
        guard let data = FileManager.default.contents(atPath: plistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return }

        // KnownNetworks dict — each key is a network with a PrivateMACAddressMode int. 0 = off,
        // 1 = static (per-network), 2 = rotating. Anything other than 1/2 on a current network is risky.
        guard let known = plist["KnownNetworks"] as? [String: [String: Any]] else { return }

        var offNetworks: [String] = []
        for (_, entry) in known {
            let mode = entry["PrivateMACAddressMode"] as? Int ?? 1
            let ssid = entry["SSIDString"] as? String ?? "unknown"
            if mode == 0 { offNetworks.append(ssid) }
        }

        // Only surface this if multiple networks are affected — single one-offs are typically intentional (corp Wi-Fi).
        if offNetworks.count >= 3 {
            let preview = offNetworks.prefix(3).joined(separator: ", ")
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Private Wi-Fi Address is off for \(offNetworks.count) networks",
                detail: "Networks: \(preview)\(offNetworks.count > 3 ? "…" : "") — your real Wi-Fi MAC is being broadcast, making you trackable",
                path: plistPath,
                remediation: "For each network: System Settings > Wi-Fi > (i) next to network > Private Wi-Fi address: Rotating"
            ))
        }
    }

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac is a recovery feature, not strictly hardening, but its absence means a stolen
        // Mac can't be remotely wiped. Only emit a finding when we can read the plist AND the value
        // is explicitly 0 — a permission failure on /Library/Preferences/com.apple.FindMyMac.plist
        // would otherwise produce a false positive every time sweep runs as a non-admin user.
        let plistPath = "/Library/Preferences/com.apple.FindMyMac.plist"
        guard FileManager.default.fileExists(atPath: plistPath) else { return }

        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.FindMyMac", "FMMEnabled"
        ], timeout: 5)
        guard result.success else { return }

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if value == "0" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Find My Mac is disabled",
                detail: "If this Mac is lost or stolen, you can't locate or remote-wipe it from iCloud",
                path: nil,
                remediation: "Sign in to iCloud and enable: System Settings > [Your Name] > iCloud > Find My Mac"
            ))
        }
    }
}
