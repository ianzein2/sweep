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

        progress?.update("checking guest access to shared folders")
        checkGuestSharedAccess(findings: &findings, errors: &errors)

        progress?.update("checking Gatekeeper AssessmentsDisabled")
        checkGatekeeperState(findings: &findings, errors: &errors)

        progress?.update("checking Bluetooth on-battery state")
        checkBluetoothPowerState(findings: &findings, errors: &errors)

        progress?.update("checking iCloud two-factor authentication")
        checkiCloudTwoFactor(findings: &findings, errors: &errors)

        progress?.update("checking XProtect / MRT database currency")
        checkAntimalwareDatabaseAge(findings: &findings, errors: &errors)

        progress?.update("checking login keychain auto-unlock")
        checkLoginKeychainAutoUnlock(findings: &findings, errors: &errors)

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

    // MARK: - Guest access to shared folders

    private func checkGuestSharedAccess(findings: inout [Finding], errors: inout [String]) {
        // Even with the Guest login account disabled, guests can still mount shared folders
        // over SMB/AFP if the "Allow guests to connect to shared folders" preference is on.
        // The corresponding key is AllowGuestBrowsingForSharing in com.apple.smb.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.AppleFileServer", "guestAccess"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Guest access to file sharing is enabled",
                    detail: "Guests can mount your shared folders without credentials",
                    path: nil,
                    remediation: "Disable: sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false"
                ))
            }
        }

        // The SMB path — separately configured
        let smbResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "AllowGuestAccess"
        ], timeout: 5)
        if smbResult.success {
            let value = smbResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "SMB guest access is enabled",
                    detail: "Unauthenticated users on the LAN can browse shared folders via SMB",
                    path: nil,
                    remediation: "Disable: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false"
                ))
            }
        }
    }

    // MARK: - Gatekeeper

    private func checkGatekeeperState(findings: inout [Finding], errors: inout [String]) {
        // Gatekeeper being fully disabled (spctl --status: assessments disabled) lets any unsigned
        // app run without prompting the user. `spctl --master-disable` is a common step in stealer
        // install scripts because it silences the warning that would otherwise expose the campaign.
        let result = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status"], timeout: 5)
        if result.success {
            let out = result.stdout.lowercased()
            if out.contains("assessments disabled") {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "Gatekeeper assessments are disabled",
                    detail: "spctl reports assessments disabled — the OS won't block or warn about unsigned apps at first launch",
                    path: nil,
                    remediation: "Re-enable: sudo spctl --master-enable"
                ))
            }
        }

        // Gatekeeper "Anywhere" is enabled if `GKAutoRearm` is off — same effect
        let rearm = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.security", "GKAutoRearm"
        ], timeout: 5)
        if rearm.success && rearm.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "0" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Gatekeeper auto-rearm is disabled",
                detail: "A user-initiated Gatekeeper bypass will remain in effect until manually reset",
                path: nil,
                remediation: "Re-enable: sudo defaults write /Library/Preferences/com.apple.security GKAutoRearm -bool true"
            ))
        }
    }

    // MARK: - Bluetooth

    private func checkBluetoothPowerState(findings: inout [Finding], errors: inout [String]) {
        // Public 2024 disclosures on unauthenticated Bluetooth exploits (BLURtooth,
        // BLESA, and various AirPlay/Bluetooth chip issues) mean Bluetooth-when-idle is
        // an unnecessary attack surface. We report the state so the user can decide.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                // We do NOT flag Bluetooth-on as a finding for most users — Mice, keyboards,
                // AirPods all need it. Only note if paired-devices count is zero.
                let devices = ShellRunner.run("/usr/sbin/system_profiler",
                                              arguments: ["SPBluetoothDataType"], timeout: 8)
                if devices.success && !devices.stdout.lowercased().contains("connected: yes") &&
                   !devices.stdout.lowercased().contains("paired") {
                    findings.append(Finding(
                        severity: .low, category: .hardening,
                        title: "Bluetooth is on but no paired devices",
                        detail: "Bluetooth is powered on with no paired devices — leaves the radio open to nearby scans/exploits",
                        path: nil,
                        remediation: "Turn off Bluetooth from Control Center or System Settings when not in use"
                    ))
                }
            }
        }
    }

    // MARK: - iCloud Two-Factor Authentication (informational)

    private func checkiCloudTwoFactor(findings: inout [Finding], errors: inout [String]) {
        // We can't read the actual iCloud 2FA state without private APIs, but we can check
        // that `MobileMeAccounts` in the user's home has an entry — and warn if the account
        // exists without 2FA-related trust tokens visible on disk. This is a "please review"
        // informational finding — not a hard error.
        let home = ShellRunner.realUserHome
        let mobileMePlist = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard FileManager.default.fileExists(atPath: mobileMePlist),
              let data = FileManager.default.contents(atPath: mobileMePlist),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let accounts = plist["Accounts"] as? [[String: Any]], !accounts.isEmpty
        else { return }

        // Look for the "AuthKitVersion" / "trusted" markers that appear when 2FA is on
        let has2FAMarker = accounts.contains { acct in
            acct["AuthKitContext"] != nil || acct["AuthCredential"] != nil ||
            (acct["AlternateDSID"] as? String) != nil
        }
        if !has2FAMarker {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "iCloud account may lack two-factor authentication",
                detail: "MobileMeAccounts.plist contains an iCloud account but does not carry the two-factor trust markers usually present",
                path: mobileMePlist,
                remediation: "Verify 2FA is enabled: System Settings > [your name] > Password & Security > Two-Factor Authentication"
            ))
        }
    }

    // MARK: - XProtect / MRT freshness

    private func checkAntimalwareDatabaseAge(findings: inout [Finding], errors: inout [String]) {
        // Apple ships silent XProtect and MRT (Malware Removal Tool) updates as data bundles.
        // A stale database means missed detections of active 2024-2025 families that Apple
        // has already added signatures for. Flag if the newest known plist is more than 60 days old.
        let candidates = [
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist",
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
            "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist",
        ]
        let fm = FileManager.default
        var newestDate: Date?
        var newestPath: String?
        for path in candidates {
            guard fm.fileExists(atPath: path),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let mod = attrs[.modificationDate] as? Date
            else { continue }
            if newestDate == nil || mod > newestDate! {
                newestDate = mod
                newestPath = path
            }
        }
        guard let modDate = newestDate else { return }
        let ageDays = Int(Date().timeIntervalSince(modDate) / 86400)
        if ageDays > 60 {
            findings.append(Finding(
                severity: ageDays > 180 ? .high : .medium,
                category: .hardening,
                title: "XProtect signatures appear stale (\(ageDays) days old)",
                detail: "Newest XProtect plist last modified \(ageDays) days ago — Apple ships silent updates weekly, so a >60-day gap suggests the update pipeline is broken",
                path: newestPath,
                remediation: "Force update: sudo softwareupdate --background-critical, then reboot. Check System Settings > General > Software Update."
            ))
        }
    }

    // MARK: - Login keychain state

    /// Ensures the login keychain is not configured to auto-unlock without a password:
    /// LoginwindowPluginDetails / AutoUnlock=true would silently release credentials
    /// to any process after login.
    private func checkLoginKeychainAutoUnlock(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // "security list-keychains" is the safest read here — no keychain contents leak.
        let listResult = ShellRunner.run("/usr/bin/security", arguments: ["list-keychains"], timeout: 5)
        guard listResult.success else { return }

        let loginKeychain = listResult.stdout.contains("login.keychain")
        let hasNoKeychain = listResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

        // Check if the login keychain password is configured to auto-unlock via defaults.
        // The key of interest is `AutoLogin` on com.apple.keychainaccess (unlocked-at-login).
        let autoUnlock = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "\(home)/Library/Preferences/com.apple.keychainaccess", "AutoUnlock"
        ], timeout: 5)
        if autoUnlock.success && autoUnlock.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Login keychain is set to auto-unlock",
                detail: "com.apple.keychainaccess AutoUnlock is enabled — credentials are released without a password prompt",
                path: nil,
                remediation: "Disable: defaults write com.apple.keychainaccess AutoUnlock -bool false, then re-lock the login keychain"
            ))
        }

        if hasNoKeychain || !loginKeychain {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Login keychain is missing from search list",
                detail: "`security list-keychains` did not include login.keychain — a missing login keychain is a rare and confusing state, sometimes caused by keychain-clearing malware",
                path: nil,
                remediation: "Restore: /Applications/Utilities/Keychain Access.app > Keychain Access menu > Preferences > Reset Default Keychain"
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
