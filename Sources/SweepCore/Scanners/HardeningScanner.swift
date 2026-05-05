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

        progress?.update("checking SSH server hardening")
        checkSSHDConfig(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine encryption")
        checkTimeMachineEncryption(findings: &findings, errors: &errors)

        progress?.update("checking Wi-Fi auto-join")
        checkWiFiAutoJoin(findings: &findings, errors: &errors)

        progress?.update("checking firmware password (Intel)")
        checkFirmwarePassword(findings: &findings, errors: &errors)

        progress?.update("checking password policy")
        checkPasswordPolicy(findings: &findings, errors: &errors)

        progress?.update("checking automatic app store updates")
        checkAppStoreAutoUpdates(findings: &findings, errors: &errors)

        progress?.update("checking iCloud Private Relay")
        checkPrivateRelay(findings: &findings, errors: &errors)

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

    // MARK: - SSH Server Hardening

    private func checkSSHDConfig(findings: inout [Finding], errors: inout [String]) {
        // Only run if Remote Login (sshd) is actually enabled — otherwise these settings are inert
        // and would be noise. The remote-login check above already warns if SSH is on.
        let sshState = ShellRunner.run("/usr/sbin/systemsetup",
                                       arguments: ["-getremotelogin"], timeout: 5)
        guard sshState.success && sshState.stdout.lowercased().contains(": on") else { return }

        // The effective sshd_config can be assembled from /etc/ssh/sshd_config plus drop-ins
        // in /etc/ssh/sshd_config.d/. Parse line-by-line, last-wins, ignoring comments.
        var configFiles = ["/etc/ssh/sshd_config"]
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/ssh/sshd_config.d") {
            for entry in dropIns where entry.hasSuffix(".conf") {
                configFiles.append("/etc/ssh/sshd_config.d/\(entry)")
            }
        }

        var settings: [String: String] = [:]
        for file in configFiles {
            guard let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                let parts = trimmed.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2 else { continue }
                settings[String(parts[0]).lowercased()] = String(parts[1]).trimmingCharacters(in: .whitespaces)
            }
        }

        // PermitRootLogin: anything other than "no"/"prohibit-password" is risky.
        if let value = settings["permitrootlogin"]?.lowercased() {
            if value == "yes" {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "SSH allows root login with password",
                    detail: "PermitRootLogin = yes — exposes root account to password brute-force over the network",
                    path: "/etc/ssh/sshd_config",
                    remediation: "Change to 'PermitRootLogin no' (or 'prohibit-password' if you need root key login)"
                ))
            } else if value != "no" && value != "prohibit-password" && value != "without-password" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "SSH PermitRootLogin set to '\(value)'",
                    detail: "Non-default value — verify this matches policy",
                    path: "/etc/ssh/sshd_config",
                    remediation: "Most users want 'PermitRootLogin no'"
                ))
            }
        }

        // PasswordAuthentication should be off if you've migrated to keys.
        if let value = settings["passwordauthentication"]?.lowercased(), value == "yes" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SSH allows password authentication",
                detail: "PasswordAuthentication = yes — vulnerable to brute-force; key-based auth is recommended",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PasswordAuthentication no' once you have an SSH key configured"
            ))
        }

        // Empty passwords must never be allowed.
        if let value = settings["permitemptypasswords"]?.lowercased(), value == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH allows empty passwords",
                detail: "PermitEmptyPasswords = yes — accounts with no password can log in remotely",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitEmptyPasswords no' immediately"
            ))
        }

        // X11 forwarding is rarely needed on a Mac and adds remote display attack surface.
        if let value = settings["x11forwarding"]?.lowercased(), value == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH X11 forwarding enabled",
                detail: "X11Forwarding = yes — adds attack surface; disable if not used",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'X11Forwarding no' unless you actively forward X11 sessions"
            ))
        }
    }

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac is a lost-device recovery feature — its absence isn't a strict CIS finding,
        // but it's a meaningful gap on a portable device, so we surface it as informational.
        // The activation status lives in nvram on Apple Silicon and CoreLocation prefs on Intel.
        let result = ShellRunner.run("/usr/sbin/nvram",
                                     arguments: ["fmm-mobileme-token-FMM"], timeout: 5)
        // nvram returns exit code 0 with the token if Find My is configured;
        // missing variable returns "Error getting variable" on stderr / nonzero exit.
        let configured = result.success &&
            !result.stdout.contains("Error") &&
            result.stdout.contains("fmm-mobileme-token-FMM")
        if !configured {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Find My Mac is not enabled",
                detail: "Find My Mac helps locate, lock, or wipe the device if it's lost or stolen",
                path: nil,
                remediation: "Enable: System Settings > [Your Name] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Time Machine Encryption

    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        // Time Machine destinations may store FileVault-encrypted data, but if the *backup* itself
        // is unencrypted, anyone with the disk can read every file you've ever had on this Mac.
        let plist = "/Library/Preferences/com.apple.TimeMachine.plist"
        guard let data = FileManager.default.contents(atPath: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let destinations = dict["Destinations"] as? [[String: Any]] else { return }

        for (idx, dest) in destinations.enumerated() {
            // The "LastKnownEncryptionState" key is "Encrypted" / "NotEncrypted" on encrypted-capable backups.
            let state = (dest["LastKnownEncryptionState"] as? String) ?? "Unknown"
            let name = (dest["LastKnownVolumeName"] as? String) ?? "Destination \(idx + 1)"
            if state == "NotEncrypted" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Time Machine backup is not encrypted",
                    detail: "Destination \"\(name)\" stores unencrypted backups — physical access to the disk reveals all data",
                    path: plist,
                    remediation: "In System Settings > General > Time Machine, remove and re-add the backup with 'Encrypt Backups' checked"
                ))
            }
        }
    }

    // MARK: - Wi-Fi Auto-Join Unknown Networks

    private func checkWiFiAutoJoin(findings: inout [Finding], errors: inout [String]) {
        // Joining unknown networks automatically exposes the Mac to evil-twin / captive-portal
        // attacks at airports, cafes, etc. Apple's default ("Ask") is safe; "Automatic" is risky.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences",
            "JoinMode"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            // Values: "Automatic" (always join), "Preferred" (prefer known), "Ranked", "Recent", "Strongest"
            if value == "Automatic" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Wi-Fi joins unknown networks automatically",
                    detail: "JoinMode = Automatic — Mac auto-joins any open network, exposing it to rogue/evil-twin SSIDs",
                    path: nil,
                    remediation: "Set 'Ask to join networks' to On in System Settings > Wi-Fi > Advanced"
                ))
            }
        }
    }

    // MARK: - Firmware Password (Intel Macs only)

    private func checkFirmwarePassword(findings: inout [Finding], errors: inout [String]) {
        // firmwarepasswd is only meaningful on Intel Macs — Apple Silicon replaces it with the
        // Recovery owner password tied to the iCloud account. We just note the state on Intel
        // and skip silently otherwise.
        let arch = ShellRunner.run("/usr/bin/uname", arguments: ["-m"], timeout: 3)
        let isAppleSilicon = arch.success && arch.stdout.contains("arm64")
        if isAppleSilicon { return }

        let result = ShellRunner.run("/usr/sbin/firmwarepasswd", arguments: ["-check"], timeout: 5)
        guard result.success else { return }
        let output = (result.stdout + result.stderr).lowercased()

        if output.contains("password is not set") || output.contains("not set") {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "EFI firmware password is not set",
                detail: "An attacker with physical access can boot from external media and bypass macOS",
                path: nil,
                remediation: "Set in Recovery Mode: Utilities > Startup Security Utility > Firmware Password (Intel only)"
            ))
        }
    }

    // MARK: - Password Policy

    private func checkPasswordPolicy(findings: inout [Finding], errors: inout [String]) {
        // pwpolicy reports the system-wide account policy. macOS does not enforce a strong policy
        // by default on personal Macs — short / never-expiring passwords are common. We surface
        // missing complexity/length only as informational since this is a personal-Mac product,
        // not a managed-fleet auditor.
        let result = ShellRunner.run("/usr/bin/pwpolicy", arguments: ["-getaccountpolicies"], timeout: 5)
        guard result.success && !result.stdout.isEmpty else { return }

        // pwpolicy prints "No accounts policies are set." when nothing is configured.
        // Match leniently — wording has varied across macOS versions.
        let lowerOut = result.stdout.lowercased()
        if lowerOut.contains("no accounts policies") ||
           lowerOut.contains("no account policies") ||
           lowerOut.contains("error getting") {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "No account password policy is set",
                detail: "macOS allows weak/short passwords by default — consider setting a minimum length",
                path: nil,
                remediation: "Set a policy with: sudo pwpolicy -setglobalpolicy 'minChars=12 requiresAlpha=1 requiresNumeric=1'"
            ))
        }
    }

    // MARK: - App Store Automatic Updates

    private func checkAppStoreAutoUpdates(findings: inout [Finding], errors: inout [String]) {
        // App Store apps that ship security fixes (browsers, password managers, IM clients) won't
        // auto-update unless this is enabled — which leaves users exposed long after fixes ship.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.commerce", "AutoUpdate"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "App Store automatic app updates are disabled",
                    detail: "Browsers, messengers, and password managers from the App Store won't receive security fixes automatically",
                    path: nil,
                    remediation: "Enable: System Settings > General > Software Update > Automatic Updates > Install App Updates"
                ))
            }
        }
    }

    // MARK: - iCloud Private Relay

    private func checkPrivateRelay(findings: inout [Finding], errors: inout [String]) {
        // Private Relay (iCloud+) hides client IP and DNS from network operators. If it has been
        // disabled despite an active subscription, that may be intentional (corporate VPN) but
        // is also a privacy regression worth surfacing.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.networkserviceproxy", "NSPDisablePrivateRelay"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "iCloud Private Relay is disabled",
                    detail: "Private Relay (iCloud+) is turned off — your IP and DNS are visible to networks and Apple-domain trackers",
                    path: nil,
                    remediation: "Enable in System Settings > [Your Name] > iCloud > Private Relay (requires iCloud+)"
                ))
            }
        }
    }
}
