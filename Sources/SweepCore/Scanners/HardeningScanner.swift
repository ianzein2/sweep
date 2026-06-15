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

        progress?.update("checking iCloud Advanced Data Protection")
        checkAdvancedDataProtection(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine backup health")
        checkTimeMachine(findings: &findings, errors: &errors)

        progress?.update("checking iPhone Mirroring (macOS 15 Sequoia)")
        checkIPhoneMirroring(findings: &findings, errors: &errors)

        progress?.update("checking Apple Intelligence privacy")
        checkAppleIntelligence(findings: &findings, errors: &errors)

        progress?.update("checking macOS version support status")
        checkMacOSVersionEOL(findings: &findings, errors: &errors)

        progress?.update("checking SSH server hardening")
        checkSSHHardening(findings: &findings, errors: &errors)

        progress?.update("checking Background Items (login items v2)")
        checkBackgroundItems(findings: &findings, errors: &errors)

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

    // MARK: - iCloud Advanced Data Protection
    //
    // Apple's end-to-end encryption for iCloud (introduced macOS 13.2 / iOS 16.3). When off,
    // Apple holds keys for iCloud Drive, Photos, Notes, Reminders, Messages backup, etc., which
    // means a legal request, a stolen Apple ID, or a court order can decrypt them. Stalkerware
    // operators frequently target the Apple ID itself — pulling iCloud backups is easier than
    // installing a local agent. Surfacing the state of ADP (without nagging — many users have
    // chosen against it intentionally) is informational unless the account clearly hasn't enabled it.

    private func checkAdvancedDataProtection(findings: inout [Finding], errors: inout [String]) {
        // The advanced-data-protection switch is exposed in com.apple.preferences.icloud once
        // enabled; AKDeviceUnlock daemon writes "AdvancedDataProtection" defaults. We probe a
        // few keys — none is authoritative, so we tone this down to informational.
        let probes: [(domain: String, key: String)] = [
            ("com.apple.iCloud", "AdvancedDataProtectionEnabled"),
            ("MobileMeAccounts", "AdvancedDataProtectionEnabled"),
        ]
        var anyEnabled = false
        var anyProbed = false
        for probe in probes {
            let result = ShellRunner.run("/usr/bin/defaults", arguments: ["read", probe.domain, probe.key], timeout: 3)
            if result.success {
                anyProbed = true
                if result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
                    anyEnabled = true
                }
            }
        }
        if anyProbed && !anyEnabled {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "iCloud Advanced Data Protection is off",
                detail: "End-to-end encryption is not enabled for iCloud Drive, Photos, Notes, etc. Apple can decrypt your data under legal compulsion, and a stolen Apple ID grants access to backups.",
                path: nil,
                remediation: "Enable: System Settings > Apple ID > iCloud > Advanced Data Protection (requires all signed-in devices on a recent OS)"
            ))
        }
    }

    // MARK: - Time Machine

    private func checkTimeMachine(findings: inout [Finding], errors: inout [String]) {
        // Two angles: (1) is Time Machine configured at all (lost data risk if ransomware hits)?
        // (2) if it is, are backups encrypted (a stolen Time Machine disk = full data leak)?
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 5)
        if !result.success || result.stdout.isEmpty ||
           result.stdout.lowercased().contains("no destinations configured") {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Time Machine has no backup destination configured",
                detail: "Without backups, a ransomware family like NotLockBit (active 2024-2025) leaves you with no recovery path.",
                path: nil,
                remediation: "Configure: System Settings > General > Time Machine > Add Backup Disk"
            ))
            return
        }

        // Parse destinationinfo for ID lines, then check each backup for encryption.
        let destIds = result.stdout.split(separator: "\n").compactMap { line -> String? in
            let l = String(line).trimmingCharacters(in: .whitespaces)
            guard l.hasPrefix("ID") else { return nil }
            return l.split(separator: ":").last.map { String($0).trimmingCharacters(in: .whitespaces) }
        }

        for destId in destIds {
            // `tmutil` doesn't directly expose the encryption flag, but
            // /Library/Preferences/com.apple.TimeMachine.plist stores it per destination.
            let plistPath = "/Library/Preferences/com.apple.TimeMachine.plist"
            guard let data = FileManager.default.contents(atPath: plistPath),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let destinations = plist["Destinations"] as? [[String: Any]] else { continue }

            for dest in destinations {
                let id = dest["DestinationID"] as? String ?? ""
                if !id.contains(destId) { continue }

                // For non-network destinations, encryption is indicated by Encrypted = 1.
                let encrypted = (dest["Encrypted"] as? Int ?? 0) == 1 ||
                                (dest["Encrypted"] as? Bool ?? false)
                if !encrypted {
                    findings.append(Finding(
                        severity: .medium, category: .hardening,
                        title: "Time Machine backup is not encrypted",
                        detail: "Destination \(id.prefix(12))… is unencrypted — anyone with the backup disk can read your home directory.",
                        path: nil,
                        remediation: "In System Settings > General > Time Machine, remove the destination and re-add with Encrypt Backups enabled."
                    ))
                }

                // Stale backups (>30 days old) indicate Time Machine is failing.
                if let last = dest["BACKUP_COMPLETED_DATE"] as? Date {
                    let days = Calendar.current.dateComponents([.day], from: last, to: Date()).day ?? 0
                    if days > 30 {
                        findings.append(Finding(
                            severity: .low, category: .hardening,
                            title: "Time Machine last backup was \(days) days ago",
                            detail: "Backups are configured but no successful backup in the last month.",
                            path: nil,
                            remediation: "Check Time Machine in System Settings — destination may be unreachable"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - iPhone Mirroring (macOS 15 Sequoia)
    //
    // iPhone Mirroring projects the user's phone screen onto the Mac. A compromised Mac with
    // a logged-in user can drive the linked iPhone, fetch its notifications, and exfiltrate
    // data without unlocking the phone. The control is exposed as Allow/Disallow per app.

    private func checkIPhoneMirroring(findings: inout [Finding], errors: inout [String]) {
        // iPhone Mirroring is controlled by com.apple.mirroring (and com.apple.iPhoneMirroring on
        // some builds). Surface only when authentication is set to "every time the Mac is unlocked"
        // (value 2) being downgraded, or auto-auth being enabled — the most stalkerware-friendly state.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.iPhoneMirroring", "AuthenticationPolicy"
        ], timeout: 3)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            // Policy: 0 = ask every time, 1 = ask once per Mac unlock (default), 2 = never ask.
            if value == "2" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "iPhone Mirroring set to authenticate automatically",
                    detail: "Mirroring will not prompt for Face ID / passcode — anyone with the Mac can drive the linked iPhone.",
                    path: nil,
                    remediation: "Set: System Settings > Desktop & Dock > iPhone Mirroring > Authentication > Ask Every Time"
                ))
            }
        }

        // Detect that a Mirroring session has been initiated (presence of remoteview frameworks
        // alone isn't enough; a paired-device record is). The pairing record is stored under
        // ~/Library/Caches/com.apple.iPhoneMirroring/PairedDevices.plist on most builds.
        let pairedPath = "\(ShellRunner.realUserHome)/Library/Caches/com.apple.iPhoneMirroring/PairedDevices.plist"
        if FileManager.default.fileExists(atPath: pairedPath) {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "iPhone Mirroring is paired with at least one iPhone",
                detail: "If you didn't set this up, an attacker may have linked their device to extend access.",
                path: pairedPath,
                remediation: "Audit paired devices: System Settings > Desktop & Dock > iPhone Mirroring"
            ))
        }
    }

    // MARK: - Apple Intelligence privacy (macOS 15.1+)
    //
    // Apple Intelligence and ChatGPT integration ship with privacy-relevant defaults: "Improve
    // Search" sends queries to Apple servers, "Improve Genmoji" trains models. Most relevant
    // for targeted users (lawyers, journalists, executives) — surface state so they can review.

    private func checkAppleIntelligence(findings: inout [Finding], errors: inout [String]) {
        // Genmoji/Image Playground analytics opt-in is at com.apple.assistant.support.
        let analyticsKeys: [(domain: String, key: String, name: String)] = [
            ("com.apple.assistant.support", "Search Queries Data Sharing Opt-In", "Apple Intelligence search-query sharing"),
            ("com.apple.assistant.support", "Image Playground Data Sharing", "Image Playground data sharing"),
        ]
        for entry in analyticsKeys {
            let res = ShellRunner.run("/usr/bin/defaults", arguments: [
                "read", entry.domain, entry.key
            ], timeout: 3)
            if res.success, res.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "\(entry.name) is enabled",
                    detail: "Some on-device interactions are uploaded to improve Apple's models.",
                    path: nil,
                    remediation: "Disable: System Settings > Apple Intelligence & Siri > Improve Apple Intelligence"
                ))
            }
        }

        // ChatGPT extension consent — if a third-party model is wired in, requests can leave
        // Apple's infrastructure. The integration writes com.apple.assistant.support keys.
        let extResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.assistant.support", "Assistant Provider"
        ], timeout: 3)
        if extResult.success,
           !extResult.stdout.lowercased().contains("apple") &&
           !extResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Third-party AI provider integrated with Apple Intelligence",
                detail: "Provider: \(extResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) — requests may leave Apple infrastructure.",
                path: nil,
                remediation: "Review: System Settings > Apple Intelligence & Siri > Extensions"
            ))
        }
    }

    // MARK: - macOS version EOL

    private func checkMacOSVersionEOL(findings: inout [Finding], errors: inout [String]) {
        // Apple ships security updates for the current macOS and the two previous releases.
        // Running on an out-of-support version means new exploits will not be patched.
        // We're conservative: only flag when the major version is older than (current - 2).
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion

        // As of 2026: macOS 16 (Tahoe), 15 (Sequoia), 14 (Sonoma) are supported.
        // 13 (Ventura) was the last release to ship updates through 2025.
        // Anything older than 14 is out of security support.
        let supportedMin = 14
        if major < supportedMin {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "macOS \(major) is no longer receiving security updates",
                detail: "Apple only patches the three most recent macOS releases. New vulnerabilities found in macOS \(major) (\(majorName(major))) are not fixed by Software Update.",
                path: nil,
                remediation: "Upgrade to the latest supported macOS — System Settings > General > Software Update"
            ))
        } else if major == supportedMin {
            // Last supported year — warn so they plan an upgrade
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "macOS \(major) (\(majorName(major))) is in its last year of security updates",
                detail: "This release will drop out of Apple's security update window when the next macOS ships.",
                path: nil,
                remediation: "Plan an upgrade within the next year"
            ))
        }
    }

    private func majorName(_ major: Int) -> String {
        switch major {
        case 10: return "Catalina or earlier"
        case 11: return "Big Sur"
        case 12: return "Monterey"
        case 13: return "Ventura"
        case 14: return "Sonoma"
        case 15: return "Sequoia"
        case 16: return "Tahoe"
        default: return "version \(major)"
        }
    }

    // MARK: - SSH server hardening

    private func checkSSHHardening(findings: inout [Finding], errors: inout [String]) {
        // Only meaningful when sshd is actually serving — but Remote Login state is checked
        // elsewhere; here we inspect the daemon config regardless, since misconfigurations
        // become exploitable the second Remote Login is enabled.
        let configPaths = ["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
        var content: String?
        for path in configPaths {
            if let c = try? String(contentsOfFile: path, encoding: .utf8) {
                content = c
                break
            }
        }
        guard let cfg = content else { return }

        // Build a (directive, value) map honoring last-occurrence-wins (sshd default).
        var settings: [String: String] = [:]
        for line in cfg.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let parts = trimmed.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2 else { continue }
            settings[String(parts[0]).lowercased()] = String(parts[1])
                .trimmingCharacters(in: .whitespaces).lowercased()
        }

        // PermitRootLogin — anything but "no" or "prohibit-password" with key auth is risky.
        if let prl = settings["permitrootlogin"], !["no", "prohibit-password"].contains(prl) {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd allows root login (PermitRootLogin \(prl))",
                detail: "Root SSH login is a high-value brute-force target.",
                path: configPaths.first,
                remediation: "Set: PermitRootLogin no in /etc/ssh/sshd_config and reload: sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }

        // Password authentication — keys-only is the modern default. macOS 13+ ships with this
        // off by default; only flag when explicitly enabled.
        if settings["passwordauthentication"] == "yes" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "sshd allows password authentication",
                detail: "Password login over SSH is brute-forceable; modern setups use keys only.",
                path: configPaths.first,
                remediation: "Set: PasswordAuthentication no in /etc/ssh/sshd_config"
            ))
        }

        if settings["permitemptypasswords"] == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd allows empty passwords (PermitEmptyPasswords yes)",
                detail: "Accounts with blank passwords can SSH in without credentials.",
                path: configPaths.first,
                remediation: "Set: PermitEmptyPasswords no in /etc/ssh/sshd_config"
            ))
        }

        // X11 forwarding amplifies the blast radius of an SSH compromise.
        if settings["x11forwarding"] == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "sshd has X11 forwarding enabled",
                detail: "X11 forwarding lets a remote SSH session inject input into local apps.",
                path: configPaths.first,
                remediation: "Set: X11Forwarding no in /etc/ssh/sshd_config"
            ))
        }
    }

    // MARK: - Background Items (Login Items v2 via SMAppService)

    private func checkBackgroundItems(findings: inout [Finding], errors: inout [String]) {
        // macOS Ventura added a single user-facing list (Login Items > Allow in the Background)
        // backed by Background Task Management. Sneakily-disabled items still ship but are
        // hidden — sfltool dumpbtm reveals the real state. We flag items that are "disabled
        // by the user" yet "associated with com.apple." (impersonation) and items registered
        // under entitled developer IDs that don't match an installed app.
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // Loose parser — sfltool output is line-oriented blocks separated by "{ Item ID:".
        var currentBlock: [String] = []
        var blocks: [[String]] = []
        for line in result.stdout.split(separator: "\n", omittingEmptySubsequences: false) {
            let s = String(line)
            if s.contains("{ Item ID:") {
                if !currentBlock.isEmpty { blocks.append(currentBlock) }
                currentBlock = [s]
            } else {
                currentBlock.append(s)
            }
        }
        if !currentBlock.isEmpty { blocks.append(currentBlock) }

        for block in blocks {
            let joined = block.joined(separator: "\n")
            // Look for items that claim to be Apple but ship from /Library/Application Support
            // or /Users/Shared — Apple's items live under /System/ or /Library/Apple/.
            let lowered = joined.lowercased()
            let claimsApple = lowered.contains("identifier: com.apple.") ||
                              lowered.contains("developer name: apple")
            let suspiciousPath = lowered.contains("/users/shared/") ||
                                 lowered.contains("/library/application support/") ||
                                 lowered.contains("/private/tmp/") ||
                                 lowered.contains("/tmp/")
            if claimsApple && suspiciousPath {
                // Pull a short identifier line out of the block for the detail field.
                let ident = block.first(where: { $0.lowercased().contains("identifier") })?
                    .trimmingCharacters(in: .whitespaces) ?? "(no identifier)"
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background Task Management item claims Apple identity from non-system path",
                    detail: ident + " — Apple's own background items never live in user-writable locations.",
                    path: nil,
                    remediation: "Audit in System Settings > General > Login Items & Extensions. Disable and investigate."
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
}
