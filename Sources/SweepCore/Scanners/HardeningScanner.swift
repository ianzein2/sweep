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

        progress?.update("checking Touch ID for sudo")
        checkTouchIDForSudo(findings: &findings, errors: &errors)

        progress?.update("checking USB accessory protection")
        checkAccessoryConnectPolicy(findings: &findings, errors: &errors)

        progress?.update("checking analytics & ad-tracking sharing")
        checkAnalyticsSharing(findings: &findings, errors: &errors)

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
        // Find My Mac is the only way to remotely lock or wipe a stolen Mac. Apple has shuffled
        // where FMM state is stored across macOS releases, so we use two independent signals:
        //   (a) is iCloud signed in at all? — MobileMeAccounts.plist contains an Accounts array
        //   (b) is the FMM daemon enabled? — `launchctl list` includes com.apple.icloud.findmydeviced
        // We only flag a problem when iCloud is clearly signed in but the FMM daemon is missing,
        // which strongly suggests Find My Mac is off for that account.
        let home = ShellRunner.realUserHome
        let mmaPath = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard let data = FileManager.default.contents(atPath: mmaPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let accounts = plist["Accounts"] as? [[String: Any]],
              !accounts.isEmpty
        else {
            // No iCloud account configured — nothing to check.
            return
        }

        let launchctl = ShellRunner.run("/bin/launchctl", arguments: ["list"], timeout: 5)
        let fmmRunning = launchctl.success &&
            (launchctl.stdout.contains("com.apple.icloud.findmydeviced") ||
             launchctl.stdout.contains("com.apple.findmy.findmydeviced"))

        if !fmmRunning {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac appears to be disabled",
                detail: "iCloud is signed in (\(accounts.count) account\(accounts.count == 1 ? "" : "s")) but the Find My daemon is not running — if this Mac is lost or stolen, you cannot lock or wipe it remotely",
                path: nil,
                remediation: "Enable: System Settings > [Your Apple Account] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Touch ID for sudo

    private func checkTouchIDForSudo(findings: inout [Finding], errors: inout [String]) {
        // macOS Sonoma+ supports persistent Touch ID for sudo via /etc/pam.d/sudo_local — a file
        // Apple created specifically so the user-added pam_tid.so line survives system updates.
        // For Macs with a Touch ID sensor, enabling this raises the cost of password phishing
        // (shoulder-surfed sudo passwords stop being enough).
        let sudoLocal = "/etc/pam.d/sudo_local"
        let hasTouchIDSudo: Bool = {
            guard let content = try? String(contentsOfFile: sudoLocal, encoding: .utf8) else {
                return false
            }
            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                if trimmed.contains("pam_tid.so") { return true }
            }
            return false
        }()

        // Only suggest enabling it if the hardware supports Touch ID. `bioutil` ships on every
        // Mac that has a Touch ID sensor — `bioutil -r` succeeds when biometric hardware is
        // present and prints "No Touch ID hardware available" otherwise. This is faster and
        // more reliable than scraping ioreg, which uses different class names per Mac generation.
        let bioutil = ShellRunner.run("/usr/bin/bioutil", arguments: ["-r"], timeout: 5)
        let combined = (bioutil.stdout + bioutil.stderr).lowercased()
        let hasTouchID = bioutil.success &&
                         !combined.contains("no touch id") &&
                         !combined.contains("no biometric")

        if hasTouchID && !hasTouchIDSudo {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Touch ID is not enabled for sudo",
                detail: "This Mac has Touch ID but /etc/pam.d/sudo_local does not enable pam_tid.so — sudo still falls back to typed passwords",
                path: sudoLocal,
                remediation: "Add to /etc/pam.d/sudo_local (create the file as root):\nauth       sufficient     pam_tid.so"
            ))
        }
    }

    // MARK: - USB Accessory Connect Policy (macOS 14+)

    private func checkAccessoryConnectPolicy(findings: inout [Finding], errors: inout [String]) {
        // Apple Silicon Macs on macOS Sonoma+ ask the user to approve every newly-connected
        // USB or Thunderbolt accessory. This is the macOS equivalent of iOS's USB Restricted Mode
        // and stops "juice-jacking" / forensic-cable attacks (Cellebrite / Graykey style).
        // The policy is stored in com.apple.security.accessory-connect with the
        // "allowAccessoryConnect" key; a value of "Always" disables the prompt entirely.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.security.accessory-connect", "allowAccessoryConnect"
        ], timeout: 5)

        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if value == "always" || value == "1" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "USB accessory prompt is disabled (Always allow)",
                    detail: "macOS will silently accept any newly-connected USB or Thunderbolt device — leaves the Mac exposed to malicious cables and forensic tools",
                    path: nil,
                    remediation: "Set: System Settings > Privacy & Security > Allow accessories to connect → \"Ask for new accessories\""
                ))
            }
        }
    }

    // MARK: - Analytics / Ad-tracking sharing

    private func checkAnalyticsSharing(findings: inout [Finding], errors: inout [String]) {
        // Apple's "Share Mac Analytics" and "Share with App Developers" toggles ship crash logs
        // and usage data off-device. They're a privacy choice rather than an attack vector, but
        // many users don't realize they're enabled by default after onboarding and a clean install.
        let analytics = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
            "AutoSubmit"
        ], timeout: 5)

        if analytics.success {
            let value = analytics.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Mac Analytics sharing is enabled",
                    detail: "Crash reports and usage data are sent to Apple. This is a privacy choice — disable if you'd rather not share diagnostics.",
                    path: nil,
                    remediation: "Disable if desired: System Settings > Privacy & Security > Analytics & Improvements"
                ))
            }
        }

        // Personalized ads (Apple Ads) — opt-out toggle in System Settings.
        let pa = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.AdLib", "allowApplePersonalizedAdvertising"
        ], timeout: 5)
        if pa.success {
            let v = pa.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if v == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Personalized Apple Advertising is enabled",
                    detail: "Apple uses on-device information to personalize ads in the App Store, News, and Stocks.",
                    path: nil,
                    remediation: "Disable if desired: System Settings > Privacy & Security > Apple Advertising > Personalized Ads"
                ))
            }
        }
    }
}
