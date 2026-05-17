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

        progress?.update("checking login window display policy")
        checkLoginWindowDisplay(findings: &findings, errors: &errors)

        progress?.update("checking sudo timeout")
        checkSudoTimeout(findings: &findings, errors: &errors)

        progress?.update("checking SSH key hygiene")
        checkSSHKeyHygiene(findings: &findings, errors: &errors)

        progress?.update("checking SSH server hardening")
        checkSSHDConfig(findings: &findings, errors: &errors)

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
        // Find My is the only thing that lets a stolen Mac be tracked, remote-locked, or wiped.
        // The configuration lives in com.apple.icloud.findmydeviced; the underlying daemons run
        // as findmydeviced (Apple Silicon) or fmfd. We surface this as LOW because not every user
        // signs in with iCloud, but missing Find My on an iCloud-bound Mac is a real gap.
        let fmd = ShellRunner.run("/bin/launchctl", arguments: [
            "list", "com.apple.findmymacd"
        ], timeout: 5)
        let helper = ShellRunner.run("/bin/launchctl", arguments: [
            "list", "com.apple.icloud.findmydeviced"
        ], timeout: 5)

        // Both should be running when Find My Mac is enabled. If neither is, and an iCloud
        // account is configured, flag it.
        let fmdRunning = fmd.success && !fmd.stdout.isEmpty
        let helperRunning = helper.success && !helper.stdout.isEmpty
        if fmdRunning || helperRunning { return }

        // Probe for an iCloud account before warning.
        let iCloud = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "MobileMeAccounts", "Accounts"
        ], timeout: 5)
        let hasICloud = iCloud.success && iCloud.stdout.contains("AccountID")
        if !hasICloud { return }

        findings.append(Finding(
            severity: .medium, category: .hardening,
            title: "Find My Mac appears disabled while iCloud is signed in",
            detail: "Find My is the only remote lock/wipe lever if this Mac is stolen.",
            path: nil,
            remediation: "Enable: System Settings > [your name] > iCloud > Find My Mac"
        ))
    }

    // MARK: - Login window display policy

    private func checkLoginWindowDisplay(findings: inout [Finding], errors: inout [String]) {
        // When the login window shows a list of users, an attacker only needs the password.
        // When it requires name+password, they need both. CIS recommends the latter.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME"
        ], timeout: 5)
        // Default behavior (no key set) is to show user list.
        var showsList = true
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" { showsList = false }
        }
        if showsList {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Login window shows a list of user accounts",
                detail: "Attackers gain half the credential (the username) just by waking the Mac.",
                path: nil,
                remediation: "Require name and password: sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true"
            ))
        }
    }

    // MARK: - Sudo timeout

    private func checkSudoTimeout(findings: inout [Finding], errors: inout [String]) {
        // sudo caches authentication for `timestamp_timeout` minutes (default 5 on macOS).
        // A value of -1 means "cache forever for this session", which is a meaningful
        // privilege-escalation window if another process compromises the terminal.
        guard let content = try? String(contentsOfFile: "/etc/sudoers", encoding: .utf8) else { return }
        var allConfig = content
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") {
            for entry in dropIns where !entry.hasPrefix(".") && entry != "README" {
                if let extra = try? String(contentsOfFile: "/etc/sudoers.d/\(entry)", encoding: .utf8) {
                    allConfig.append("\n")
                    allConfig.append(extra)
                }
            }
        }

        for raw in allConfig.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard line.contains("timestamp_timeout") else { continue }
            // Match "timestamp_timeout=<value>" — sudo accepts whitespace around the equals sign
            // sometimes, so be lenient.
            let parts = line.split(separator: "=").map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count >= 2 else { continue }
            // Find the numeric token at the start of the trailing portion.
            let tail = parts.last ?? ""
            let numStr = tail.split(whereSeparator: { !$0.isNumber && $0 != "-" }).first.map(String.init) ?? ""
            guard let value = Int(numStr) else { continue }
            if value < 0 {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "sudo timestamp_timeout is set to never expire (\(value))",
                    detail: "A negative timestamp_timeout caches sudo authentication for the lifetime of the terminal session.",
                    path: "/etc/sudoers",
                    remediation: "Set to a small positive value (default is 5): sudo visudo"
                ))
            } else if value > 60 {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "sudo authentication cached for \(value) minutes",
                    detail: "Long sudo caching widens the window in which compromised processes can escalate.",
                    path: "/etc/sudoers",
                    remediation: "Lower to <=15 minutes: sudo visudo"
                ))
            }
            break  // first match wins; sudoers is parsed in order
        }
    }

    // MARK: - SSH key hygiene

    private func checkSSHKeyHygiene(findings: inout [Finding], errors: inout [String]) {
        // Unencrypted private keys are bearer credentials: anything that reads the file gets
        // your access. Stealers from 2024-2025 specifically harvest these. We can detect an
        // unencrypted key by header signature alone — no need to attempt to load it.
        let home = ShellRunner.realUserHome
        let dir = "\(home)/.ssh"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }

        for entry in entries {
            // Look only at things that smell like private keys
            let lower = entry.lowercased()
            guard lower.hasPrefix("id_") || lower.hasSuffix(".pem") || lower == "identity" else { continue }
            if lower.hasSuffix(".pub") { continue }
            let path = "\(dir)/\(entry)"
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Confirm it's actually a private key
            guard content.contains("BEGIN") && content.contains("PRIVATE KEY") else { continue }

            // Classic PEM keys advertise "Proc-Type: 4,ENCRYPTED" + "DEK-Info" when encrypted.
            // OpenSSH-format keys carry the cipher name in a length-prefixed binary header at
            // the start of the base64 body — see hasOpenSSHCipher for the decode.
            let isOpenSSH = content.contains("BEGIN OPENSSH PRIVATE KEY")
            let encrypted: Bool
            if isOpenSSH {
                encrypted = hasOpenSSHCipher(content)
            } else {
                encrypted = content.contains("Proc-Type: 4,ENCRYPTED") ||
                            content.contains("DEK-Info:")
            }
            if !encrypted {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "SSH private key has no passphrase: \(entry)",
                    detail: "Anything that read this file (stealer, backup, leaked sync) gets your SSH access.",
                    path: path,
                    remediation: "Add a passphrase: ssh-keygen -p -f \"\(path)\""
                ))
            }

            // Group/world-readable permissions on a private key — OpenSSH refuses to use these
            // anyway, but their existence is sloppy and stealer-friendly.
            if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
               let posix = attrs[.posixPermissions] as? Int {
                let groupOrWorldReadable = (posix & 0o077) != 0
                if groupOrWorldReadable {
                    findings.append(Finding(
                        severity: .medium, category: .hardening,
                        title: "SSH private key has overly permissive mode: \(entry)",
                        detail: String(format: "Mode: 0%o — other users on the system can read this key.", posix),
                        path: path,
                        remediation: "Restrict to user only: chmod 600 \"\(path)\""
                    ))
                }
            }
        }
    }

    /// True if an OpenSSH-format private key body looks encrypted (cipher field is not "none").
    private func hasOpenSSHCipher(_ content: String) -> Bool {
        guard let startRange = content.range(of: "BEGIN OPENSSH PRIVATE KEY"),
              let endRange = content.range(of: "END OPENSSH PRIVATE KEY") else { return false }
        let body = content[startRange.upperBound..<endRange.lowerBound]
            .components(separatedBy: .newlines)
            .joined()
        // The body is base64; the binary preamble begins "openssh-key-v1\0" followed by a length
        // and the cipher name. Decoding the first ~32 bytes is enough to read the cipher.
        guard let data = Data(base64Encoded: body, options: .ignoreUnknownCharacters), data.count > 32 else {
            return false
        }
        // Look for "none" as a length-prefixed string near the start.
        if let nameRange = data.range(of: Data("none".utf8)), nameRange.lowerBound < 64 {
            return false  // cipher is literally "none" — key is unencrypted
        }
        return true
    }

    // MARK: - SSH server hardening

    private func checkSSHDConfig(findings: inout [Finding], errors: inout [String]) {
        // Only relevant when Remote Login is enabled, but even with it disabled a permissive
        // sshd_config means the next time it gets toggled on, the Mac is exposed.
        let candidates = [
            "/etc/ssh/sshd_config",
            "/private/etc/ssh/sshd_config",
        ]
        var content: String?
        var path: String?
        for c in candidates {
            if let body = try? String(contentsOfFile: c, encoding: .utf8) {
                content = body
                path = c
                break
            }
        }
        guard let body = content, let configPath = path else { return }

        var permitRootLogin = "prohibit-password"   // OpenSSH default
        var passwordAuth = "yes"                    // OpenSSH default
        var permitEmpty = "no"                      // OpenSSH default

        for raw in body.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2 else { continue }
            let key = parts[0].lowercased()
            let value = String(parts[1]).trimmingCharacters(in: .whitespaces).lowercased()
            switch key {
            case "permitrootlogin":   permitRootLogin = value
            case "passwordauthentication": passwordAuth = value
            case "permitemptypasswords": permitEmpty = value
            default: break
            }
        }

        if permitRootLogin == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd allows direct root login over SSH",
                detail: "PermitRootLogin yes — root can SSH in directly with just a password.",
                path: configPath,
                remediation: "Set 'PermitRootLogin no' in sshd_config, then sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }
        if permitEmpty == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd allows empty passwords",
                detail: "PermitEmptyPasswords yes — accounts with no password set can SSH in.",
                path: configPath,
                remediation: "Set 'PermitEmptyPasswords no' in sshd_config and restart the daemon."
            ))
        }
        if passwordAuth == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "sshd allows password authentication",
                detail: "PasswordAuthentication yes — brute-force is possible. Key-based auth is preferred.",
                path: configPath,
                remediation: "Switch to keys: add your public key to ~/.ssh/authorized_keys, then set 'PasswordAuthentication no'."
            ))
        }
    }
}
