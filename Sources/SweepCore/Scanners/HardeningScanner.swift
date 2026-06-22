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

        progress?.update("checking SSH configuration")
        checkSSHConfiguration(findings: &findings, errors: &errors)

        progress?.update("checking sudo Touch ID")
        checkSudoTouchID(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac / activation lock")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking quarantine for downloaded apps")
        checkQuarantineEnabled(findings: &findings, errors: &errors)

        progress?.update("checking Bluetooth state")
        checkBluetoothExposure(findings: &findings, errors: &errors)

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

    // MARK: - SSH Configuration

    private func checkSSHConfiguration(findings: inout [Finding], errors: inout [String]) {
        // Only meaningful if Remote Login is enabled — otherwise sshd never runs and the daemon
        // config is irrelevant. We still parse it because partial configs are sometimes shipped
        // by management profiles and become live as soon as SSH gets turned on.
        let configPath = "/etc/ssh/sshd_config"
        guard let raw = try? String(contentsOfFile: configPath, encoding: .utf8) else { return }

        // Collect effective directives. macOS ships almost everything commented-out so the
        // OpenSSH built-in defaults apply (PasswordAuth=yes, PermitRootLogin=prohibit-password).
        var passwordAuthExplicit: String?
        var permitRootLogin: String?
        var challengeResponseAuth: String?

        for rawLine in raw.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map { String($0) }
            guard tokens.count >= 2 else { continue }
            switch tokens[0].lowercased() {
            case "passwordauthentication":           passwordAuthExplicit = tokens[1].lowercased()
            case "permitrootlogin":                  permitRootLogin = tokens[1].lowercased()
            case "challengeresponseauthentication",
                 "kbdinteractiveauthentication":     challengeResponseAuth = tokens[1].lowercased()
            default: break
            }
        }

        // Whether Remote Login is actually on shapes the severity.
        let sshOn: Bool = {
            let r = ShellRunner.run("/usr/sbin/systemsetup", arguments: ["-getremotelogin"], timeout: 5)
            return r.success && r.stdout.lowercased().contains(": on")
        }()

        // Password auth: default ON in OpenSSH. Only safe state is an explicit "no".
        if passwordAuthExplicit != "no" {
            findings.append(Finding(
                severity: sshOn ? .medium : .low, category: .hardening,
                title: "SSH allows password authentication",
                detail: "sshd_config does not set 'PasswordAuthentication no'" +
                    (sshOn ? " and Remote Login is enabled — exposed to network brute-force" :
                             " (Remote Login is currently off, but config takes effect if it's enabled)"),
                path: configPath,
                remediation: "Edit \(configPath): set 'PasswordAuthentication no' and use SSH keys only"
            ))
        }

        if let v = permitRootLogin, v == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH permits direct root login",
                detail: "PermitRootLogin yes — attackers can target the root account directly",
                path: configPath,
                remediation: "Edit \(configPath): set 'PermitRootLogin no' (or 'prohibit-password' for key-only)"
            ))
        }

        if let v = challengeResponseAuth, v == "yes", passwordAuthExplicit != "no" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH challenge-response (keyboard-interactive) auth is enabled",
                detail: "Keyboard-interactive auth provides another password-style entry vector",
                path: configPath,
                remediation: "Edit \(configPath): set 'ChallengeResponseAuthentication no'"
            ))
        }
    }

    // MARK: - sudo Touch ID

    private func checkSudoTouchID(findings: inout [Finding], errors: inout [String]) {
        // Touch ID for sudo is opt-in. We surface this purely as a hardening tip — a missing
        // pam_tid module in /etc/pam.d/sudo (or sudo_local on Sonoma+) is a low-severity heads-up
        // rather than a problem to fix, so this is informational only.
        let sudoLocal = "/etc/pam.d/sudo_local"
        let sudo = "/etc/pam.d/sudo"

        // Sonoma+: /etc/pam.d/sudo_local is the persistent drop-in (survives OS updates).
        if FileManager.default.fileExists(atPath: sudoLocal),
           let content = try? String(contentsOfFile: sudoLocal, encoding: .utf8),
           content.contains("pam_tid.so") {
            return  // Already configured — nothing to suggest
        }

        if let content = try? String(contentsOfFile: sudo, encoding: .utf8),
           content.contains("pam_tid.so") {
            return  // Configured directly in /etc/pam.d/sudo (older macOS)
        }

        // Only suggest Touch ID on Macs that actually have it.
        let bioCheck = ShellRunner.run("/usr/sbin/system_profiler", arguments: ["SPiBridgeDataType"], timeout: 5)
        let hasTouchID = bioCheck.success && bioCheck.stdout.lowercased().contains("touch id")
        guard hasTouchID else { return }

        findings.append(Finding(
            severity: .low, category: .hardening,
            title: "Touch ID is not enabled for sudo",
            detail: "Enabling Touch ID for sudo means a fingerprint is required for privileged terminal commands, mitigating shoulder-surfing and unattended-keyboard attacks",
            path: nil,
            remediation: "Create /etc/pam.d/sudo_local with: 'auth       sufficient     pam_tid.so' (one line) — see `man pam_tid` for details"
        ))
    }

    // MARK: - Find My Mac / Activation Lock

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac protects against device theft via Activation Lock — without it, a stolen
        // Mac can be wiped and reused. The state lives in MobileMeAccounts.plist under the user.
        let home = ShellRunner.realUserHome
        let plistPath = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard let data = FileManager.default.contents(atPath: plistPath),
              let root = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let accounts = root["Accounts"] as? [[String: Any]] else {
            return  // No iCloud account configured — covered elsewhere, skip silently
        }

        // Walk each iCloud account's service list looking for FIND_MY_MAC=enabled.
        var anyEnabled = false
        var anyAccount = false
        for account in accounts {
            anyAccount = true
            guard let services = account["Services"] as? [[String: Any]] else { continue }
            for service in services {
                let name = (service["Name"] as? String) ?? ""
                if name == "FIND_MY_MAC" {
                    let enabled = (service["Enabled"] as? Bool) ?? false
                    if enabled { anyEnabled = true }
                }
            }
        }

        if anyAccount && !anyEnabled {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is disabled",
                detail: "Without Find My Mac, a stolen or lost Mac can be wiped and reused — Activation Lock won't prevent reuse",
                path: nil,
                remediation: "Enable: System Settings > Apple ID > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Quarantine

    private func checkQuarantineEnabled(findings: inout [Finding], errors: inout [String]) {
        // LSQuarantine causes Safari / Mail / Messages to attach com.apple.quarantine to downloads,
        // which is what triggers the "first-launch" Gatekeeper prompt. Disabling it lets downloaded
        // apps run silently.
        let r = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.LaunchServices", "LSQuarantine"
        ], timeout: 5)
        if r.success {
            let v = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if v == "0" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Download quarantine is disabled",
                    detail: "LSQuarantine is 0 — downloaded apps won't get the com.apple.quarantine xattr, so they won't trigger Gatekeeper's first-launch prompt",
                    path: nil,
                    remediation: "Re-enable: defaults delete com.apple.LaunchServices LSQuarantine (or set to 1)"
                ))
            }
        }
    }

    // MARK: - Bluetooth exposure

    private func checkBluetoothExposure(findings: inout [Finding], errors: inout [String]) {
        // Bluetooth being on is normal. What matters is whether the Mac is discoverable to any
        // device, which is a precondition for BlueBorne-class attacks and AirDrop spoofing.
        let r = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.Bluetooth", "DiscoverableState"
        ], timeout: 5)
        guard r.success else { return }
        let v = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if v == "1" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Bluetooth is in discoverable mode",
                detail: "Mac is broadcasting itself to any nearby Bluetooth device — usually only needed temporarily during pairing",
                path: nil,
                remediation: "Close System Settings > Bluetooth (discoverable mode auto-disables when the pane is closed)"
            ))
        }
    }
}
