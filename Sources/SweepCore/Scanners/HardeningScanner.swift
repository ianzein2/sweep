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

        progress?.update("checking AirPlay Receiver")
        checkAirPlayReceiver(findings: &findings, errors: &errors)

        progress?.update("checking SSH configuration")
        checkSSHConfig(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine encryption")
        checkTimeMachineEncryption(findings: &findings, errors: &errors)

        progress?.update("checking Bonjour advertising")
        checkBonjourAdvertising(findings: &findings, errors: &errors)

        progress?.update("checking Siri privacy")
        checkSiriPrivacy(findings: &findings, errors: &errors)

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

    // MARK: - AirPlay Receiver

    private func checkAirPlayReceiver(findings: inout [Finding], errors: inout [String]) {
        // On macOS 12+, AirPlay Receiver is a network service that accepts screen streams / audio
        // from nearby devices. On macOS 14 Sonoma it defaults to ON for many users after upgrade.
        // A misconfigured "Anyone on the same network" setting is a real surveillance/data-exfil vector
        // (the Mac appears as an AirPlay target and can be sent screens/audio without authentication).
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.RemoteManagement", "AirplayReceiverEnabled"
        ], timeout: 5)
        // Fall back to the user-scope key if the system-scope one is unset
        let userScope = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.controlcenter", "AirplayRecieverEnabled"
        ], timeout: 5)

        let enabled = (result.success && result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1")
                   || (userScope.success && userScope.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1")

        if enabled {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "AirPlay Receiver is enabled",
                detail: "This Mac accepts AirPlay streams from other devices — a network-facing surface that has had multiple CVEs",
                path: nil,
                remediation: "Disable if not needed: System Settings > General > AirDrop & Handoff > AirPlay Receiver"
            ))
        }
    }

    // MARK: - SSH Configuration

    private func checkSSHConfig(findings: inout [Finding], errors: inout [String]) {
        // /etc/ssh/sshd_config controls the incoming SSH service. Even when SSH is disabled today,
        // a permissive config makes turn-it-on-and-forget-it risky. Two settings are consistently
        // flagged by the CIS benchmark: PermitRootLogin and PasswordAuthentication.
        guard let content = try? String(contentsOfFile: "/etc/ssh/sshd_config", encoding: .utf8) else { return }

        var rootLoginAllowed = false
        var passwordAuthAllowed = false
        var permitEmptyPasswords = false
        var x11ForwardingEnabled = false

        for line in content.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
                .map { String($0).lowercased() }
            guard parts.count >= 2 else { continue }

            switch parts[0] {
            case "permitrootlogin":
                // "yes" or "without-password" (a.k.a. prohibit-password) both allow root
                if parts[1] == "yes" || parts[1] == "without-password" {
                    rootLoginAllowed = true
                }
            case "passwordauthentication":
                if parts[1] == "yes" { passwordAuthAllowed = true }
            case "permitemptypasswords":
                if parts[1] == "yes" { permitEmptyPasswords = true }
            case "x11forwarding":
                if parts[1] == "yes" { x11ForwardingEnabled = true }
            default:
                continue
            }
        }

        if rootLoginAllowed {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH allows root login",
                detail: "sshd_config has 'PermitRootLogin yes' — remote root access massively widens the attack surface",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }

        if permitEmptyPasswords {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH permits empty passwords",
                detail: "sshd_config has 'PermitEmptyPasswords yes' — accounts without passwords can log in over the network",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
            ))
        }

        if passwordAuthAllowed {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SSH allows password authentication",
                detail: "sshd_config has 'PasswordAuthentication yes' — key-based auth is stronger and eliminates brute-force risk",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PasswordAuthentication no' and use SSH keys instead"
            ))
        }

        if x11ForwardingEnabled {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH X11 forwarding is enabled",
                detail: "X11 forwarding is a known vector for GUI keylogging attacks — rarely needed on modern macOS",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'X11Forwarding no' in /etc/ssh/sshd_config"
            ))
        }
    }

    // MARK: - Time Machine Encryption

    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        // Unencrypted Time Machine backups snapshot the whole disk — if the drive walks away,
        // so does everything on your Mac (including keychain items, mail, etc.).
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        var currentDest: String?
        var unencryptedDests: [String] = []

        for line in result.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("Name") {
                if let colonRange = trimmed.range(of: ":") {
                    currentDest = String(trimmed[colonRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                }
            } else if trimmed.hasPrefix("Kind") {
                // Some destination kinds imply encryption; on network volumes we check separately
                let value = trimmed.lowercased()
                if let dest = currentDest, value.contains("local") && !value.contains("encrypted") {
                    // Ask tmutil directly whether encryption is on for this destination — best-effort.
                    unencryptedDests.append(dest)
                }
            }
        }

        // If no destinations are configured, tmutil returns empty output — no finding is appropriate.
        // We only flag when the user has an unencrypted local destination in use.
        for dest in unencryptedDests {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Time Machine backup may not be encrypted",
                detail: "Destination \"\(dest)\" appears unencrypted — a stolen backup drive exposes your data even if FileVault is on",
                path: nil,
                remediation: "Turn on 'Encrypt Backup' in System Settings > General > Time Machine > (i)"
            ))
        }
    }

    // MARK: - Bonjour / mDNS Advertising

    private func checkBonjourAdvertising(findings: inout [Finding], errors: inout [String]) {
        // Bonjour advertising broadcasts services on the local network. Disabling advertising while
        // leaving discovery on is a common privacy hardening step for users on hostile networks.
        // NoMulticastAdvertisements = 1 means advertising is off.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.mDNSResponder", "NoMulticastAdvertisements"
        ], timeout: 5)

        // If the key doesn't exist, advertising is ON (the default).
        let advertisingOff = result.success &&
            result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1"

        if !advertisingOff {
            // Only surface as informational — most users want Bonjour for AirPlay, printers, etc.
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Bonjour multicast advertising is enabled",
                detail: "This Mac broadcasts its hostname / services on the local network — routine, but a fingerprinting vector on untrusted networks",
                path: nil,
                remediation: "To disable advertising while keeping discovery: sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES"
            ))
        }
    }

    // MARK: - Siri Privacy

    private func checkSiriPrivacy(findings: inout [Finding], errors: inout [String]) {
        // "Improve Siri & Dictation" opts your voice snippets into Apple's grading pool.
        // For high-privacy users this is a real leak — flag as informational so the user can decide.
        let optIn = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.assistant.support", "Siri Data Sharing Opt-In Status"
        ], timeout: 5)
        if optIn.success {
            let value = optIn.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            // Apple encodes: 2 = opted in, 1 = opted out. Anything else usually means "not yet asked".
            if value == "2" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Siri voice-sample sharing is enabled",
                    detail: "Voice snippets are shared with Apple for grading — a privacy trade-off worth reviewing",
                    path: nil,
                    remediation: "Disable: System Settings > Privacy & Security > Analytics & Improvements > Improve Siri & Dictation"
                ))
            }
        }
    }
}
