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

        progress?.update("checking SSH server config")
        checkSSHServerConfig(findings: &findings, errors: &errors)

        progress?.update("checking Terminal secure keyboard entry")
        checkTerminalSecureKeyboardEntry(findings: &findings, errors: &errors)

        progress?.update("checking Personal Hotspot")
        checkPersonalHotspot(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine backups")
        checkTimeMachine(findings: &findings, errors: &errors)

        progress?.update("checking macOS background items")
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
        // Find My Mac is a critical anti-theft control: without it, a lost or stolen Mac cannot be
        // remotely locked or erased. We can't reliably read the iCloud account state without
        // entitlements, but we can detect whether the locationd daemon has the iCloud Find My
        // client enrolled via the MobileMeAccounts plist.
        let home = ShellRunner.realUserHome
        let mmePlist = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard let data = FileManager.default.contents(atPath: mmePlist),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let accounts = plist["Accounts"] as? [[String: Any]] else {
            // Not signed into iCloud — informational only
            return
        }

        var findMyEnabled = false
        for acct in accounts {
            if let services = acct["Services"] as? [[String: Any]] {
                for svc in services {
                    if let name = svc["Name"] as? String,
                       name == "FIND_MY_MAC",
                       (svc["Enabled"] as? Bool == true || svc["Enabled"] as? Int == 1) {
                        findMyEnabled = true
                    }
                }
            }
        }

        if !findMyEnabled {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is disabled",
                detail: "iCloud is configured but Find My Mac is not enabled — a stolen Mac cannot be remotely locked or erased",
                path: nil,
                remediation: "Enable: System Settings > [Your Name] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - SSH Server Config (sshd_config)

    private func checkSSHServerConfig(findings: inout [Finding], errors: inout [String]) {
        // If SSH (Remote Login) is on, sshd_config controls who can connect and how. Risky settings
        // like `PermitRootLogin yes` or `PasswordAuthentication yes` materially weaken the box.
        let configPaths = ["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
        var configContent: String?
        var foundPath: String?
        for path in configPaths {
            if let content = try? String(contentsOfFile: path, encoding: .utf8) {
                configContent = content
                foundPath = path
                break
            }
        }
        guard let content = configContent, let configPath = foundPath else { return }

        // Parse simple "key value" directives, skipping commented lines.
        var settings: [String: String] = [:]
        for rawLine in content.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.components(separatedBy: CharacterSet.whitespaces)
                .filter { !$0.isEmpty }
            guard parts.count >= 2 else { continue }
            settings[parts[0].lowercased()] = parts[1].lowercased()
        }

        // PermitRootLogin yes lets attackers brute-force root directly. Default on modern macOS is
        // "no" or "prohibit-password" — "yes" is a deliberate weakening.
        if let permitRoot = settings["permitrootlogin"], permitRoot == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH allows direct root login",
                detail: "sshd_config has PermitRootLogin=yes — attackers can attempt to log in as root over SSH",
                path: configPath,
                remediation: "Change to 'no' or 'prohibit-password' in \(configPath), then: sudo launchctl stop com.openssh.sshd"
            ))
        }

        // PasswordAuthentication yes leaves the door open to credential brute-force from the network.
        // Apple's default for the bundled sshd is `yes`, so we only escalate if Remote Login is ON.
        let sshRunning = ShellRunner.run("/usr/sbin/systemsetup",
                                         arguments: ["-getremotelogin"], timeout: 5)
        let sshIsOn = sshRunning.success && sshRunning.stdout.lowercased().contains(": on")

        if sshIsOn {
            // PasswordAuthentication defaults to yes when unset
            let passAuth = settings["passwordauthentication"] ?? "yes"
            if passAuth == "yes" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "SSH allows password authentication",
                    detail: "Remote Login is enabled and sshd_config permits password auth — keys-only is recommended",
                    path: configPath,
                    remediation: "Set 'PasswordAuthentication no' in \(configPath) after adding a key to ~/.ssh/authorized_keys"
                ))
            }

            // ChallengeResponseAuthentication / KbdInteractiveAuthentication can also accept passwords
            let kbdAuth = settings["kbdinteractiveauthentication"] ?? settings["challengeresponseauthentication"] ?? "no"
            if kbdAuth == "yes" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "SSH allows keyboard-interactive authentication",
                    detail: "KbdInteractiveAuthentication is enabled — typically used for PAM-driven password prompts",
                    path: configPath,
                    remediation: "If using keys, set 'KbdInteractiveAuthentication no' in \(configPath)"
                ))
            }

            // PermitEmptyPasswords yes would allow accounts with blank passwords to log in — never expected
            if let emptyPass = settings["permitemptypasswords"], emptyPass == "yes" {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "SSH allows empty passwords",
                    detail: "sshd_config has PermitEmptyPasswords=yes — accounts without a password can log in remotely",
                    path: configPath,
                    remediation: "Set 'PermitEmptyPasswords no' in \(configPath) immediately"
                ))
            }
        }
    }

    // MARK: - Terminal Secure Keyboard Entry

    private func checkTerminalSecureKeyboardEntry(findings: inout [Finding], errors: inout [String]) {
        // Secure Keyboard Entry tells macOS to deny event-tap access to the Terminal window, blocking
        // keyloggers from capturing things typed into shells (including SSH sessions and sudo prompts).
        // It's off by default. We check Apple Terminal here — iTerm2 has its own setting.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.Terminal", "SecureKeyboardEntry"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Terminal Secure Keyboard Entry is off",
                    detail: "Apple Terminal isn't blocking event-tap keyloggers from reading keystrokes typed in the shell",
                    path: nil,
                    remediation: "Enable in Terminal > Secure Keyboard Entry (menu), or: defaults write com.apple.Terminal SecureKeyboardEntry -bool true"
                ))
            }
        } else {
            // Key not present at all means default (off) — surface only on machines that use Terminal
            // We don't want to nag if Terminal has never been opened, so only flag if the prefs file exists.
            let plist = "\(ShellRunner.realUserHome)/Library/Preferences/com.apple.Terminal.plist"
            if FileManager.default.fileExists(atPath: plist) {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Terminal Secure Keyboard Entry is off (default)",
                    detail: "Recommended for keylogger defense when typing passwords in the shell",
                    path: nil,
                    remediation: "Enable in Terminal > Secure Keyboard Entry (menu), or: defaults write com.apple.Terminal SecureKeyboardEntry -bool true"
                ))
            }
        }
    }

    // MARK: - Personal Hotspot

    private func checkPersonalHotspot(findings: inout [Finding], errors: inout [String]) {
        // Personal Hotspot turns the Mac into a Wi-Fi access point sharing the cellular/iCloud
        // connection. An open hotspot is a meaningful exposure on untrusted networks.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.MobileBluetooth.services.personalhotspot", "PersonalHotspotEnabled"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Personal Hotspot is enabled",
                    detail: "Mac is sharing its internet via Wi-Fi — make sure it has a strong WPA2/3 password",
                    path: nil,
                    remediation: "Disable when not needed: System Settings > General > Sharing > Internet Sharing"
                ))
            }
        }
    }

    // MARK: - Time Machine

    private func checkTimeMachine(findings: inout [Finding], errors: inout [String]) {
        // Time Machine backups are the single best defense against macOS ransomware (NotLockBit etc.).
        // We flag absence as a hardening gap, not an active threat.
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 5)
        guard result.success else { return }

        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if output.isEmpty || output.contains("No destinations configured") {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "No Time Machine backup destination is configured",
                detail: "Without a backup, ransomware (NotLockBit and others) leaves no recovery path",
                path: nil,
                remediation: "Configure: System Settings > General > Time Machine > Add Backup Disk"
            ))
            return
        }

        // Check last backup recency (any destination)
        let latestResult = ShellRunner.run("/usr/bin/tmutil", arguments: ["latestbackup"], timeout: 5)
        if latestResult.success {
            let path = latestResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !path.isEmpty {
                // Parse a date from the snapshot path (Apple uses YYYY-MM-DD-HHMMSS in snapshot names)
                if let match = path.range(of: #"\d{4}-\d{2}-\d{2}"#, options: .regularExpression) {
                    let dateStr = String(path[match])
                    let fmt = DateFormatter()
                    fmt.dateFormat = "yyyy-MM-dd"
                    if let backupDate = fmt.date(from: dateStr) {
                        let daysSince = Calendar.current.dateComponents([.day], from: backupDate, to: Date()).day ?? 0
                        if daysSince > 14 {
                            findings.append(Finding(
                                severity: .low, category: .hardening,
                                title: "Last Time Machine backup was \(daysSince) days ago",
                                detail: "Backups exist but the most recent one is stale — connect your backup disk",
                                path: nil,
                                remediation: "Plug in your Time Machine disk and run: tmutil startbackup --auto"
                            ))
                        }
                    }
                }
            }
        }
    }

    // MARK: - macOS Background Items (SMAppService, macOS 13+)

    private func checkBackgroundItems(findings: inout [Finding], errors: inout [String]) {
        // macOS Ventura introduced "Login & Background Items" managed via SMAppService.
        // These are a modern persistence mechanism — sfltool dumps the registry. We don't
        // know the user's "expected" list, so we surface counts and any items that resolve to
        // hidden or temp paths (a strong spyware indicator).
        let result = ShellRunner.run("/usr/bin/sfltool",
                                     arguments: ["dumpbtm"], timeout: 10)
        guard result.success && !result.stdout.isEmpty else { return }

        // sfltool prints item records in the form:
        //   Name:    <name>
        //   URL:     file:///path/to/thing
        //   Type:    ...
        var currentItem: (name: String, url: String)?
        var hiddenOrTempItems: [(name: String, url: String)] = []

        for rawLine in result.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Name:") {
                if let item = currentItem, isSuspiciousBackgroundItemURL(item.url) {
                    hiddenOrTempItems.append(item)
                }
                currentItem = (name: line.replacingOccurrences(of: "Name:", with: "").trimmingCharacters(in: .whitespaces),
                               url: "")
            } else if line.hasPrefix("URL:") {
                currentItem?.url = line.replacingOccurrences(of: "URL:", with: "").trimmingCharacters(in: .whitespaces)
            }
        }
        // Flush last
        if let item = currentItem, isSuspiciousBackgroundItemURL(item.url) {
            hiddenOrTempItems.append(item)
        }

        for item in hiddenOrTempItems.prefix(10) {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Background item points to hidden or temp path",
                detail: "Item: \(item.name) — URL: \(item.url)",
                path: nil,
                remediation: "Review in System Settings > General > Login Items & Extensions > Allow in the Background, then remove if unexpected"
            ))
        }
    }

    private func isSuspiciousBackgroundItemURL(_ url: String) -> Bool {
        guard !url.isEmpty else { return false }
        let lower = url.lowercased()
        // Background items registered from temp dirs or hidden paths are almost never legitimate
        if lower.contains("/private/tmp/") || lower.contains("/private/var/tmp/") ||
           lower.contains("/tmp/") || lower.contains("/var/tmp/") {
            return true
        }
        // Hidden path components after the scheme (file:///Users/x/.foo/bar)
        let stripped = lower.replacingOccurrences(of: "file://", with: "")
        for component in stripped.split(separator: "/") {
            let c = String(component)
            if c.hasPrefix(".") && c != "." && c != ".." {
                return true
            }
        }
        return false
    }
}
