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

        progress?.update("checking Private Wi-Fi Address randomization")
        checkPrivateWiFiAddress(findings: &findings, errors: &errors)

        progress?.update("checking iCloud Private Relay state")
        checkPrivateRelay(findings: &findings, errors: &errors)

        progress?.update("checking Safari Advanced Fingerprinting Protection")
        checkSafariFingerprintingProtection(findings: &findings, errors: &errors)

        progress?.update("checking Apple Silicon LocalPolicy (bputil)")
        checkApplePolicyBoot(findings: &findings, errors: &errors)

        progress?.update("checking Background Task Management inventory")
        checkBackgroundTaskInventory(findings: &findings, errors: &errors)

        progress?.update("checking Gatekeeper assessment state")
        checkGatekeeperState(findings: &findings, errors: &errors)

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
        // Tahoe 26.1 rebranded this as "Background Security Improvements" (BSI); the underlying
        // CriticalUpdateInstall pref still gates both.
        let rsrInstall = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"
        ], timeout: 5)
        if rsrInstall.success {
            let value = rsrInstall.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Automatic install of security responses is disabled",
                    detail: "Rapid Security Responses / Background Security Improvements patch actively " +
                            "exploited bugs — leaving this off delays urgent fixes",
                    path: nil,
                    remediation: "Enable: System Settings > General > Software Update > (i) > Install Security Responses and system files"
                ))
            }
        }
    }

    // MARK: - Private Wi-Fi Address (Sequoia)
    //
    // Sequoia added per-SSID MAC randomization with a system-wide kill switch in
    // /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist.
    // When the kill switch is set, every Wi-Fi network sees the Mac's hardware MAC,
    // re-enabling cross-network tracking.
    // https://www.brunerd.com/blog/2024/09/27/getting-ahead-of-private-wi-fi-address-changes-in-macos-sequoia/
    private func checkPrivateWiFiAddress(findings: inout [Finding], errors: inout [String]) {
        let plist = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
        guard let data = FileManager.default.contents(atPath: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return
        }

        // "1" / true = system-wide kill switch ON (insecure: randomization disabled).
        let killSwitch = (dict["PrivateMACAddressModeSystemSetting"] as? Int ?? 0) == 1 ||
                         (dict["PrivateMACAddressModeSystemSetting"] as? Bool ?? false)
        if killSwitch {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Private Wi-Fi Address (MAC randomization) is disabled system-wide",
                detail: "Mac broadcasts its real hardware MAC address on every Wi-Fi network, " +
                        "enabling cross-network tracking",
                path: plist,
                remediation: "Re-enable: System Settings > Wi-Fi > (i next to network) > Private Wi-Fi Address"
            ))
        }
    }

    // MARK: - iCloud Private Relay
    //
    // Private Relay proxies Safari and unencrypted traffic through Apple+partner relays,
    // hiding the user's IP. An admin-set `DisablePrivateRelay` flag turns it off entirely.
    // https://www.brunerd.com/blog/2022/09/27/determining-icloud-private-relay-and-limit-ip-tracking-status-in-macos/
    private func checkPrivateRelay(findings: inout [Finding], errors: inout [String]) {
        let prefs = "/Library/Preferences/SystemConfiguration/preferences.plist"
        guard let data = FileManager.default.contents(atPath: prefs),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return
        }
        let disabled = (dict["DisablePrivateRelay"] as? Int ?? 0) == 1 ||
                       (dict["DisablePrivateRelay"] as? Bool ?? false)
        if disabled {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "iCloud Private Relay is administratively disabled",
                detail: "Outbound Safari/unencrypted traffic shows the Mac's real public IP " +
                        "and is not proxied through Apple's relay network",
                path: prefs,
                remediation: "If not required by your network admin, re-enable: System Settings > Apple ID > iCloud > Private Relay"
            ))
        }
    }

    // MARK: - Safari Advanced Fingerprinting Protection (Tahoe / Sequoia)
    //
    // Tahoe 26 made Advanced Fingerprinting Protection the default for all browsing; the
    // user-facing scope can still be set to Disabled / Trackers Only / All.
    // https://lapcatsoftware.com/articles/2025/9/4.html
    private func checkSafariFingerprintingProtection(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.Safari", "WBSPrivacyProxyAvailabilityTraffic"
        ], timeout: 5)
        guard result.success else { return }

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        // The integer values Apple uses for the three scopes:
        //   66976992 = Disabled, 66976996 = Trackers Only, 66977004 = Trackers and Websites.
        if value == "66976992" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Safari Advanced Fingerprinting Protection is disabled",
                detail: "Safari's fingerprinting defenses are turned off across all browsing modes",
                path: nil,
                remediation: "Enable: Safari > Settings > Advanced > Advanced Fingerprinting Protection > Trackers and Websites"
            ))
        }
    }

    // MARK: - Apple Silicon LocalPolicy (bputil)
    //
    // The Apple Silicon equivalent of "SIP off" is a Reduced/Permissive Security boot
    // policy: it allows unsigned kexts, arbitrary kernels, and disables boot-args
    // filtering. bputil -d is the only way to read this; the call is harmless and
    // password-free for non-mutating reads but does require root.
    // https://github.com/ernw/hardening/blob/master/operating_system/osx/26/Hardening_Guide-macOS_26_Tahoe_1.0.md
    private func checkApplePolicyBoot(findings: inout [Finding], errors: inout [String]) {
        // Skip on Intel Macs (no bputil) and as non-root (read access denied).
        guard getuid() == 0 else { return }
        guard FileManager.default.fileExists(atPath: "/usr/bin/bputil") else { return }

        let result = ShellRunner.run("/usr/bin/bputil", arguments: ["-d"], timeout: 5)
        guard result.success else { return }

        let stdout = result.stdout
        // bputil prints "Security Mode: 1 (Full)" for Full Security, lower values are reduced.
        let isFull = stdout.contains("Security Mode: 1") ||
                     stdout.lowercased().contains("full security")
        if !isFull && stdout.contains("Security Mode") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Apple Silicon boot security is reduced",
                detail: "LocalPolicy is not in Full Security mode — unsigned kexts, custom kernels, " +
                        "or boot-arg filtering bypass may be permitted",
                path: nil,
                remediation: "Restore Full Security from recoveryOS: Startup Security Utility > Full Security"
            ))
        }

        // 3rd-party kext approval is also a major hardening regression.
        if stdout.contains("3rd Party Kexts Status") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Apple Silicon allows user-approved 3rd-party kexts",
                detail: "Boot policy permits loading non-Apple kernel extensions — broadens kernel attack surface",
                path: nil,
                remediation: "Disable from recoveryOS Startup Security Utility unless a specific kext is required"
            ))
        }
    }

    // MARK: - Background Task Management (BTM) inventory via sfltool
    //
    // BTM is the system of record for login items, LaunchAgents, LaunchDaemons, and
    // legacy persistence registered via SMAppService. Any persistence Sweep wants to
    // surface via Apple's own ledger flows through `sfltool dumpbtm`. We only flag if
    // sfltool succeeds and we see non-Apple entries from user-writable paths.
    // https://eclecticlight.co/2025/12/03/manage-login-and-background-items/
    private func checkBackgroundTaskInventory(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 10)
        guard result.success && !result.stdout.isEmpty else { return }

        // sfltool dumps a human-readable record block per item. Look for enabled records
        // whose executable URL lives under /Users/, /tmp/, or /private/tmp/.
        let lines = result.stdout.components(separatedBy: "\n")
        var current: [String] = []
        var enabledUserItems = 0

        for line in lines {
            if line.trimmingCharacters(in: .whitespaces).isEmpty {
                if shouldFlagBTMRecord(current) { enabledUserItems += 1 }
                current.removeAll()
            } else {
                current.append(line)
            }
        }
        if shouldFlagBTMRecord(current) { enabledUserItems += 1 }

        if enabledUserItems > 0 {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Background Items registered from user-writable locations (\(enabledUserItems))",
                detail: "sfltool dumpbtm reports enabled background items whose executable lives in " +
                        "/Users, /tmp, or /private/tmp — these are common persistence locations for stealers",
                path: nil,
                remediation: "Review: sudo sfltool dumpbtm | less — disable unrecognised items in " +
                             "System Settings > General > Login Items & Extensions"
            ))
        }
    }

    private func shouldFlagBTMRecord(_ record: [String]) -> Bool {
        // Each record block contains lines like "Name: ...", "Path: ...", "Disposition: enabled".
        guard !record.isEmpty else { return false }
        let joined = record.joined(separator: "\n").lowercased()
        guard joined.contains("disposition") && joined.contains("enabled") else { return false }
        // Apple-issued items live under /System/, /Library/Apple/, or have team ID == Apple.
        if joined.contains("team identifier: apple") { return false }
        // Hits if any path field references a user-writable area.
        let suspiciousRoots = ["/users/", "/private/tmp/", "/tmp/"]
        return suspiciousRoots.contains { joined.contains($0) }
    }

    // MARK: - Gatekeeper assessment state
    //
    // `spctl --status` should always say "assessments enabled". On older macOS versions
    // (pre-Sequoia) `spctl --master-disable` could turn the whole subsystem off; even
    // post-upgrade, an inherited disabled state silently allows any binary to launch.
    private func checkGatekeeperState(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status"], timeout: 5)
        guard result.success else { return }
        if result.stdout.lowercased().contains("assessments disabled") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Gatekeeper assessments are disabled",
                detail: "macOS will not verify code signatures or notarisation for downloaded apps",
                path: nil,
                remediation: "Re-enable: sudo spctl --global-enable (then sudo spctl --master-enable on older macOS)"
            ))
        }
    }
}
