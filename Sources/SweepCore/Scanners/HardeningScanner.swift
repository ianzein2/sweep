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

        progress?.update("checking XProtect / MRT freshness")
        checkXProtectFreshness(findings: &findings, errors: &errors)

        progress?.update("checking Signed System Volume (SSV) integrity")
        checkSignedSystemVolume(findings: &findings, errors: &errors)

        progress?.update("checking Safari auto-open of downloaded files")
        checkSafariAutoOpenDownloads(findings: &findings, errors: &errors)

        progress?.update("checking Terminal Secure Keyboard Entry")
        checkTerminalSecureKeyboardEntry(findings: &findings, errors: &errors)

        progress?.update("checking Wi-Fi auto-join for known open networks")
        checkWiFiOpenAutoJoin(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine encryption / freshness")
        checkTimeMachineBackups(findings: &findings, errors: &errors)

        progress?.update("checking Background Task Management state")
        checkBackgroundTaskManagement(findings: &findings, errors: &errors)

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

    // MARK: - XProtect / MRT Freshness

    private func checkXProtectFreshness(findings: inout [Finding], errors: inout [String]) {
        // Apple ships silent signature updates for XProtect (bundle version) and XProtect
        // Remediator. If the last modification is very old, either signature updates are
        // disabled/blocked or the machine has been offline — both delay defenses for
        // actively exploited macOS malware families.
        let candidates = [
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
            "/Library/Apple/System/Library/CoreServices/XProtect.app",
            "/System/Library/CoreServices/XProtect.bundle",
        ]
        let fm = FileManager.default
        var newest: Date?
        var newestPath: String?
        for path in candidates where fm.fileExists(atPath: path) {
            if let attrs = try? fm.attributesOfItem(atPath: path),
               let modDate = attrs[.modificationDate] as? Date {
                if newest == nil || modDate > newest! {
                    newest = modDate
                    newestPath = path
                }
            }
        }

        guard let modDate = newest, let modPath = newestPath else { return }
        let ageDays = -modDate.timeIntervalSinceNow / 86400
        if ageDays > 60 {
            findings.append(Finding(
                severity: ageDays > 180 ? .high : .medium,
                category: .hardening,
                title: "XProtect signatures are stale (\(Int(ageDays)) days old)",
                detail: "XProtect bundle last updated \(Int(ageDays)) days ago — Apple usually ships new IOCs every 1-3 weeks",
                path: modPath,
                remediation: "Ensure network access to Apple, then: sudo /usr/sbin/softwareupdate --background-critical"
            ))
        }
    }

    // MARK: - Signed System Volume (SSV) Integrity

    private func checkSignedSystemVolume(findings: inout [Finding], errors: inout [String]) {
        // macOS Big Sur+ ships the OS on a cryptographically sealed Signed System Volume.
        // If `csrutil authenticated-root` is disabled, an attacker or careless admin has
        // broken the seal — a HIGH-severity hardening regression that also blocks OS updates.
        let result = ShellRunner.run("/usr/bin/csrutil",
                                     arguments: ["authenticated-root", "status"], timeout: 5)
        if result.success {
            let lower = result.stdout.lowercased()
            if lower.contains("disabled") {
                findings.append(Finding(
                    severity: .high, category: .systemIntegrity,
                    title: "Signed System Volume (SSV) is disabled",
                    detail: "csrutil authenticated-root is off — the OS is no longer cryptographically sealed against tampering",
                    path: nil,
                    remediation: "Re-seal from Recovery: boot into Recovery, open Terminal, run: csrutil authenticated-root enable"
                ))
            }
        }
    }

    // MARK: - Safari Auto-Open of "Safe" Downloads

    private func checkSafariAutoOpenDownloads(findings: inout [Finding], errors: inout [String]) {
        // Safari's "Open safe files after downloading" auto-mounts DMGs and auto-extracts
        // ZIPs, which has repeatedly been abused (recent 2024-2025 stealer chains such as
        // ClickFix and FrigidStealer social-engineer users into downloading a DMG that
        // then autoruns installers). Recommend disabling.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.Safari", "AutoOpenSafeDownloads"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Safari auto-opens \"safe\" downloads",
                    detail: "AutoOpenSafeDownloads=1 — DMGs and ZIPs auto-mount/extract after download, abused by recent macOS stealer campaigns",
                    path: nil,
                    remediation: "Disable: Safari > Settings > General > uncheck \"Open ‘safe’ files after downloading\""
                ))
            }
        }
    }

    // MARK: - Terminal Secure Keyboard Entry

    private func checkTerminalSecureKeyboardEntry(findings: inout [Finding], errors: inout [String]) {
        // Terminal's "Secure Keyboard Entry" prevents other apps (including Accessibility-
        // authorized keyloggers and event taps) from reading keystrokes typed into Terminal.
        // Off by default; enabling is a cheap, high-value defense on developer machines.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.Terminal", "SecureKeyboardEntry"
        ], timeout: 5)
        // Absent-or-0 both mean "off". Only surface as LOW — this is guidance, not a fault.
        if !result.success || result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "1" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Terminal Secure Keyboard Entry is off",
                detail: "Other apps (including keyloggers with Accessibility permission) can read keystrokes typed in Terminal",
                path: nil,
                remediation: "Enable: open Terminal > Terminal menu > Secure Keyboard Entry"
            ))
        }
    }

    // MARK: - Wi-Fi Auto-Join Open Networks

    private func checkWiFiOpenAutoJoin(findings: inout [Finding], errors: inout [String]) {
        // Auto-joining known networks is fine; auto-joining OPEN networks with the same
        // SSID as ones you've used before is how rogue-AP attacks (Karma, Wifi Pineapple)
        // hijack traffic. Flag if the "auto-join" hotspot list is populated but this is
        // best expressed as a check on the "AutoJoinDisabled" flag.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.wifi.known-networks.plist"
        ], timeout: 5)
        // If we can't read the file (SIP-protected on modern macOS), skip silently.
        guard result.success else { return }

        // Count networks whose SecurityType is "Open"; each is an auto-join Rogue-AP risk.
        let output = result.stdout
        let openHits = output.components(separatedBy: "SecurityType").filter {
            $0.hasPrefix(" = \"Open\";") || $0.hasPrefix(" = Open;")
        }.count
        if openHits > 0 {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "\(openHits) open Wi-Fi network(s) set to auto-join",
                detail: "Open networks in your saved list auto-connect on match — a rogue access point can spoof the SSID and MITM your traffic",
                path: nil,
                remediation: "Review: System Settings > Wi-Fi > … next to each open network > \"Auto-Join\": Off"
            ))
        }
    }

    // MARK: - Time Machine Backup Freshness

    private func checkTimeMachineBackups(findings: inout [Finding], errors: inout [String]) {
        // Ransomware families targeting macOS (recently: NotLockBit, TurtleRAT) rely on the
        // victim having no working recovery point. A stale Time Machine backup means recovery
        // from a ransomware or stealer incident may not be possible.
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["latestbackup"], timeout: 10)
        if result.success {
            let out = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if out.isEmpty || out.lowercased().contains("no machine directory") {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "No Time Machine backups found",
                    detail: "tmutil reports no backups — without a snapshot, ransomware or drive failure means data loss",
                    path: nil,
                    remediation: "Set up a Time Machine destination: System Settings > General > Time Machine"
                ))
                return
            }
        }

        // Local snapshots freshness: `tmutil listlocalsnapshots /` should return one per day.
        let snaps = ShellRunner.run("/usr/bin/tmutil",
                                    arguments: ["listlocalsnapshots", "/"], timeout: 10)
        if snaps.success {
            let lines = snaps.stdout.split(separator: "\n")
                .map { String($0).trimmingCharacters(in: .whitespaces) }
                .filter { $0.hasPrefix("com.apple.TimeMachine.") }
            if lines.isEmpty {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "No local Time Machine snapshots present",
                    detail: "APFS local snapshots let you roll back the disk without an external drive — none exist right now",
                    path: nil,
                    remediation: "Enable Time Machine so local snapshots are created: System Settings > General > Time Machine"
                ))
            }
        }
    }

    // MARK: - Background Task Management (macOS Ventura+)

    private func checkBackgroundTaskManagement(findings: inout [Finding], errors: inout [String]) {
        // macOS 13+ tracks every persistent background item (LaunchAgents, LaunchDaemons,
        // login items) in a system database (`sfltool`). Malware families like Adload
        // and FlexibleFerret rely on users not noticing new entries. Surface the count
        // when it is unusually high — a rough proxy for "look at what's set to auto-launch".
        //
        // We can't parse the internal database, but we can read the total count from
        // `sfltool dumpbtm`; failing that, we fall back to counting user-installed
        // LaunchAgents which is what BTM entries roughly cover.
        let btm = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 10)
        if btm.success {
            let items = btm.stdout.components(separatedBy: "\nRecord type: ")
            // First split segment is the header; each subsequent segment is one BTM record.
            let total = max(items.count - 1, 0)
            if total > 40 {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Large number of Background Items (\(total))",
                    detail: "Background Task Management is tracking \(total) launch/login items — recent stealers hide as extra items here",
                    path: nil,
                    remediation: "Review: System Settings > General > Login Items & Extensions"
                ))
            }
            return
        }

        // sfltool requires elevated privileges on some macOS versions; fall back to a rough
        // headcount of user LaunchAgents.
        let home = ShellRunner.realUserHome
        let userAgents = "\(home)/Library/LaunchAgents"
        if let count = try? FileManager.default.contentsOfDirectory(atPath: userAgents)
            .filter({ $0.hasSuffix(".plist") }).count, count > 15 {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Many user LaunchAgents (\(count))",
                detail: "Login/background items are tracked by Background Task Management (macOS Ventura+) — a high count may hide unwanted entries",
                path: userAgents,
                remediation: "Review: System Settings > General > Login Items & Extensions"
            ))
        }
    }
}
