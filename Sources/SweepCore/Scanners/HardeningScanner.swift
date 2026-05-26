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

        progress?.update("checking macOS end-of-life status")
        checkMacOSEndOfLife(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine encryption")
        checkTimeMachineEncryption(findings: &findings, errors: &errors)

        progress?.update("checking FileVault recovery key escrow")
        checkFileVaultRecoveryKey(findings: &findings, errors: &errors)

        progress?.update("checking XProtect Remediator scan recency")
        checkXProtectRemediatorScans(findings: &findings, errors: &errors)

        progress?.update("checking secure keyboard entry in Terminal")
        checkSecureKeyboardEntry(findings: &findings, errors: &errors)

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

    // MARK: - macOS End-of-Life
    //
    // Apple stops shipping security patches for macOS major versions roughly three years after
    // release. Running an EOL macOS is one of the highest-impact security exposures a Mac can have,
    // because public exploits (including kernel & WebKit RCEs) accumulate that Apple no longer fixes.

    private func checkMacOSEndOfLife(findings: inout [Finding], errors: inout [String]) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let major = v.majorVersion

        // Stop-shipping-security-patches major versions (approximate — Apple does not publish a formal
        // EOL date, but historically only the latest three majors receive patches). Adjust as new macOS
        // ships. As of late 2025 the supported set is roughly Sonoma (14), Sequoia (15), Tahoe (16).
        struct VersionInfo {
            let name: String
            let supported: Bool
            let note: String
        }
        let map: [Int: VersionInfo] = [
            10: VersionInfo(name: "macOS 10.x (Sierra–Catalina)", supported: false,
                            note: "EOL — no security patches. Public kernel and Safari exploits exist."),
            11: VersionInfo(name: "macOS 11 Big Sur", supported: false,
                            note: "EOL — Apple stopped shipping security updates in 2023."),
            12: VersionInfo(name: "macOS 12 Monterey", supported: false,
                            note: "EOL — Apple stopped shipping security updates in late 2024."),
            13: VersionInfo(name: "macOS 13 Ventura", supported: false,
                            note: "End-of-life: no longer receiving regular security patches."),
            14: VersionInfo(name: "macOS 14 Sonoma", supported: true, note: ""),
            15: VersionInfo(name: "macOS 15 Sequoia", supported: true, note: ""),
            16: VersionInfo(name: "macOS 16 Tahoe", supported: true, note: ""),
        ]

        if let info = map[major] {
            if !info.supported {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "\(info.name) no longer receives security patches",
                    detail: "\(info.note) Running an unsupported macOS major version is a top-tier risk — public 0days are not backported.",
                    path: nil,
                    remediation: "Upgrade to a currently supported macOS via System Settings > General > Software Update. If your hardware can't run a newer macOS, consider replacement — patch-free Macs are a known target for stealer campaigns."
                ))
            }
        } else if major < 10 {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Very old macOS version (\(major).\(v.minorVersion))",
                detail: "macOS major version \(major) is years past EOL.",
                path: nil,
                remediation: "Upgrade or replace this Mac."
            ))
        }
    }

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // The presence of a com.apple.icloud.findmydeviced launchd job is a heuristic for Find My being
        // enabled; we can't query the iCloud state directly without entitlements. If the user account
        // looks signed-in to iCloud (presence of MobileMeAccounts.plist) but findmydeviced is absent,
        // flag it — anyone with physical access can wipe and re-pair the Mac.
        let home = ShellRunner.realUserHome
        let mobileMe = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard FileManager.default.fileExists(atPath: mobileMe) else {
            // No iCloud account signed in — out of scope, do not flag.
            return
        }

        let launchctl = ShellRunner.run("/bin/launchctl", arguments: ["list"], timeout: 5)
        let listOutput = launchctl.success ? launchctl.stdout : ""
        let hasFindMy = listOutput.contains("com.apple.icloud.findmydeviced") ||
                        listOutput.contains("com.apple.findmymacd") ||
                        listOutput.contains("com.apple.icloud.searchpartyd")

        if !hasFindMy {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac appears to be disabled",
                detail: "iCloud is signed in but no Find My daemon is running — a stolen or lost Mac cannot be located, locked, or remotely erased.",
                path: nil,
                remediation: "Enable: System Settings > [your name] > iCloud > Find My Mac. This also turns on Activation Lock on Apple-silicon Macs."
            ))
        }
    }

    // MARK: - Time Machine encryption
    //
    // Time Machine snapshots contain a near-complete copy of the user's files; an unencrypted
    // backup volume undermines FileVault entirely. tmutil doesn't report encryption directly, so
    // we read the destination's mount point and ask diskutil whether the underlying volume is
    // FileVault-encrypted.

    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // Each destination block is separated by "====" lines; within a block we want "Name" and "Mount Point".
        let blocks = result.stdout.components(separatedBy: "====")
        for block in blocks {
            let trimmed = block.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.contains("Name") else { continue }

            var destName = "Time Machine destination"
            var mountPoint: String?
            for line in trimmed.split(separator: "\n") {
                let l = String(line).trimmingCharacters(in: .whitespaces)
                if l.hasPrefix("Name") {
                    let parts = l.split(separator: ":", maxSplits: 1)
                    if parts.count == 2 {
                        destName = String(parts[1]).trimmingCharacters(in: .whitespaces)
                    }
                } else if l.hasPrefix("Mount Point") {
                    let parts = l.split(separator: ":", maxSplits: 1)
                    if parts.count == 2 {
                        mountPoint = String(parts[1]).trimmingCharacters(in: .whitespaces)
                    }
                }
            }

            // Network destinations (Time Capsule, NAS) don't have a local mount point and have
            // their own encryption settings; we can't probe them remotely, so skip.
            guard let mount = mountPoint, !mount.isEmpty else { continue }

            let info = ShellRunner.run("/usr/sbin/diskutil", arguments: ["info", mount], timeout: 10)
            guard info.success else { continue }

            // diskutil info reports "FileVault: Yes" / "FileVault: No" for APFS volumes, and
            // "Encrypted: Yes" for legacy CoreStorage. Treat either as encrypted.
            let out = info.stdout
            let encrypted = out.contains("FileVault:                 Yes") ||
                            out.contains("FileVault:          Yes") ||
                            out.contains("Encrypted:                 Yes") ||
                            out.contains("Encrypted:          Yes")
            if !encrypted {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "Time Machine destination '\(destName)' is not encrypted",
                    detail: "Backup volume at \(mount) is not FileVault-encrypted. Backups contain near-complete copies of your files; an unencrypted backup undermines FileVault on the source.",
                    path: mount,
                    remediation: "Remove the destination, then re-add it with 'Encrypt Backups' enabled: System Settings > General > Time Machine."
                ))
            }
        }
    }

    // MARK: - FileVault recovery key escrow / institutional key

    private func checkFileVaultRecoveryKey(findings: inout [Finding], errors: inout [String]) {
        // If FileVault is on, the user should have a recovery key set up. fdesetup reports recovery
        // status — we don't print the key, only its presence.
        let status = ShellRunner.run("/usr/bin/fdesetup", arguments: ["status"], timeout: 5)
        guard status.success, status.stdout.contains("FileVault is On") else { return }

        // Check if an institutional / personal recovery key exists.
        let hasInstitutional = ShellRunner.run("/usr/bin/fdesetup",
                                               arguments: ["hasinstitutionalrecoverykey"], timeout: 5)
        let hasPersonal = ShellRunner.run("/usr/bin/fdesetup",
                                          arguments: ["haspersonalrecoverykey"], timeout: 5)

        let hasAnyKey = (hasInstitutional.success && hasInstitutional.stdout.contains("true")) ||
                        (hasPersonal.success && hasPersonal.stdout.contains("true"))

        if !hasAnyKey {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "FileVault has no recovery key on file",
                detail: "FileVault is enabled but no personal or institutional recovery key is registered. If you forget your password, the disk is unrecoverable.",
                path: nil,
                remediation: "Generate one: sudo fdesetup changerecovery -personal. Store the key in a password manager — not on the same Mac."
            ))
        }
    }

    // MARK: - XProtect Remediator scan recency

    private func checkXProtectRemediatorScans(findings: inout [Finding], errors: inout [String]) {
        // XProtect Remediator (macOS 13+) runs hourly-ish scans for known stealer families and logs the
        // last-run time per scanner under com.apple.XProtectFramework.PluginService. If the last
        // scan is unusually old, definitions may be stale or the service is being suppressed.
        let prefsPath = "/Library/Preferences/com.apple.XProtectFramework.PluginService.plist"
        let fm = FileManager.default
        guard fm.fileExists(atPath: prefsPath) else { return }

        guard let attrs = try? fm.attributesOfItem(atPath: prefsPath),
              let modDate = attrs[.modificationDate] as? Date else { return }

        let daysSince = Calendar.current.dateComponents([.day], from: modDate, to: Date()).day ?? 0
        if daysSince > 7 {
            findings.append(Finding(
                severity: daysSince > 30 ? .high : .medium,
                category: .hardening,
                title: "XProtect Remediator hasn't run in \(daysSince) days",
                detail: "Apple's background malware sweeps (XProtect Remediator scanners — Adload, Pirrit, Genieo, ColdSnap, FloppyFlipper, ToyDrop, etc.) appear to have stalled.",
                path: prefsPath,
                remediation: "Reboot, then check Console.app for 'XProtectRemediator' messages. If they remain absent, run: sudo defaults read \(prefsPath) | head"
            ))
        }
    }

    // MARK: - Secure Keyboard Entry in Terminal

    private func checkSecureKeyboardEntry(findings: inout [Finding], errors: inout [String]) {
        // Terminal.app's Secure Keyboard Entry blocks other processes (including keyloggers using
        // CGEvent taps) from reading what you type into a terminal session — including sudo passwords
        // and SSH passphrases. Recommended for anyone who runs admin commands locally.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.Terminal", "SecureKeyboardEntry"
        ], timeout: 5)
        // Default is OFF on stock macOS.
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Terminal.app: Secure Keyboard Entry is disabled",
                    detail: "Other apps with Accessibility / Input Monitoring access can read what you type in Terminal — including sudo passwords and SSH passphrases.",
                    path: nil,
                    remediation: "Enable: Terminal > Secure Keyboard Entry (menu) — or: defaults write com.apple.Terminal SecureKeyboardEntry -bool true"
                ))
            }
        } else {
            // Key not set — default is off
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Terminal.app: Secure Keyboard Entry not set",
                detail: "Defaults to off — other apps with Input Monitoring access could intercept what you type into Terminal.",
                path: nil,
                remediation: "Enable: Terminal > Secure Keyboard Entry (menu)"
            ))
        }
    }
}
