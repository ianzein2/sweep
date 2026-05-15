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

        progress?.update("checking Touch ID for sudo")
        checkSudoTouchID(findings: &findings, errors: &errors)

        progress?.update("checking audit logging")
        checkAuditLogging(findings: &findings, errors: &errors)

        progress?.update("checking kernel boot-args")
        checkSecureBoot(findings: &findings, errors: &errors)

        progress?.update("checking macOS support status")
        checkMacOSSupportStatus(findings: &findings, errors: &errors)

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

    // MARK: - Touch ID for sudo (macOS Sonoma+)

    private func checkSudoTouchID(findings: inout [Finding], errors: inout [String]) {
        // macOS Sonoma+ ships /etc/pam.d/sudo_local.template, which means the platform
        // supports authenticating sudo with Touch ID via /etc/pam.d/sudo_local — a drop-in
        // that survives system updates. /etc/pam.d/sudo, on the other hand, is overwritten on
        // each upgrade, so a pam_tid.so line added there silently disappears and the user
        // thinks Touch ID is on when it isn't. We only run this check on systems where the
        // template file exists (i.e. the feature is supported in the first place).
        let fm = FileManager.default
        guard fm.fileExists(atPath: "/etc/pam.d/sudo_local.template") else { return }

        let sudoLocal = (try? String(contentsOfFile: "/etc/pam.d/sudo_local", encoding: .utf8)) ?? ""
        let sudoMain = (try? String(contentsOfFile: "/etc/pam.d/sudo", encoding: .utf8)) ?? ""

        let hasTid: (String) -> Bool = { content in
            content.split(separator: "\n").contains { line in
                let t = line.trimmingCharacters(in: .whitespaces)
                return !t.hasPrefix("#") && t.contains("pam_tid.so")
            }
        }
        let localHasTid = hasTid(sudoLocal)
        let mainHasTid = hasTid(sudoMain)

        // If only /etc/pam.d/sudo was edited, the next macOS update will silently wipe it.
        if mainHasTid && !localHasTid {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Touch ID for sudo configured in /etc/pam.d/sudo (not persistent)",
                detail: "/etc/pam.d/sudo is overwritten on every macOS update — your Touch ID rule will be lost",
                path: "/etc/pam.d/sudo",
                remediation: "Move the pam_tid.so line into /etc/pam.d/sudo_local (sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local) — survives updates"
            ))
        }
    }

    // MARK: - Audit logging (BSM / auditd)

    private func checkAuditLogging(findings: inout [Finding], errors: inout [String]) {
        // macOS ships BSM audit logging (auditd) which records sudo, login, and authorization events.
        // Apple has been deprecating it but it still ships in macOS 14/15. Forensic investigations
        // depend on these logs — if disabled, you lose the audit trail after a compromise.
        // We only flag this if the audit_control file exists (some lab/clean installs may have removed it).
        let fm = FileManager.default
        guard fm.fileExists(atPath: "/etc/security/audit_control") else { return }

        let launchctl = ShellRunner.run("/bin/launchctl", arguments: ["list"], timeout: 5)
        guard launchctl.success else { return }

        // com.apple.auditd is the audit log daemon — if it isn't loaded, the audit trail is silent.
        let auditdLoaded = launchctl.stdout.contains("com.apple.auditd")
        if !auditdLoaded {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Audit logging (auditd) is not running",
                detail: "BSM audit logs record sudo/login/authorization events — without them, forensic analysis after a compromise is much harder",
                path: "/etc/security/audit_control",
                remediation: "Load auditd: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist (note: Apple deprecated BSM, may not be available on all macOS versions)"
            ))
        }
    }

    // MARK: - Boot Security (kernel boot-args and KEXT loading policy)

    private func checkSecureBoot(findings: inout [Finding], errors: inout [String]) {
        // Apple Silicon and T2 Macs default to a locked-down boot policy — only signed, current
        // macOS can boot, and third-party kernel extensions can't load without an explicit
        // user authorization. Two settings reliably degrade this without root:
        //   1. NVRAM `boot-args` contains debugging flags (e.g. `-v`, `keepsyms=1`, `arch=...`)
        //      — most worrying is `amfi_get_out_of_my_way=1` which disables AMFI signature checks.
        //   2. `csrutil status` reports kext-signing disabled even with SIP otherwise on.
        // We can read NVRAM without root using `nvram -p`.
        let nvram = ShellRunner.run("/usr/sbin/nvram", arguments: ["-p"], timeout: 5)
        guard nvram.success else { return }

        for line in nvram.stdout.split(separator: "\n") {
            let lineStr = String(line)
            guard lineStr.hasPrefix("boot-args\t") || lineStr.hasPrefix("boot-args ") else { continue }
            // boot-args value follows the first whitespace
            let parts = lineStr.split(separator: "\t", maxSplits: 1).map { String($0) }
            let args = (parts.count > 1 ? parts[1] : "").trimmingCharacters(in: .whitespaces)
            if args.isEmpty { continue }

            // amfi_get_out_of_my_way=1 disables Apple Mobile File Integrity — kills code-signing enforcement.
            if args.contains("amfi_get_out_of_my_way=1") || args.contains("amfi=") {
                findings.append(Finding(
                    severity: .high, category: .systemIntegrity,
                    title: "Apple Mobile File Integrity (AMFI) disabled via boot-args",
                    detail: "boot-args contains an AMFI override: \(args) — unsigned code can run as if signed",
                    path: nil,
                    remediation: "Clear boot-args in Recovery Mode: sudo nvram -d boot-args"
                ))
                return
            }
            // arch= forces booting a non-native architecture (rare and a red flag on Apple Silicon).
            // -v / keepsyms=1 are developer-only but not strictly insecure; report as low informational.
            if args.contains("arch=") {
                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "Custom architecture forced via boot-args",
                    detail: "boot-args: \(args) — forcing a non-native boot architecture is unusual outside developer testing",
                    path: nil,
                    remediation: "Clear unless intentional: sudo nvram -d boot-args"
                ))
                return
            }
            if !args.isEmpty {
                findings.append(Finding(
                    severity: .low, category: .systemIntegrity,
                    title: "Non-default kernel boot-args set",
                    detail: "boot-args: \(args) — typically empty on consumer Macs",
                    path: nil,
                    remediation: "Review and clear if unexpected: sudo nvram -d boot-args"
                ))
            }
        }
    }

    // MARK: - macOS Support Status

    private func checkMacOSSupportStatus(findings: inout [Finding], errors: inout [String]) {
        // Apple typically supports the current macOS plus the two prior majors. Older versions
        // stop receiving security patches entirely — running them is the single highest-impact
        // hardening miss most users have.
        // This table needs to be updated periodically; the date below records the last review.
        // Last reviewed: 2025-11 — Apple ships Sequoia (15), Sonoma (14), and Ventura (13) updates.
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion

        // macOS 11 (Big Sur) lost security updates in Sep 2023.
        // macOS 12 (Monterey) lost security updates in Sep 2024.
        // macOS 13 (Ventura) is on its last support year as of 2025.
        if major < 13 {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "macOS \(major) no longer receives security updates",
                detail: "Apple stopped shipping security patches for this version of macOS — every newly disclosed kernel/Safari bug remains exploitable forever",
                path: nil,
                remediation: "Upgrade to macOS 13 (Ventura) or newer: System Settings > General > Software Update. Verify hardware compatibility first."
            ))
        } else if major == 13 {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "macOS 13 (Ventura) is in its final year of security support",
                detail: "Apple typically supports the current macOS plus the two prior majors — plan an upgrade before security patches stop",
                path: nil,
                remediation: "Consider upgrading to macOS 14 (Sonoma) or 15 (Sequoia): System Settings > General > Software Update"
            ))
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
