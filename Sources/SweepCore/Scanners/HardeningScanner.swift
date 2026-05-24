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

        progress?.update("checking Gatekeeper")
        checkGatekeeper(findings: &findings, errors: &errors)

        progress?.update("checking boot-args")
        checkBootArgs(findings: &findings, errors: &errors)

        progress?.update("checking NVRAM CSR-Active-Config")
        checkPartialSIPDisable(findings: &findings, errors: &errors)

        progress?.update("checking SMB v1 protocol")
        checkSMBv1(findings: &findings, errors: &errors)

        progress?.update("checking Wake-on-LAN")
        checkWakeOnLAN(findings: &findings, errors: &errors)

        progress?.update("checking iCloud Private Relay")
        checkPrivateRelay(findings: &findings, errors: &errors)

        progress?.update("checking screen-lock hot corner")
        checkHotCorners(findings: &findings, errors: &errors)

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

    // MARK: - Gatekeeper

    private func checkGatekeeper(findings: inout [Finding], errors: inout [String]) {
        // `spctl --status` is the canonical check. macOS 13+ defaults assessments to enabled
        // and disallows "Anywhere" through the UI, but `sudo spctl --master-disable` is still
        // a one-shot bypass that some users leave on.
        let result = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status"], timeout: 5)
        guard result.success else { return }

        let output = result.stdout.lowercased()
        if output.contains("disabled") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Gatekeeper is disabled",
                detail: "macOS will run apps from any source without signature or notarization checks — anything downloaded can execute",
                path: nil,
                remediation: "Re-enable: sudo spctl --master-enable"
            ))
        }

        // Also check developer-mode assessments (specific to Notarization)
        let assess = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status", "--verbose"], timeout: 5)
        if assess.success && assess.stdout.lowercased().contains("developer id disabled") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Gatekeeper Developer ID checks disabled",
                detail: "Notarization checks are off — apps from identified developers run without verification",
                path: nil,
                remediation: "Re-enable: sudo spctl --enable --label \"Developer ID\""
            ))
        }
    }

    // MARK: - Boot arguments (rootkit / jailbreak indicators)

    private func checkBootArgs(findings: inout [Finding], errors: inout [String]) {
        // nvram boot-args holds kernel boot flags. Legitimate Macs have boot-args unset or
        // empty. Common malicious / risky flags: `-v` (verbose), `-s` (single-user),
        // `debug=0x100`, `keepsyms=1`. Together they often indicate someone is reverse-
        // engineering the system or has installed a kernel-level rootkit/instrumentation.
        let result = ShellRunner.run("/usr/sbin/nvram", arguments: ["boot-args"], timeout: 5)
        guard result.success else { return }

        // Output is like: `boot-args\t-v debug=0x100`
        let value = result.stdout
            .replacingOccurrences(of: "boot-args", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }

        let riskyFlags: [(flag: String, why: String)] = [
            ("-v", "verbose boot (often used during system tampering)"),
            ("-s", "single-user boot (root shell without password)"),
            ("debug=", "kernel debugger enabled"),
            ("kcsuffix=", "non-standard kernel collection — possible rootkit"),
            ("amfi_get_out_of_my_way=", "Apple Mobile File Integrity disabled — bypasses code signing"),
            ("amfi=", "AMFI configuration modified — bypasses code signing"),
            ("rootless=0", "SIP filesystem protections disabled"),
        ]

        for (flag, why) in riskyFlags where value.contains(flag) {
            findings.append(Finding(
                severity: flag.hasPrefix("amfi") || flag == "rootless=0" ? .high : .medium,
                category: .hardening,
                title: "Risky kernel boot flag set: \(flag)",
                detail: "Current boot-args: \(value) — \(why)",
                path: nil,
                remediation: "Reset boot args: sudo nvram -d boot-args"
            ))
        }
    }

    // MARK: - Partial SIP disable via CSR-Active-Config

    private func checkPartialSIPDisable(findings: inout [Finding], errors: inout [String]) {
        // `csrutil status` reports overall enabled/disabled, but a partial-disable (e.g. only
        // unsigned-kexts allowed) leaves SIP "enabled (custom)" — a subtle weakening that the
        // existing SystemIntegrityScanner may not surface. We read the raw NVRAM word.
        let result = ShellRunner.run("/usr/sbin/nvram", arguments: ["csr-active-config"], timeout: 5)
        guard result.success else { return }

        let value = result.stdout
            .replacingOccurrences(of: "csr-active-config", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }

        // Apple's default unset state ⇒ key absent. Any non-zero word ⇒ at least one SIP
        // protection was deliberately disabled. We don't try to decode the bitmap — just
        // flagging the existence of a custom config is enough for users to investigate.
        if !value.contains("00 00 00 00") && !value.contains("00%00%00%00") {
            findings.append(Finding(
                severity: .medium, category: .systemIntegrity,
                title: "System Integrity Protection has a custom configuration",
                detail: "csr-active-config = \(value) — at least one SIP protection is selectively disabled",
                path: nil,
                remediation: "Run `csrutil status` for details; restore full SIP from Recovery: `csrutil enable`"
            ))
        }
    }

    // MARK: - SMB v1 (CVE-laden legacy protocol)

    private func checkSMBv1(findings: inout [Finding], errors: inout [String]) {
        // macOS disables SMB1 by default but the setting can be re-enabled in
        // /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist
        // or via `defaults write`. SMB1 carries the EternalBlue family of bugs.
        let serverResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "ProtocolVersionMap"
        ], timeout: 5)
        if serverResult.success {
            // ProtocolVersionMap is a bitmask: 1 = SMB1, 2 = SMB2, 4 = SMB3. Any odd value
            // means SMB1 is allowed. The default (unset) maps to SMB2/3.
            let value = serverResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if let mask = Int(value), mask & 0x1 != 0 {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "SMB v1 protocol is enabled on the file server",
                    detail: "ProtocolVersionMap=\(mask) includes SMB1 — vulnerable to EternalBlue-class exploits",
                    path: "/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
                    remediation: "Disable SMB1: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server ProtocolVersionMap -int 6"
                ))
            }
        }

        // The client side has the same key under nsmb.conf — flag if SMB1 is enabled there
        let clientResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.NetworkBrowser", "ProtocolVersionMap"
        ], timeout: 5)
        if clientResult.success {
            let value = clientResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if let mask = Int(value), mask & 0x1 != 0 {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "SMB v1 protocol is enabled on the SMB client",
                    detail: "Your Mac can connect to ancient SMB1 servers — fingerprintable on hostile networks",
                    path: nil,
                    remediation: "Disable: defaults write com.apple.NetworkBrowser ProtocolVersionMap -int 6"
                ))
            }
        }
    }

    // MARK: - Wake-on-LAN

    private func checkWakeOnLAN(findings: inout [Finding], errors: inout [String]) {
        // `pmset -g` shows current power state including womp (Wake On Magic Packet).
        // WoL allows anyone on the LAN to wake the Mac — paired with auto-login or an
        // unlocked session, that's full physical access from across the network.
        let result = ShellRunner.run("/usr/bin/pmset", arguments: ["-g"], timeout: 5)
        guard result.success else { return }

        for line in result.stdout.split(separator: "\n") {
            let trimmed = String(line).trimmingCharacters(in: .whitespaces)
            // Lines look like:  womp                 1
            if trimmed.hasPrefix("womp") {
                let value = trimmed.replacingOccurrences(of: "womp", with: "").trimmingCharacters(in: .whitespaces)
                if value == "1" {
                    findings.append(Finding(
                        severity: .low, category: .hardening,
                        title: "Wake-on-LAN (magic packet) is enabled",
                        detail: "Anyone on your local network can wake this Mac from sleep",
                        path: nil,
                        remediation: "Disable if not needed: sudo pmset -a womp 0"
                    ))
                }
                break
            }
        }
    }

    // MARK: - iCloud Private Relay

    private func checkPrivateRelay(findings: inout [Finding], errors: inout [String]) {
        // Private Relay anonymizes Safari traffic and DNS lookups. It can be disabled
        // either at the Apple ID level or per-network — we only flag the per-network
        // override, since some networks (work / corporate Wi-Fi) legitimately block it.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.networkserviceproxy", "NSPDisabled"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "iCloud Private Relay is disabled for the current network",
                    detail: "Safari traffic and DNS lookups are not being anonymized — expected on corporate networks that require visibility",
                    path: nil,
                    remediation: "If on a personal network: System Settings > [Apple ID] > iCloud > Private Relay"
                ))
            }
        }
    }

    // MARK: - Hot Corners

    private func checkHotCorners(findings: inout [Finding], errors: inout [String]) {
        // Hot corner action `6` = Disable Screen Saver. Combined with no automatic
        // screen lock, this lets someone disable lock-out by parking the cursor.
        // (Actions: 1=screen saver, 2=disable, 5=sleep, 6=disable SS, 10=lock screen, 13=quick note)
        let corners = ["wvous-tl-corner", "wvous-tr-corner",
                       "wvous-bl-corner", "wvous-br-corner"]
        for corner in corners {
            let result = ShellRunner.run("/usr/bin/defaults", arguments: [
                "read", "com.apple.dock", corner
            ], timeout: 5)
            guard result.success else { continue }

            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "6" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Hot corner configured to disable screen saver: \(corner)",
                    detail: "Parking the cursor in this screen corner will prevent the screen saver — and therefore the lock — from triggering",
                    path: nil,
                    remediation: "Change to a safer action (e.g. 'Lock Screen'): System Settings > Desktop & Dock > Hot Corners"
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
