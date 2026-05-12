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

        progress?.update("checking secure boot policy")
        checkSecureBoot(findings: &findings, errors: &errors)

        progress?.update("checking quarantine enforcement")
        checkQuarantineEnforcement(findings: &findings, errors: &errors)

        progress?.update("checking SSH directory permissions")
        checkSSHDirectoryPermissions(findings: &findings, errors: &errors)

        progress?.update("checking PATH integrity")
        checkPathIntegrity(findings: &findings, errors: &errors)

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

    // MARK: - Find My Mac / Activation Lock

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac protects a stolen Mac — without it, an attacker who physically takes
        // the machine can wipe it and reuse it. Status is reported by `fmm-tool` on newer
        // macOS, but the universal path is the MobileMeAccount key in com.apple.MobileMeSettings.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.FindMyMac"
        ], timeout: 5)

        // If the plist doesn't exist or has FMMEnabled = 0, Find My is off.
        let off = !result.success ||
            result.stdout.contains("FMMEnabled = 0") ||
            result.stdout.contains("\"FMMEnabled\" = 0")

        if off {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is not enabled",
                detail: "Without Find My Mac, a stolen Mac can be wiped and reused; remote lock/erase is impossible",
                path: nil,
                remediation: "Sign in to iCloud and enable: System Settings > Apple ID > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Secure Boot / Reduced Security

    private func checkSecureBoot(findings: inout [Finding], errors: inout [String]) {
        // Apple Silicon Macs default to "Full Security". "Reduced Security" and
        // "Permissive Security" allow unsigned kernel extensions and arbitrary OS versions
        // — both are required to install kernel-level spyware on a modern Mac.
        let result = ShellRunner.run("/usr/bin/bputil", arguments: ["-d"], timeout: 5)
        // bputil requires admin; if we can't run it, skip rather than emit a false positive.
        guard result.success, !result.stdout.isEmpty else { return }

        let lower = result.stdout.lowercased()
        if lower.contains("permissive security") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Permissive Security boot policy is active",
                detail: "Apple Silicon Mac is in Permissive Security — unsigned kexts can load and SIP is effectively bypassable",
                path: nil,
                remediation: "Restore Full Security: reboot into recoveryOS, run Startup Security Utility > Full Security"
            ))
        } else if lower.contains("reduced security") {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Reduced Security boot policy is active",
                detail: "Apple Silicon Mac is in Reduced Security — third-party kexts can be loaded by an attacker with admin",
                path: nil,
                remediation: "Restore Full Security in recoveryOS if you don't need third-party kexts"
            ))
        }

        // MDM-marked "any user can approve" kernel extensions is another weakening of the
        // default policy that's worth surfacing.
        if lower.contains("3rd party kexts: 1") || lower.contains("3rd party kernel extensions: enabled") {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Third-party kernel extensions are allowed at boot",
                detail: "The current boot policy permits third-party kexts — investigate any non-Apple kext in the Kernel scan",
                path: nil,
                remediation: "Disable if no third-party kext is required, via recoveryOS Startup Security Utility"
            ))
        }
    }

    // MARK: - Quarantine Enforcement

    private func checkQuarantineEnforcement(findings: inout [Finding], errors: inout [String]) {
        // LSQuarantine attaches the com.apple.quarantine xattr to every file downloaded by
        // Safari/Mail/Messages/AirDrop, which then triggers Gatekeeper before first run.
        // Setting `LSQuarantine` to 0 in the safari/global domain disables this check —
        // a deliberate weakening that some stealers perform after gaining a foothold.
        let domains: [(domain: String, label: String)] = [
            ("com.apple.LaunchServices", "LaunchServices"),
            ("com.apple.Safari", "Safari"),
            ("NSGlobalDomain", "Global"),
        ]

        for (domain, label) in domains {
            let result = ShellRunner.run("/usr/bin/defaults", arguments: [
                "read", domain, "LSQuarantine"
            ], timeout: 5)
            guard result.success else { continue }
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "0" || value.lowercased() == "false" {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "Download quarantine is disabled (\(label))",
                    detail: "LSQuarantine is off in domain \(domain) — Gatekeeper will not warn about new binaries downloaded by browsers/Mail",
                    path: nil,
                    remediation: "Re-enable: defaults write \(domain) LSQuarantine -bool true (then log out / in)"
                ))
            }
        }

        // Gatekeeper assessments are independent of LSQuarantine. If a user has run
        // `spctl --master-disable`, Gatekeeper is fully off, which is also a strong weakening.
        // The dedicated Gatekeeper status check lives in SystemIntegrityScanner; we don't
        // duplicate it here.
    }

    // MARK: - SSH directory permissions

    private func checkSSHDirectoryPermissions(findings: inout [Finding], errors: inout [String]) {
        // Loose permissions on ~/.ssh let any local process (including web-content-style
        // exploit chains) read your private keys, known_hosts, and SSH config.
        let home = ShellRunner.realUserHome
        let sshDir = "\(home)/.ssh"
        guard FileManager.default.fileExists(atPath: sshDir),
              let attrs = try? FileManager.default.attributesOfItem(atPath: sshDir),
              let perms = attrs[.posixPermissions] as? NSNumber else { return }

        let mode = perms.intValue
        // 0700 is the only safe mode. Group/other read or write should not be set.
        if (mode & 0o077) != 0 {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "~/.ssh has insecure permissions",
                detail: String(format: "Mode: 0%o — other users / processes can read SSH config & keys", mode & 0o777),
                path: sshDir,
                remediation: "Restore: chmod 700 \"\(sshDir)\" && chmod 600 \"\(sshDir)\"/* (keep .pub files at 644)"
            ))
        }

        // Also flag private keys that are world/group readable.
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: sshDir) {
            for entry in entries {
                // Heuristic: keys are typically id_*, *_rsa, *_ed25519, etc., and
                // do NOT end in .pub.
                if entry.hasPrefix(".") || entry.hasSuffix(".pub") { continue }
                let lower = entry.lowercased()
                let looksLikeKey = lower.hasPrefix("id_") || lower.hasSuffix("_rsa") ||
                    lower.hasSuffix("_ed25519") || lower.hasSuffix("_ecdsa") ||
                    lower.hasSuffix("_dsa") || lower == "identity"
                guard looksLikeKey else { continue }

                let keyPath = "\(sshDir)/\(entry)"
                guard let keyAttrs = try? FileManager.default.attributesOfItem(atPath: keyPath),
                      let keyPerms = keyAttrs[.posixPermissions] as? NSNumber else { continue }
                let keyMode = keyPerms.intValue
                if (keyMode & 0o077) != 0 {
                    let modeStr = String(format: "0%o", keyMode & 0o777)
                    findings.append(Finding(
                        severity: .high, category: .hardening,
                        title: "SSH private key is world/group readable",
                        detail: "\(entry) has mode \(modeStr) — other local processes can read this key",
                        path: keyPath,
                        remediation: "chmod 600 \"\(keyPath)\""
                    ))
                }
            }
        }

        // ~/.ssh/config with a ProxyCommand running an unknown binary is a classic
        // persistence trick — every SSH the user runs invokes the attacker's tool.
        let sshConfig = "\(sshDir)/config"
        if let content = try? String(contentsOfFile: sshConfig, encoding: .utf8) {
            let lines = content.split(separator: "\n")
            for (idx, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                let lower = trimmed.lowercased()
                guard lower.hasPrefix("proxycommand") else { continue }
                // ProxyCommand pointing into /tmp or hidden dirs is suspicious.
                if lower.contains("/tmp/") || lower.contains(" /.") || lower.contains("\t/.") {
                    findings.append(Finding(
                        severity: .high, category: .hardening,
                        title: "SSH ProxyCommand points to a temp/hidden binary",
                        detail: "Line \(idx + 1): \(String(trimmed.prefix(160)))",
                        path: sshConfig,
                        remediation: "Inspect: nano \(sshConfig) — remove ProxyCommand if not yours"
                    ))
                }
            }
        }
    }

    // MARK: - PATH integrity (/etc/paths.d & /etc/paths)

    private func checkPathIntegrity(findings: inout [Finding], errors: inout [String]) {
        // /etc/paths and any file under /etc/paths.d are concatenated into the system
        // default PATH. An attacker who can write to /etc/paths.d can prepend a temp
        // directory, shadowing /usr/bin commands with malicious binaries.
        let fm = FileManager.default
        let pathsD = "/etc/paths.d"
        guard let entries = try? fm.contentsOfDirectory(atPath: pathsD) else { return }

        // Stock macOS ships small text files here (e.g. 100-rvictl, 40-XQuartz). Apple's
        // own entries reference /usr/, /opt/X11, etc. Anything in /tmp or /private/tmp is suspect.
        for entry in entries where !entry.hasPrefix(".") {
            let path = "\(pathsD)/\(entry)"
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lower = content.lowercased()
            let suspicious = lower.contains("/tmp/") || lower.contains("/private/tmp") ||
                             lower.contains("/var/tmp") ||
                             content.split(separator: "\n").contains(where: {
                                 let s = String($0).trimmingCharacters(in: .whitespaces)
                                 // A path that starts with a dot directory inside the user home
                                 // is unusual for a system PATH entry.
                                 return !s.isEmpty && s.contains("/.") && !s.contains("/.local") && !s.contains("/.cargo")
                             })

            if suspicious {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "Suspicious PATH entry in /etc/paths.d",
                    detail: "File: \(entry) — contents prepend a temp/hidden directory to the system PATH",
                    path: path,
                    remediation: "Inspect: cat \"\(path)\" — remove the file if not from Apple/Homebrew"
                ))
            }
        }
    }
}
