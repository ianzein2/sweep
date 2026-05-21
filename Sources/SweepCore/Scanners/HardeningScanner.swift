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

        progress?.update("checking macOS version support status")
        checkOSVersionSupport(findings: &findings, errors: &errors)

        progress?.update("checking for pending software updates")
        checkPendingUpdates(findings: &findings, errors: &errors)

        progress?.update("checking Gatekeeper assessment policy")
        checkGatekeeperPolicy(findings: &findings, errors: &errors)

        progress?.update("checking firewall block-all-incoming")
        checkFirewallBlockAll(findings: &findings, errors: &errors)

        progress?.update("checking SecureToken / FileVault recovery posture")
        checkSecureToken(findings: &findings, errors: &errors)

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

    // MARK: - macOS Version End-of-Life

    private func checkOSVersionSupport(findings: inout [Finding], errors: inout [String]) {
        // Apple typically supports the current macOS release plus the two prior majors with
        // security updates. Anything older stops receiving patches and is a serious risk.
        // We compare the running major version against a "newest supported major" floor.
        //
        // Floor is set conservatively — bump it forward as Apple ships new majors.
        // As of 2026 the supported range is Sonoma (14), Sequoia (15), and the 2025 release (16).
        // Macs on macOS 13 (Ventura) or earlier no longer get general security fixes.
        let oldestSupportedMajor = 14
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion

        if major < oldestSupportedMajor {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "macOS \(major).\(version.minorVersion) no longer receives security updates",
                detail: "Apple maintains the latest macOS plus two prior releases; major \(major) is out of that window — known CVEs will not be patched",
                path: nil,
                remediation: "Upgrade macOS: System Settings > General > Software Update — or buy a newer Mac if this model can't run the latest release"
            ))
        } else if major == oldestSupportedMajor {
            // Older-but-supported releases miss some new mitigations (e.g. updated Lockdown Mode protections).
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "macOS \(major).\(version.minorVersion) is the oldest still-supported major",
                detail: "Still receives security updates, but newer releases have additional mitigations (memory tagging, updated TCC enforcement)",
                path: nil,
                remediation: "Consider upgrading to the latest macOS major when convenient"
            ))
        }
    }

    // MARK: - Pending Software Updates

    private func checkPendingUpdates(findings: inout [Finding], errors: inout [String]) {
        // `softwareupdate -l` lists pending updates. softwareupdate sometimes prints to stderr
        // and exits 0; we only trust output when the command succeeded.
        let result = ShellRunner.run("/usr/sbin/softwareupdate", arguments: ["-l", "--no-scan"], timeout: 15)
        guard result.success else { return }
        let combined = result.stdout + result.stderr

        // Apple's CLI prints "No new software available." when the cache says you're current.
        if combined.contains("No new software available") { return }

        // Each candidate is reported on a "* Label: ..." line.
        let updateLines = combined.split(separator: "\n").compactMap { line -> String? in
            let s = String(line).trimmingCharacters(in: .whitespaces)
            // Only "* Label:" — broader prefixes match unrelated help/usage output.
            return s.hasPrefix("* Label:") ? s : nil
        }

        guard !updateLines.isEmpty else { return }

        // Flag harder if anything mentions a Security/Safari update specifically.
        let lower = combined.lowercased()
        let hasSecurity = lower.contains("security update") ||
                          lower.contains("safari") ||
                          lower.contains("rapid security")

        let example = updateLines.first.map { String($0.prefix(120)) } ?? ""
        findings.append(Finding(
            severity: hasSecurity ? .high : .medium,
            category: .hardening,
            title: "Pending software update\(updateLines.count == 1 ? "" : "s") not yet installed (\(updateLines.count))",
            detail: "\(hasSecurity ? "Includes a security update — install ASAP. " : "")Example: \(example)",
            path: nil,
            remediation: "Install: System Settings > General > Software Update, or: sudo softwareupdate -ia --restart"
        ))
    }

    // MARK: - Gatekeeper Assessment Policy

    private func checkGatekeeperPolicy(findings: inout [Finding], errors: inout [String]) {
        // System-wide Gatekeeper status is verified in SystemIntegrityScanner. Here we check
        // whether the developer-ID assessment subsystem has been weakened (`spctl --status` says
        // "assessments enabled" while `--global-disable` toggles per-policy). We also flag
        // the legacy "Anywhere" preference if anyone re-enabled it via the hidden 10.13- flag.
        let global = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status"], timeout: 5)
        if global.success {
            let out = (global.stdout + global.stderr).lowercased()
            if out.contains("assessments disabled") {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "Gatekeeper assessments are disabled",
                    detail: "spctl reports assessments disabled — unsigned and unnotarized apps will run with no warning",
                    path: nil,
                    remediation: "Re-enable: sudo spctl --global-enable (or --master-enable on older macOS)"
                ))
            }
        }

        // The classic "Allow apps downloaded from: Anywhere" preference disappeared from the UI
        // on Sequoia but the underlying flag still works. If anyone toggled it back, this matters.
        let allowAny = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.security", "GKAutoRearm"
        ], timeout: 5)
        if allowAny.success {
            let value = allowAny.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            // GKAutoRearm=0 means Gatekeeper won't re-arm itself after a temporary bypass — usually
            // set by malicious installers that disable Gatekeeper for a window.
            if value == "0" {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Gatekeeper auto-rearm is disabled",
                    detail: "GKAutoRearm=0 — once Gatekeeper is bypassed it will not automatically restore the policy",
                    path: nil,
                    remediation: "Restore: sudo defaults delete /Library/Preferences/com.apple.security GKAutoRearm"
                ))
            }
        }
    }

    // MARK: - Firewall block-all-incoming

    private func checkFirewallBlockAll(findings: inout [Finding], errors: inout [String]) {
        // "Block all incoming connections" is the strictest application-firewall setting — most
        // users don't enable it because it breaks sharing, but the opposite (allow signed apps
        // automatically) can also be relaxed. We only flag the obvious unsafe end of the spectrum:
        // signed apps are allowed in *and* unsigned apps are allowed in. That combination means
        // any newly-installed background process can listen on the network.
        let allowSigned = ShellRunner.run("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                          arguments: ["--getallowsigned"], timeout: 5)
        guard allowSigned.success else { return }

        // The flag is reported as two separate lines: "Automatically allow signed built-in software"
        // and "Automatically allow downloaded signed software". When BOTH are enabled, almost any
        // code-signed app (even paid Developer ID) can bypass the firewall. We need per-line parsing
        // because both lines share the word "enabled".
        var builtInAuto = false
        var downloadedAuto = false
        for rawLine in allowSigned.stdout.split(separator: "\n") {
            let line = String(rawLine).lowercased()
            let enabled = line.contains("enabled") && !line.contains("disabled")
            if line.contains("built-in") && enabled { builtInAuto = true }
            if line.contains("downloaded") && enabled { downloadedAuto = true }
        }
        if builtInAuto && downloadedAuto {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Firewall auto-allows all signed software",
                detail: "Any Developer ID-signed app can accept incoming connections without prompting — convenient but lowers the signal-to-noise of the firewall",
                path: nil,
                remediation: "Consider tightening: System Settings > Network > Firewall > Options — uncheck 'Automatically allow downloaded signed software'"
            ))
        }
    }

    // MARK: - SecureToken / FileVault recovery posture

    private func checkSecureToken(findings: inout [Finding], errors: inout [String]) {
        // On Apple Silicon, SecureToken (and its companion Bootstrap Token) controls who can
        // unlock the system volume and approve OS updates. If the current user has *no* SecureToken,
        // even an enabled FileVault is fragile — there's no SecureToken-holding account to recover
        // the drive. This is a real-world misconfiguration on Macs that were re-bound to MDM
        // or had admin accounts swapped.
        //
        // We resolve the active console user, then ask `sysadminctl` whether they have a token.
        let user = ShellRunner.run("/usr/bin/stat", arguments: ["-f", "%Su", "/dev/console"], timeout: 5)
        let username = user.success ? user.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : ""
        guard !username.isEmpty, username != "root" else { return }

        let token = ShellRunner.run("/usr/sbin/sysadminctl", arguments: ["-secureTokenStatus", username], timeout: 5)
        let combined = (token.stdout + token.stderr).lowercased()
        guard !combined.isEmpty else { return }

        if combined.contains("secure token is disabled") {
            // Cross-check FileVault: it's only a high-severity issue if FileVault is actually on.
            let fv = ShellRunner.run("/usr/bin/fdesetup", arguments: ["status"], timeout: 5)
            let fvOn = fv.success && fv.stdout.contains("FileVault is On")
            findings.append(Finding(
                severity: fvOn ? .high : .medium,
                category: .hardening,
                title: "Current user has no SecureToken",
                detail: "User \(username) is not a SecureToken holder. \(fvOn ? "FileVault is on — recovery requires a SecureToken-holding admin." : "FileVault not enabled, but token gates OS updates and recovery.")",
                path: nil,
                remediation: "Grant via a SecureToken-holding admin: sudo sysadminctl -secureTokenOn \(username) -password - -adminUser <admin> -adminPassword -"
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
