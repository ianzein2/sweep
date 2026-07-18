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

        progress?.update("checking sudo version (CVE-2025-32463)")
        checkSudoVulnerability(findings: &findings, errors: &errors)

        progress?.update("checking XProtect Remediator activity")
        checkXProtectRemediatorFreshness(findings: &findings, errors: &errors)

        progress?.update("checking pending software updates")
        checkPendingSoftwareUpdates(findings: &findings, errors: &errors)

        progress?.update("checking App Management (Sonoma+)")
        checkAppManagement(findings: &findings, errors: &errors)

        progress?.update("checking Sensitive Content Warning")
        checkSensitiveContentWarning(findings: &findings, errors: &errors)

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

    // MARK: - AirPlay Receiver

    /// AirPlay Receiver turns any Mac into an AirPlay sink — meaning anyone on the local
    /// network can attempt to project to it. On macOS Sonoma+ it's enabled by default on
    /// some hardware. Attackers routinely use it as a lateral-movement / social-engineering
    /// surface. Users who don't AirPlay to their Mac should have it off.
    private func checkAirPlayReceiver(findings: inout [Finding], errors: inout [String]) {
        // System-wide AirPlay Receiver setting
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.RemoteDesktop.plist", "AirPlayReceiverEnabled"
        ], timeout: 5)

        var systemEnabled = false
        if result.success && result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            systemEnabled = true
        }

        // The airplayreceiverd launchd service is present when enabled.
        let launchctl = ShellRunner.run("/bin/launchctl", arguments: ["list"], timeout: 5)
        let daemonRunning = launchctl.success && launchctl.stdout.contains("airplayreceiver")

        if systemEnabled || daemonRunning {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "AirPlay Receiver is enabled",
                detail: "This Mac accepts AirPlay from nearby devices — increases attack surface on shared networks",
                path: nil,
                remediation: "Disable if not needed: System Settings > General > AirDrop & Handoff > AirPlay Receiver"
            ))
        }
    }

    // MARK: - Sudo CVE-2025-32463 (chwoot)

    /// CVE-2025-32463 ("chwoot", disclosed June 2025) lets any local user gain root through
    /// sudo's -R/--chroot flag. Affected: sudo 1.9.14 through 1.9.17. Fixed in 1.9.17p1.
    /// macOS 15 (Sequoia) shipped an unpatched sudo for months; users on stalled Xcode CLT
    /// or Homebrew installs may still have vulnerable binaries in $PATH.
    private func checkSudoVulnerability(findings: inout [Finding], errors: inout [String]) {
        // Check every sudo binary reachable via common paths — a stale Homebrew copy on
        // /usr/local/bin can shadow /usr/bin/sudo even after a system update.
        let candidates = ["/usr/bin/sudo", "/usr/local/bin/sudo", "/opt/homebrew/bin/sudo"]

        for path in candidates {
            guard FileManager.default.isExecutableFile(atPath: path) else { continue }
            let result = ShellRunner.run(path, arguments: ["--version"], timeout: 5)
            guard result.success else { continue }

            // Grab the first "Sudo version X.Y.Z[pN]" line.
            var version: String?
            for line in result.stdout.split(separator: "\n") {
                let s = String(line).trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("Sudo version") {
                    version = s.replacingOccurrences(of: "Sudo version ", with: "")
                    break
                }
            }
            guard let v = version else { continue }

            if isSudoVulnerableToChwoot(v) {
                findings.append(Finding(
                    severity: .high, category: .hardening,
                    title: "sudo is vulnerable to CVE-2025-32463 (chwoot)",
                    detail: "sudo version \(v) at \(path) allows any local user to escalate to root via -R/--chroot. Fixed in 1.9.17p1.",
                    path: path,
                    remediation: path.hasPrefix("/usr/bin/")
                        ? "Update macOS via System Settings > General > Software Update"
                        : "Update via `brew upgrade sudo` or remove the stale binary at \(path)"
                ))
            }
        }
    }

    /// Returns true when the given "Sudo version" string is in the chwoot-vulnerable range.
    /// Public so it can be unit-tested; free of external state.
    static func isSudoVulnerableToChwoot(_ versionString: String) -> Bool {
        // Format: MAJOR.MINOR.PATCH[pN]. Anything before 1.9.14 is unaffected; 1.9.17p1+ is fixed.
        let core = versionString.split(separator: "p").first.map(String.init) ?? versionString
        let parts = core.split(separator: ".").compactMap { Int($0) }
        guard parts.count >= 3 else { return false }
        let major = parts[0], minor = parts[1], patch = parts[2]

        if major != 1 || minor != 9 { return false }
        if patch < 14 || patch > 17 { return false }
        // 1.9.17p1+ is patched; earlier p-levels of 1.9.17 are still vulnerable.
        if patch == 17 {
            let pSuffix = versionString.split(separator: "p").dropFirst().first.map(String.init) ?? "0"
            if let p = Int(pSuffix), p >= 1 { return false }
        }
        return true
    }

    // MARK: - XProtect Remediator Freshness

    /// XProtect Remediator (XPR) is Apple's malware removal service on Ventura+. It periodically
    /// scans for the exact families we're listing in this scanner. If XPR hasn't run recently,
    /// the machine has been walking around without an active defense sweep. XPR writes reports
    /// under /private/var/protected/xprotect/; the newest file's mtime tells us when it last ran.
    private func checkXProtectRemediatorFreshness(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        let candidates = [
            "/private/var/protected/xprotect",
            "/var/protected/xprotect",
        ]

        var newest: Date?
        for dir in candidates {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where !entry.hasPrefix(".") {
                let full = "\(dir)/\(entry)"
                if let attrs = try? fm.attributesOfItem(atPath: full),
                   let modDate = attrs[.modificationDate] as? Date {
                    if newest == nil || modDate > newest! { newest = modDate }
                }
            }
        }

        guard let last = newest else {
            // Directory unreadable without root — silent skip is fine; SIP protects it anyway.
            return
        }

        let daysSince = Calendar.current.dateComponents([.day], from: last, to: Date()).day ?? 0
        if daysSince > 14 {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "XProtect Remediator hasn't run in \(daysSince) days",
                detail: "Apple's built-in malware removal service (XPR) normally runs every few days. Last activity: \(daysSince) days ago.",
                path: nil,
                remediation: "Force a run: `sudo /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediator` — or reboot"
            ))
        }
    }

    // MARK: - Pending Software Updates

    /// Apple pushes security patches through the Software Update mechanism. Users that stall
    /// on updates while running a version with published CVEs (WebKit, kernel, sudo…) leave
    /// themselves exposed. Rather than run `softwareupdate --list` (network + slow), we look
    /// at when macOS last checked and whether any recommended updates are pending on disk.
    private func checkPendingSoftwareUpdates(findings: inout [Finding], errors: inout [String]) {
        // LastRecommendedUpdatesAvailable — count of pending recommended updates (Ventura+).
        let pendingResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "RecommendedUpdates"
        ], timeout: 5)
        if pendingResult.success {
            // Output is an array literal like "( { ... }, { ... } )". A quick line-count heuristic
            // avoids pulling in a full plist parser for a status check.
            let displayNames = pendingResult.stdout
                .split(separator: "\n")
                .filter { $0.contains("Display Name") }
            if !displayNames.isEmpty {
                let sample = displayNames.prefix(3).map {
                    String($0).trimmingCharacters(in: .whitespaces)
                        .replacingOccurrences(of: "\"", with: "")
                        .replacingOccurrences(of: ";", with: "")
                }.joined(separator: "; ")
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "\(displayNames.count) recommended software update(s) pending",
                    detail: "Pending: \(sample)",
                    path: nil,
                    remediation: "Install: System Settings > General > Software Update"
                ))
            }
        }

        // How long since macOS last checked? Anything over 14 days suggests updates are blocked.
        let lastCheckResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastFullSuccessfulDate"
        ], timeout: 5)
        if lastCheckResult.success {
            let text = lastCheckResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let fmt = DateFormatter()
            fmt.locale = Locale(identifier: "en_US_POSIX")
            fmt.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
            if let date = fmt.date(from: text) {
                let daysSince = Calendar.current.dateComponents([.day], from: date, to: Date()).day ?? 0
                if daysSince > 14 {
                    findings.append(Finding(
                        severity: .medium, category: .hardening,
                        title: "macOS hasn't checked for updates in \(daysSince) days",
                        detail: "Last successful check: \(text) — security patches may be missing",
                        path: nil,
                        remediation: "Trigger a check: System Settings > General > Software Update, or run `softwareupdate --list`"
                    ))
                }
            }
        }
    }

    // MARK: - App Management (Sonoma+)

    /// macOS Sonoma introduced "App Management" (TCC service kTCCServiceAppleEvents-adjacent),
    /// which blocks apps from silently modifying other installed apps (a classic infostealer
    /// dropper technique). When the toggle is off system-wide, malware can quietly overwrite
    /// or hollow out legitimate apps in /Applications.
    private func checkAppManagement(findings: inout [Finding], errors: inout [String]) {
        // Only meaningful on Sonoma (14+); silently skip on older systems.
        let osVer = ProcessInfo.processInfo.operatingSystemVersion
        guard osVer.majorVersion >= 14 else { return }

        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.LaunchServices", "LSAppManagementDisabled"
        ], timeout: 5)
        if result.success &&
           result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "App Management is disabled",
                detail: "System-wide App Management is off — apps can silently modify other apps in /Applications",
                path: nil,
                remediation: "Re-enable in System Settings > Privacy & Security > App Management, or clear the override: sudo defaults delete com.apple.LaunchServices LSAppManagementDisabled"
            ))
        }
    }

    // MARK: - Sensitive Content Warning (Sonoma+)

    /// Sonoma+ can blur nude images/videos before showing them in Messages, FaceTime and AirDrop.
    /// This is more anti-harassment than anti-malware, but disabling it also disables the AirDrop
    /// warning path that flags unexpected sensitive files — worth surfacing.
    private func checkSensitiveContentWarning(findings: inout [Finding], errors: inout [String]) {
        let osVer = ProcessInfo.processInfo.operatingSystemVersion
        guard osVer.majorVersion >= 14 else { return }

        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.security.SensitiveContentAnalysis", "CMPhotoAnalysisEnabled"
        ], timeout: 5)
        // Absence = default (on); explicit 0 = disabled.
        if result.success &&
           result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "0" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Sensitive Content Warning is disabled",
                detail: "Explicit-content detection in Messages/AirDrop is turned off",
                path: nil,
                remediation: "Enable in System Settings > Privacy & Security > Sensitive Content Warning"
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
