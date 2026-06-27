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

        progress?.update("checking SSH server configuration")
        checkSSHServerConfig(findings: &findings, errors: &errors)

        progress?.update("checking macOS version support status")
        checkMacOSVersionSupport(findings: &findings, errors: &errors)

        progress?.update("checking Background Login Items")
        checkBackgroundItems(findings: &findings, errors: &errors)

        progress?.update("checking Bluetooth state")
        checkBluetoothExposure(findings: &findings, errors: &errors)

        progress?.update("checking Wi-Fi auto-join exposure")
        checkWiFiAutoJoin(findings: &findings, errors: &errors)

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

    // MARK: - SSH Server Configuration

    private func checkSSHServerConfig(findings: inout [Finding], errors: inout [String]) {
        // Only meaningful if SSH (Remote Login) is enabled. If it's off, the config doesn't matter.
        let sshState = ShellRunner.run("/usr/sbin/systemsetup",
                                       arguments: ["-getremotelogin"], timeout: 5)
        guard sshState.success, sshState.stdout.lowercased().contains(": on") else { return }

        // sshd config locations differ by macOS version. Newer macOS uses drop-ins under
        // /etc/ssh/sshd_config.d, but the main file is still the source of truth.
        var configContent = ""
        let configPaths = ["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
        for path in configPaths {
            if let content = try? String(contentsOfFile: path, encoding: .utf8) {
                configContent += "\n" + content
            }
        }
        // Drop-in directory — additional sshd_config fragments
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/ssh/sshd_config.d") {
            for entry in dropIns where entry.hasSuffix(".conf") {
                if let content = try? String(contentsOfFile: "/etc/ssh/sshd_config.d/\(entry)", encoding: .utf8) {
                    configContent += "\n" + content
                }
            }
        }
        guard !configContent.isEmpty else { return }

        // Parse the merged config. Lines starting with # are comments.
        // Apple's default sshd_config has most directives commented out (defaults apply).
        let active = configContent
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.hasPrefix("#") && !$0.isEmpty }

        func directive(_ key: String) -> String? {
            // Match case-insensitively per OpenSSH semantics.
            for line in active {
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2 else { continue }
                if parts[0].lowercased() == key.lowercased() {
                    return String(parts[1]).trimmingCharacters(in: .whitespaces)
                }
            }
            return nil
        }

        // PermitRootLogin — Apple default since macOS 10.15 is "prohibit-password", but explicit "yes" is risky.
        if let value = directive("PermitRootLogin"), value.lowercased() == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH allows direct root login (PermitRootLogin yes)",
                detail: "An attacker who guesses the root password gets full system access without escalation",
                path: "/etc/ssh/sshd_config",
                remediation: "Set PermitRootLogin to \"prohibit-password\" or \"no\" in sshd_config, then: sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }

        // PasswordAuthentication — public-key-only is the hardened baseline.
        if let value = directive("PasswordAuthentication"), value.lowercased() == "yes" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SSH password authentication is enabled",
                detail: "SSH is exposed to brute-force / credential stuffing — public-key authentication is the hardened baseline",
                path: "/etc/ssh/sshd_config",
                remediation: "Disable: set PasswordAuthentication no in sshd_config after confirming you have SSH keys configured"
            ))
        }

        // PermitEmptyPasswords — never acceptable.
        if let value = directive("PermitEmptyPasswords"), value.lowercased() == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH permits empty passwords",
                detail: "Any account with an empty password can log in via SSH — almost always a misconfiguration",
                path: "/etc/ssh/sshd_config",
                remediation: "Remove or set PermitEmptyPasswords no in sshd_config immediately"
            ))
        }

        // X11 / agent forwarding can be abused to pivot off this host once a session exists.
        if let value = directive("X11Forwarding"), value.lowercased() == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH X11 forwarding is enabled",
                detail: "Allows graphical apps to tunnel through SSH; not needed on most macOS hosts and widens the attack surface",
                path: "/etc/ssh/sshd_config",
                remediation: "Disable if unused: set X11Forwarding no in sshd_config"
            ))
        }

        // Custom port is fine, but we surface non-22 listeners so the user sees what's exposed.
        if let value = directive("Port"), let port = Int(value), port != 22 {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH is listening on a non-standard port (\(port))",
                detail: "This is sometimes deliberate (security-through-obscurity) and sometimes attacker-installed",
                path: "/etc/ssh/sshd_config",
                remediation: "Verify this port change was intentional"
            ))
        }
    }

    // MARK: - macOS Version Support

    private func checkMacOSVersionSupport(findings: inout [Finding], errors: inout [String]) {
        // Apple actively patches the current macOS release plus the two immediately prior.
        // Older majors stop receiving security updates and are vulnerable to disclosed CVEs forever.
        // Map: major version → human name → status.
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion

        // Names for context in the finding text.
        let majorName: [Int: String] = [
            11: "Big Sur",
            12: "Monterey",
            13: "Ventura",
            14: "Sonoma",
            15: "Sequoia",
            16: "Tahoe",
            17: "macOS 17",
        ]
        let name = majorName[major] ?? "macOS \(major)"

        // Anything older than 14 (Sonoma) is outside Apple's update window as of late 2025.
        // We give a 1-version buffer to avoid noisy alerts the same week a new macOS ships.
        if major < 14 {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "macOS \(major) (\(name)) is no longer receiving security updates",
                detail: "Apple supports only the current macOS plus the two prior majors. Running \(name) leaves disclosed kernel and Safari CVEs unpatched.",
                path: nil,
                remediation: "Upgrade to the latest macOS your Mac supports: System Settings > General > Software Update"
            ))
        } else if major == 14 {
            // Sonoma is on the way out — surface as medium so users plan an upgrade.
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "macOS \(major) (\(name)) is in its final year of security updates",
                detail: "Apple maintains \(name) for a limited window. Plan to upgrade before patches stop.",
                path: nil,
                remediation: "Schedule an upgrade to a supported macOS via System Settings > General > Software Update"
            ))
        }
    }

    // MARK: - Background Items (SMAppService persistence — Ventura+)

    private func checkBackgroundItems(findings: inout [Finding], errors: inout [String]) {
        // macOS Ventura introduced SMAppService for app-managed background items. The system tracks
        // them in BackgroundItems.btm, an opaque sqlite/proplist store. We can't parse it portably
        // from a sandboxed CLI, but `sfltool dumpbtm` (root only) prints a readable listing.
        let dump = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 15)
        guard dump.success, !dump.stdout.isEmpty else { return }

        // The dump groups items per user. We look for entries that are:
        //   - Disabled by the user (sign someone tried to install something they declined)
        //   - From unsigned developers (no Team ID)
        //   - From temporary directories
        var currentName: String?
        var currentPath: String?
        var currentTeamId: String?
        var currentDisposition: String?

        func flushItem() {
            defer {
                currentName = nil
                currentPath = nil
                currentTeamId = nil
                currentDisposition = nil
            }
            guard let name = currentName, let path = currentPath else { return }
            // Apple-bundled background items are not noteworthy.
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") { return }
            if name.hasPrefix("com.apple.") { return }

            let isTempPath = path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") ||
                             path.hasPrefix("/var/tmp/")
            let isHiddenPath = path.split(separator: "/").contains { $0.hasPrefix(".") }
            let hasTeamId = !(currentTeamId?.isEmpty ?? true) && currentTeamId != "(null)"

            if isTempPath || isHiddenPath {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background Login Item from temp / hidden path",
                    detail: "\(name) → \(path)\(currentDisposition.map { " — \($0)" } ?? "")",
                    path: path,
                    remediation: "Review in System Settings > General > Login Items & Extensions, and remove if unrecognized"
                ))
            } else if !hasTeamId {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Background Login Item with no developer Team ID",
                    detail: "\(name) → \(path) — no signing team identifier",
                    path: path,
                    remediation: "Review in System Settings > General > Login Items & Extensions"
                ))
            }
        }

        for rawLine in dump.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                flushItem()
                continue
            }
            // sfltool output uses keys like "Name:", "URL:", "Team:", "Identifier:", "Disposition:".
            if line.hasPrefix("Name:") {
                flushItem()
                currentName = line.replacingOccurrences(of: "Name:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("Identifier:") && currentName == nil {
                currentName = line.replacingOccurrences(of: "Identifier:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("URL:") || line.hasPrefix("Executable Path:") {
                let v = line.contains("Executable Path:")
                    ? line.replacingOccurrences(of: "Executable Path:", with: "")
                    : line.replacingOccurrences(of: "URL:", with: "")
                currentPath = v.trimmingCharacters(in: .whitespaces)
                    .replacingOccurrences(of: "file://", with: "")
            } else if line.hasPrefix("Team Identifier:") || line.hasPrefix("Team:") {
                currentTeamId = line.replacingOccurrences(of: "Team Identifier:", with: "")
                    .replacingOccurrences(of: "Team:", with: "")
                    .trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("Disposition:") {
                currentDisposition = line.replacingOccurrences(of: "Disposition:", with: "")
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        flushItem()
    }

    // MARK: - Bluetooth Exposure

    private func checkBluetoothExposure(findings: inout [Finding], errors: inout [String]) {
        // Bluetooth left on and discoverable is an entry vector — recent CVEs (e.g. BLURtooth,
        // SweynTooth, and Apple-specific BLE handoff bugs) all required Bluetooth to be active.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"
        ], timeout: 5)
        guard result.success else { return }
        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value == "1" else { return }

        // Only flag discoverability separately; Bluetooth-on-by-default is normal for most users.
        let discov = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.Bluetooth", "DiscoverableState"
        ], timeout: 5)
        if discov.success, discov.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Bluetooth is in discoverable mode",
                detail: "Other devices nearby can see this Mac. macOS normally only enters discoverable mode while the Bluetooth settings pane is open.",
                path: nil,
                remediation: "Close System Settings > Bluetooth, or turn Bluetooth off when not in use"
            ))
        }
    }

    // MARK: - Wi-Fi Auto-Join Exposure

    private func checkWiFiAutoJoin(findings: inout [Finding], errors: inout [String]) {
        // macOS keeps a list of preferred networks and auto-joins by SSID alone.
        // An attacker on the same airwaves can stand up an open AP with a remembered SSID
        // (e.g., "xfinitywifi", "attwifi", "Starbucks WiFi") and silently capture traffic.
        // The risk is auto-joining OPEN preferred networks.
        let result = ShellRunner.run("/usr/sbin/networksetup",
                                     arguments: ["-listpreferredwirelessnetworks", "en0"],
                                     timeout: 5)
        guard result.success, !result.stdout.isEmpty else { return }

        let knownOpenSSIDs: Set<String> = [
            "xfinitywifi", "attwifi", "Starbucks WiFi", "Google Starbucks",
            "Boingo Hotspot", "Boingo Wireless", "Boingo Hot Spot",
            "Marriott_GUEST", "Hyatt", "Hilton Honors", "GoGoInflight",
            "T-Mobile Wi-Fi", "Optimum WiFi", "_The Free Internet",
            "Hotel WiFi", "Free WiFi", "Free Public WiFi", "Wayport_Access",
        ]
        let lines = result.stdout.split(separator: "\n").map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        let preferred = lines.dropFirst().filter { !$0.isEmpty } // first line is a label

        let matched = preferred.filter { knownOpenSSIDs.contains($0) }
        if !matched.isEmpty {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Mac auto-joins \(matched.count) known-open hotspot SSID(s)",
                detail: "Auto-joining: \(matched.joined(separator: ", ")) — these SSIDs are trivially impersonated by attackers running an evil-twin AP",
                path: nil,
                remediation: "Forget what you don't need: System Settings > Wi-Fi > Advanced — and enable \"Ask to join networks\""
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
