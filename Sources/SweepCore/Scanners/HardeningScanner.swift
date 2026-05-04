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

        progress?.update("checking Time Machine status")
        checkTimeMachine(findings: &findings, errors: &errors)

        progress?.update("checking macOS version freshness")
        checkMacOSVersion(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking quarantine and Gatekeeper assessments")
        checkQuarantineExceptions(findings: &findings, errors: &errors)

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

    // MARK: - SSH Server Configuration

    private func checkSSHServerConfig(findings: inout [Finding], errors: inout [String]) {
        // Even when Remote Login is off, a permissive sshd_config means the next time it gets
        // turned on the system is exposed. Modern best-practice is keys-only with root login off.
        let sshdConfigPaths = [
            "/private/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config",
        ]
        let dropInDir = "/private/etc/ssh/sshd_config.d"

        // Combine main config + drop-ins. Drop-in files override defaults in alphabetical order.
        var configFiles: [String] = []
        for p in sshdConfigPaths where FileManager.default.fileExists(atPath: p) {
            configFiles.append(p)
            break
        }
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: dropInDir) {
            for entry in dropIns.sorted() where !entry.hasPrefix(".") {
                configFiles.append("\(dropInDir)/\(entry)")
            }
        }

        guard !configFiles.isEmpty else { return }

        // sshd resolves the FIRST matching directive — so iterate in order and keep first values.
        var permitRootLogin: String?
        var passwordAuth: String?
        var permitEmptyPasswords: String?
        var protocolVersion: String?
        var x11Forwarding: String?

        for path in configFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for raw in content.split(separator: "\n") {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }

                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2 else { continue }
                let key = parts[0].lowercased()
                let value = String(parts[1]).trimmingCharacters(in: .whitespaces).lowercased()

                switch key {
                case "permitrootlogin":      if permitRootLogin == nil { permitRootLogin = value }
                case "passwordauthentication": if passwordAuth == nil { passwordAuth = value }
                case "permitemptypasswords": if permitEmptyPasswords == nil { permitEmptyPasswords = value }
                case "protocol":             if protocolVersion == nil { protocolVersion = value }
                case "x11forwarding":        if x11Forwarding == nil { x11Forwarding = value }
                default: break
                }
            }
        }

        // Apple's stock macOS sshd default is "PermitRootLogin without-password" (key-only root).
        // Anything resolving to "yes" is the dangerous case — prohibits the no-password default.
        if permitRootLogin == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH server allows root login with password",
                detail: "PermitRootLogin yes — remote attackers can attempt password-guessing against the root account",
                path: configFiles.first,
                remediation: "Set 'PermitRootLogin no' (or 'prohibit-password') and reload sshd: sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }

        if passwordAuth == "yes" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SSH password authentication is enabled",
                detail: "PasswordAuthentication yes — accounts are reachable via password brute-force; key-only auth is recommended",
                path: configFiles.first,
                remediation: "Set 'PasswordAuthentication no' after deploying SSH keys to all needed accounts"
            ))
        }

        if permitEmptyPasswords == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH allows empty passwords",
                detail: "PermitEmptyPasswords yes — accounts with blank passwords are reachable over SSH",
                path: configFiles.first,
                remediation: "Set 'PermitEmptyPasswords no' in sshd_config and restart sshd"
            ))
        }

        // Protocol 1 has been removed from upstream OpenSSH but a stale config with this line is
        // a strong signal that something has tampered with the SSH stack. Only flag the literal
        // legacy values — "1" or "1,2" / "2,1".
        if let proto = protocolVersion,
           proto == "1" || proto.contains("1,2") || proto.contains("2,1") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "SSH server configured for legacy Protocol 1",
                detail: "Protocol \(proto) — SSHv1 is cryptographically broken and is not supported by modern macOS",
                path: configFiles.first,
                remediation: "Remove the 'Protocol' line from sshd_config — modern sshd implies Protocol 2"
            ))
        }

        if x11Forwarding == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH X11 forwarding is enabled",
                detail: "X11Forwarding yes — increases the SSH attack surface; macOS does not run an X server by default",
                path: configFiles.first,
                remediation: "Set 'X11Forwarding no' unless you specifically need it"
            ))
        }
    }

    // MARK: - Time Machine

    private func checkTimeMachine(findings: inout [Finding], errors: inout [String]) {
        // Backups are the only realistic recovery path against macOS-targeting ransomware
        // (NotLockBit, 2024). Surface backup absence / staleness as a hardening issue.
        let plistPath = "/Library/Preferences/com.apple.TimeMachine.plist"
        guard let data = FileManager.default.contents(atPath: plistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Time Machine has never been configured",
                detail: "No Time Machine preferences found — there is no automatic backup of this Mac",
                path: nil,
                remediation: "Configure Time Machine in System Settings > General > Time Machine, or use another backup tool"
            ))
            return
        }

        let autoBackup = (plist["AutoBackup"] as? Int ?? 0) == 1 ||
                         (plist["AutoBackup"] as? Bool ?? false)
        if !autoBackup {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Time Machine automatic backups are disabled",
                detail: "AutoBackup is off — the Mac will not back up unless you trigger it manually",
                path: plistPath,
                remediation: "Enable: System Settings > General > Time Machine > Back Up Automatically"
            ))
        }

        // Find the most recent successful backup across all destinations
        var lastBackup: Date?
        if let dests = plist["Destinations"] as? [[String: Any]] {
            for dest in dests {
                if let snaps = dest["SnapshotDates"] as? [Date] {
                    for d in snaps {
                        if lastBackup == nil || d > lastBackup! { lastBackup = d }
                    }
                }
            }
        }

        if let last = lastBackup {
            let days = Calendar.current.dateComponents([.day], from: last, to: Date()).day ?? 0
            if days > 14 {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Most recent Time Machine backup is \(days) days old",
                    detail: "Last backup completed \(days) days ago — recovery from ransomware or hardware failure may be incomplete",
                    path: nil,
                    remediation: "Reconnect / verify the backup destination and run a fresh backup"
                ))
            }
        } else if autoBackup {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Time Machine is enabled but has no completed backups",
                detail: "AutoBackup is on but no successful snapshot has been recorded yet",
                path: nil,
                remediation: "Verify that the backup destination is reachable and writable"
            ))
        }
    }

    // MARK: - macOS Version Freshness

    private func checkMacOSVersion(findings: inout [Finding], errors: inout [String]) {
        // Apple maintains the current and previous two major releases ("n", "n-1", "n-2").
        // Anything older has stopped receiving security patches. We check the running OS rather
        // than the installer because that's what's actually exposed.
        let result = ShellRunner.run("/usr/bin/sw_vers", arguments: ["-productVersion"], timeout: 5)
        guard result.success else { return }
        let version = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let major = Int(version.split(separator: ".").first.map(String.init) ?? "") ?? 0

        // Current at time of writing (2026): Sequoia 15 / Sonoma 14 / Ventura 13 still get patches.
        // 12 (Monterey) and earlier are EOL. Catalina (10.15) and Big Sur (11) are well past EOL.
        if major > 0 && major < 13 {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "macOS \(version) is past Apple's security-update window",
                detail: "Apple typically patches the current and two prior major releases. macOS 13+ still receives fixes; this Mac is on \(version).",
                path: nil,
                remediation: "Upgrade to a supported major release: System Settings > General > Software Update"
            ))
        } else if major == 13 {
            // Ventura: still patched but on the way out — informational
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "macOS \(version) is on the older end of supported releases",
                detail: "macOS 13 (Ventura) still receives security updates but will be retired before macOS 14/15. Plan an upgrade.",
                path: nil,
                remediation: "Consider upgrading to a current major release when convenient"
            ))
        }

        // Also flag anything past the publicly-released Build ID by a long way — covers people
        // running stale point releases. We use sw_vers -buildVersion so we don't have to hard-code
        // a build map, just look for a missing point-release bump.
        let pointParts = version.split(separator: ".").map(String.init)
        if pointParts.count >= 2, let minor = Int(pointParts[1]), major >= 13 && minor == 0 {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "macOS \(version) appears to be a .0 release",
                detail: "Running the .0 of a major release means you are missing the subsequent point-release security fixes",
                path: nil,
                remediation: "Install pending updates: System Settings > General > Software Update"
            ))
        }
    }

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My provides remote-lock and remote-wipe — useful against a stolen / lost Mac.
        // Activation Lock relies on it. We check the system-wide flag as well as Bluetooth Find My.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.FindMyMac", "FMMEnabled"
        ], timeout: 5)
        let enabled = result.success && result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
        if !enabled {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "Find My Mac is not enabled",
                detail: "Find My Mac lets you remotely locate, lock, and erase a lost Mac. It also enables Activation Lock.",
                path: nil,
                remediation: "Enable: System Settings > [Your name] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Quarantine / Gatekeeper Exception List

    private func checkQuarantineExceptions(findings: inout [Finding], errors: inout [String]) {
        // `spctl --status` is already covered. Here we flag user-added Gatekeeper exceptions
        // (`spctl --list`), and the more recent attack of stripping com.apple.quarantine xattrs
        // from downloaded apps to skip Gatekeeper verification.
        let exceptionsResult = ShellRunner.run("/usr/sbin/spctl", arguments: ["--list"], timeout: 5)
        if exceptionsResult.success {
            let allowList = exceptionsResult.stdout.split(separator: "\n").filter {
                $0.contains("anchor apple") == false && $0.contains("notarized developer id") == false
            }
            // Anything beyond the stock anchor / notarized developer rules is a user-allowed
            // exception — surface it so users can audit.
            let custom = allowList.filter { !$0.isEmpty && !$0.hasPrefix("0[") && !$0.contains("apple") }
            if !custom.isEmpty {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Custom Gatekeeper allow rules present (\(custom.count))",
                    detail: "spctl --list shows non-default rules. Each rule is a Gatekeeper bypass you previously approved.",
                    path: nil,
                    remediation: "Audit: spctl --list — remove unrecognized rules with: sudo spctl --remove --rule <id>"
                ))
            }
        }

        // Recently-installed apps in /Applications without the quarantine xattr are unusual —
        // they were either copied from another machine or had the xattr deliberately stripped.
        // We only check the user Applications folder to keep this fast.
        let userApps = "\(ShellRunner.realUserHome)/Applications"
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: userApps) else { return }

        for entry in entries where entry.hasSuffix(".app") {
            let appPath = "\(userApps)/\(entry)"
            // Was the app added in the last 30 days?
            guard let attrs = try? fm.attributesOfItem(atPath: appPath),
                  let added = attrs[.creationDate] as? Date,
                  added.timeIntervalSinceNow > -86400 * 30 else { continue }

            let xattrResult = ShellRunner.run("/usr/bin/xattr", arguments: ["-p", "com.apple.quarantine", appPath], timeout: 3)
            // Exit 1 + "No such xattr" means quarantine xattr is absent.
            let noQuarantine = !xattrResult.success ||
                xattrResult.stderr.contains("No such xattr") ||
                xattrResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            if noQuarantine {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Recently-added app missing quarantine attribute",
                    detail: "App: \(entry) — added without the macOS download quarantine flag, so Gatekeeper did not get a chance to verify it",
                    path: appPath,
                    remediation: "Verify you intentionally installed this app (e.g. from the App Store, Homebrew, or your own build)"
                ))
            }
        }
    }
}
