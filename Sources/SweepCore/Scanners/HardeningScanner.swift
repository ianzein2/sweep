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

        progress?.update("checking macOS version freshness")
        checkMacOSVersionFreshness(findings: &findings, errors: &errors)

        progress?.update("checking sshd configuration")
        checkSSHDConfig(findings: &findings, errors: &errors)

        progress?.update("checking Time Machine encryption")
        checkTimeMachineEncryption(findings: &findings, errors: &errors)

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

    // MARK: - macOS Version Freshness

    /// Latest *known-supported* macOS major version. Apple supports the current and the
    /// previous two majors with security updates; anything older receives no patches.
    /// Bumped manually when a new major ships. As of late 2025 the current major is 15
    /// (Sequoia); 14 (Sonoma) and 13 (Ventura) still receive security updates.
    private static let knownLatestMacOSMajor = 15
    private static let oldestSupportedMajor = 13

    private func checkMacOSVersionFreshness(findings: inout [Finding], errors: inout [String]) {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion

        if major < Self.oldestSupportedMajor {
            // Apple no longer ships security fixes for this major — the kernel, Safari, and
            // XProtect definitions are frozen at whatever shipped at end-of-support. Any 0-day
            // disclosed since then is unpatched on this Mac.
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "macOS \(major).\(version.minorVersion) is past Apple's security support window",
                detail: "Apple supports macOS \(Self.oldestSupportedMajor)+; this Mac is on \(major).\(version.minorVersion).\(version.patchVersion). Public CVEs disclosed after EoL will not be patched here.",
                path: nil,
                remediation: "Upgrade to a supported macOS in System Settings > General > Software Update. If hardware can't, isolate this machine from sensitive workloads."
            ))
        } else if major < Self.knownLatestMacOSMajor - 1 {
            // Two majors behind — supported but missing the newer mitigations Apple has added
            // since (e.g. Lockdown Mode improvements, kernel hardening, App Management TCC bucket).
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "macOS \(major) is two majors behind the latest release",
                detail: "Current Apple release is macOS \(Self.knownLatestMacOSMajor). Older majors get fewer mitigations (Lockdown Mode, Private Relay, App Management).",
                path: nil,
                remediation: "Plan an upgrade to macOS \(Self.knownLatestMacOSMajor) when convenient: System Settings > General > Software Update"
            ))
        }
    }

    // MARK: - sshd Configuration

    /// Inspect the active sshd configuration whenever Remote Login is enabled. We only
    /// emit findings if SSH is actually serving — disabling the daemon already neutralizes
    /// these settings, and the existing remote-access check covers that case.
    private func checkSSHDConfig(findings: inout [Finding], errors: inout [String]) {
        // Cheap probe: is Remote Login on?
        let sshState = ShellRunner.run("/usr/sbin/systemsetup",
                                       arguments: ["-getremotelogin"], timeout: 5)
        guard sshState.success && sshState.stdout.lowercased().contains(": on") else { return }

        // sshd -T prints the *effective* config (including drop-ins), which is what the daemon actually uses.
        let dump = ShellRunner.run("/usr/sbin/sshd", arguments: ["-T"], timeout: 5)
        guard dump.success else {
            // Fall back to the static file — incomplete but better than nothing.
            if let content = try? String(contentsOfFile: "/etc/ssh/sshd_config", encoding: .utf8) {
                inspectSSHDLines(content.split(separator: "\n").map(String.init),
                                 source: "/etc/ssh/sshd_config",
                                 findings: &findings)
            }
            return
        }

        inspectSSHDLines(dump.stdout.split(separator: "\n").map(String.init),
                         source: "sshd -T",
                         findings: &findings)
    }

    private func inspectSSHDLines(_ lines: [String], source: String, findings: inout [Finding]) {
        // sshd -T prints "key value" with a single space; comments stripped. Build a dict.
        var cfg: [String: String] = [:]
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let parts = trimmed.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            cfg[parts[0].lowercased()] = String(parts[1])
        }

        // PermitRootLogin must not be "yes" — direct root login over SSH is a brute-force magnet.
        if let v = cfg["permitrootlogin"]?.lowercased(), v == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd allows direct root login (PermitRootLogin yes)",
                detail: "Anyone who guesses the root password gets a root shell. Source: \(source)",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config.d/, then reload: sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }

        // PasswordAuthentication should be off in 2025 — keys only.
        if let v = cfg["passwordauthentication"]?.lowercased(), v == "yes" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "sshd accepts password authentication",
                detail: "Password auth is brute-forceable. Key-based auth is dramatically safer. Source: \(source)",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PasswordAuthentication no' once you have an SSH key set up: sudo nano /etc/ssh/sshd_config.d/99-sweep.conf"
            ))
        }

        // PermitEmptyPasswords must never be on. macOS default is no.
        if let v = cfg["permitemptypasswords"]?.lowercased(), v == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd permits empty passwords (PermitEmptyPasswords yes)",
                detail: "Accounts with no password can log in remotely with no credential at all. Source: \(source)",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'PermitEmptyPasswords no' and reload sshd"
            ))
        }

        // X11 forwarding lets a remote attacker inject keystrokes / read screen content
        // through a connected client. Almost never legitimately needed on modern macOS.
        if let v = cfg["x11forwarding"]?.lowercased(), v == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "sshd has X11 forwarding enabled",
                detail: "X11 forwarding can be abused to read remote-client screens. Source: \(source)",
                path: "/etc/ssh/sshd_config",
                remediation: "Set 'X11Forwarding no' unless you specifically rely on it"
            ))
        }

        // Protocol < 2 has been removed by OpenSSH but call it out anyway in case of stale config.
        if let v = cfg["protocol"], v.contains("1") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd configured to accept SSH protocol 1",
                detail: "SSH 1 is cryptographically broken. Source: \(source)",
                path: "/etc/ssh/sshd_config",
                remediation: "Remove the 'Protocol 1' line — modern OpenSSH only supports SSH 2"
            ))
        }
    }

    // MARK: - Time Machine Encryption

    /// Backups commonly contain the entire user library — keychains, browser profiles,
    /// SSH keys. An unencrypted Time Machine destination is effectively a clear-text copy
    /// of the user's secrets sitting on a disk that may travel.
    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/tmutil",
                                     arguments: ["destinationinfo", "-X"], timeout: 10)
        guard result.success, let data = result.stdout.data(using: .utf8) else { return }

        // tmutil emits a plist with a "Destinations" array.
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let destinations = plist["Destinations"] as? [[String: Any]] else { return }

        for dest in destinations {
            // Encryption may be reported as "Encryption" (Bool) or "Kind" (string) depending on macOS version.
            let name = dest["Name"] as? String ?? "Time Machine destination"
            let kind = dest["Kind"] as? String ?? ""

            // The most reliable signal: "Encrypted" key in some macOS versions, or kind containing "Encrypted".
            let encryptedFlag = (dest["Encrypted"] as? Bool) ??
                                ((dest["Encrypted"] as? Int).map { $0 != 0 } ?? false)
            let kindEncrypted = kind.lowercased().contains("encrypted")

            // If we can't determine encryption, skip rather than false-positive.
            // Both "Encrypted" presence (older macOS) and a "Kind" containing it (newer) are checked.
            if dest["Encrypted"] == nil && !kindEncrypted {
                continue
            }

            if !encryptedFlag && !kindEncrypted {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Time Machine destination is not encrypted",
                    detail: "Destination \"\(name)\" stores backups in clear text — anyone holding the disk can read your keychain, browser data, and SSH keys",
                    path: nil,
                    remediation: "Open System Settings > General > Time Machine > (i) on the destination > Encrypt Backups. Existing backups must be re-encrypted from scratch."
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
