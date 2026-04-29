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

        progress?.update("checking Remote Apple Events")
        checkRemoteAppleEvents(findings: &findings, errors: &errors)

        progress?.update("checking SSH server hardening")
        checkSSHDConfig(findings: &findings, errors: &errors)

        progress?.update("checking hidden file extensions")
        checkHiddenFileExtensions(findings: &findings, errors: &errors)

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking accessory connections (USB Restricted Mode)")
        checkAccessoryConnections(findings: &findings, errors: &errors)

        progress?.update("checking microphone & camera global state")
        checkCameraMicState(findings: &findings, errors: &errors)

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

    // MARK: - Remote Apple Events

    /// Remote Apple Events lets remote machines drive AppleScript on this Mac. It's almost
    /// never enabled deliberately and is a very high-risk surface.
    private func checkRemoteAppleEvents(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/systemsetup",
                                     arguments: ["-getremoteappleevents"], timeout: 5)
        if result.success && result.stdout.lowercased().contains(": on") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Remote Apple Events is enabled",
                detail: "Remote machines can run AppleScript on this Mac — broad scripting surface, frequently abused for code execution",
                path: nil,
                remediation: "Disable: sudo systemsetup -setremoteappleevents off, or System Settings > General > Sharing > Remote Apple Events"
            ))
        }
    }

    // MARK: - SSH Daemon Hardening

    /// When Remote Login is enabled, the policy in /etc/ssh/sshd_config decides who can get in
    /// and how. Several common defaults (root login allowed, password authentication on,
    /// PermitEmptyPasswords yes) turn a routine SSH service into a wide-open backdoor.
    private func checkSSHDConfig(findings: inout [Finding], errors: inout [String]) {
        // Only audit if SSH is on — otherwise these settings don't matter.
        let sshStatus = ShellRunner.run("/usr/sbin/systemsetup",
                                        arguments: ["-getremotelogin"], timeout: 5)
        guard sshStatus.success && sshStatus.stdout.lowercased().contains(": on") else { return }

        let sshdCandidates = ["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
        var content: String?
        for path in sshdCandidates {
            if let c = try? String(contentsOfFile: path, encoding: .utf8) {
                content = c
                break
            }
        }
        guard let cfg = content else { return }

        // Effective values: explicitly-set lines win; otherwise sshd defaults apply.
        // The defaults are: PermitRootLogin prohibit-password, PasswordAuthentication yes,
        // PermitEmptyPasswords no, ChallengeResponseAuthentication yes.
        let lines = cfg.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }
        func valueOf(_ key: String) -> String? {
            for line in lines {
                if line.hasPrefix("#") || line.isEmpty { continue }
                let parts = line.split(separator: " ", maxSplits: 1).map { String($0) }
                if parts.count == 2 && parts[0].lowercased() == key.lowercased() {
                    return parts[1].trimmingCharacters(in: .whitespaces).lowercased()
                }
            }
            return nil
        }

        // PermitRootLogin yes is the canonical SSH backdoor.
        if let v = valueOf("PermitRootLogin"), v == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd_config allows direct root login",
                detail: "PermitRootLogin yes — anyone with root's password (or key) can SSH in as root",
                path: "/etc/ssh/sshd_config",
                remediation: "Set: PermitRootLogin no — then: sudo launchctl kickstart -k system/com.openssh.sshd"
            ))
        }

        if let v = valueOf("PermitEmptyPasswords"), v == "yes" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd_config permits empty passwords",
                detail: "PermitEmptyPasswords yes — accounts without passwords can log in",
                path: "/etc/ssh/sshd_config",
                remediation: "Set: PermitEmptyPasswords no in /etc/ssh/sshd_config"
            ))
        }

        // Password-only auth + internet-exposed SSH = brute-forceable.
        if let v = valueOf("PasswordAuthentication"), v == "yes" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "SSH allows password authentication",
                detail: "PasswordAuthentication yes — SSH accepts passwords, enabling online brute-force",
                path: "/etc/ssh/sshd_config",
                remediation: "Switch to keys only: PasswordAuthentication no (after adding your public key to ~/.ssh/authorized_keys)"
            ))
        }

        // X11 forwarding adds a side channel for screen capture from compromised X11 clients.
        if let v = valueOf("X11Forwarding"), v == "yes" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "SSH X11 forwarding enabled",
                detail: "X11Forwarding yes — rarely needed on macOS; expands attack surface for compromised remote clients",
                path: "/etc/ssh/sshd_config",
                remediation: "Set: X11Forwarding no unless you specifically need it"
            ))
        }

        // Allowing legacy protocol 1 or weak MACs/Ciphers — flag if explicitly downgraded.
        if let v = valueOf("Protocol"), v.contains("1") {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "sshd configured to accept SSH protocol 1",
                detail: "Protocol 1 is cryptographically broken and was removed from OpenSSH. Explicit re-enabling is suspicious.",
                path: "/etc/ssh/sshd_config",
                remediation: "Remove the Protocol 1 line from /etc/ssh/sshd_config"
            ))
        }
    }

    // MARK: - Hidden File Extensions (anti-spoofing)

    /// Files like `Resume.pdf.app` look like PDFs in Finder when extensions are hidden — a
    /// classic social-engineering vector for macOS droppers (Bundlore, Shlayer, AMOS).
    /// Forcing extensions visible neutralises the trick.
    private func checkHiddenFileExtensions(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "NSGlobalDomain", "AppleShowAllExtensions"
        ], timeout: 5)

        // Default is 0 (hidden). Only show this if 0/missing.
        let value = result.success
            ? result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            : "0"
        if value == "0" {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "File extensions are hidden in Finder",
                detail: "Hidden extensions let \"Resume.pdf.app\" look like a PDF — a common dropper trick",
                path: nil,
                remediation: "Enable: defaults write NSGlobalDomain AppleShowAllExtensions -bool true && killall Finder"
            ))
        }
    }

    // MARK: - Find My Mac

    /// Find My Mac enables remote-lock and remote-erase if the device is stolen. It also
    /// enables Activation Lock on Apple-silicon Macs, which prevents reuse without the owner's
    /// Apple ID. We surface it as informational because we can only positively confirm presence,
    /// not the live cloud-side state.
    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // The Find My Mac token lives under /Library/Preferences/com.apple.FindMyMac.plist
        // and the iCloud account in ~/Library/Application Support/iCloud/Accounts.
        let fm = FileManager.default
        let fmmPlist = "/Library/Preferences/com.apple.FindMyMac.plist"
        let hasFMM = fm.fileExists(atPath: fmmPlist)

        let home = ShellRunner.realUserHome
        let icloudDir = "\(home)/Library/Application Support/iCloud/Accounts"
        let hasICloud = fm.fileExists(atPath: icloudDir)

        if hasICloud && !hasFMM {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is not enabled",
                detail: "iCloud is signed in but Find My Mac is off — remote lock/erase and Activation Lock are unavailable if stolen",
                path: nil,
                remediation: "Enable: System Settings > [Apple ID] > iCloud > Find My Mac"
            ))
        } else if !hasICloud {
            findings.append(Finding(
                severity: .low, category: .hardening,
                title: "No iCloud account configured",
                detail: "Without iCloud, Find My Mac, Activation Lock, and Lost Mode are not available",
                path: nil,
                remediation: "Sign in: System Settings > Apple Account"
            ))
        }
    }

    // MARK: - USB Accessory Restricted Mode

    /// macOS 13+ added "Allow accessories to connect" to Apple-silicon Macs. Setting it to
    /// "Always" effectively disables USB Restricted Mode — letting any USB device (including
    /// rogue HID emulators / data exfil sticks) attach without the user explicitly approving.
    private func checkAccessoryConnections(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.security.libraryvalidation",
            "AllowedAccessories"
        ], timeout: 5)
        if result.success {
            let v = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            // "always" or "alwaysallowed" disables the protection.
            if v.contains("always") {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "USB accessory protection set to Always Allow",
                    detail: "Any USB-C device can connect without approval — USB Restricted Mode is effectively off",
                    path: nil,
                    remediation: "Tighten: System Settings > Privacy & Security > Allow accessories to connect — choose \"Ask for new accessories\""
                ))
            }
        }
    }

    // MARK: - Camera / Microphone Indicator State

    /// macOS Sonoma+ has a hardware-style green dot when the camera is in use. Some MDM /
    /// stalkerware tools attempt to suppress it via the SystemUIServer agent. The indicator
    /// itself is enforced by the secure enclave on Apple-silicon, but legacy x86 Macs and
    /// some configurations still allow disabling it via a defaults key.
    private func checkCameraMicState(findings: inout [Finding], errors: inout [String]) {
        // 1. Check that the universal camera/mic privacy indicators are not suppressed.
        let suppress = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.controlcenter", "DisableCameraIndicator"
        ], timeout: 5)
        if suppress.success && suppress.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "Camera-in-use indicator is suppressed",
                detail: "Control Center is configured to hide the orange/green camera dot — strong indicator of stalkerware tampering",
                path: nil,
                remediation: "Remove the override: defaults delete com.apple.controlcenter DisableCameraIndicator"
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
