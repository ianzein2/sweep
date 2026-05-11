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

        progress?.update("checking Find My Mac")
        checkFindMyMac(findings: &findings, errors: &errors)

        progress?.update("checking accessory authorization")
        checkAccessoryAuthorization(findings: &findings, errors: &errors)

        progress?.update("checking Apple Intelligence")
        checkAppleIntelligence(findings: &findings, errors: &errors)

        progress?.update("checking personalised ads")
        checkPersonalizedAds(findings: &findings, errors: &errors)

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

    // MARK: - AirPlay Receiver

    private func checkAirPlayReceiver(findings: inout [Finding], errors: inout [String]) {
        // AirPlay Receiver lets the Mac accept screen mirroring / Continuity Camera from
        // anyone on the local network when set to "Everyone". macOS Ventura+ exposes it
        // via Control Center; the underlying preference is com.apple.airplayreceiver.
        let enabledResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.controlcenter", "AirplayRecieverEnabled"
        ], timeout: 5)
        // Apple misspelled the key as "Reciever" — keep both for compatibility.
        let alt = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.airplay", "ReceiverEnabled"
        ], timeout: 5)

        let isEnabled =
            (enabledResult.success && enabledResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1") ||
            (alt.success && alt.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1")
        guard isEnabled else { return }

        // "Allow AirPlay for: Everyone" is the risky setting. Other values: 0 = Current User,
        // 1 = Anyone on same network, 2 = Everyone.
        let scopeResult = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.airplay", "DiscoverableMode"
        ], timeout: 5)
        let scope = scopeResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let isEveryone = scope == "Everyone" || scope == "2"
        let severity: Severity = isEveryone ? .high : .medium

        findings.append(Finding(
            severity: severity, category: .hardening,
            title: "AirPlay Receiver is enabled\(isEveryone ? " for Everyone" : "")",
            detail: isEveryone
                ? "Any nearby Apple device can request to mirror its screen to this Mac"
                : "AirPlay Receiver accepts incoming screen mirroring",
            path: nil,
            remediation: "Disable: System Settings > General > AirDrop & Handoff > AirPlay Receiver"
        ))
    }

    // MARK: - Find My Mac

    private func checkFindMyMac(findings: inout [Finding], errors: inout [String]) {
        // Find My Mac is the anti-theft control — without it, a stolen Mac can be wiped
        // and resold. The plist lives under /Library/Preferences and is root-readable;
        // a non-root scan that fails to read it isn't an actionable signal, so we stay
        // quiet in that case rather than nag every non-sudo run.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.FindMyMac", "FMMEnabled"
        ], timeout: 5)
        guard result.success else { return }
        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if value == "0" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Find My Mac is disabled",
                detail: "Without Find My Mac, a stolen Mac cannot be located, locked, or wiped remotely",
                path: nil,
                remediation: "Enable: System Settings > [Your Apple ID] > iCloud > Find My Mac"
            ))
        }
    }

    // MARK: - Accessory Authorization (Apple Silicon)

    private func checkAccessoryAuthorization(findings: inout [Finding], errors: inout [String]) {
        // Apple Silicon Macs and recent Intel models gained an "Allow accessories to
        // connect" option (Sonoma 14.4+). Setting it to "Always" disables the prompt
        // for new USB/Thunderbolt devices, leaving the Mac vulnerable to malicious
        // peripherals (BadUSB, charge-only juice-jacking dongles, etc.).
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.security.AccessoryAllowed", "Status"
        ], timeout: 5)
        let alt = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.AccessoryUpdateSecurity", "Mode"
        ], timeout: 5)
        let primary = result.success ? result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : ""
        let secondary = alt.success ? alt.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : ""

        // "Always" / "0" both indicate the prompt has been disabled.
        if primary == "Always" || primary == "0" || secondary == "Always" || secondary == "0" {
            findings.append(Finding(
                severity: .medium, category: .hardening,
                title: "Mac auto-allows new USB/Thunderbolt accessories",
                detail: "macOS will not prompt before granting USB or Thunderbolt access to a new device",
                path: nil,
                remediation: "Set to \"Ask Every Time\": System Settings > Privacy & Security > Allow accessories to connect"
            ))
        }
    }

    // MARK: - Apple Intelligence Privacy

    private func checkAppleIntelligence(findings: inout [Finding], errors: inout [String]) {
        // Apple Intelligence (macOS 15.1+) sends some prompts to Apple's Private Cloud
        // Compute and, optionally, ChatGPT. The data is processed off-device. We flag
        // this as informational so privacy-conscious users can audit it.
        let aiOn = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.CloudSubscriptionFeatures.optIn", "AppleIntelligenceEnabled"
        ], timeout: 5)
        let aiAlt = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.AppleIntelligence", "Enabled"
        ], timeout: 5)
        let enabled =
            (aiOn.success && aiOn.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1") ||
            (aiAlt.success && aiAlt.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1")
        guard enabled else { return }

        // Also check if the ChatGPT extension is enabled — that sends data to OpenAI.
        let chatGPT = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.generativeexperiencesd", "ChatGPTEnabled"
        ], timeout: 5)
        let chatGPTOn = chatGPT.success && chatGPT.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1"

        findings.append(Finding(
            severity: .low, category: .hardening,
            title: "Apple Intelligence is enabled\(chatGPTOn ? " with ChatGPT extension" : "")",
            detail: chatGPTOn
                ? "Apple Intelligence and the ChatGPT extension can send prompts off-device (to Apple's Private Cloud Compute and OpenAI)"
                : "Some Apple Intelligence requests are processed in Apple's Private Cloud Compute",
            path: nil,
            remediation: "Review or disable: System Settings > Apple Intelligence & Siri"
        ))
    }

    // MARK: - Personalised Advertising

    private func checkPersonalizedAds(findings: inout [Finding], errors: inout [String]) {
        // "Personalised Ads" (com.apple.AdLib.allowApplePersonalizedAdvertising) lets
        // Apple's ad framework tie purchases, App Store searches, and Apple News
        // activity to a profile. The default in macOS 13+ is OFF; legacy users may
        // still have it on.
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.AdLib", "allowApplePersonalizedAdvertising"
        ], timeout: 5)
        if result.success {
            let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if value == "1" {
                findings.append(Finding(
                    severity: .low, category: .hardening,
                    title: "Personalised advertising is enabled",
                    detail: "Apple uses Apple ID activity to target ads in the App Store and News",
                    path: nil,
                    remediation: "Disable: System Settings > Privacy & Security > Apple Advertising"
                ))
            }
        }
    }

    // MARK: - Time Machine Encryption

    private func checkTimeMachineEncryption(findings: inout [Finding], errors: inout [String]) {
        // Unencrypted Time Machine destinations expose every file you've backed up to
        // anyone with physical access to the drive. tmutil reports destination info
        // including whether the volume is encrypted.
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["destinationinfo"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // Output is grouped per destination — split on blank lines.
        let blocks = result.stdout.components(separatedBy: "\n\n")
        for block in blocks {
            let lines = block.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }
            let name = lines.first(where: { $0.hasPrefix("Name") })
                .map { $0.split(separator: ":", maxSplits: 1).last.map { String($0).trimmingCharacters(in: .whitespaces) } ?? "?" } ?? "Time Machine destination"
            // tmutil reports "Encrypted : 0" when the destination is plaintext.
            let encrypted = lines.contains { line in
                line.hasPrefix("Encrypted") && line.contains("1")
            }
            let unencrypted = lines.contains { line in
                line.hasPrefix("Encrypted") && line.contains("0")
            }
            if unencrypted && !encrypted {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "Time Machine backup is not encrypted",
                    detail: "Destination \"\(name)\" stores backups without encryption — anyone with the drive can read every backed-up file",
                    path: nil,
                    remediation: "Re-add the destination with Encryption: System Settings > General > Time Machine"
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
