import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

/// Deep inspection scanner for sophisticated spyware that hides from name-based detection.
/// Focuses on behavioral anomalies rather than signatures.
public final class DeepScanner: Scanner {
    public let name = "Deep Inspection Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // Dylib injection is now handled by ProcessScanner (full enumeration)

        // 1. Check for suspicious root CA certificates
        progress?.update("checking root certificates")
        scanRootCertificates(findings: &findings, errors: &errors)

        // 2. Check DNS configuration
        progress?.update("checking DNS configuration")
        scanDNSConfiguration(findings: &findings, errors: &errors)

        // 3. Check for hidden extended attributes
        progress?.update("scanning for hidden files")
        scanHiddenAttributes(findings: &findings, errors: &errors)

        // 4. Check for root-owned files in user home
        progress?.update("checking file ownership anomalies")
        scanOwnershipAnomalies(findings: &findings, errors: &errors)

        // 5. Check for suspicious environment variables in processes
        progress?.update("checking process environments")
        scanProcessEnvironments(findings: &findings, errors: &errors)

        // 6. Check for crypto wallet stealer artifacts (recent stealers target known wallet dirs)
        progress?.update("checking crypto wallet stealer artifacts")
        scanCryptoWalletArtifacts(findings: &findings, errors: &errors)

        // 7. Detect quarantine-bypass on recently installed apps (com.apple.quarantine xattr
        //    explicitly stripped, allowing the app to bypass Gatekeeper)
        progress?.update("checking quarantine bypass on recent installs")
        scanQuarantineBypass(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Root CA Certificate Scanning

    private func scanRootCertificates(findings: inout [Finding], errors: inout [String]) {
        // List custom certificates added to the system keychain
        let result = ShellRunner.run("/usr/bin/security", arguments: [
            "find-certificate", "-a", "-p", "-c", "",
            "/Library/Keychains/System.keychain"
        ], timeout: 10)

        guard result.success else {
            // Try user keychain
            let userResult = ShellRunner.run("/usr/bin/security", arguments: [
                "dump-trust-settings", "-d"
            ], timeout: 10)

            if userResult.success && !userResult.stdout.isEmpty {
                parseAdminTrustSettings(userResult.stdout, findings: &findings)
            }
            return
        }

        // Check admin trust settings — these are manually added root CAs
        let trustResult = ShellRunner.run("/usr/bin/security", arguments: [
            "dump-trust-settings", "-d"
        ], timeout: 10)

        if trustResult.success && !trustResult.stdout.isEmpty {
            parseAdminTrustSettings(trustResult.stdout, findings: &findings)
        }

        // Also check user-level trust settings
        let userTrustResult = ShellRunner.run("/usr/bin/security", arguments: [
            "dump-trust-settings"
        ], timeout: 10)

        if userTrustResult.success && !userTrustResult.stdout.isEmpty &&
           !userTrustResult.stdout.contains("No Trust Settings") {
            parseAdminTrustSettings(userTrustResult.stdout, findings: &findings, isUser: true)
        }
    }

    private func parseAdminTrustSettings(_ output: String, findings: inout [Finding], isUser: Bool = false) {
        // Look for certificates with trust settings
        let lines = output.split(separator: "\n")
        var currentCert: String?

        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)

            // Certificate name line
            if lineStr.hasPrefix("Cert ") && lineStr.contains(":") {
                // Extract cert name
                if let colonRange = lineStr.range(of: ": ") {
                    currentCert = String(lineStr[colonRange.upperBound...])
                }
            }

            // Trust setting — "SSL" with "Allow" means it's a trusted root for HTTPS
            if lineStr.contains("kSecTrustSettingsResult") && lineStr.contains("kSecTrustSettingsResultTrustRoot") {
                if let certName = currentCert {
                    // Skip well-known CA names
                    let knownCAs = ["DigiCert", "Let's Encrypt", "GlobalSign", "Comodo",
                                    "GeoTrust", "Symantec", "VeriSign", "Entrust",
                                    "Sectigo", "GoDaddy", "Amazon", "Microsoft",
                                    "Google Trust", "Apple", "Baltimore", "Starfield"]
                    let isKnownCA = knownCAs.contains(where: { certName.contains($0) })

                    if !isKnownCA {
                        findings.append(Finding(
                            severity: .high, category: .systemIntegrity,
                            title: "Custom root CA certificate installed",
                            detail: "Certificate: \(certName) — \(isUser ? "user" : "admin") trust, can intercept all HTTPS traffic",
                            path: nil,
                            remediation: "Remove in Keychain Access if not expected. Spyware uses custom CAs for man-in-the-middle attacks."
                        ))
                    }
                }
            }
        }
    }

    // MARK: - DNS Configuration Anomalies

    private func scanDNSConfiguration(findings: inout [Finding], errors: inout [String]) {
        // Check DNS resolver configuration
        let result = ShellRunner.run("/usr/sbin/scutil", arguments: ["--dns"], timeout: 5)
        guard result.success else { return }

        let knownDNS: Set<String> = [
            // ISP/default
            "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            // Google
            "8.8.8.8", "8.8.4.4",
            // Cloudflare
            "1.1.1.1", "1.0.0.1",
            // Quad9
            "9.9.9.9", "149.112.112.112",
            // OpenDNS
            "208.67.222.222", "208.67.220.220",
            // Apple
            "17.",
        ]

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let lineStr = String(line).trimmingCharacters(in: .whitespaces)
            if lineStr.hasPrefix("nameserver") {
                // Extract IP
                let parts = lineStr.components(separatedBy: CharacterSet.whitespaces).filter { !$0.isEmpty }
                guard parts.count >= 3 else { continue }
                let ip = parts[2]

                // Check if it's a known/expected DNS server
                let isKnown = knownDNS.contains(where: { ip.hasPrefix($0) })

                if !isKnown && ip != "127.0.0.1" && ip != "::1" && ip != "fe80::" {
                    findings.append(Finding(
                        severity: .medium, category: .networkActivity,
                        title: "Unusual DNS resolver configured",
                        detail: "DNS server: \(ip) — not a common public or private DNS",
                        path: nil,
                        remediation: "Verify this DNS server in System Settings > Network > DNS. Spyware may redirect DNS for interception."
                    ))
                }
            }
        }

        // Check if DNS-over-HTTPS proxy is running (could be legitimate or malicious)
        let dohResult = ShellRunner.run("/bin/sh", arguments: [
            "-c", "lsof -i :853 -n -P 2>/dev/null | head -5"
        ], timeout: 5)
        if dohResult.success && !dohResult.stdout.isEmpty && !dohResult.stdout.contains("COMMAND") {
            // Something is listening on DNS-over-TLS port
            findings.append(Finding(
                severity: .low, category: .networkActivity,
                title: "Process listening on DNS-over-TLS port (853)",
                detail: dohResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines),
                path: nil,
                remediation: "This could be a legitimate privacy tool or a DNS interceptor"
            ))
        }
    }

    // MARK: - Hidden Extended Attributes

    private func scanHiddenAttributes(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome

        // Check key directories for files with the hidden flag set via extended attributes
        let dirsToCheck = [
            "\(home)/Library/Application Support",
            "\(home)/Library",
            "/Library/Application Support",
        ]

        for dir in dirsToCheck {
            let result = ShellRunner.run("/usr/bin/xattr", arguments: ["-lr", dir], timeout: 10)
            guard result.success else { continue }

            let lines = result.stdout.split(separator: "\n")
            for line in lines {
                let lineStr = String(line)

                // Look for com.apple.FinderInfo with hidden flag, or com.apple.metadata with hidden
                if lineStr.contains("com.apple.FinderInfo") {
                    // The file path precedes the attribute name
                    if let colonRange = lineStr.range(of: ": com.apple.FinderInfo") {
                        let filePath = String(lineStr[..<colonRange.lowerBound])

                        // Skip known app data directories
                        let knownPaths = ["com.apple.", "com.google.", "com.microsoft.",
                                          "Electron", "Code", "Slack", "Discord", "Claude"]
                        if knownPaths.contains(where: { filePath.contains($0) }) { continue }

                        // Check if file is actually hidden using ls
                        let lsResult = ShellRunner.run("/bin/ls", arguments: ["-lO", filePath], timeout: 2)
                        if lsResult.success && lsResult.stdout.contains("hidden") {
                            findings.append(Finding(
                                severity: .medium, category: .suspiciousFile,
                                title: "File hidden via extended attributes",
                                detail: "File is flagged as hidden from Finder but exists on disk",
                                path: filePath,
                                remediation: "Reveal: chflags nohidden \"\(filePath)\" — then inspect contents"
                            ))
                        }
                    }
                }
            }
        }
    }

    // MARK: - File Ownership Anomalies

    private func scanOwnershipAnomalies(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Check for root-owned files in user's Library that aren't in standard Apple paths
        let userLibrary = "\(home)/Library"
        guard fm.fileExists(atPath: userLibrary) else { return }

        // Use find to locate root-owned files (more efficient than walking)
        let result = ShellRunner.run("/usr/bin/find", arguments: [
            "\(home)/Library/Application Support",
            "-user", "root",
            "-not", "-path", "*/com.apple.*",
            "-not", "-path", "*/.Trash/*",
            "-not", "-path", "*/Caches/*",
            "-maxdepth", "3",
            "-type", "f"
        ], timeout: 10)

        guard result.success && !result.stdout.isEmpty else { return }

        let files = result.stdout.split(separator: "\n").prefix(10) // Cap at 10
        for file in files {
            let filePath = String(file).trimmingCharacters(in: .whitespaces)
            guard !filePath.isEmpty else { continue }

            // Skip known legitimate root-owned files
            let knownRootFiles = ["com.docker.", "com.vmware.", "com.parallels."]
            if knownRootFiles.contains(where: { filePath.contains($0) }) { continue }

            findings.append(Finding(
                severity: .medium, category: .suspiciousFile,
                title: "Root-owned file in user library",
                detail: "This file is owned by root in your user directory — unusual for user apps",
                path: filePath,
                remediation: "Investigate: ls -la \"\(filePath)\" — root-owned files in user dirs may indicate privilege escalation"
            ))
        }
    }

    // MARK: - Process Environment Inspection

    private func scanProcessEnvironments(findings: inout [Finding], errors: inout [String]) {
        // Check for processes with DYLD environment variables set (runtime injection)
        let result = ShellRunner.run("/bin/ps", arguments: ["eww", "-o", "pid,command"], timeout: 5)
        guard result.success else { return }

        let dangerousEnvVars = ["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
                                "CFNETWORK_DIAGNOSTICS", "MallocStackLogging"]

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let lineStr = String(line)
            for envVar in dangerousEnvVars {
                if lineStr.contains(envVar) {
                    // Extract PID
                    let parts = lineStr.trimmingCharacters(in: .whitespaces)
                        .split(separator: " ", maxSplits: 1)
                    let pid = parts.first.map(String.init) ?? "?"

                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Process running with \(envVar)",
                        detail: "PID \(pid) — this environment variable enables runtime code injection",
                        path: nil,
                        remediation: "Investigate: ps eww \(pid) — then kill if not expected"
                    ))
                }
            }
        }
    }

    // MARK: - Crypto Wallet Stealer Artifacts

    private func scanCryptoWalletArtifacts(findings: inout [Finding], errors: inout [String]) {
        // 2023-2025 macOS stealers (AMOS, Banshee, Cthulhu, Realst, Poseidon) follow a near-identical
        // playbook: enumerate ~/Library/Application Support/<wallet>/ and copy or zip the
        // wallet.dat / keystores / mnemonics into /private/tmp/ (or ~/Documents/) before
        // exfiltration. The intermediate archive sometimes survives if the exfil fails or the
        // user kills the process mid-flight. Finding one of these artifacts is a strong IOC.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Stealers stage extracted data in /tmp before exfiltration — using user-writable
        // staging in $HOME would cause false positives (many users keep passwords.zip etc.
        // in Documents legitimately), so we only inspect tmpfs locations.
        let stagingDirs = ["/private/tmp", "/private/var/tmp"]

        // Filename patterns observed in published AMOS/Banshee/Cthulhu/Realst analyses.
        // These are highly unusual filenames in /tmp on a clean Mac. Generic names like
        // "passwords.txt" are intentionally not in this list — they'd false-positive on
        // any developer that drops a credentials file in /tmp during testing.
        let stealerArtifactPatterns: [String] = [
            "wallets.zip", "wallet_backup.zip", "wallet.dat.bak",
            "keychain.dump", "keychain_dump.zip",
            "atomic_wallets", "exodus_wallets",
            "amos_loot", "banshee_loot", "poseidon_loot",
            "metamask_wallet.zip", "metamask_keystore",
            "browsers.zip", "system_info.txt.zip",
        ]

        let now = Date()
        for dir in stagingDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries {
                let lower = entry.lowercased()
                // Match exact basename or as a directory containing the pattern as substring —
                // but require the substring to be at least 8 chars to avoid trivial coincidences.
                guard stealerArtifactPatterns.contains(where: { pattern in
                    lower == pattern || (pattern.count >= 8 && lower.contains(pattern))
                }) else { continue }

                let fullPath = "\(dir)/\(entry)"

                // Skip files older than 30 days — stale leftovers are less actionable, and the user
                // has likely already been notified by their wallet provider if it's older than that.
                if let attrs = try? fm.attributesOfItem(atPath: fullPath),
                   let modDate = attrs[.modificationDate] as? Date,
                   now.timeIntervalSince(modDate) > 30 * 86_400 {
                    continue
                }

                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Crypto wallet stealer staging artifact",
                    detail: "File: \(entry) in \(dir) — matches an infostealer's typical extraction pattern",
                    path: fullPath,
                    remediation: "Treat this as a strong compromise indicator. Move funds from any wallet on this Mac to a new wallet on a clean device. Inspect: ls -la \"\(fullPath)\""
                ))
            }
        }

        // Also detect a known-wallet directory name appearing inside /tmp — stealers commonly
        // copy the wallet dir into /tmp/<wallet_name>_* before zipping it for exfiltration.
        let knownWalletDirs: [(name: String, dir: String)] = [
            ("Exodus", "\(home)/Library/Application Support/Exodus"),
            ("Electrum", "\(home)/.electrum"),
            ("Atomic Wallet", "\(home)/Library/Application Support/atomic"),
            ("Coinomi", "\(home)/Library/Application Support/Coinomi"),
            ("Wasabi", "\(home)/Library/Application Support/WalletWasabi"),
            ("Daedalus", "\(home)/Library/Application Support/Daedalus Mainnet"),
            ("Ledger Live", "\(home)/Library/Application Support/Ledger Live"),
            ("Trezor Suite", "\(home)/Library/Application Support/@trezor"),
        ]

        for wallet in knownWalletDirs {
            guard fm.fileExists(atPath: wallet.dir) else { continue }

            // Stealers commonly copy the wallet dir into /tmp/<wallet_name>_* or .<wallet>/
            // Look for a directory in /tmp whose name contains the wallet name and was created
            // within the last 7 days — strong signal of active extraction.
            for staging in ["/private/tmp", "/private/var/tmp"] {
                guard let stagingEntries = try? fm.contentsOfDirectory(atPath: staging) else { continue }
                for entry in stagingEntries {
                    let lowerEntry = entry.lowercased()
                    let walletKey = wallet.name.lowercased().replacingOccurrences(of: " ", with: "")
                    guard lowerEntry.contains(walletKey) || lowerEntry.contains(wallet.name.lowercased()) else { continue }

                    let copyPath = "\(staging)/\(entry)"
                    if let attrs = try? fm.attributesOfItem(atPath: copyPath),
                       let modDate = attrs[.modificationDate] as? Date,
                       now.timeIntervalSince(modDate) < 7 * 86_400 {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "\(wallet.name) wallet data staged in /tmp",
                            detail: "Recently-modified copy of \(wallet.name) wallet data in \(staging) — matches stealer extraction pattern",
                            path: copyPath,
                            remediation: "Treat as compromised. Move funds to a new wallet on a clean device immediately."
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Quarantine Bypass on Recent Installs

    private func scanQuarantineBypass(findings: inout [Finding], errors: inout [String]) {
        // macOS attaches com.apple.quarantine to every file downloaded from the internet so
        // Gatekeeper can prompt the user before first launch. Recent stealer installers (Atomic,
        // Banshee, Poseidon) ship as DMGs whose install script explicitly runs
        // `xattr -d com.apple.quarantine` on the dropped app, then immediately spawns it — the
        // user never sees the Gatekeeper prompt. An app in /Applications that's < 30 days old
        // and has NO quarantine xattr (yet wasn't put there by the App Store or a package manager)
        // is suspicious.
        let fm = FileManager.default
        let appsDir = "/Applications"
        guard let apps = try? fm.contentsOfDirectory(atPath: appsDir) else { return }

        let now = Date()
        let userAppsDir = "\(ShellRunner.realUserHome)/Applications"

        // Combine /Applications and ~/Applications
        var allApps: [(name: String, path: String)] = apps
            .filter { $0.hasSuffix(".app") }
            .map { (name: $0, path: "\(appsDir)/\($0)") }
        if let userApps = try? fm.contentsOfDirectory(atPath: userAppsDir) {
            allApps.append(contentsOf: userApps
                .filter { $0.hasSuffix(".app") }
                .map { (name: $0, path: "\(userAppsDir)/\($0)") })
        }

        for app in allApps {
            // Skip Apple-shipped apps (these never carry quarantine xattr by design)
            let infoPlist = "\(app.path)/Contents/Info.plist"
            if let data = fm.contents(atPath: infoPlist),
               let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
               let bundleId = plist["CFBundleIdentifier"] as? String,
               bundleId.hasPrefix("com.apple.") { continue }

            // Recently added apps only (last 30 days) — older apps may legitimately have had
            // quarantine cleared by the user or by package managers like Homebrew.
            guard let attrs = try? fm.attributesOfItem(atPath: app.path),
                  let creationDate = attrs[.creationDate] as? Date,
                  now.timeIntervalSince(creationDate) < 30 * 86_400 else { continue }

            // Check for the quarantine xattr — quick `xattr -p` returns non-zero if absent.
            let xattrResult = ShellRunner.run("/usr/bin/xattr",
                                              arguments: ["-p", "com.apple.quarantine", app.path],
                                              timeout: 3)

            // Apps installed via the Mac App Store, Homebrew Cask, or `mas` are explicitly
            // unquarantined — fingerprint those by looking for receipt files / cask metadata.
            let isMASInstalled = fm.fileExists(atPath: "\(app.path)/Contents/_MASReceipt/receipt")
            let isHomebrewCask = (try? fm.destinationOfSymbolicLink(atPath: app.path))?
                .contains("homebrew") ?? false

            if !xattrResult.success && !isMASInstalled && !isHomebrewCask {
                // App was added recently AND has no quarantine xattr AND wasn't installed via
                // a known package manager / the App Store — Gatekeeper was bypassed.
                let daysOld = Int(now.timeIntervalSince(creationDate) / 86_400)
                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "Recently installed app bypassed Gatekeeper (no quarantine xattr)",
                    detail: "App: \(app.name) — installed \(daysOld) day(s) ago, no quarantine attribute, not from App Store or Homebrew",
                    path: app.path,
                    remediation: "Verify you trust this app's source. Stealer installers explicitly strip quarantine to skip the Gatekeeper prompt. To inspect: codesign -dv --verbose=2 \"\(app.path)\""
                ))
            }
        }
    }
}
