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

        // 6. Check Time Machine exclusions on suspicious paths — malware asks tmutil to
        //    exclude its install directory so it doesn't get restored/backed up.
        progress?.update("checking Time Machine exclusions")
        scanTimeMachineExclusions(findings: &findings, errors: &errors)

        // 7. Look for ClickFix / clipboard-run traces in shell history — the dominant
        //    initial-access vector in 2024-2025 macOS campaigns.
        progress?.update("checking shell history for ClickFix indicators")
        scanShellHistoryForClickFix(findings: &findings, errors: &errors)

        // 8. Look for staged pkg installers dropped by loaders — a common stealer intermediate.
        progress?.update("checking for staged installers")
        scanStagedInstallers(findings: &findings, errors: &errors)

        // 9. Look for AppleScript files that mimic macOS password prompts.
        progress?.update("checking for fake password prompt scripts")
        scanFakePasswordPrompts(findings: &findings, errors: &errors)

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

    // MARK: - Time Machine Exclusions

    /// Malware calls `tmutil addexclusion` on its install directory so backups don't preserve
    /// evidence of the compromise. Real users normally exclude large caches (node_modules,
    /// virtual machines, Xcode DerivedData) — anything hidden or under /tmp is suspect.
    private func scanTimeMachineExclusions(findings: inout [Finding], errors: inout [String]) {
        // Sticky Time Machine exclusions live in Spotlight metadata under the
        // com_apple_backup_excludeItem attribute — mdfind is the fastest way to enumerate them.
        let candidateRoots = [
            "/tmp", "/private/tmp", "/var/tmp",
            "\(ShellRunner.realUserHome)/Library/Application Support",
            "\(ShellRunner.realUserHome)/.local",
        ]

        for root in candidateRoots {
            let cmd = "mdfind -onlyin \"\(root)\" 'com_apple_backup_excludeItem == *' 2>/dev/null | head -20"
            let res = ShellRunner.run("/bin/sh", arguments: ["-c", cmd], timeout: 5)
            guard res.success && !res.stdout.isEmpty else { continue }

            for line in res.stdout.split(separator: "\n") {
                let path = String(line).trimmingCharacters(in: .whitespaces)
                if path.isEmpty { continue }

                let last = URL(fileURLWithPath: path).lastPathComponent
                let hasHiddenComponent = path.split(separator: "/").contains { $0.hasPrefix(".") }
                let inTemp = path.hasPrefix("/tmp") || path.hasPrefix("/private/tmp") ||
                             path.hasPrefix("/var/tmp")

                // Skip known legitimate cache directories.
                let legitCaches = ["node_modules", "DerivedData", ".build", "target",
                                   "Caches", ".cache", "venv", ".venv", ".Trash",
                                   "vmware", "parallels", "Docker.raw"]
                if legitCaches.contains(where: { last.contains($0) || path.contains("/\($0)/") }) {
                    continue
                }

                if hasHiddenComponent || inTemp {
                    findings.append(Finding(
                        severity: .medium, category: .suspiciousFile,
                        title: "Backup-excluded file in hidden or temp location",
                        detail: "Time Machine will skip this path — malware excludes its install directory to avoid restoration",
                        path: path,
                        remediation: "Remove exclusion after inspection: sudo tmutil removeexclusion \"\(path)\""
                    ))
                }
            }
        }
    }

    // MARK: - ClickFix / clipboard-run detection

    /// ClickFix (also called FakeCAPTCHA) works by tricking the user into pasting a shell
    /// command copied by a malicious webpage. The command usually chains `curl … | sh`,
    /// pipes `pbpaste`, or decodes base64. Traces linger in `.zsh_history` / `.bash_history`.
    private func scanShellHistoryForClickFix(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let histFiles = [
            "\(home)/.zsh_history", "\(home)/.bash_history",
            "\(home)/.history", "\(home)/.local/share/fish/fish_history",
        ]

        // Every hit is a HIGH — these idioms are essentially only used by malicious loaders.
        let clickFixPatterns: [(String, String)] = [
            ("pbpaste | sh", "shell reading from clipboard"),
            ("pbpaste|sh", "shell reading from clipboard"),
            ("pbpaste | bash", "shell reading from clipboard"),
            ("pbpaste|bash", "shell reading from clipboard"),
            ("echo -n \"\" | pbcopy", "clipboard scrubbed after paste (ClickFix cleanup)"),
            ("curl -s -o /tmp/", "silent curl into /tmp"),
            ("| base64 -d | sh", "base64-decoded shell payload"),
            ("| base64 --decode | sh", "base64-decoded shell payload"),
            ("osascript -e 'do shell script", "AppleScript one-liner running shell"),
            ("chmod +x /tmp/", "chmod on freshly downloaded /tmp binary"),
        ]

        for histFile in histFiles {
            guard let content = try? String(contentsOfFile: histFile, encoding: .utf8) else { continue }
            let lower = content.lowercased()
            let fileName = URL(fileURLWithPath: histFile).lastPathComponent

            var hits: [(pattern: String, why: String)] = []
            for (pattern, why) in clickFixPatterns where lower.contains(pattern.lowercased()) {
                hits.append((pattern, why))
            }
            if hits.isEmpty { continue }

            // Deduplicate by pattern.
            let uniqueHits = Array(Set(hits.map { $0.pattern }))
            let firstWhy = hits.first?.why ?? ""

            findings.append(Finding(
                severity: .high, category: .suspiciousProcess,
                title: "Shell history contains ClickFix-style command",
                detail: "In \(fileName): \(firstWhy) — matched \(uniqueHits.count) pattern(s). Attacker got you to paste a command from a fake CAPTCHA or error dialog.",
                path: histFile,
                remediation: "Open \(histFile), review recent entries, rotate any secrets typed after the paste, and scan for follow-on malware."
            ))
        }
    }

    // MARK: - Staged installers

    /// A signed `.pkg` sitting in /tmp is a stealer's second stage — it was downloaded and
    /// left there for the user to double-click. Legitimate software never installs from /tmp.
    private func scanStagedInstallers(findings: inout [Finding], errors: inout [String]) {
        let stagingDirs = ["/tmp", "/private/tmp", "/var/tmp",
                           "\(ShellRunner.realUserHome)/Downloads"]
        let fm = FileManager.default

        for dir in stagingDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            let isDownloads = dir.hasSuffix("/Downloads")

            for entry in contents {
                let ext = URL(fileURLWithPath: entry).pathExtension.lowercased()
                guard ["pkg", "dmg", "mpkg"].contains(ext) else { continue }
                let filePath = "\(dir)/\(entry)"

                guard let attrs = try? fm.attributesOfItem(atPath: filePath),
                      let modDate = attrs[.modificationDate] as? Date else { continue }
                // Only flag recent drops — old files in Downloads are the user's own.
                let ageSeconds = -modDate.timeIntervalSinceNow
                if isDownloads && ageSeconds > 86400 * 3 { continue }

                let severity: Severity = isDownloads ? .low : .high
                let where_ = isDownloads ? "Downloads" : "system temp directory"

                findings.append(Finding(
                    severity: severity, category: .suspiciousFile,
                    title: "\(ext.uppercased()) installer staged in \(where_)",
                    detail: "File: \(entry) — installers dropped in /tmp are almost always malicious second-stage payloads",
                    path: filePath,
                    remediation: isDownloads
                        ? "Verify you downloaded this and know the source"
                        : "Do not run. Inspect origin, then remove: sudo rm \"\(filePath)\""
                ))
            }
        }
    }

    // MARK: - Fake password-prompt AppleScripts

    /// A canonical AMOS / Poseidon / Cthulhu step: drop a `.scpt` into /tmp that prompts the
    /// user with a fake macOS system dialog asking for their login password, then pipe the
    /// answer to `sudo -S`. We look for AppleScripts under /tmp that contain both a password
    /// prompt and a shell-exec instruction.
    private func scanFakePasswordPrompts(findings: inout [Finding], errors: inout [String]) {
        let stagingDirs = ["/tmp", "/private/tmp", "/var/tmp"]
        let fm = FileManager.default

        for dir in stagingDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in contents {
                let ext = URL(fileURLWithPath: entry).pathExtension.lowercased()
                guard ["scpt", "applescript", "osascript"].contains(ext) else { continue }
                let filePath = "\(dir)/\(entry)"

                // `.scpt` is compiled — read as raw text; strings we're after are plain ASCII.
                guard let raw = fm.contents(atPath: filePath),
                      let text = String(data: raw, encoding: .utf8)
                            ?? String(data: raw, encoding: .isoLatin1) else { continue }
                let lower = text.lowercased()

                let promptsForPassword =
                    lower.contains("hidden answer") ||   // AppleScript flag for password fields
                    lower.contains("with hidden") ||
                    lower.contains("password")
                let runsShell =
                    lower.contains("do shell script") ||
                    lower.contains("sudo -s") ||
                    lower.contains("| sudo -s") ||
                    lower.contains("| sudo ")

                if promptsForPassword && runsShell {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "AppleScript in /tmp mimics macOS password prompt",
                        detail: "File \(entry) both prompts for a password and executes a shell — classic AMOS-style credential theft",
                        path: filePath,
                        remediation: "Do not run. Change your login password, then: sudo rm \"\(filePath)\""
                    ))
                }
            }
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
}
