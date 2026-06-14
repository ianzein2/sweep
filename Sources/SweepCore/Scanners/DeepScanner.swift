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

        // 6. Look for recent TCC.db mutations — direct edits are the canonical TCC bypass.
        progress?.update("checking TCC database mutations")
        scanRecentTCCMutations(findings: &findings, errors: &errors)

        // 7. Inspect package-manager config for registry / proxy hijacks. Recent supply-chain
        //    attacks (PyPI, npm) drop registry overrides into the user's profile to route every
        //    `npm install` through an attacker-controlled mirror.
        progress?.update("checking package-manager config")
        scanPackageManagerConfig(findings: &findings, errors: &errors)

        // 8. AppleScript droppers — AMOS-family infostealers commonly stage `.scpt` payloads
        //    in /tmp before running them via osascript.
        progress?.update("checking AppleScript drops in /tmp")
        scanAppleScriptDrops(findings: &findings, errors: &errors)

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

    // MARK: - Recent TCC.db Mutations

    /// macOS protects TCC.db via SIP, but every documented TCC bypass technique (CVE-2023-32369,
    /// CVE-2024-44131, the "Hot Spare" trick) ends in modifying it. The system TCC.db is
    /// effectively never written by anything other than tccd itself; if it changed in the last
    /// few days without a macOS update, something interesting happened.
    private func scanRecentTCCMutations(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dbs = [
            ("user TCC.db", "\(home)/Library/Application Support/com.apple.TCC/TCC.db"),
            ("system TCC.db", "/Library/Application Support/com.apple.TCC/TCC.db"),
        ]

        let fm = FileManager.default
        for (label, path) in dbs {
            guard fm.fileExists(atPath: path),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let modDate = attrs[.modificationDate] as? Date else { continue }

            let hoursSinceMod = -modDate.timeIntervalSinceNow / 3600
            // The user DB legitimately changes every time you toggle a permission, so a 7-day
            // window for "recent" keeps false positives down. The system DB should almost never
            // change outside of an OS update — flag tighter (3-day window) and higher severity.
            let isSystem = label.hasPrefix("system")
            let windowHours: Double = isSystem ? 72 : 168

            if hoursSinceMod < windowHours {
                // Cross-check: was there a macOS install in roughly the same window?
                let installLog = "/var/log/install.log"
                let logChanged = (try? fm.attributesOfItem(atPath: installLog))?[.modificationDate] as? Date
                let recentInstall: Bool = {
                    guard let d = logChanged else { return false }
                    return -d.timeIntervalSinceNow / 3600 < windowHours
                }()
                if isSystem && recentInstall { continue }

                let ageStr = hoursSinceMod < 24
                    ? "\(Int(hoursSinceMod))h ago"
                    : "\(Int(hoursSinceMod / 24))d ago"
                findings.append(Finding(
                    severity: isSystem ? .high : .low,
                    category: .permission,
                    title: "\(label) was modified recently (\(ageStr))",
                    detail: isSystem
                        ? "System TCC.db should only change during macOS updates. Recent unexplained mutation can indicate a TCC bypass exploit."
                        : "User TCC.db changed — normal if you recently granted/revoked a permission, suspicious otherwise.",
                    path: path,
                    remediation: isSystem
                        ? "Check System Settings > Privacy & Security for unexpected grants; consider a full security review."
                        : "If you didn't grant or revoke a permission recently, review System Settings > Privacy & Security."
                ))
            }
        }
    }

    // MARK: - Package-Manager Config Hijacks

    /// Supply-chain campaigns (recent `npm` 2024-2025 events, PyPI typosquatting) often plant a
    /// registry override or pre-install hook in the user's per-tool config files. These look
    /// boring to a developer but reroute every package install through attacker infra.
    private func scanPackageManagerConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        struct ConfigCheck {
            let path: String
            let label: String
            let registryKey: String
            let trustedRegistries: [String]
        }

        let checks: [ConfigCheck] = [
            ConfigCheck(
                path: "\(home)/.npmrc",
                label: "npm",
                registryKey: "registry=",
                trustedRegistries: [
                    "https://registry.npmjs.org",
                    "https://registry.yarnpkg.com",
                    "https://npm.pkg.github.com",
                ]
            ),
            ConfigCheck(
                path: "\(home)/.yarnrc",
                label: "yarn (classic)",
                registryKey: "registry ",
                trustedRegistries: [
                    "https://registry.yarnpkg.com",
                    "https://registry.npmjs.org",
                ]
            ),
            ConfigCheck(
                path: "\(home)/.yarnrc.yml",
                label: "yarn (berry)",
                registryKey: "npmRegistryServer:",
                trustedRegistries: [
                    "https://registry.yarnpkg.com",
                    "https://registry.npmjs.org",
                ]
            ),
            ConfigCheck(
                path: "\(home)/.config/pip/pip.conf",
                label: "pip",
                registryKey: "index-url",
                trustedRegistries: ["https://pypi.org", "https://files.pythonhosted.org"]
            ),
            ConfigCheck(
                path: "\(home)/.pip/pip.conf",
                label: "pip",
                registryKey: "index-url",
                trustedRegistries: ["https://pypi.org", "https://files.pythonhosted.org"]
            ),
        ]

        for check in checks {
            guard fm.fileExists(atPath: check.path),
                  let content = try? String(contentsOfFile: check.path, encoding: .utf8) else { continue }

            for rawLine in content.split(separator: "\n") {
                let line = String(rawLine).trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }

                // Registry override
                let lower = line.lowercased()
                if lower.contains(check.registryKey.lowercased()) {
                    let trusted = check.trustedRegistries.contains { lower.contains($0.lowercased()) }
                    if !trusted {
                        findings.append(Finding(
                            severity: .high, category: .networkActivity,
                            title: "\(check.label) registry overridden to an untrusted host",
                            detail: "Line: \(String(line.prefix(120)))",
                            path: check.path,
                            remediation: "Inspect \(check.path) — every `\(check.label) install` is going through this host. Remove the line if it isn't your employer's mirror."
                        ))
                    }
                }

                // Proxy override — same idea, lets attacker intercept all package traffic
                if (lower.contains("proxy=") || lower.contains("proxy ")) &&
                   !lower.contains("noproxy") && !lower.contains("no_proxy") {
                    findings.append(Finding(
                        severity: .medium, category: .networkActivity,
                        title: "\(check.label) HTTP proxy is configured",
                        detail: "Line: \(String(line.prefix(120))) — every package install will route through this proxy",
                        path: check.path,
                        remediation: "Verify the proxy is yours. Remove the line otherwise: nano \(check.path)"
                    ))
                }

                // The "always-auth + custom registry" combo is how npm credential-stealing
                // proxies harvest CI tokens.
                if lower.contains("always-auth") && lower.contains("true") {
                    findings.append(Finding(
                        severity: .low, category: .networkActivity,
                        title: "\(check.label) is configured to always send auth tokens",
                        detail: "Line: \(String(line.prefix(120))) — paired with a custom registry this leaks credentials on every install",
                        path: check.path,
                        remediation: "Remove if not required by your registry: nano \(check.path)"
                    ))
                }
            }
        }
    }

    // MARK: - AppleScript drops in /tmp

    /// Atomic macOS Stealer (AMOS) and its variants ship a stage-1 payload that writes a `.scpt`
    /// file to /tmp, then runs it with `osascript`. The script typically prompts for the user's
    /// password via `display dialog` and pipes the answer to `curl` for exfiltration. A `.scpt`
    /// file sitting in /tmp is, on its own, a very strong indicator.
    private func scanAppleScriptDrops(findings: inout [Finding], errors: inout [String]) {
        let dirs = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]
        let fm = FileManager.default

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries {
                let lower = entry.lowercased()
                guard lower.hasSuffix(".scpt") || lower.hasSuffix(".applescript") else { continue }

                let path = "\(dir)/\(entry)"
                var detail = "AppleScript file in temp directory"

                // Read first ~4KB and look for the canonical AMOS markers (display dialog asking
                // for the user's password). Helps us distinguish "developer test script" from
                // "active stealer payload" in the same finding.
                if let fh = FileHandle(forReadingAtPath: path) {
                    let head = fh.readData(ofLength: 4096)
                    fh.closeFile()
                    if let str = String(data: head, encoding: .utf8) {
                        let amosMarkers = [
                            "display dialog",
                            "with hidden answer",
                            "System Preferences", // typical lure
                            "curl",
                            "do shell script",
                        ]
                        let hit = amosMarkers.filter { str.localizedCaseInsensitiveContains($0) }
                        if hit.count >= 2 {
                            detail += " — markers: \(hit.joined(separator: ", "))"
                            findings.append(Finding(
                                severity: .high, category: .suspiciousFile,
                                title: "AppleScript dropper in temp directory: \(entry)",
                                detail: detail,
                                path: path,
                                remediation: "Inspect: cat \"\(path)\" — then delete. Likely AMOS-family stealer stage 1."
                            ))
                            continue
                        }
                    }
                }

                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "AppleScript file in temp directory: \(entry)",
                    detail: detail,
                    path: path,
                    remediation: "Inspect: cat \"\(path)\""
                ))
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
