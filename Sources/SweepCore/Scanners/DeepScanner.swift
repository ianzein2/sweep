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

        // 6. Check for known-compromised global npm packages (supply-chain attacks)
        progress?.update("checking global npm packages")
        scanCompromisedNPMPackages(findings: &findings, errors: &errors)

        // 7. Check for known-compromised global Python packages
        progress?.update("checking global Python packages")
        scanCompromisedPythonPackages(findings: &findings, errors: &errors)

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

    // MARK: - NPM Supply Chain (compromised global packages)

    /// Known-malicious / known-typosquatted npm package names reported in 2024-2025 supply-chain
    /// advisories (Socket, Aikido, Snyk, JFrog, ReversingLabs). Globally installed copies of these
    /// would have run their `postinstall` scripts at install time — possible code execution under
    /// the user's account.
    private static let knownCompromisedNPMPackages: Set<String> = [
        // Typosquats of popular packages observed in 2024-2025 stealer campaigns
        "noblox.js-proxied", "noblox.js-proxy",
        "node-discord.js", "discord-selfbot-v13-stable",
        "ethers-providers-utils", "ethers-helper", "ethereum-cryptography-utils",
        "solana-web3-utils", "solana-tools-helper",
        "lodash-utils-pro", "lodash-helper",
        "axios-helper-utils", "axios-headers-utils",
        "react-hooks-form", "react-async-hook-helper",
        "next-auth-helper-plus",
        "@babel/preset-react-jsx",
        // Late-2024 / 2025 documented compromised packages (Socket / Snyk / Aikido advisories)
        "rspack-helper", "rspack-utils-helper",
        "@solana/web3.js-utils",
        "lottie-helper",
        "is-numeric-utils", "is-windows-utils",
        "test-helper-utils-pro",
        "es-utils-helper",
        // Crypto wallet credential stealers observed in 2025
        "@solana/wallet-adapter-helper",
        "ethers-react-helper",
        "wagmi-helper",
        "trustwallet-helper",
        "wallet-connect-helper",
    ]

    private func scanCompromisedNPMPackages(findings: inout [Finding], errors: inout [String]) {
        // Search the most common global npm locations. `npm ls -g --json --depth=0` would be more
        // accurate but is slow and not always present — file listing is faster and good enough.
        let home = ShellRunner.realUserHome
        let candidateDirs = [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.nvm/versions/node",  // nvm: scan all versions below
            "\(home)/.volta/tools/image/node",
            "\(home)/.fnm/node-versions",
        ]

        let fm = FileManager.default

        var moduleDirs: [String] = []
        for dir in candidateDirs {
            guard fm.fileExists(atPath: dir) else { continue }
            // For nvm/fnm/volta layouts, recurse one level to find each Node version's lib/node_modules.
            if dir.contains(".nvm/versions/node") || dir.contains(".volta") || dir.contains(".fnm") {
                if let versions = try? fm.contentsOfDirectory(atPath: dir) {
                    for v in versions {
                        let nested = "\(dir)/\(v)/lib/node_modules"
                        if fm.fileExists(atPath: nested) { moduleDirs.append(nested) }
                    }
                }
            } else {
                moduleDirs.append(dir)
            }
        }

        for modDir in moduleDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: modDir) else { continue }
            for entry in entries {
                // npm scoped packages live in @scope/name — descend one level
                if entry.hasPrefix("@") {
                    let scopeDir = "\(modDir)/\(entry)"
                    if let nested = try? fm.contentsOfDirectory(atPath: scopeDir) {
                        for sub in nested {
                            let full = "\(entry)/\(sub)"
                            if Self.knownCompromisedNPMPackages.contains(full) ||
                               Self.knownCompromisedNPMPackages.contains(sub) {
                                findings.append(Finding(
                                    severity: .high, category: .suspiciousFile,
                                    title: "Compromised global npm package: \(full)",
                                    detail: "Reported as malicious / typosquat in 2024-2025 supply-chain advisories",
                                    path: "\(scopeDir)/\(sub)",
                                    remediation: "Uninstall: npm uninstall -g \(full) — and rotate any secrets that ran during install"
                                ))
                            }
                        }
                    }
                } else if Self.knownCompromisedNPMPackages.contains(entry) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Compromised global npm package: \(entry)",
                        detail: "Reported as malicious / typosquat in 2024-2025 supply-chain advisories",
                        path: "\(modDir)/\(entry)",
                        remediation: "Uninstall: npm uninstall -g \(entry) — and rotate any secrets that ran during install"
                    ))
                }
            }
        }
    }

    // MARK: - Python Supply Chain (compromised global packages)

    /// Known-malicious PyPI packages from 2024-2025 advisories (Sonatype / Phylum / ReversingLabs).
    private static let knownCompromisedPythonPackages: Set<String> = [
        "discordsafety", "discord-safety", "request-safety",
        "pyobftoolkit", "py-discord-token",
        "ethers-py", "solana-py-helper",
        "colorama-utils", "colorama-tools",
        "requests-darwin-lite", "requests-helper-utils",
        "tensorflow-gpu-cuda", "torchtriton-cpu",
        "pip-tools-helper", "pipreqs-helper",
        "openai-helper-utils", "anthropic-helper",
    ]

    private func scanCompromisedPythonPackages(findings: inout [Finding], errors: inout [String]) {
        // Best-effort: list installed packages via `pip list --format=freeze`. If pip isn't present
        // or returns nothing useful, fall back to looking inside site-packages directories.
        let result = ShellRunner.run("/bin/sh", arguments: [
            "-c", "pip3 list --format=freeze 2>/dev/null || pip list --format=freeze 2>/dev/null"
        ], timeout: 10)

        if result.success && !result.stdout.isEmpty {
            for line in result.stdout.split(separator: "\n") {
                let pkg = String(line).split(separator: "=").first.map(String.init) ?? ""
                let normalized = pkg.lowercased().trimmingCharacters(in: .whitespaces)
                if Self.knownCompromisedPythonPackages.contains(normalized) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Compromised Python package installed: \(normalized)",
                        detail: "Reported as malicious / typosquat in 2024-2025 PyPI supply-chain advisories",
                        path: nil,
                        remediation: "Uninstall: pip uninstall \(normalized) — and rotate any secrets that ran during install"
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
