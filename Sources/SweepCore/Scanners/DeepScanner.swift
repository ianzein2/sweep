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

        // 6. Supply-chain: unknown Homebrew taps and system extensions
        progress?.update("checking Homebrew taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("checking user-approved system extensions")
        scanSystemExtensions(findings: &findings, errors: &errors)

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

    // MARK: - Homebrew Taps (supply-chain surface)

    /// Third-party Homebrew taps can install arbitrary formulae with pre/post-install hooks
    /// that run as the user (or via `sudo` for casks). A tap from an unknown GitHub org that
    /// the user does not remember adding is a plausible supply-chain vector, especially for
    /// developer targets. We enumerate configured taps and flag anything outside the well-known
    /// upstream namespaces.
    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // brew is not always on PATH under our environment; call it via a login shell if present.
        let brewPaths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        let brew = brewPaths.first(where: { FileManager.default.fileExists(atPath: $0) })
        guard let brewBin = brew else { return }

        let result = ShellRunner.run(brewBin, arguments: ["tap"], timeout: 10)
        guard result.success else { return }

        // Officially-blessed taps and common well-known third-party ones.
        let trustedTaps: Set<String> = [
            "homebrew/core", "homebrew/cask", "homebrew/services",
            "homebrew/bundle", "homebrew/command-not-found",
            "homebrew/cask-fonts", "homebrew/cask-versions",
            "homebrew/cask-drivers", "homebrew/aliases", "homebrew/autoupdate",
            "hashicorp/tap", "mongodb/brew", "aws/tap", "azure/functions",
            "microsoft/git", "cloudflare/cloudflare",
            "oven-sh/bun", "supabase/tap", "vercel/tap",
            "cli/cli",  // gh
        ]

        // Only surface taps whose names match a suspicious keyword — third-party taps are
        // routine for developers, so a low-severity finding on every one of them would be noise.
        let suspiciousKeywords = ["mirror", "cracked", "warez", "loader", "keygen",
                                   "spy", "hidden", "stealth"]
        for rawLine in result.stdout.split(separator: "\n") {
            let tap = String(rawLine).trimmingCharacters(in: .whitespaces)
            if tap.isEmpty { continue }
            if trustedTaps.contains(tap) { continue }
            let lowerTap = tap.lowercased()
            guard suspiciousKeywords.contains(where: { lowerTap.contains($0) }) else { continue }

            findings.append(Finding(
                severity: .high, category: .suspiciousFile,
                title: "Suspicious Homebrew tap installed",
                detail: "Tap '\(tap)' matches a suspicious naming pattern — third-party taps run pre/post-install scripts as your user",
                path: nil,
                remediation: "Remove if you don't recognize it: brew untap \(tap)"
            ))
        }
    }

    // MARK: - Approved System Extensions

    /// System Extensions replaced kernel extensions for network filters, endpoint security, and
    /// DriverKit devices. Because they run with high privilege and can capture traffic or
    /// device I/O, an unauthorized one is a serious concern. `systemextensionsctl list` shows
    /// what the user has approved.
    private func scanSystemExtensions(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/systemextensionsctl", arguments: ["list"], timeout: 10)
        guard result.success else { return }

        // Reasonably common team IDs — pass-through so the user isn't warned about their own VPN
        // or endpoint tools. Any team ID not in this set is surfaced for review.
        let knownTeamIds: Set<String> = [
            "PWA5E9TQ59",  // Objective Development (Little Snitch)
            "VB5E2TV963",  // Lulu (Objective-See)
            "K97H2NPKQC",  // 1Password
            "DE8Y96K9QP",  // Docker
            "9DLLWXU8ZQ",  // Parallels
            "EG7KH642X6",  // VMware
            "QED4VVPZWA",  // Microsoft
            "UBF8T346G9",  // Microsoft AutoUpdate
            "6HB5Y2QTA3",  // JamF
            "GRP7GJQ5NF",  // CrowdStrike
            "L28GYP5Y87",  // SentinelOne
            "AY9DMEQTB6",  // Cisco Umbrella
            "N57S25YS5A",  // Cloudflare
            "78MK8UM2Q9",  // Tailscale
        ]

        // Sections look like "--- com.apple.system_extension.<type> ---" followed by TAB-
        // separated rows: "*  *  TEAMID  com.example.bundle (1.0/1)  Extension Name  [activated enabled]".
        // We do a coarse pass: any row that includes an activated ("[activated enabled]") state
        // whose team id is unfamiliar gets surfaced.
        for rawLine in result.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            let cols = line.split(separator: "\t").map { String($0).trimmingCharacters(in: .whitespaces) }
            guard cols.count >= 4 else { continue }
            guard line.contains("[activated enabled]") else { continue }

            // Team IDs are 10-char alphanumerics; digits have no case so upper == self works.
            let teamId = cols.first { field in
                field.count == 10 && field.allSatisfy { $0.isLetter || $0.isNumber }
                    && field.uppercased() == field
            }
            guard let team = teamId else { continue }
            if knownTeamIds.contains(team) { continue }

            // Bundle field may include a trailing " (version/build)" suffix — strip it.
            let bundleField = cols.first(where: {
                $0.hasPrefix("com.") || $0.hasPrefix("org.") ||
                $0.hasPrefix("net.") || $0.hasPrefix("io.")
            }) ?? "unknown"
            let bundle = bundleField.split(separator: " ").first.map(String.init) ?? bundleField
            if bundle.hasPrefix("com.apple.") { continue }

            findings.append(Finding(
                severity: .medium, category: .kernelExtension,
                title: "System extension from unfamiliar developer active",
                detail: "Bundle: \(bundle), Team ID: \(team) — system extensions can filter network traffic or intercept device I/O",
                path: nil,
                remediation: "Review in System Settings > General > Login Items & Extensions > Endpoint Security / Network. Remove if not intentional: systemextensionsctl uninstall \(team) \(bundle)"
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
}
