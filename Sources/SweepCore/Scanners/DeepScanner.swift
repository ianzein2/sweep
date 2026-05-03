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

        // 6. Check for oversized extended attributes (RustyAttr-style xattr payload smuggling)
        progress?.update("checking extended attribute payloads")
        scanXattrPayloads(findings: &findings, errors: &errors)

        // 7. Check Quarantine database for recent risky downloads
        progress?.update("checking recent risky downloads")
        scanQuarantineDatabase(findings: &findings, errors: &errors)

        // 8. Check for AppleScript persistence (HZ RAT, ClickFix lures)
        progress?.update("checking AppleScript helpers")
        scanAppleScriptArtifacts(findings: &findings, errors: &errors)

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

    // MARK: - Extended-attribute Payload Smuggling (RustyAttr / xattr-resident loaders)

    /// RustyAttr (Lazarus, Nov 2024) hides its second-stage payload inside an extended
    /// attribute on a benign-looking Mach-O. The host binary calls `xattr` at runtime to
    /// extract and decrypt the blob. Apple/Finder show no special icon for a file with
    /// a multi-megabyte xattr — only `xattr -lr` reveals it. We hunt for files whose xattrs
    /// dominate their visible byte size, which is the smoking gun.
    private func scanXattrPayloads(findings: inout [Finding], errors: inout [String]) {
        // Scope is intentionally narrow: places legitimate apps wouldn't park a binary with a
        // massive xattr — Downloads, /tmp, and hidden user directories.
        let home = ShellRunner.realUserHome
        let roots = [
            "\(home)/Downloads",
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "\(home)/.local",
            "\(home)/.config",
        ]

        // We use `xattr -lz` to also list compressed (decoded) attributes, capturing total bytes
        // per file. Then we look for files where the xattr blob is large compared to the file body.
        for root in roots {
            guard FileManager.default.fileExists(atPath: root) else { continue }
            // -r recurses; -s shows sizes; we keep it shallow with maxdepth via find first
            // so we don't blow up on huge trees like Downloads.
            let listing = ShellRunner.run("/bin/sh", arguments: [
                "-c",
                "find \(shellQuote(root)) -maxdepth 3 -type f -size +1k 2>/dev/null | head -200 | while read f; do " +
                "  total=$(xattr -l \"$f\" 2>/dev/null | wc -c | tr -d ' '); " +
                "  if [ \"$total\" -gt 65536 ]; then echo \"$total $f\"; fi; " +
                "done"
            ], timeout: 15)

            guard listing.success, !listing.stdout.isEmpty else { continue }

            let lines = listing.stdout.split(separator: "\n").prefix(20)
            for line in lines {
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2, let xattrBytes = Int(parts[0]) else { continue }
                let path = String(parts[1]).trimmingCharacters(in: .whitespaces)
                guard !path.isEmpty else { continue }

                // Compare to file size — a payload-bearing file is small with a big xattr.
                let attrs = try? FileManager.default.attributesOfItem(atPath: path)
                let fileSize = (attrs?[.size] as? Int) ?? 0
                let isImbalanced = fileSize > 0 && xattrBytes > fileSize / 2

                let mb = String(format: "%.1f", Double(xattrBytes) / 1_048_576)
                let severity: Severity = (isImbalanced || xattrBytes > 1_048_576) ? .high : .medium
                findings.append(Finding(
                    severity: severity,
                    category: .suspiciousFile,
                    title: "Oversized extended attribute on file (possible xattr payload)",
                    detail: "File: \(path) — extended attribute size: \(mb)MB" +
                        (isImbalanced ? " (larger than the file body itself — RustyAttr-style smuggling)" : ""),
                    path: path,
                    remediation: "Inspect: xattr -l \"\(path)\" — RustyAttr and similar Lazarus loaders hide payloads here"
                ))
            }
        }
    }

    /// Quote a path for `/bin/sh -c`. Single-quote and escape any embedded single quotes.
    private func shellQuote(_ path: String) -> String {
        return "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: - Quarantine Database — recent risky downloads

    /// LaunchServices records every quarantined download in a per-user SQLite DB. Reviewing
    /// the most recent entries flags ClickFix lures: DMGs and apps downloaded from typosquatted
    /// domains, .pkg files with names like "Safari Updater", and unsigned binaries from /tmp.
    private func scanQuarantineDatabase(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dbPath = "\(home)/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        guard FileManager.default.fileExists(atPath: dbPath) else { return }

        // The DB stays open during user sessions. Use a read-only sqlite3 query and limit to
        // the last 30 entries. Columns: LSQuarantineEventIdentifier, LSQuarantineTimeStamp,
        // LSQuarantineDataURLString, LSQuarantineOriginURLString.
        let result = ShellRunner.run("/usr/bin/sqlite3", arguments: [
            "-readonly", dbPath,
            "SELECT LSQuarantineTimeStamp, LSQuarantineDataURLString, LSQuarantineOriginURLString " +
            "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 30;"
        ], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // Heuristics for "risky" downloads:
        // - Hosted on an IP literal (no domain), known typosquats, or *.zip/.run vanity TLDs;
        // - Filename ending in .pkg/.dmg from a domain that doesn't match the implied vendor;
        // - Any download whose origin URL impersonates Apple/Safari/Chrome/Visual Studio.
        let impersonationKeywords = [
            "safari", "chrome", "edge", "firefox", "vscode", "visualstudio",
            "zoom", "teams", "1password", "appstore", "icloud",
        ]
        let suspiciousTLDs = [".zip", ".run", ".cfd", ".click", ".country", ".rest", ".today"]

        let lines = result.stdout.split(separator: "\n")
        for line in lines.prefix(30) {
            // sqlite3 default separator is '|'
            let cols = line.split(separator: "|", maxSplits: 2, omittingEmptySubsequences: false)
                            .map(String.init)
            guard cols.count >= 2 else { continue }
            let dataURL = cols[1].lowercased()
            let originURL = (cols.count >= 3 ? cols[2] : "").lowercased()
            let urlForCheck = dataURL.isEmpty ? originURL : dataURL
            guard !urlForCheck.isEmpty else { continue }

            // Skip Apple's own domains and the App Store.
            if urlForCheck.contains("apple.com") || urlForCheck.contains("itunes.apple") { continue }
            if urlForCheck.contains("microsoft.com") || urlForCheck.contains("github.com") { continue }

            // IP-literal origin
            let isIPLiteral = urlForCheck.range(
                of: #"https?://(\d{1,3}\.){3}\d{1,3}"#,
                options: .regularExpression
            ) != nil

            // Vendor impersonation in URL path/host vs. unrelated TLD
            let impersonates = impersonationKeywords.first(where: { urlForCheck.contains($0) })
            let weirdTLD = suspiciousTLDs.first(where: { urlForCheck.contains($0) })

            if isIPLiteral || weirdTLD != nil ||
               (impersonates != nil && !urlForCheck.contains("apple.com")
                                     && !urlForCheck.contains("microsoft.com")
                                     && !urlForCheck.contains("google.com")
                                     && !urlForCheck.contains("mozilla.org")
                                     && !urlForCheck.contains("zoom.us")
                                     && !urlForCheck.contains("1password.com")) {
                let why: String
                if isIPLiteral { why = "downloaded directly from an IP address (no domain)" }
                else if let tld = weirdTLD { why = "downloaded from a TLD commonly used in malware campaigns (\(tld))" }
                else { why = "URL impersonates a vendor (\(impersonates!)) but the host doesn't match" }

                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Risky recent download in Quarantine database",
                    detail: "\(why): \(String(urlForCheck.prefix(160)))",
                    path: nil,
                    remediation: "Locate the downloaded file in ~/Downloads — if you don't recognize it, move it to Trash and run sweep again."
                ))
            }
        }
    }

    // MARK: - AppleScript persistence artifacts (.scpt drops)

    /// ClickFix lures and HZ RAT often leave a .scpt or .applescript file in /tmp or under
    /// ~/Library/Application Scripts. Apple Events from these scripts can read documents,
    /// trigger downloads, and drive other apps with the user's full TCC privileges.
    private func scanAppleScriptArtifacts(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let roots = [
            "/private/tmp",
            "/tmp",
            "/var/tmp",
            "\(home)/Library/Application Scripts",
        ]

        for root in roots {
            let result = ShellRunner.run("/bin/sh", arguments: [
                "-c",
                "find \(shellQuote(root)) -maxdepth 3 -type f \\( -name '*.scpt' -o -name '*.applescript' \\) -mtime -14 2>/dev/null | head -20"
            ], timeout: 8)
            guard result.success else { continue }

            for raw in result.stdout.split(separator: "\n") {
                let path = String(raw).trimmingCharacters(in: .whitespaces)
                guard !path.isEmpty else { continue }

                // Skip Apple's own per-app folders under Application Scripts.
                if path.contains("Application Scripts/com.apple.") { continue }

                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Recent AppleScript dropped in temp/scripts directory",
                    detail: "File: \(path) — AppleScript files in /tmp or generic Application Scripts dirs are a hallmark of ClickFix and HZ RAT campaigns",
                    path: path,
                    remediation: "Inspect contents (osadecompile \"\(path)\") and remove if not yours: rm \"\(path)\""
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
