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

        // 6. Check for stealer staging artifacts in /private/tmp — AMOS-family infostealers
        //    drop a `.scpt` AppleScript next to a `password` text file.
        progress?.update("checking stealer staging artifacts")
        scanStealerStagingArtifacts(findings: &findings, errors: &errors)

        // 7. Look for recently-downloaded Mach-O binaries that have had their quarantine
        //    attribute stripped — a common technique to bypass Gatekeeper after the file
        //    arrived from the Internet.
        progress?.update("checking quarantine bypass")
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

    // MARK: - Stealer Staging Artifacts in /private/tmp

    private func scanStealerStagingArtifacts(findings: inout [Finding], errors: inout [String]) {
        // AMOS, SHAMOS, Banshee, Poseidon and their derivatives stage themselves in
        // /private/tmp before exfiltration. The hallmarks: a `.scpt` AppleScript with a
        // generated name (often AppleScript-XXX.scpt), an unsigned Mach-O dropped alongside
        // a `password.txt` / `pass.txt`, or a tarball whose name starts with `out.` or
        // `screenshots.`. None of these are normal contents of /private/tmp.
        let tempRoots = ["/private/tmp", "/tmp", "/var/tmp"]
        let fm = FileManager.default

        for root in tempRoots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

            for entry in entries {
                let path = "\(root)/\(entry)"
                let lc = entry.lowercased()

                // 1. AppleScript staging files
                if lc.hasSuffix(".scpt") &&
                   (lc.contains("applescript-") || lc.contains("update") ||
                    lc.contains("install") || lc.contains("loader")) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "AppleScript staged in temp directory",
                        detail: "File \(entry) in \(root) — matches AMOS / SHAMOS / Banshee staging filename pattern",
                        path: path,
                        remediation: "Inspect with: osadecompile \"\(path)\" — and remove if it's a dropper"
                    ))
                    continue
                }

                // 2. Plaintext password dumps left behind by stealers after `dscl` / keychain extraction
                if lc == "password.txt" || lc == "pass.txt" || lc == "passwd.txt" ||
                   lc == "keychain.txt" || lc == "kc.txt" {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Plaintext password dump in temp directory",
                        detail: "File \(entry) in \(root) — stealers stash extracted credentials here before upload",
                        path: path,
                        remediation: "Rotate every password that may have been stored on this Mac. Then remove the file: rm \"\(path)\""
                    ))
                    continue
                }

                // 3. Stealer archive staging
                if (lc.hasSuffix(".zip") || lc.hasSuffix(".tar.gz") || lc.hasSuffix(".tgz")) &&
                   (lc.contains("out.") || lc.contains("loot") || lc.contains("data.") ||
                    lc.contains("dump.") || lc.contains("screenshots") || lc.hasPrefix("bnsh") ||
                    lc.hasPrefix("amos") || lc.hasPrefix("shamos")) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Stealer-style archive in temp directory",
                        detail: "File \(entry) in \(root) — matches infostealer exfil-bundle naming",
                        path: path,
                        remediation: "Inspect contents (unzip -l), then remove. Investigate the process that created the file."
                    ))
                }
            }
        }
    }

    // MARK: - Quarantine Bypass

    private func scanQuarantineBypass(findings: inout [Finding], errors: inout [String]) {
        // Browsers and curl/wget (when invoked via Terminal) attach `com.apple.quarantine`
        // to files they save. If a recently-modified Mach-O binary in ~/Downloads or other
        // common drop targets is *missing* that attribute, the user (or a script) likely
        // stripped it — that's the technique recommended by every ClickFix-style malware
        // installation page ("just run xattr -d com.apple.quarantine to fix the warning").
        let home = ShellRunner.realUserHome
        let watchDirs = [
            "\(home)/Downloads",
            "\(home)/Desktop",
            "/Users/Shared",
        ]
        let fm = FileManager.default

        for dir in watchDirs {
            guard fm.fileExists(atPath: dir),
                  let enumerator = fm.enumerator(
                    at: URL(fileURLWithPath: dir),
                    includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey, .fileSizeKey],
                    options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { continue }

            var checked = 0
            for case let url as URL in enumerator {
                // Cap inspection so we don't crawl multi-thousand-file Downloads folders.
                checked += 1
                if checked > 200 { break }
                if enumerator.level > 2 { enumerator.skipDescendants(); continue }

                guard let values = try? url.resourceValues(forKeys: [
                    .isRegularFileKey, .contentModificationDateKey, .fileSizeKey
                ]), values.isRegularFile == true,
                      let modDate = values.contentModificationDate,
                      let size = values.fileSize, size > 4_000,
                      modDate.timeIntervalSinceNow > -86400 * 14  // last 14 days
                else { continue }

                let path = url.path

                // Only inspect Mach-O binaries — that's what stealers drop.
                guard let fh = FileHandle(forReadingAtPath: path) else { continue }
                let header = fh.readData(ofLength: 4)
                fh.closeFile()
                guard header.count == 4 else { continue }
                let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
                let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
                guard machoMagics.contains(magic) else { continue }

                // Check for the quarantine xattr. Absent = it was stripped (or the file was
                // moved out of a browser/curl context). Either way, surface it.
                let xattrResult = ShellRunner.run("/usr/bin/xattr", arguments: [path], timeout: 3)
                let hasQuarantine = xattrResult.success &&
                    xattrResult.stdout.contains("com.apple.quarantine")
                if hasQuarantine { continue }

                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Recent Mach-O binary without quarantine attribute",
                    detail: "Modified \(formatAge(modDate)) — file lacks com.apple.quarantine, so Gatekeeper / XProtect did not screen it",
                    path: path,
                    remediation: "If you didn't intentionally strip the attribute (e.g. with `xattr -d`), treat this binary as untrusted. Verify the signature: codesign -dv \"\(path)\""
                ))
            }
        }
    }

    private func formatAge(_ date: Date) -> String {
        let seconds = -date.timeIntervalSinceNow
        if seconds < 3600 { return "\(Int(seconds / 60))m ago" }
        if seconds < 86400 { return "\(Int(seconds / 3600))h ago" }
        return "\(Int(seconds / 86400))d ago"
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
