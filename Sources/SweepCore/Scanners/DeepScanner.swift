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

        // 6. RustyAttr-style stealth: malware hiding payloads in extended attributes
        progress?.update("scanning for xattr-stashed payloads")
        scanExtendedAttributeStealth(findings: &findings, errors: &errors)

        // 7. Quarantine bypass attempts — files downloaded via browser that have had their
        //    com.apple.quarantine xattr stripped, a common defense evasion technique.
        progress?.update("checking for quarantine removal")
        scanQuarantineStripping(findings: &findings, errors: &errors)

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

        // DYLD_* variables cover every known dylib-injection technique. FALLBACK_LIBRARY_PATH and
        // VERSIONED_LIBRARY_PATH are less common but equally abusable — CVE-2023-32364
        // (XPC LaunchServices injection) exploited exactly these.
        let dangerousEnvVars = ["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
                                "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH",
                                "DYLD_VERSIONED_LIBRARY_PATH", "DYLD_VERSIONED_FRAMEWORK_PATH",
                                "DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH",
                                "DYLD_IMAGE_SUFFIX", "DYLD_PRINT_TO_FILE",
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

    // MARK: - Extended-Attribute Stealth (RustyAttr-style)

    /// RustyAttr (DPRK, Nov 2024) and similar families stash payload scripts or shell code inside
    /// extended attributes on otherwise-empty carrier files. xattrs can hold megabytes of opaque
    /// data that never surface in Finder or `ls`. Legitimate xattrs are few and well-known.
    private func scanExtendedAttributeStealth(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Known-legitimate xattr names — anything outside this list warrants attention when it
        // holds a large payload.
        let benignXattrs: Set<String> = [
            "com.apple.FinderInfo",
            "com.apple.metadata:_kMDItemUserTags",
            "com.apple.metadata:kMDItemDownloadedDate",
            "com.apple.metadata:kMDItemWhereFroms",
            "com.apple.metadata:kMDItemIsScreenCapture",
            "com.apple.quarantine",
            "com.apple.lastuseddate#PS",
            "com.apple.ResourceFork",
            "com.apple.TextEncoding",
            "com.apple.macl",
            "com.apple.diskimages.recentcksum",
            "com.apple.diskimages.fsck",
            "com.apple.provenance",
        ]

        let dirs = [
            "\(home)/Library/Application Support",
            "\(home)/Library/LaunchAgents",
            "\(home)/Downloads",
            "/private/tmp",
            "/private/var/tmp",
        ]

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            // Cap at 40 entries per dir to stay fast
            for entry in entries.prefix(40) where !entry.hasPrefix(".") {
                let filePath = "\(dir)/\(entry)"

                // `xattr <path>` prints one attribute name per line. Much easier to parse than -l.
                let namesResult = ShellRunner.run("/usr/bin/xattr", arguments: [filePath], timeout: 3)
                guard namesResult.success, !namesResult.stdout.isEmpty else { continue }

                let attrNames = namesResult.stdout
                    .split(separator: "\n")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }

                for name in attrNames where !benignXattrs.contains(name) {
                    // Skip anything that starts with com.apple. — still Apple metadata we haven't listed.
                    if name.hasPrefix("com.apple.") { continue }

                    // Measure the attribute size by printing it and counting bytes. Any xattr with
                    // more than a few hundred bytes that isn't Apple metadata is unusual; megabyte-
                    // scale xattrs are the RustyAttr giveaway.
                    let sizeResult = ShellRunner.run("/bin/sh", arguments: [
                        "-c", "/usr/bin/xattr -p \"\(name)\" \"\(filePath)\" 2>/dev/null | wc -c"
                    ], timeout: 3)
                    let size = Int(sizeResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
                    if size > 512 {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "File hides large payload in extended attribute",
                            detail: "xattr \"\(name)\" (~\(size) bytes) on \(entry) — RustyAttr-style stealth",
                            path: filePath,
                            remediation: "Inspect: xattr -p \"\(name)\" \"\(filePath)\" | head — remove if malicious"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Quarantine Stripping

    /// `com.apple.quarantine` is the flag that triggers Gatekeeper first-run checks. Malware
    /// delivered via curl/brew scripts routinely clears it so the payload runs without a prompt.
    /// We sample Downloads and temp dirs for executables that are suspiciously un-quarantined.
    private func scanQuarantineStripping(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default
        let dirs = ["\(home)/Downloads", "/private/tmp", "/private/var/tmp"]

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries.prefix(40) where !entry.hasPrefix(".") {
                let path = "\(dir)/\(entry)"

                // Only care about Mach-O binaries or .app bundles
                var isApp = false
                if entry.hasSuffix(".app") {
                    isApp = true
                }

                let isMachO: Bool = {
                    guard !isApp,
                          let fh = FileHandle(forReadingAtPath: path) else { return false }
                    defer { fh.closeFile() }
                    let header = fh.readData(ofLength: 4)
                    guard header.count == 4 else { return false }
                    let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
                    let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
                    return machoMagics.contains(magic)
                }()

                guard isApp || isMachO else { continue }

                // Check attributes — if file has MDItemWhereFroms (came from the internet)
                // but no com.apple.quarantine, someone stripped the quarantine flag.
                let xattrResult = ShellRunner.run("/usr/bin/xattr", arguments: [path], timeout: 3)
                guard xattrResult.success else { continue }
                let attrs = xattrResult.stdout
                let fromInternet = attrs.contains("com.apple.metadata:kMDItemWhereFroms") ||
                    attrs.contains("com.apple.metadata:kMDItemDownloadedDate")
                let hasQuarantine = attrs.contains("com.apple.quarantine")

                if fromInternet && !hasQuarantine {
                    findings.append(Finding(
                        severity: .medium, category: .suspiciousFile,
                        title: "Executable downloaded from the internet with quarantine stripped",
                        detail: "File: \(entry) — has WhereFroms metadata but no quarantine flag (Gatekeeper bypass)",
                        path: path,
                        remediation: "Inspect origin: xattr -p com.apple.metadata:kMDItemWhereFroms \"\(path)\""
                    ))
                }
            }
        }
    }
}
