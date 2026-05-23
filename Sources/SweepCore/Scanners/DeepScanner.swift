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

        // 6. Check for malicious payloads stored in extended attributes (RustyAttr / BlueNoroff, 2024)
        progress?.update("scanning extended attributes for hidden payloads")
        scanXattrPayloads(findings: &findings, errors: &errors)

        // 7. Check for osascript-based credential phishing (Atomic / AMOS pattern)
        progress?.update("checking for credential-prompt phishing")
        scanOSAScriptPhishing(findings: &findings, errors: &errors)

        // 8. Check for LSQuarantine database staleness (Gatekeeper-bypass indicator)
        progress?.update("checking quarantine database freshness")
        scanQuarantineDatabase(findings: &findings, errors: &errors)

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

    // MARK: - Extended Attribute Payloads (RustyAttr / BlueNoroff)

    /// BlueNoroff's RustyAttr (Nov 2024) hides AppleScript / shell payloads inside extended
    /// attributes — typically `com.apple.metadata:_kMDItemUserTags`, custom keys, or oversized
    /// xattrs on otherwise innocuous-looking files. The on-disk file is benign; the malicious
    /// blob only appears when the attribute is read and executed. We flag any non-Apple
    /// extended attribute over a sane size threshold and any custom xattrs containing shell
    /// or AppleScript indicators.
    private func scanXattrPayloads(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // RustyAttr's victims tend to receive lures saved to Downloads / Desktop, plus
        // /private/tmp and /Users/Shared as stage-2 drop points. We deliberately do not
        // re-scan Library here — the existing scanHiddenAttributes() already walks Library.
        let dirsToCheck = [
            "\(home)/Downloads",
            "\(home)/Desktop",
            "/private/tmp",
            "/Users/Shared",
        ]

        // Apple-controlled xattrs that legitimately appear on user files. Anything else, or
        // any of these that is unexpectedly large, deserves a closer look.
        let benignXattrPrefixes = [
            "com.apple.quarantine",
            "com.apple.metadata:kMDItemWhereFroms",
            "com.apple.metadata:kMDItemDownloadedDate",
            "com.apple.FinderInfo",
            "com.apple.lastuseddate",
            "com.apple.macl",
            "com.apple.diskimages",
            "com.apple.ResourceFork",
            "com.apple.TextEncoding",
            "com.apple.metadata:_kTimeMachineNewestSnapshot",
        ]

        struct AttrSize {
            var bytes = 0
        }
        // key: "path|attr"
        var bucket: [String: AttrSize] = [:]
        // Order-preserved keys so we don't rely on dictionary iteration order
        var orderedKeys: [String] = []

        // Hex-dump-line detector: `xattr -l` (and `-lr`) emits indented hex rows of the form
        //   "00000000  62 70 6C ... |bplist00 ...|"
        // — eight hex digits, two spaces, hex pairs. We treat each hex line as 16 bytes.
        func isHexDumpLine(_ s: String) -> Bool {
            guard s.count >= 10 else { return false }
            // First eight chars should be hex digits, followed by two spaces.
            for ch in s.prefix(8) where !ch.isHexDigit { return false }
            let idx = s.index(s.startIndex, offsetBy: 8)
            return s[idx] == " "
        }

        for dir in dirsToCheck {
            guard FileManager.default.fileExists(atPath: dir) else { continue }
            // One recursive xattr call per directory is dramatically faster than per-file.
            let result = ShellRunner.run("/usr/bin/xattr", arguments: ["-lr", dir], timeout: 15)
            guard result.success, !result.stdout.isEmpty else { continue }

            // `xattr -lr` produces two interleaved line shapes:
            //   (a) Header:    "<path>: <attribute_name>:[ inline-value]"
            //   (b) Hex dump:  "<path>: 00000000  62 70 6C ...  |...|"
            //                  (`-r` prefixes the path before each hex row)
            // We carry the last header forward and accumulate hex rows against it.
            var currentKey: String?

            for line in result.stdout.split(separator: "\n") {
                let lineStr = String(line)
                guard let firstColon = lineStr.range(of: ": ") else { continue }
                let path = String(lineStr[..<firstColon.lowerBound])
                let rest = String(lineStr[firstColon.upperBound...])

                // Hex-dump rows? attribute_name doesn't start with an 8-char hex prefix,
                // so this is a robust way to distinguish.
                if isHexDumpLine(rest), let key = currentKey, key.hasPrefix("\(path)|") {
                    bucket[key, default: AttrSize()].bytes += 16
                    continue
                }

                // Otherwise it must be a header line. Attribute name is everything up to
                // the next ":" — but it may itself contain colons (com.apple.metadata:_kMDItemUserTags),
                // so we look for ":" followed by EOL or a space.
                var attrName = ""
                if rest.hasSuffix(":") {
                    attrName = String(rest.dropLast())
                } else if let colonSpace = rest.range(of: ": ") {
                    attrName = String(rest[..<colonSpace.lowerBound])
                    // Inline value (short attributes). Add the rough byte estimate.
                    let inlineValue = rest[colonSpace.upperBound...]
                    let key = "\(path)|\(attrName)"
                    if bucket[key] == nil { orderedKeys.append(key) }
                    bucket[key, default: AttrSize()].bytes += inlineValue.count
                    currentKey = key
                    continue
                } else {
                    continue
                }

                guard attrName.contains("."), !attrName.isEmpty else { continue }
                let key = "\(path)|\(attrName)"
                if bucket[key] == nil { orderedKeys.append(key) }
                _ = bucket[key, default: AttrSize()]
                currentKey = key
            }
        }

        for key in orderedKeys {
            guard let acc = bucket[key] else { continue }
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { continue }
            let path = parts[0]
            let attr = parts[1]
            let isBenign = benignXattrPrefixes.contains { attr.hasPrefix($0) }
            if isBenign { continue }

            if attr.contains("com.apple.metadata:_kMDItemUserTags") && acc.bytes > 1024 {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Oversized macOS metadata tag — RustyAttr indicator",
                    detail: "_kMDItemUserTags is ~\(acc.bytes) bytes (normally <100). BlueNoroff abuses this attribute to hide AppleScript stage-2 payloads.",
                    path: path,
                    remediation: "Inspect: xattr -p com.apple.metadata:_kMDItemUserTags \"\(path)\""
                ))
            } else if acc.bytes >= 4096 {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Large non-Apple extended attribute (possible hidden payload)",
                    detail: "Attribute \"\(attr)\" is ~\(acc.bytes) bytes — RustyAttr-style malware hides script payloads this way",
                    path: path,
                    remediation: "Inspect with: xattr -p \"\(attr)\" \"\(path)\" — remove if malicious: xattr -d \"\(attr)\" \"\(path)\""
                ))
            } else if attr.contains("script") || attr.contains("payload") || attr.contains("exec") {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Suspiciously named extended attribute",
                    detail: "Attribute name \"\(attr)\" suggests stored executable content",
                    path: path,
                    remediation: "Inspect with: xattr -p \"\(attr)\" \"\(path)\""
                ))
            }
        }
    }

    // MARK: - osascript credential-prompt phishing (AMOS / Atomic Stealer pattern)

    /// Atomic macOS Stealer (AMOS) and many of its copycats display a native-looking
    /// "macOS needs your password" prompt by calling `osascript` with a `display dialog`
    /// containing the word "password". Real Apple processes never authenticate via
    /// osascript — so a running osascript whose command line contains "password" is a
    /// high-confidence phishing indicator.
    private func scanOSAScriptPhishing(findings: inout [Finding], errors: inout [String]) {
        // Use ps with a wide output column to capture the full command line — osascript
        // payloads can be long.
        let result = ShellRunner.run("/bin/ps", arguments: ["-Awwo", "pid,user,command"], timeout: 5)
        guard result.success else { return }

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let lineStr = String(line)
            guard lineStr.contains("osascript") || lineStr.contains("/usr/bin/osascript") else { continue }

            // Suspicious tells: requesting a password, hidden-text dialog, or fake
            // System Preferences branding combined with password capture.
            let lower = lineStr.lowercased()
            let hasPasswordPrompt = lower.contains("password") ||
                lower.contains("passcode") || lower.contains("administrator") ||
                lower.contains("authenticate")
            let hasHiddenAnswer = lower.contains("hidden answer") ||
                lower.contains("with hidden answer")
            let mimicsApple = lower.contains("system preferences") || lower.contains("system settings") ||
                lower.contains("touch id") || lower.contains("keychain")

            guard hasPasswordPrompt else { continue }

            let severity: Severity = hasHiddenAnswer ? .high : (mimicsApple ? .high : .medium)
            findings.append(Finding(
                severity: severity, category: .suspiciousProcess,
                title: "osascript displaying a password prompt (possible AMOS-style phishing)",
                detail: String(lineStr.prefix(200)),
                path: nil,
                remediation: "Do NOT enter your password. Kill this process immediately, then run a full scan. Apple never prompts for your password via osascript."
            ))
        }
    }

    // MARK: - LSQuarantine database staleness

    /// macOS records each downloaded file in the LaunchServices quarantine database. When
    /// a downloaded file has its quarantine xattr stripped (a known stealer technique to
    /// bypass Gatekeeper on next launch) the database stops growing while new files keep
    /// arriving on disk. We surface that mismatch as a soft signal.
    private func scanQuarantineDatabase(findings: inout [Finding], errors: inout [String]) {
        let lsRegister = "\(ShellRunner.realUserHome)/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        if let attrs = try? FileManager.default.attributesOfItem(atPath: lsRegister),
           let modDate = attrs[.modificationDate] as? Date {
            // If the quarantine DB hasn't been written to in months but you've downloaded files,
            // it's worth noting. We use a soft heuristic — last write older than 90 days.
            let ageDays = -modDate.timeIntervalSinceNow / 86_400
            if ageDays > 90 {
                // Only meaningful if there are recent downloads — check Downloads dir
                let downloads = "\(ShellRunner.realUserHome)/Downloads"
                let recent = ShellRunner.run("/usr/bin/find", arguments: [
                    downloads, "-maxdepth", "1", "-type", "f", "-mtime", "-30",
                ], timeout: 5)
                if recent.success && !recent.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    findings.append(Finding(
                        severity: .medium, category: .systemIntegrity,
                        title: "Quarantine event database is stale despite recent downloads",
                        detail: "LSQuarantine database last written \(Int(ageDays)) days ago, but Downloads has files modified in the last 30 days — quarantine flagging may be disabled",
                        path: lsRegister,
                        remediation: "Some downloaded files may be running without Gatekeeper checks. Inspect recent downloads, especially DMGs."
                    ))
                }
            }
        }
    }
}
