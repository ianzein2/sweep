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

        // 6. RustyAttr (Nov 2024) — malware that stores its actual payload in extended
        //    file attributes so the on-disk file body looks empty or benign to scanners.
        progress?.update("checking for xattr-hidden payloads")
        scanLargeXattrPayloads(findings: &findings, errors: &errors)

        // 7. Quarantine-strip detection — apps outside the App Store that have had
        //    com.apple.quarantine removed via `xattr -d` bypass Gatekeeper's first-launch check.
        progress?.update("checking Gatekeeper quarantine state")
        scanQuarantineBypass(findings: &findings, errors: &errors)

        // 8. Developer-mode / task-port entitlements on non-dev binaries — abused by
        //    malware that needs to read memory or bypass library validation.
        progress?.update("checking binary entitlements")
        scanRiskyEntitlements(findings: &findings, errors: &errors)

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

    // MARK: - Extended Attribute Payloads (RustyAttr, Nov 2024)

    /// Modern macOS malware hides executable payloads inside extended file attributes
    /// so the file's on-disk body looks harmless to size-based and static scanners.
    /// Real-world samples (RustyAttr, 2024) stash ~20KB+ Mach-O payloads in an xattr,
    /// then read and eval them at runtime. Legitimate xattrs rarely exceed a few KB;
    /// anything over 8KB in a user-writable location is worth a closer look.
    private func scanLargeXattrPayloads(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let roots = [
            "\(home)/Downloads",
            "\(home)/Documents",
            "\(home)/Desktop",
            "\(home)/Library/Application Support",
            "/tmp", "/private/tmp", "/var/tmp",
            "/Users/Shared",
        ]

        // xattr -lxz is quiet and prints `<filename>: <attr>\n<hex dump>`. We count
        // the size of each attribute's value as a proxy for "this is data, not metadata".
        // Known harmless xattr names are skipped so we don't drown in FinderInfo noise.
        let benignAttrs: Set<String> = [
            "com.apple.FinderInfo",
            "com.apple.ResourceFork",
            "com.apple.metadata:kMDItemWhereFroms",
            "com.apple.metadata:kMDItemDownloadedDate",
            "com.apple.metadata:kMDItemIsScreenCapture",
            "com.apple.metadata:_kMDItemUserTags",
            "com.apple.quarantine",
            "com.apple.macl",
            "com.apple.lastuseddate#PS",
            "com.apple.provenance",
        ]

        var flagged = 0
        for root in roots {
            guard FileManager.default.fileExists(atPath: root) else { continue }
            // Use find to list files with xattrs present. `xattr -r` over a huge tree
            // is slow, so we rely on `ls -l@` via shell which quickly reveals xattr size.
            let result = ShellRunner.run("/bin/sh", arguments: [
                "-c",
                "find \(root) -type f -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/.Trash/*' -maxdepth 3 -print0 2>/dev/null | xargs -0 ls -l@ 2>/dev/null | head -400"
            ], timeout: 15)
            guard result.success else { continue }

            var currentFile: String?
            for rawLine in result.stdout.split(separator: "\n") {
                let line = String(rawLine)
                // `ls -l@` output alternates: a file header line, then indented attr lines
                // like "\tcom.apple.FinderInfo     32".
                if line.hasPrefix("\t") || line.hasPrefix("    ") {
                    let parts = line.trimmingCharacters(in: .whitespaces)
                        .split(separator: " ", omittingEmptySubsequences: true)
                    guard parts.count >= 2 else { continue }
                    let attr = String(parts[0])
                    let size = Int(parts[1]) ?? 0
                    if benignAttrs.contains(attr) { continue }
                    if size < 8192 { continue }   // <8KB — not a viable payload

                    if let file = currentFile {
                        findings.append(Finding(
                            severity: .high, category: .suspiciousFile,
                            title: "Large extended attribute on file (possible RustyAttr-style hidden payload)",
                            detail: "File: \(file), xattr: \(attr), size: \(size) bytes — this is the exact trick RustyAttr uses to hide Mach-O or shell payloads",
                            path: file,
                            remediation: "Inspect: xattr -l \"\(file)\" | head. Strip if malicious: xattr -d \(attr) \"\(file)\""
                        ))
                        flagged += 1
                        if flagged >= 20 { return }  // cap to avoid flooding
                    }
                } else {
                    // New file header — usually "-rw-r--r--@ 1 user staff 123 Jan 1 00:00 /path"
                    // Take everything after the timestamp as the path. Fall back to last token.
                    let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                    if parts.count >= 9 {
                        let pathPieces = parts[8...].map(String.init)
                        currentFile = pathPieces.joined(separator: " ")
                    }
                }
            }
        }
    }

    // MARK: - Gatekeeper Quarantine Bypass

    /// macOS tags files downloaded from browsers and mail with `com.apple.quarantine`,
    /// which triggers Gatekeeper's first-launch prompt. Malware installers routinely
    /// run `xattr -dr com.apple.quarantine` on their payload to avoid that prompt.
    /// An app in /Applications that was NOT installed via the App Store and has no
    /// quarantine xattr is not a smoking gun on its own (e.g. Homebrew casks also
    /// strip it), but combined with an unsigned binary it's a strong IOC.
    private func scanQuarantineBypass(findings: inout [Finding], errors: inout [String]) {
        let appsDir = "/Applications"
        guard let apps = try? FileManager.default.contentsOfDirectory(atPath: appsDir) else { return }

        // Batch: ask `mdls` for the quarantine attribute on each app bundle in one go.
        var missingQuarantine: [String] = []
        for app in apps.filter({ $0.hasSuffix(".app") }).prefix(200) {
            let appPath = "\(appsDir)/\(app)"
            // Skip Apple-shipped apps and known signed vendors (App Store + Developer ID).
            let infoPlist = "\(appPath)/Contents/Info.plist"
            guard let data = FileManager.default.contents(atPath: infoPlist),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { continue }
            let bundleId = plist["CFBundleIdentifier"] as? String ?? ""
            if bundleId.hasPrefix("com.apple.") { continue }

            // Presence of the attribute means GateKeeper already handled this app.
            let xattr = ShellRunner.run("/usr/bin/xattr", arguments: ["-p", "com.apple.quarantine", appPath], timeout: 3)
            if xattr.success { continue }
            // App Store installs don't carry quarantine but have `com.apple.installer`/receipt.
            // Tell App Store apps apart via `mdls` — kMDItemAppStoreHasReceipt is reliable.
            let mdls = ShellRunner.run("/usr/bin/mdls", arguments: [
                "-name", "kMDItemAppStoreHasReceipt", "-raw", appPath
            ], timeout: 3)
            if mdls.success && mdls.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" { continue }

            missingQuarantine.append(appPath)
        }

        // Of the apps missing quarantine AND no App Store receipt, flag the unsigned ones.
        for appPath in missingQuarantine {
            let isSigned = checkAppIsSigned(appPath: appPath)
            if !isSigned {
                let name = URL(fileURLWithPath: appPath).lastPathComponent
                findings.append(Finding(
                    severity: .high, category: .systemIntegrity,
                    title: "Unsigned app in /Applications with quarantine stripped",
                    detail: "App: \(name) — no App Store receipt, no Developer ID signature, and com.apple.quarantine has been removed. This is how stealers (AMOS, Banshee) bypass Gatekeeper.",
                    path: appPath,
                    remediation: "Verify the installer, then re-quarantine for safety: xattr -w com.apple.quarantine \"0081;00000000;Safari;\" \"\(appPath)\" — or remove the app"
                ))
            }
        }
    }

    private func checkAppIsSigned(appPath: String) -> Bool {
        let url = URL(fileURLWithPath: appPath) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return false
        }
        return SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil) == errSecSuccess
    }

    // MARK: - Risky Entitlements on User Binaries

    /// Entitlements like `com.apple.security.cs.allow-dyld-environment-variables`,
    /// `com.apple.security.cs.disable-library-validation`, and `com.apple.security.get-task-allow`
    /// exist for developer workflows but are exactly what malware needs to inject code or
    /// read another process's memory. Apple- and App-Store-signed binaries legitimately
    /// use these; a user-installed unsigned binary with these entitlements is a red flag.
    private func scanRiskyEntitlements(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirsToCheck = [
            "\(home)/Applications",
            "\(home)/Downloads",
            "/Applications",  // still check but skip Apple-signed
            "/Users/Shared",
        ]

        let riskyEntitlements: [(key: String, why: String)] = [
            ("com.apple.security.cs.disable-library-validation",
             "disables library validation (allows loading any code)"),
            ("com.apple.security.cs.allow-dyld-environment-variables",
             "allows DYLD_* injection variables"),
            ("com.apple.security.get-task-allow",
             "allows other processes to attach to this one (debugger / memory read)"),
            ("com.apple.security.cs.disable-executable-page-protection",
             "disables W^X page protection"),
        ]

        let fm = FileManager.default
        var flagged = 0
        for dir in dirsToCheck {
            guard fm.fileExists(atPath: dir),
                  let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for app in apps where app.hasSuffix(".app") {
                if flagged >= 15 { return }
                let appPath = "\(dir)/\(app)"

                let entResult = ShellRunner.run("/usr/bin/codesign",
                                                arguments: ["-d", "--entitlements", ":-", appPath],
                                                timeout: 5)
                guard entResult.success || !entResult.stdout.isEmpty else { continue }
                let ents = entResult.stdout

                var matched: [String] = []
                for (key, reason) in riskyEntitlements where ents.contains(key) {
                    matched.append("\(key) (\(reason))")
                }
                guard !matched.isEmpty else { continue }

                // Skip Apple-signed and Developer-ID-signed apps — these use the
                // entitlements legitimately (Electron, IDEs, debuggers).
                let id = ShellRunner.run("/usr/bin/codesign",
                                         arguments: ["-dv", "--verbose=4", appPath],
                                         timeout: 5)
                let combined = id.stdout + id.stderr
                if combined.contains("Authority=Apple") ||
                   combined.contains("Authority=Developer ID Application") ||
                   combined.contains("Authority=Apple Mac OS Application Signing") { continue }

                findings.append(Finding(
                    severity: .medium, category: .suspiciousProcess,
                    title: "App has injection-friendly entitlements without Apple signature",
                    detail: "App: \(app) — \(matched.prefix(2).joined(separator: "; "))",
                    path: appPath,
                    remediation: "Verify this app's origin. Unsigned apps with these entitlements can be used for code injection or memory inspection."
                ))
                flagged += 1
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
