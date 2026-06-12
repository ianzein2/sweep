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

        // 6. Check for Gatekeeper bypass — downloaded binaries that have had their
        //    com.apple.quarantine xattr stripped. Common technique for FrigidStealer,
        //    ClickFix, and other 2024-2025 social-engineering droppers.
        progress?.update("checking for Gatekeeper bypass")
        scanForQuarantineBypass(findings: &findings, errors: &errors)

        // 7. Check for exposed developer secrets — .env, AWS creds, npm tokens, GH PATs.
        //    Atomic Stealer / BeaverTail explicitly scrape these on every macOS infection.
        progress?.update("checking for exposed credentials")
        scanForExposedCredentials(findings: &findings, errors: &errors)

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

    // MARK: - Gatekeeper Bypass (quarantine xattr stripping)

    /// macOS attaches `com.apple.quarantine` to every file downloaded via Safari, Chrome, AirDrop, etc.
    /// Gatekeeper uses this xattr to gate first-run execution. A common 2024-2025 social-engineering
    /// pattern (ClickFix, FrigidStealer, AMOS DMGs) is to instruct users to run `xattr -d` on the
    /// downloaded payload to bypass that check. We detect the result: a Mach-O binary in Downloads
    /// or a temp dir that was downloaded but has had its quarantine attribute stripped.
    private func scanForQuarantineBypass(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Directories where downloaded payloads land but where Gatekeeper has not yet had a chance
        // to evaluate the file's first-run. /Applications is excluded — apps moved there are
        // legitimately "installed".
        let searchDirs = [
            "\(home)/Downloads",
            "\(home)/Desktop",
            "/private/tmp",
            "/tmp",
            "/var/tmp",
        ]

        let fm = FileManager.default
        var flaggedCount = 0
        let flagLimit = 8

        for dir in searchDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries {
                if flaggedCount >= flagLimit { break }
                if entry.hasPrefix(".") { continue }

                let entryPath = "\(dir)/\(entry)"

                // We're after standalone binaries (Mach-O) and .app bundles.
                let isApp = entry.hasSuffix(".app")
                let mainBinary = isApp
                    ? "\(entryPath)/Contents/MacOS/\(entry.replacingOccurrences(of: ".app", with: ""))"
                    : entryPath
                guard isMachOBinary(path: mainBinary) else { continue }

                // Was this file ever downloaded? Look for *WhereFroms* (Spotlight's "downloaded from"
                // metadata) and the absence of a quarantine xattr. Either alone is noisy; the combo is rare.
                let xattrResult = ShellRunner.run("/usr/bin/xattr", arguments: [entryPath], timeout: 3)
                guard xattrResult.success else { continue }
                let xattrs = xattrResult.stdout
                let hasWhereFroms = xattrs.contains("com.apple.metadata:kMDItemWhereFroms")
                let hasQuarantine = xattrs.contains("com.apple.quarantine")
                guard hasWhereFroms && !hasQuarantine else { continue }

                // Final filter: a notarized app may not need quarantine — only flag the unsigned ones.
                let sigInfo = checkCodeSignatureForBypass(path: mainBinary)
                guard !sigInfo.isAppleSignedOrNotarized else { continue }

                // Extract origin URL for context — helps the user recognize where the file came from.
                let originResult = ShellRunner.run("/bin/sh", arguments: [
                    "-c", "xattr -p com.apple.metadata:kMDItemWhereFroms \"\(entryPath)\" 2>/dev/null | xxd -r -p | strings | head -1"
                ], timeout: 3)
                let origin = originResult.success
                    ? originResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                    : ""
                let originNote = origin.isEmpty ? "" : " (downloaded from: \(String(origin.prefix(80))))"

                findings.append(Finding(
                    severity: .high, category: .systemIntegrity,
                    title: "Downloaded binary missing Gatekeeper quarantine attribute",
                    detail: "File: \(entry) — appears downloaded but quarantine xattr was stripped\(originNote)",
                    path: entryPath,
                    remediation: "Common bypass: `xattr -d com.apple.quarantine`. Verify you trust the source. " +
                                 "If not, delete the file: rm -rf \"\(entryPath)\""
                ))
                flaggedCount += 1
            }
            if flaggedCount >= flagLimit { break }
        }
    }

    private func isMachOBinary(path: String) -> Bool {
        guard let fh = FileHandle(forReadingAtPath: path) else { return false }
        defer { fh.closeFile() }
        let header = fh.readData(ofLength: 4)
        guard header.count == 4 else { return false }
        let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
        let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
        return machoMagics.contains(magic)
    }

    private struct BypassCheckSigInfo {
        let isAppleSignedOrNotarized: Bool
    }

    private func checkCodeSignatureForBypass(path: String) -> BypassCheckSigInfo {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return BypassCheckSigInfo(isAppleSignedOrNotarized: false)
        }
        // "anchor apple generic" matches anything signed with an Apple-issued cert chain,
        // including notarized Developer ID code. That's the bar Gatekeeper itself uses.
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess,
              let req = requirement else {
            return BypassCheckSigInfo(isAppleSignedOrNotarized: false)
        }
        let valid = SecStaticCodeCheckValidityWithErrors(code, [], req, nil) == errSecSuccess
        return BypassCheckSigInfo(isAppleSignedOrNotarized: valid)
    }

    // MARK: - Exposed Developer Credentials

    /// 2024-2025 macOS infostealers (AMOS, BeaverTail, FrigidStealer) explicitly exfiltrate developer
    /// credential files. We don't have a way to know if these have already been stolen, but we can
    /// at least surface the high-risk ones so the user can move them into a secrets manager or
    /// tighten their permissions before the next stealer lands.
    private func scanForExposedCredentials(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        struct CredTarget {
            let path: String
            let label: String
            let why: String
            let severityIfWorldReadable: Severity
        }

        let targets: [CredTarget] = [
            CredTarget(path: "\(home)/.aws/credentials",
                       label: "AWS credentials",
                       why: "AWS keys give programmatic access to your cloud account — a top target for stealers",
                       severityIfWorldReadable: .high),
            CredTarget(path: "\(home)/.aws/config",
                       label: "AWS config",
                       why: "May contain MFA or SSO session tokens",
                       severityIfWorldReadable: .medium),
            CredTarget(path: "\(home)/.gcp/credentials.json",
                       label: "GCP credentials",
                       why: "Google Cloud service-account keys",
                       severityIfWorldReadable: .high),
            CredTarget(path: "\(home)/.config/gcloud/application_default_credentials.json",
                       label: "gcloud ADC",
                       why: "Application Default Credentials — gives access to GCP resources you own",
                       severityIfWorldReadable: .high),
            CredTarget(path: "\(home)/.kube/config",
                       label: "Kubernetes kubeconfig",
                       why: "Cluster admin tokens for any cluster you've kubectl'd into",
                       severityIfWorldReadable: .high),
            CredTarget(path: "\(home)/.npmrc",
                       label: "npm credentials",
                       why: "npm auth tokens — used for publishing packages and reading private registries",
                       severityIfWorldReadable: .medium),
            CredTarget(path: "\(home)/.pypirc",
                       label: "PyPI credentials",
                       why: "PyPI auth tokens",
                       severityIfWorldReadable: .medium),
            CredTarget(path: "\(home)/.netrc",
                       label: "netrc credentials",
                       why: "Plaintext credentials used by curl/wget/git",
                       severityIfWorldReadable: .high),
            CredTarget(path: "\(home)/.config/gh/hosts.yml",
                       label: "GitHub CLI token",
                       why: "GitHub Personal Access Token with the scopes you've granted to `gh`",
                       severityIfWorldReadable: .high),
            CredTarget(path: "\(home)/.docker/config.json",
                       label: "Docker config",
                       why: "May contain registry auth tokens",
                       severityIfWorldReadable: .medium),
        ]

        for target in targets {
            guard fm.fileExists(atPath: target.path) else { continue }
            guard let attrs = try? fm.attributesOfItem(atPath: target.path),
                  let posix = attrs[.posixPermissions] as? NSNumber else { continue }
            let mode = posix.uint16Value

            // Anything group-readable or world-readable is dangerous for a secrets file. The "correct"
            // mode is 0600 (owner-only).
            let groupReadable = (mode & 0o040) != 0
            let worldReadable = (mode & 0o004) != 0

            if worldReadable {
                findings.append(Finding(
                    severity: target.severityIfWorldReadable, category: .suspiciousFile,
                    title: "\(target.label) is world-readable",
                    detail: "Permissions: \(String(mode, radix: 8)) — \(target.why)",
                    path: target.path,
                    remediation: "Tighten permissions: chmod 600 \"\(target.path)\""
                ))
            } else if groupReadable {
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "\(target.label) is group-readable",
                    detail: "Permissions: \(String(mode, radix: 8)) — \(target.why)",
                    path: target.path,
                    remediation: "Tighten permissions: chmod 600 \"\(target.path)\""
                ))
            }
        }

        // SSH private keys: same idea, but the key files have varied names. List the contents of
        // ~/.ssh and check for any private key with overly-broad permissions.
        let sshDir = "\(home)/.ssh"
        if let entries = try? fm.contentsOfDirectory(atPath: sshDir) {
            for entry in entries {
                // Recognize OpenSSH private key conventions.
                let isLikelyPrivateKey = entry == "id_rsa" || entry == "id_ed25519" ||
                                         entry == "id_ecdsa" || entry == "id_dsa" ||
                                         (entry.hasPrefix("id_") && !entry.hasSuffix(".pub"))
                guard isLikelyPrivateKey else { continue }

                let keyPath = "\(sshDir)/\(entry)"
                guard let attrs = try? fm.attributesOfItem(atPath: keyPath),
                      let posix = attrs[.posixPermissions] as? NSNumber else { continue }
                let mode = posix.uint16Value
                let groupReadable = (mode & 0o040) != 0
                let worldReadable = (mode & 0o004) != 0
                guard groupReadable || worldReadable else { continue }

                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "SSH private key has overly-broad permissions: \(entry)",
                    detail: "Permissions: \(String(mode, radix: 8)) — anyone with shell access on this Mac can copy your key",
                    path: keyPath,
                    remediation: "Tighten permissions: chmod 600 \"\(keyPath)\""
                ))
            }
        }

        // Stray .env files in the user's home dir top level are unusual — projects keep them inside
        // a project directory. A top-level one often means someone (or something) copied secrets out.
        let topLevelEnv = "\(home)/.env"
        if fm.fileExists(atPath: topLevelEnv) {
            findings.append(Finding(
                severity: .medium, category: .suspiciousFile,
                title: "Stray .env file in home directory",
                detail: "Found ~/.env — unusual location; this file usually belongs inside a project",
                path: topLevelEnv,
                remediation: "Inspect the contents — if you didn't put it there, treat the secrets as compromised and rotate them"
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
