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

        // 6. Check for quarantine-attribute stripping on recently downloaded binaries
        progress?.update("checking Gatekeeper quarantine tampering")
        scanQuarantineTampering(findings: &findings, errors: &errors)

        // 7. Check for suspicious LSQuarantine metadata (recently downloaded binaries)
        progress?.update("checking sudo credential caching")
        scanSudoCredentialCaching(findings: &findings, errors: &errors)

        // 8. Check for AppleScript / osascript persistence artifacts
        progress?.update("checking AppleScript history")
        scanAppleScriptHistory(findings: &findings, errors: &errors)

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

    // MARK: - Gatekeeper Quarantine Tampering

    private func scanQuarantineTampering(findings: inout [Finding], errors: inout [String]) {
        // Every file downloaded via a browser gets the com.apple.quarantine xattr; Gatekeeper
        // reads that to decide whether to prompt on first launch. A common attacker technique
        // (used by Atomic Stealer, RustDoor droppers, and "how to bypass Gatekeeper" instructions
        // handed to victims) is: `xattr -d com.apple.quarantine ~/Downloads/App.app`.
        //
        // We flag executables in Downloads / Desktop that (a) look like they were downloaded and
        // (b) have had their quarantine attribute stripped. Presence of the attribute is normal
        // and expected; ABSENCE on a downloaded binary is the anomaly.
        let home = ShellRunner.realUserHome
        let scanDirs = [
            "\(home)/Downloads",
            "\(home)/Desktop",
        ]
        let fm = FileManager.default

        for dir in scanDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for file in contents.prefix(50) {  // cap per-directory workload
                if file.hasPrefix(".") { continue }
                let filePath = "\(dir)/\(file)"

                // Only care about executables and app bundles — .zip/.dmg auto-clear on unarchive
                let isApp = file.hasSuffix(".app")
                let isBinary: Bool = {
                    guard !isApp,
                          let attrs = try? fm.attributesOfItem(atPath: filePath),
                          let perms = attrs[.posixPermissions] as? Int else { return false }
                    return (perms & 0o111) != 0
                }()
                guard isApp || isBinary else { continue }

                // Check LSQuarantine metadata — the Spotlight kMDItemWhereFroms says "downloaded"
                // even if the xattr was stripped. If we can prove it was downloaded AND has no
                // quarantine xattr, that's tampering.
                let whereFromResult = ShellRunner.run("/usr/bin/mdls",
                                                     arguments: ["-name", "kMDItemWhereFroms", filePath], timeout: 3)
                let looksDownloaded = whereFromResult.success &&
                    whereFromResult.stdout.contains("http")

                guard looksDownloaded else { continue }

                let xattrResult = ShellRunner.run("/usr/bin/xattr", arguments: [filePath], timeout: 3)
                let hasQuarantine = xattrResult.success &&
                    xattrResult.stdout.contains("com.apple.quarantine")

                if !hasQuarantine {
                    findings.append(Finding(
                        severity: .medium, category: .systemIntegrity,
                        title: "Downloaded file has Gatekeeper quarantine stripped",
                        detail: "File: \(file) — was downloaded from the web but quarantine attribute removed. Attackers instruct victims to run `xattr -d com.apple.quarantine` to bypass Gatekeeper warnings.",
                        path: filePath,
                        remediation: "Verify you trust the source. If not: rm \"\(filePath)\""
                    ))
                }
            }
        }
    }

    // MARK: - Sudo Credential Caching

    private func scanSudoCredentialCaching(findings: inout [Finding], errors: inout [String]) {
        // The sudoers directive `Defaults timestamp_timeout=-1` disables the sudo password-cache
        // expiration, so once you sudo once, sudo stays authenticated forever. Attackers set this
        // via /etc/sudoers.d/ so their followup commands don't prompt.
        // Also flag `Defaults tty_tickets` being off (shared tty tickets across sessions).
        let sudoersMain = "/etc/sudoers"
        var allPaths = [sudoersMain]
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") {
            for entry in dropIns where !entry.hasPrefix(".") && entry != "README" {
                allPaths.append("/etc/sudoers.d/\(entry)")
            }
        }

        for path in allPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("#") { continue }

                // timestamp_timeout=-1 disables sudo password caching timeout entirely
                if trimmed.contains("timestamp_timeout=-1") {
                    findings.append(Finding(
                        severity: .high, category: .systemIntegrity,
                        title: "sudo password cache never expires",
                        detail: "\(URL(fileURLWithPath: path).lastPathComponent): \(trimmed) — after one sudo, no re-prompt for the session's lifetime",
                        path: path,
                        remediation: "Remove or change to a positive number: sudo visudo -f \(path)"
                    ))
                }
                // !tty_tickets removes per-terminal isolation of the sudo timestamp
                if trimmed.contains("!tty_tickets") ||
                   (trimmed.contains("tty_tickets") && trimmed.contains("=false")) {
                    findings.append(Finding(
                        severity: .medium, category: .systemIntegrity,
                        title: "sudo tty_tickets disabled",
                        detail: "\(URL(fileURLWithPath: path).lastPathComponent): \(trimmed) — a sudo timestamp in one terminal grants sudo in every terminal",
                        path: path,
                        remediation: "Remove this line: sudo visudo -f \(path)"
                    ))
                }
            }
        }
    }

    // MARK: - AppleScript / osascript Persistence

    private func scanAppleScriptHistory(findings: inout [Finding], errors: inout [String]) {
        // Both stalkerware and infostealers pull off the "trojan AppleScript" trick: drop a .scpt
        // into ~/Library/Scripts/ or /Library/Scripts/, then have a launch agent invoke it via
        // osascript. XCSSET and Atomic Stealer both do this.
        // We flag any .scpt whose contents mention shell exec, curl/wget, base64, or dangerous
        // keychain/keychain-item access.
        let home = ShellRunner.realUserHome
        let scriptDirs = [
            "\(home)/Library/Scripts",
            "/Library/Scripts",
            "\(home)/Library/Application Scripts",
        ]
        let fm = FileManager.default

        let suspiciousInScript = [
            "do shell script",           // AppleScript → shell — infostealers use this constantly
            "curl -s",                    // silent download
            "curl -o",                    // download-to-file
            "wget",                       // ditto
            "base64 --decode",           // hidden payload
            "keychain-item",             // reading keychain
            "security find-generic",     // keychain enumeration
            "sudo -A",                    // askpass sudo (used to trick user via dialog)
            "osascript -e",              // nested osascript exec
        ]

        for dir in scriptDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".scpt") || entry.hasSuffix(".applescript") {
                let path = "\(dir)/\(entry)"
                // .scpt files are compiled AppleScript — read them as raw bytes and grep, since
                // the compiled form preserves the source strings inline.
                guard let data = fm.contents(atPath: path),
                      let text = String(data: data, encoding: .utf8) ??
                                 String(data: data, encoding: .macOSRoman) else { continue }

                let hits = suspiciousInScript.filter { text.lowercased().contains($0) }
                if !hits.isEmpty {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "AppleScript with shell/network capabilities",
                        detail: "\(entry) contains: \(hits.joined(separator: ", ")) — verify this script's origin",
                        path: path,
                        remediation: "Inspect: osadecompile \"\(path)\" (or open in Script Editor)"
                    ))
                }
            }
        }
    }
}
