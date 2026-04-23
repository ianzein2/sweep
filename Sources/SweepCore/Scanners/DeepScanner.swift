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

        // 6. Scan shell history for "ClickFix" / pipe-to-shell attack residue.
        //    ClickFix (2024-2025) tricks users via fake CAPTCHA or fake error prompts into
        //    pasting a shell command from their clipboard — the command lands in history,
        //    so history is forensic gold even after the attack completes.
        progress?.update("scanning shell history for pipe-to-shell attacks")
        scanShellHistoryForClickFix(findings: &findings, errors: &errors)

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

    // MARK: - Shell History (ClickFix / pipe-to-shell residue)

    /// Classic pipe-to-shell loader patterns. Any of these in a user's shell history is
    /// worth surfacing — they are rarely typed by hand and are a staple of ClickFix,
    /// fake-browser-update, and fake-CAPTCHA lures that have been dominant in 2024-2025.
    private let clickFixPatterns: [(regex: String, severity: Severity, label: String)] = [
        // curl ... | sh / bash / zsh — the canonical drop-and-run.
        (#"curl[^\n]*\|\s*(sh|bash|zsh)\b"#, .high,
         "downloaded script piped directly into a shell"),
        (#"wget[^\n]*\|\s*(sh|bash|zsh)\b"#, .high,
         "downloaded script piped directly into a shell"),
        // base64 -d | sh — obfuscated payload decode-and-run.
        (#"base64\s+(-d|--decode)[^\n]*\|\s*(sh|bash|zsh)\b"#, .high,
         "base64-decoded payload piped into a shell"),
        // osascript -e 'do shell script ...' — AppleScript-wrapped execution, often with
        // elevated-privilege prompts attackers prefer because they look native.
        (#"osascript\s+-e\s*['"]do shell script"#, .high,
         "AppleScript wrapper used to run a shell command (common lure technique)"),
        // `xattr -d com.apple.quarantine` on a downloaded file — strips Gatekeeper flag so
        // a just-downloaded app can run without the usual warning.
        (#"xattr\s+-d\s+com\.apple\.quarantine"#, .medium,
         "quarantine flag stripped from a downloaded file — bypasses Gatekeeper"),
        // `sudo spctl --master-disable` — turns off Gatekeeper system-wide.
        (#"spctl\s+--master-disable"#, .high,
         "Gatekeeper was disabled via spctl"),
        // eval "$(curl ...)" — direct remote-code execution in a shell evaluator.
        (#"eval\s*["`\$]?\s*\(?\s*curl"#, .high,
         "remote output evaluated as shell code"),
        // python -c "... urllib ... exec(...)" — Python one-liner loader.
        (#"python3?\s+-c[^\n]*urllib[^\n]*exec\("#, .high,
         "Python one-liner that fetches and executes remote code"),
        // `chmod +x /tmp/...` followed by invocation — downloaded-binary loader shape.
        (#"chmod\s+\+x\s+/(tmp|var/tmp|private/tmp)/"#, .medium,
         "made a file in a temp directory executable"),
        // killall Terminal after running something — common finisher in ClickFix lures to
        // hide shell output from the user.
        (#"killall\s+Terminal"#, .medium,
         "killed Terminal from the command line — common in ClickFix lures that hide their trail"),
    ]

    private func scanShellHistoryForClickFix(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let histories = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.sh_history",
            "\(home)/.history",
            "\(home)/.local/share/fish/fish_history",
        ]

        let fm = FileManager.default

        for path in histories {
            guard fm.fileExists(atPath: path) else { continue }
            // Read latest portion only — long histories can be dozens of MB.
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let size = attrs[.size] as? Int, size > 0 else { continue }

            let readSize = min(size, 2_000_000)  // last 2MB is plenty for recent commands
            guard let handle = FileHandle(forReadingAtPath: path) else { continue }
            defer { try? handle.close() }
            if size > readSize {
                try? handle.seek(toOffset: UInt64(size - readSize))
            }
            let data = handle.readDataToEndOfFile()
            guard let content = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .ascii) else { continue }

            // De-dupe: the same pattern firing on every invocation isn't useful — one finding
            // per (file, pattern) with a count and a sample line is much more readable.
            struct Hit { var count: Int; var sample: String }
            var hits: [String: Hit] = [:]

            let lines = content.split(separator: "\n", omittingEmptySubsequences: true)
            for rawLine in lines.suffix(5_000) {  // cap on lines to bound work
                // .zsh_history uses ": <timestamp>:0;<command>" — strip the metadata prefix.
                var line = String(rawLine)
                if line.hasPrefix(":"), let semicolon = line.firstIndex(of: ";") {
                    line = String(line[line.index(after: semicolon)...])
                }
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                for pattern in clickFixPatterns {
                    if trimmed.range(of: pattern.regex, options: [.regularExpression, .caseInsensitive]) != nil {
                        var h = hits[pattern.label] ?? Hit(count: 0, sample: String(trimmed.prefix(160)))
                        h.count += 1
                        hits[pattern.label] = h
                    }
                }
            }

            // Find the severity we want from the first pattern matching each label.
            for (label, hit) in hits {
                let severity = clickFixPatterns.first { $0.label == label }?.severity ?? .medium
                findings.append(Finding(
                    severity: severity, category: .suspiciousProcess,
                    title: "Shell history: \(label)",
                    detail: "\(hit.count) occurrence(s) in \(URL(fileURLWithPath: path).lastPathComponent). Sample: \(hit.sample)",
                    path: path,
                    remediation: "Open the file and inspect these lines; if you don't recognize them, assume compromise and rotate credentials."
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
