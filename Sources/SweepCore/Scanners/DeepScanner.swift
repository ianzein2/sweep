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

        // 6. Inspect recent quarantined downloads — the macOS social-engineering
        //    chain (fake browser updates, cracked-app sites) shows up here first.
        progress?.update("inspecting quarantine events")
        scanQuarantineEvents(findings: &findings, errors: &errors)

        // 7. Files that lost their quarantine attribute via xattr stripping — a
        //    common technique stealers use to bypass Gatekeeper prompts.
        progress?.update("checking for quarantine xattr stripping")
        scanStrippedQuarantine(findings: &findings, errors: &errors)

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

    // MARK: - Quarantine Events (recent risky downloads)

    /// Reads LaunchServices' QuarantineEventsV2 SQLite database — the canonical log
    /// of every file downloaded with the quarantine attribute set (anything from a
    /// browser, Mail, Messages, AirDrop, etc.). Lets us correlate "recent download
    /// from a sketchy host that is still on disk" with active threats.
    private func scanQuarantineEvents(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dbPath = "\(home)/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        guard FileManager.default.fileExists(atPath: dbPath) else { return }

        // Copy first — sqlite refuses to open a live DB without WAL access.
        let tempPath = "/tmp/sweep-qe-\(UUID().uuidString).db"
        let copyResult = ShellRunner.run("/bin/cp", arguments: [dbPath, tempPath])
        let queryPath = copyResult.success ? tempPath : dbPath
        defer { try? FileManager.default.removeItem(atPath: tempPath) }

        // Pull the most recent quarantined items (last 30 days). Columns:
        //   LSQuarantineEventIdentifier, LSQuarantineTimeStamp, LSQuarantineAgentName,
        //   LSQuarantineDataURLString, LSQuarantineOriginURLString, ...
        // CoreFoundation epoch is seconds since 2001-01-01; we just print the URL.
        let query = """
        SELECT LSQuarantineTimeStamp, LSQuarantineAgentName,
               COALESCE(LSQuarantineDataURLString,''),
               COALESCE(LSQuarantineOriginURLString,'')
        FROM LSQuarantineEvent
        WHERE LSQuarantineTimeStamp > strftime('%s','now') - 978307200 - (30*86400)
        ORDER BY LSQuarantineTimeStamp DESC
        LIMIT 200;
        """
        let result = ShellRunner.run("/usr/bin/sqlite3",
                                     arguments: ["-separator", "|", queryPath, query],
                                     timeout: 10)
        guard result.success, !result.stdout.isEmpty else {
            if result.stderr.contains("locked") || result.stderr.contains("Operation not permitted") {
                errors.append("Quarantine DB unreadable — grant Full Disk Access to read")
            }
            return
        }

        // Hosts that legitimate users rarely download .pkg/.dmg from. Free-tier
        // file-share and PaaS hostnames dominate macOS social-engineering campaigns
        // (AMOS, FrigidStealer, BeaverTail). github.io / gh-pages staging
        // landing pages were heavily abused in 2024-2025.
        let riskyHostFragments: [(fragment: String, reason: String)] = [
            ("discordapp.com/attachments", "Discord CDN — common malware drop point"),
            ("discord.com/attachments",    "Discord CDN — common malware drop point"),
            ("cdn.discordapp.com",         "Discord CDN — common malware drop point"),
            (".github.io",                 "GitHub Pages — used to stage fake update sites"),
            ("transfer.sh",                "Public file-share — used for short-lived stealer drops"),
            ("anonfiles.com",              "Anonymous file host — heavily abused by stealers"),
            ("send.cm",                    "Anonymous file host — heavily abused by stealers"),
            ("mega.nz",                    "Mega — common drop point for cracked-app stealers"),
            ("mediafire.com",              "Mediafire — common drop point for cracked-app stealers"),
            ("dropmefiles.com",            "Anonymous file host — heavily abused by stealers"),
            ("workers.dev",                "Cloudflare Workers — used for fake-update redirectors"),
            ("pages.dev",                  "Cloudflare Pages — used for fake-update redirectors"),
            ("vercel.app",                 "Vercel preview — used for fake-update landing pages"),
            ("netlify.app",                "Netlify preview — used for fake-update landing pages"),
            (".onion",                     "Tor hidden service — exceptionally suspicious as a download source"),
        ]

        // Risky extensions that should normally only come from the Mac App Store or
        // a vendor's signed installer page.
        let riskyExtensions = ["pkg", "dmg", "mpkg", "app.zip", "dylib", "scpt"]

        // Track risky downloads still on disk (we don't have file paths in the DB,
        // but the agent name tells us roughly which app handled the download).
        var emittedAgents = Set<String>()  // dedupe per agent

        for rawLine in result.stdout.split(separator: "\n") {
            let parts = String(rawLine).split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
            guard parts.count >= 4 else { continue }
            let agent = String(parts[1])
            let dataURL = String(parts[2])
            let originURL = String(parts[3])
            let urls = (dataURL + " " + originURL).lowercased()

            // Self-quarantined events with no URL aren't actionable.
            guard !urls.trimmingCharacters(in: .whitespaces).isEmpty else { continue }

            // Match risky hosts
            for entry in riskyHostFragments where urls.contains(entry.fragment) {
                let key = "\(agent)|\(entry.fragment)"
                if emittedAgents.contains(key) { continue }
                emittedAgents.insert(key)

                let isExecExtension = riskyExtensions.contains { urls.contains(".\($0)") }
                findings.append(Finding(
                    severity: isExecExtension ? .high : .medium,
                    category: .suspiciousFile,
                    title: "Recent download from suspicious host (\(entry.fragment))",
                    detail: "Agent: \(agent), \(entry.reason)" +
                        (isExecExtension ? " — and the file is executable (.pkg/.dmg/.dylib)" : ""),
                    path: nil,
                    remediation: "Verify the file in ~/Downloads and remove it if unfamiliar. Origin: \(String(originURL.prefix(160)))"
                ))
                break
            }
        }
    }

    // MARK: - Quarantine Attribute Stripping

    /// Stealers commonly strip `com.apple.quarantine` off a freshly-downloaded
    /// payload (via `xattr -d` or `xattr -cr`) so Gatekeeper won't prompt the user.
    /// We can't tell *which* file was stripped, but we can check recent Mach-O
    /// downloads in ~/Downloads and flag any that no longer carry the attribute —
    /// a strong indicator of attacker-driven xattr manipulation.
    private func scanStrippedQuarantine(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let downloads = "\(home)/Downloads"
        let fm = FileManager.default
        guard fm.fileExists(atPath: downloads) else { return }

        // Limit ourselves to files touched in the last 14 days — older items have
        // usually been opened (which legitimately clears the attribute).
        let cutoff = Date().addingTimeInterval(-14 * 86400)
        guard let entries = try? fm.contentsOfDirectory(atPath: downloads) else { return }

        let machoExtensions: Set<String> = ["dmg", "pkg", "mpkg", "app", "dylib"]
        var flagged = 0

        for entry in entries where flagged < 5 {
            let entryPath = "\(downloads)/\(entry)"
            let ext = (entry as NSString).pathExtension.lowercased()
            guard machoExtensions.contains(ext) else { continue }

            guard let attrs = try? fm.attributesOfItem(atPath: entryPath),
                  let modDate = attrs[.modificationDate] as? Date,
                  modDate > cutoff else { continue }

            // Read the quarantine xattr; an empty value means the attribute is gone.
            let xattr = ShellRunner.run("/usr/bin/xattr", arguments: ["-p", "com.apple.quarantine", entryPath], timeout: 3)
            let hasQuarantine = xattr.success && !xattr.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            if !hasQuarantine {
                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Recent download missing quarantine attribute: \(entry)",
                    detail: "Modified \(formatRelative(modDate)) — a stealer or sideload script may have stripped com.apple.quarantine to bypass Gatekeeper",
                    path: entryPath,
                    remediation: "Inspect: xattr -l \"\(entryPath)\" — if you didn't intentionally strip the attribute, treat this file as untrusted"
                ))
                flagged += 1
            }
        }
    }

    private func formatRelative(_ date: Date) -> String {
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
