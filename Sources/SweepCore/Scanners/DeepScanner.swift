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

        // 6. ClickFix / curl|sh drop-and-run stager artifacts left in tmp locations.
        //    Recent AMOS, MacSync, and Ferret campaigns all fetch a stage-2 script into /tmp
        //    or /private/var/tmp with distinctive names — flag the artifacts even after the
        //    process has exited so we catch a compromise the user tried to "close and forget".
        progress?.update("checking for ClickFix / dropper artifacts")
        scanClickFixArtifacts(findings: &findings, errors: &errors)

        // 7. Cryptojacking — XMRig-family miners on macOS almost always land in one of a few
        //    known paths, run under generic names ("kdevtmpfsi", "kinsing", "Final Cut Pro"),
        //    and pin CPU cores from a hidden binary.
        progress?.update("checking for cryptominers")
        scanCryptojackers(findings: &findings, errors: &errors)

        // 8. Malicious npm / pip / homebrew supply-chain artifacts. The 2025 PhantomRaven
        //    campaign, the @kodane wallet-drainer, and the @openclaw-ai GhostClaw RAT all
        //    stage payloads in the user's package cache — flag by known package names.
        progress?.update("checking developer package caches")
        scanDeveloperSupplyChain(findings: &findings, errors: &errors)

        // 9. Shell-history hits for the exact "copy-paste this into Terminal" strings that
        //    ClickFix / fake-CAPTCHA / fake-Homebrew pages use. The command line itself is the
        //    evidence — even after cleanup, zsh_history usually retains it.
        progress?.update("scanning shell history for ClickFix commands")
        scanShellHistoryForClickFix(findings: &findings, errors: &errors)

        // 10. Signature-database file-path IOCs. Every entry in SpywareSignature.known carries
        //     a filePaths list — until now nothing was scanning them. Even if the malicious
        //     process is dormant, its files often remain.
        progress?.update("checking known IOC file paths")
        scanKnownIOCFilePaths(findings: &findings, errors: &errors)

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

    // MARK: - ClickFix / Dropper Artifacts

    /// Filenames left behind by publicly documented 2024-2026 ClickFix and drive-by-install
    /// campaigns. These are the loader scripts (not the final payload) — any of them sitting in
    /// /tmp weeks after an infection is a strong compromise indicator.
    private let clickfixStagerFilenames: [String] = [
        // FlexibleFerret / Contagious Interview (SentinelOne, Feb 2025)
        "macpatch.sh", "drivfixer.sh", "CDrivers.zip",
        // MacSync (Jamf / CloudSEK, 2025-2026)
        "runner", "osalogging.zip", "UserSyncWorker",
        // SHub Reaper (SentinelOne, 2026)
        "shub_split.sh", "shub",
        // AMOS / Atomic — common stager naming across leaks
        "AppleScript.scpt", "installer.sh", "install.sh", "update.sh",
        // Generic ClickFix cocktail (Microsoft SecBlog, 2026)
        "fix.sh", "verify.sh", "loader.sh", "captcha.sh",
    ]

    private func scanClickFixArtifacts(findings: inout [Finding], errors: inout [String]) {
        let dirs = ["/tmp", "/private/tmp", "/private/var/tmp", "/var/tmp"]
        let fm = FileManager.default

        for dir in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                // Direct filename match against stager names
                if clickfixStagerFilenames.contains(entry) {
                    let full = "\(dir)/\(entry)"
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Known ClickFix / dropper artifact in temp directory",
                        detail: "\"\(entry)\" matches a loader script used by MacSync / FlexibleFerret / SHub Reaper / AMOS",
                        path: full,
                        remediation: "Inspect and remove: sudo rm \"\(full)\" — then run a full Sweep scan"
                    ))
                    continue
                }
                // Hidden AppleScript files in /tmp are a canonical AMOS pattern
                if entry.hasPrefix(".") && (entry.hasSuffix(".scpt") || entry.hasSuffix(".sh")) {
                    let full = "\(dir)/\(entry)"
                    findings.append(Finding(
                        severity: .medium, category: .suspiciousFile,
                        title: "Hidden script in temp directory",
                        detail: "Hidden .sh/.scpt files in /tmp are commonly dropped by macOS infostealers",
                        path: full,
                        remediation: "Inspect: cat \"\(full)\" — remove if unknown"
                    ))
                }
            }
        }
    }

    // MARK: - Cryptojackers

    /// Filenames and identifiers used by XMRig-family miners repackaged for macOS.
    /// Real XMRig binaries are usually renamed to blend in — but the miner's config filename
    /// (config.json / pool.txt) plus a hidden binary in an unusual path is a distinctive combo.
    private let minerBinaryNames: Set<String> = [
        "xmrig", "XMRig", "xmr-stak", "cpuminer", "minerd",
        "kdevtmpfsi", "kinsing", "kthreaddi",
    ]

    private let minerConfigFilenames: Set<String> = [
        "config.json", "pools.json", "pool.txt",
    ]

    private let minerPoolStrings: [String] = [
        "xmr-eu", "xmr-us", "monero.crypto-pool", "supportxmr.com",
        "moneroocean.stream", "nanopool.org/xmr", "minexmr.com",
        "pool.hashvault.pro", "randomx", "cryptonight",
    ]

    private func scanCryptojackers(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // 1. Running miner processes — match by name, then verify via config lookup
        let ps = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,comm"], timeout: 5)
        if ps.success {
            for line in ps.stdout.split(separator: "\n") {
                let parts = String(line).trimmingCharacters(in: .whitespaces)
                    .split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2 else { continue }
                let pid = String(parts[0])
                let commPath = String(parts[1])
                let commName = (commPath as NSString).lastPathComponent
                if minerBinaryNames.contains(commName) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Cryptominer process running: \(commName)",
                        detail: "PID \(pid), path: \(commPath) — mines Monero using this Mac's CPU",
                        path: commPath,
                        remediation: "Terminate: kill \(pid) — then locate persistence and remove the miner binary"
                    ))
                }
            }
        }

        // 2. Config files with known pool strings under hidden or /tmp locations
        let dirsToScan = [
            "/tmp", "/private/tmp", "/private/var/tmp", "/var/tmp",
            "\(home)/.config", "\(home)/Library/Application Support",
        ]
        for dir in dirsToScan {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries.prefix(200) {
                guard minerConfigFilenames.contains(entry) else { continue }
                let full = "\(dir)/\(entry)"
                guard let attrs = try? fm.attributesOfItem(atPath: full),
                      let size = attrs[.size] as? Int, size < 64_000,
                      let content = try? String(contentsOfFile: full, encoding: .utf8) else { continue }
                let lower = content.lowercased()
                if minerPoolStrings.contains(where: { lower.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Cryptominer config file",
                        detail: "\"\(entry)\" references a known Monero mining pool — indicates active cryptojacking",
                        path: full,
                        remediation: "Remove: rm \"\(full)\" — then find and kill the miner process"
                    ))
                }
            }
        }
    }

    // MARK: - Developer Supply-Chain Artifacts

    /// npm / pip / homebrew package names that publicly-documented supply-chain attacks used to
    /// deliver macOS infostealers or wallet drainers in 2024-2026. We flag if any of these ever
    /// landed in the user's package cache — the payload runs at install time via postinstall,
    /// so presence in the cache alone is worth alerting on.
    private let compromisedNpmPackages: Set<String> = [
        // @kodane/patch-manager (July 2025) — wallet drainer
        "@kodane/patch-manager",
        "kodane-patch-manager",
        // @openclaw-ai/openclawai (March 2026) — GhostClaw RAT
        "@openclaw-ai/openclawai",
        "openclaw-ai",
        // js-logger-pack (SafeDep, 2025) — WebSocket stealer
        "js-logger-pack",
        // Fake-Homebrew-installer campaign (2024)
        "fakebrew", "brew-installer-mac",
        // PhantomRaven package cluster (Nov 2025) — top-level names publicly linked
        "phantomraven", "raven-utils", "raven-http",
        // Cuckoo delivered via typosquatted homebrew utilities
        "dumpmedia-spotify-music-converter",
    ]

    private let compromisedPyPIPackages: Set<String> = [
        // 2025 crypto-drainer typosquats
        "requestss", "urllib4", "python3-dateutill",
    ]

    private func scanDeveloperSupplyChain(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // npm cache — flat directory of packages that have EVER been installed
        let npmCache = "\(home)/.npm/_cacache/content-v2"
        if fm.fileExists(atPath: npmCache) {
            for pkg in compromisedNpmPackages {
                // Fast textual check across npm's package-key index — avoids walking the tree.
                let hits = ShellRunner.run("/usr/bin/grep", arguments: [
                    "-rl", "--include=package.json", pkg, "\(home)/.npm"
                ], timeout: 15)
                if hits.success && !hits.stdout.isEmpty {
                    let firstHit = hits.stdout.split(separator: "\n").first.map(String.init) ?? "\(home)/.npm"
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "npm package cache contains known malicious package \"\(pkg)\"",
                        detail: "This package name is publicly linked to a macOS wallet-drainer / infostealer supply-chain attack. Even a single install runs the malicious postinstall script",
                        path: firstHit.trimmingCharacters(in: .whitespaces),
                        remediation: "Clear cache: npm cache clean --force — then rotate all crypto wallet secrets, browser passwords, and SSH keys touched from this account"
                    ))
                }
            }
        }

        // Also check the plain `node_modules` root in the user's home in case globals were installed
        let nodeGlobals = [
            "\(home)/.nvm/versions/node",
            "/opt/homebrew/lib/node_modules",
            "/usr/local/lib/node_modules",
        ]
        for base in nodeGlobals {
            guard fm.fileExists(atPath: base),
                  let entries = try? fm.contentsOfDirectory(atPath: base) else { continue }
            for entry in entries {
                // node_modules keeps scoped packages as `@scope` directories with per-package
                // subfolders inside; unscoped packages sit at the top level.
                if entry.hasPrefix("@") {
                    let scopeDir = "\(base)/\(entry)"
                    guard let sub = try? fm.contentsOfDirectory(atPath: scopeDir) else { continue }
                    for name in sub {
                        let full = "\(entry)/\(name)"
                        if compromisedNpmPackages.contains(full) {
                            findings.append(Finding(
                                severity: .high, category: .suspiciousFile,
                                title: "Globally installed npm package is a known dropper",
                                detail: "\"\(full)\" is publicly linked to a macOS infostealer campaign",
                                path: "\(scopeDir)/\(name)",
                                remediation: "Uninstall: npm -g rm \(full) — rotate credentials touched from this account"
                            ))
                        }
                    }
                } else if compromisedNpmPackages.contains(entry) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Globally installed npm package is a known dropper",
                        detail: "\"\(entry)\" is publicly linked to a macOS infostealer campaign",
                        path: "\(base)/\(entry)",
                        remediation: "Uninstall: npm -g rm \(entry) — rotate credentials touched from this account"
                    ))
                }
            }
        }

        // pip cache
        let pipDirs = [
            "\(home)/Library/Caches/pip",
            "\(home)/.cache/pip",
        ]
        for base in pipDirs {
            guard fm.fileExists(atPath: base) else { continue }
            for pkg in compromisedPyPIPackages {
                let hits = ShellRunner.run("/usr/bin/find", arguments: [
                    base, "-name", "*\(pkg)*", "-maxdepth", "5"
                ], timeout: 10)
                if hits.success && !hits.stdout.trimmingCharacters(in: .whitespaces).isEmpty {
                    let firstHit = hits.stdout.split(separator: "\n").first.map(String.init) ?? base
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "pip cache references malicious PyPI package \"\(pkg)\"",
                        detail: "This name matches a documented PyPI typosquat used to deliver crypto drainers",
                        path: firstHit.trimmingCharacters(in: .whitespaces),
                        remediation: "pip cache purge — audit installed packages: pip list"
                    ))
                }
            }
        }
    }

    // MARK: - Shell History ClickFix Detection

    /// Substrings that, if present in zsh_history / bash_history, are near-certain evidence
    /// the user pasted a ClickFix "verification" or "captcha" one-liner into their terminal.
    private let clickfixHistoryIndicators: [String] = [
        // Payload retrieval with TLS verification stripped, piped into a shell — the canonical shape
        "curl -sSL http", "curl -k http", "curl -kL http", "curl -s http",
        // Common tail
        "| sh", "| bash", "| zsh", "|sh", "|bash", "|zsh",
        // AppleScript-based Terminal detour used by Reaper / ClickFix
        "osascript -e do shell script",
        // The exact strings observed in fake-Homebrew and fake-Maccy pages
        "brew.sh/install)", "avngr.netlify", "sync-master.online",
        // Spellings copied by users from social-engineering pages
        "system_updater", "captcha_verify",
    ]

    private func scanShellHistoryForClickFix(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
        ]
        let fm = FileManager.default

        for path in historyFiles {
            guard fm.fileExists(atPath: path),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let size = attrs[.size] as? Int, size < 5_000_000,
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Only look at the last ~2000 commands — anything older is likely not actionable
            let recent = content.split(separator: "\n").suffix(2000)
            var hits: [(indicator: String, line: String)] = []

            for lineSub in recent {
                let line = String(lineSub)
                let lower = line.lowercased()
                // "curl … | sh" — both halves must appear on the same command
                let hasCurlPipe =
                    (lower.contains("curl ") || lower.contains("wget ")) &&
                    (lower.contains("| sh") || lower.contains("| bash") ||
                     lower.contains("| zsh") || lower.contains("|sh") ||
                     lower.contains("|bash") || lower.contains("|zsh"))
                if hasCurlPipe {
                    hits.append(("curl|sh drop-and-run", line))
                    if hits.count >= 3 { break }
                    continue
                }
                for indicator in clickfixHistoryIndicators {
                    if lower.contains(indicator.lowercased()) {
                        hits.append((indicator, line))
                        break
                    }
                }
                if hits.count >= 3 { break }
            }

            for hit in hits {
                // Truncate the line so we don't leak huge one-liners into the report
                var display = hit.line.trimmingCharacters(in: .whitespaces)
                if display.count > 180 {
                    display = String(display.prefix(180)) + "…"
                }
                findings.append(Finding(
                    severity: .medium, category: .suspiciousProcess,
                    title: "Shell history contains a ClickFix-style paste command",
                    detail: "Matched \"\(hit.indicator)\": \(display)",
                    path: path,
                    remediation: "Investigate: recent \"curl … | sh\" one-liners are the top macOS malware delivery vector in 2025-2026. Review \(path) and rotate credentials if you don't recognize the command"
                ))
            }
        }
    }

    // MARK: - Signature Database File-Path IOCs

    /// Cross-check every filePath IOC in the signature database against the local filesystem.
    /// Signatures ship a filePaths list for a reason — until this method existed, none of them
    /// were being tested, which meant families that only leave dormant on-disk artifacts (no
    /// running process, no launchd plist) went undetected between reinfections.
    private func scanKnownIOCFilePaths(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        var seen = Set<String>()

        for sig in SpywareSignature.known {
            for rawPath in sig.filePaths {
                // Glob-style suffix (e.g. "/private/tmp/AppleScript-*.scpt") means "any file
                // matching this pattern" — handle by listing the parent directory once.
                if rawPath.contains("*") {
                    let expandedPattern = SpywareSignature.expandPath(rawPath)
                    let url = URL(fileURLWithPath: expandedPattern)
                    let parent = url.deletingLastPathComponent().path
                    let pattern = url.lastPathComponent
                        .replacingOccurrences(of: ".", with: "\\.")
                        .replacingOccurrences(of: "*", with: ".*")
                    guard let regex = try? NSRegularExpression(pattern: "^\(pattern)$"),
                          let entries = try? fm.contentsOfDirectory(atPath: parent) else { continue }
                    for entry in entries {
                        let range = NSRange(entry.startIndex..., in: entry)
                        guard regex.firstMatch(in: entry, range: range) != nil else { continue }
                        let full = "\(parent)/\(entry)"
                        if seen.insert(full).inserted {
                            findings.append(makeIOCFinding(sig: sig, path: full))
                        }
                    }
                    continue
                }

                let expanded = SpywareSignature.expandPath(rawPath)
                guard fm.fileExists(atPath: expanded), seen.insert(expanded).inserted else { continue }
                findings.append(makeIOCFinding(sig: sig, path: expanded))
            }
        }
    }

    private func makeIOCFinding(sig: SpywareSignature, path: String) -> Finding {
        Finding(
            severity: .high, category: .suspiciousFile,
            title: "Known IOC file present on disk: \(sig.name)",
            detail: "File matches a publicly documented indicator-of-compromise for \(sig.name). Even without an active process, this file signals prior infection or an in-progress install",
            path: path,
            remediation: "Investigate and remove: sudo rm -rf \"\(path)\" — then run the full Sweep scan to confirm nothing is running"
        )
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
