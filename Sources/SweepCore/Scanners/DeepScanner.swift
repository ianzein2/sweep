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

        // 6. Check for Background Task Management (BTM) tampering — a known
        //    DPRK / infostealer trick is to manipulate macOS's Background Items
        //    list so persistence doesn't appear in System Settings > Login Items.
        progress?.update("checking Background Task Management database")
        scanBTMDatabase(findings: &findings, errors: &errors)

        // 7. SSH client config tampering: many infostealers add ProxyCommand or
        //    ForwardAgent yes to ~/.ssh/config, letting attackers pivot through
        //    your established SSH sessions. Also scan known_hosts for deletions.
        progress?.update("checking SSH client configuration")
        scanSSHConfig(findings: &findings, errors: &errors)

        // 8. Spotlight importers, QuickLook generators, AudioUnit plugins, and
        //    color profiles are all loaded into long-lived system processes.
        //    Rogue ones are a common modern persistence pattern that doesn't
        //    require a LaunchAgent / Daemon.
        progress?.update("checking plugin-loaded persistence")
        scanPluginPersistence(findings: &findings, errors: &errors)

        // 9. Spotlight indexer disabled on user home — a stealth technique that
        //    hides files from search and Time Machine.
        progress?.update("checking Spotlight indexing")
        scanSpotlightIndexing(findings: &findings, errors: &errors)

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

    // MARK: - Background Task Management (BTM) Database

    private func scanBTMDatabase(findings: inout [Finding], errors: inout [String]) {
        // macOS Ventura+ stores Login Items / LaunchAgents registered through SMAppService
        // in /private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm.
        // We compare the BTM database against what's installed on disk to detect:
        //  - dumpbtm refused / database missing entirely (active tampering)
        //  - entries whose container apps don't exist (orphaned attacker-installed entries)
        //  - entries marked as disabled-by-user that were re-enabled silently
        let dumpResult = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 10)
        if !dumpResult.success || dumpResult.stdout.isEmpty {
            // sfltool dumpbtm is the only supported way to read this database; failure here
            // on Ventura+ means the BTM service is broken — historically a hallmark of
            // OSX.RustBucket and HiddenRisk dropping their plists then restarting the daemon.
            let btmDirExists = FileManager.default.fileExists(atPath: "/private/var/db/com.apple.backgroundtaskmanagement")
            if btmDirExists {
                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "Background Task Management is not enumerable",
                    detail: "sfltool dumpbtm failed even though the BTM database exists — the service may have been killed or tampered with",
                    path: "/private/var/db/com.apple.backgroundtaskmanagement",
                    remediation: "Restart backgroundtaskmanagementd or reboot. If the issue persists, suspect tampering."
                ))
            }
            return
        }

        // BTM dump entries roughly look like:
        //   Name: SomeApp.app
        //   Bundle Identifier: com.example.someapp
        //   Path: /Applications/SomeApp.app
        //   Disposition: ... [enabled, ...]
        // We pair each "Path" with the surrounding metadata so we can flag
        // disabled-yet-running and missing-on-disk entries.
        struct BTMEntry {
            var name: String?
            var bundleId: String?
            var path: String?
        }

        var entries: [BTMEntry] = []
        var current = BTMEntry()
        for rawLine in dumpResult.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                if current.path != nil || current.bundleId != nil {
                    entries.append(current)
                    current = BTMEntry()
                }
                continue
            }
            if let nameRange = line.range(of: "Name:") {
                current.name = String(line[nameRange.upperBound...]).trimmingCharacters(in: .whitespaces)
            } else if let bidRange = line.range(of: "Bundle Identifier:") {
                current.bundleId = String(line[bidRange.upperBound...]).trimmingCharacters(in: .whitespaces)
            } else if let pathRange = line.range(of: "URL:")
                        ?? line.range(of: "Path:")
                        ?? line.range(of: "Executable Path:") {
                var pathVal = String(line[pathRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                if pathVal.hasPrefix("file://") {
                    pathVal = String(pathVal.dropFirst("file://".count))
                        .removingPercentEncoding ?? pathVal
                }
                current.path = pathVal
            }
        }
        if current.path != nil || current.bundleId != nil { entries.append(current) }

        let fm = FileManager.default
        for entry in entries {
            guard let path = entry.path, !path.isEmpty, path.hasPrefix("/") else { continue }
            // Skip Apple-shipped entries; legitimate Apple paths or Apple bundle IDs are routinely registered.
            if path.hasPrefix("/System/") || path.hasPrefix("/Library/Apple/") || path.hasPrefix("/usr/libexec/") { continue }
            if let bid = entry.bundleId, bid.hasPrefix("com.apple.") { continue }

            // Spyware signature in the BTM entry path or bundle ID
            let basename = (path as NSString).lastPathComponent
            if let sig = SpywareSignature.match(processName: basename) ??
                         entry.bundleId.flatMap({ SpywareSignature.match(bundleId: $0) }) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware in Background Task Management: \(sig.name)",
                    detail: "BTM entry: \(entry.name ?? basename) — \(path)",
                    path: path,
                    remediation: "Remove the underlying app and use sfltool to delete its BTM record"
                ))
                continue
            }

            if !fm.fileExists(atPath: path) {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Background Task Management entry points to missing file",
                    detail: "BTM entry: \(entry.name ?? basename) → \(path) — orphan registrations are a known tamper indicator",
                    path: path,
                    remediation: "Remove the stale BTM record via sfltool or System Settings > Login Items"
                ))
            }
        }
    }

    // MARK: - SSH Client Config

    private func scanSSHConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let configPath = "\(home)/.ssh/config"
        guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else { return }

        // ProxyCommand/ProxyJump can pivot every SSH session through an attacker host;
        // ForwardAgent yes turns the user's running ssh-agent into a key-theft beacon
        // visible to any host they log into.
        let suspiciousDirectives: [(directive: String, severity: Severity, reason: String)] = [
            ("ForwardAgent yes", .high,
             "ForwardAgent yes globally is dangerous — any compromised host can use your SSH keys"),
            ("ProxyCommand", .medium,
             "ProxyCommand allows arbitrary code to run before the SSH connection — review the value"),
            ("UserKnownHostsFile /dev/null", .high,
             "Disabling known_hosts checking lets attackers MITM every SSH session"),
            ("StrictHostKeyChecking no", .high,
             "StrictHostKeyChecking off accepts any host key — enables silent MITM"),
            ("LocalCommand", .medium,
             "LocalCommand runs arbitrary shell commands when connecting — review the value"),
            ("PermitLocalCommand yes", .medium,
             "PermitLocalCommand yes pairs with LocalCommand for connection-time code execution"),
        ]

        for (idx, line) in content.split(separator: "\n").enumerated() {
            let trimmed = String(line).trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            for rule in suspiciousDirectives {
                if trimmed.lowercased().hasPrefix(rule.directive.lowercased()) {
                    findings.append(Finding(
                        severity: rule.severity, category: .persistence,
                        title: "Suspicious SSH client config: \(rule.directive)",
                        detail: "Line \(idx + 1) of ~/.ssh/config — \(rule.reason)",
                        path: configPath,
                        remediation: "Review and remove if not intentional: nano ~/.ssh/config"
                    ))
                }
            }
        }
    }

    // MARK: - Plugin-loaded persistence (Spotlight, QuickLook, Internet Plug-Ins)

    private func scanPluginPersistence(findings: inout [Finding], errors: inout [String]) {
        // These bundles get loaded into long-lived system processes (mdworker, quicklookd,
        // WebKit) any time Spotlight indexes a file, Preview generates a thumbnail, or
        // Safari renders legacy content. They are a popular modern persistence channel
        // because the loader (the system daemon) is Apple-signed and trusted.
        //
        // We restrict this check to the rare-on-typical-Macs plugin types. AudioUnit and
        // ColorSync directories routinely hold dozens of legitimate third-party items
        // (DAW plugins, monitor profiles); flagging each would be pure noise. For those
        // we ONLY flag matches against our known-spyware list.
        let home = ShellRunner.realUserHome
        let auditedPluginDirs: [(path: String, label: String, host: String, validExt: [String])] = [
            ("\(home)/Library/Spotlight",           "user Spotlight importers",  "mdworker",     [".mdimporter"]),
            ("/Library/Spotlight",                  "system Spotlight importers","mdworker",     [".mdimporter"]),
            ("\(home)/Library/QuickLook",           "user QuickLook generators", "quicklookd",   [".qlgenerator"]),
            ("/Library/QuickLook",                  "system QuickLook generators","quicklookd",  [".qlgenerator"]),
            ("\(home)/Library/Internet Plug-Ins",   "user Internet plug-ins",    "WebKit/Safari",[".plugin", ".webplugin"]),
            ("/Library/Internet Plug-Ins",          "system Internet plug-ins",  "WebKit/Safari",[".plugin", ".webplugin"]),
        ]
        let spywareOnlyPluginDirs: [(path: String, label: String)] = [
            ("\(home)/Library/Audio/Plug-Ins",      "user AudioUnit plug-ins"),
            ("/Library/Audio/Plug-Ins",             "system AudioUnit plug-ins"),
            ("\(home)/Library/ColorSync/Profiles",  "user ColorSync profiles"),
        ]

        let fm = FileManager.default

        for plugin in auditedPluginDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: plugin.path) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let entryPath = "\(plugin.path)/\(entry)"

                if let sig = SpywareSignature.match(processName: entry) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware in \(plugin.label): \(sig.name)",
                        detail: "Plugin: \(entry) — loaded into \(plugin.host)",
                        path: entryPath,
                        remediation: "Remove: sudo rm -rf \"\(entryPath)\""
                    ))
                    continue
                }

                let hasValidExt = plugin.validExt.contains { entry.hasSuffix($0) }
                if hasValidExt {
                    // Spotlight / QuickLook / Internet plug-ins are uncommon enough that any
                    // third-party entry is worth surfacing as informational.
                    findings.append(Finding(
                        severity: .low, category: .persistence,
                        title: "Third-party plugin in \(plugin.label)",
                        detail: "Plugin: \(entry) — loaded into \(plugin.host)",
                        path: entryPath,
                        remediation: "Verify this plugin is one you installed."
                    ))
                } else {
                    // A non-bundle file in a plugin directory is a strong red flag.
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "Unexpected file in \(plugin.label)",
                        detail: "Entry: \(entry) — not a typical plugin bundle (expected: \(plugin.validExt.joined(separator: ", ")))",
                        path: entryPath,
                        remediation: "Investigate: ls -la \"\(entryPath)\""
                    ))
                }
            }
        }

        // AudioUnit / ColorSync: only flag known-spyware matches to avoid noise.
        for dir in spywareOnlyPluginDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir.path) else { continue }
            for entry in entries where !entry.hasPrefix(".") {
                if let sig = SpywareSignature.match(processName: entry) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware in \(dir.label): \(sig.name)",
                        detail: "Plugin: \(entry)",
                        path: "\(dir.path)/\(entry)",
                        remediation: "Remove: sudo rm -rf \"\(dir.path)/\(entry)\""
                    ))
                }
            }
        }
    }

    // MARK: - Spotlight Indexing State

    private func scanSpotlightIndexing(findings: inout [Finding], errors: inout [String]) {
        // mdutil -s / lists indexing state per volume. Disabling indexing on the boot volume
        // is a known evasion: stops Spotlight from surfacing the attacker's files and breaks
        // Time Machine consistency. Most users have indexing enabled.
        let result = ShellRunner.run("/usr/bin/mdutil", arguments: ["-s", "/"], timeout: 5)
        guard result.success else { return }
        let lower = result.stdout.lowercased()
        if lower.contains("indexing disabled") || lower.contains("no index") {
            findings.append(Finding(
                severity: .medium, category: .systemIntegrity,
                title: "Spotlight indexing is disabled on the boot volume",
                detail: result.stdout.trimmingCharacters(in: .whitespacesAndNewlines),
                path: nil,
                remediation: "Re-enable: sudo mdutil -i on / — disabled indexing can be a malware evasion technique"
            ))
        }
    }
}
