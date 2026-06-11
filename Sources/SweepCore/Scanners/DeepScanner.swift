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

        // 6. Check for browser native messaging host registrations — a 2024/2025
        //    growth area: a native host is a binary that any extension with
        //    `nativeMessaging` permission can launch outside the browser sandbox.
        progress?.update("checking browser native messaging hosts")
        scanNativeMessagingHosts(findings: &findings, errors: &errors)

        // 7. Recent package installs — `.pkg` installers can ship preinstall/postinstall
        //    scripts that run as root, a very common initial-access vector on macOS.
        progress?.update("checking recent package installs")
        scanRecentPackageInstalls(findings: &findings, errors: &errors)

        // 8. APFS local snapshots can be used to stash data for later exfiltration
        //    or to roll back undesirable changes after compromise.
        progress?.update("checking APFS snapshots")
        scanAPFSSnapshots(findings: &findings, errors: &errors)

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

    // MARK: - Browser Native Messaging Hosts
    //
    // Native messaging hosts are JSON manifests that point at a local binary; any browser
    // extension with the `nativeMessaging` permission can launch the binary out-of-process,
    // bypassing browser sandboxing. Malicious extensions in 2024-2025 increasingly rely on
    // these to drop payloads outside the browser's reach.

    private func scanNativeMessagingHosts(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let hostDirs: [(path: String, browser: String)] = [
            ("\(home)/Library/Application Support/Google/Chrome/NativeMessagingHosts", "Chrome"),
            ("/Library/Google/Chrome/NativeMessagingHosts", "Chrome (system)"),
            ("\(home)/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts", "Brave"),
            ("\(home)/Library/Application Support/Microsoft Edge/NativeMessagingHosts", "Edge"),
            ("\(home)/Library/Application Support/Chromium/NativeMessagingHosts", "Chromium"),
            ("\(home)/Library/Application Support/Mozilla/NativeMessagingHosts", "Firefox"),
            ("/Library/Application Support/Mozilla/NativeMessagingHosts", "Firefox (system)"),
            ("\(home)/Library/Application Support/Google/Chrome Canary/NativeMessagingHosts", "Chrome Canary"),
            ("\(home)/Library/Application Support/Arc/User Data/NativeMessagingHosts", "Arc"),
        ]

        // Well-known legitimate native hosts. Anything outside this set warrants surfacing.
        let knownLegit: Set<String> = [
            "com.1password.1password",            // 1Password
            "com.1password.browser_support",
            "com.bitwarden.browser",              // Bitwarden
            "com.dashlane.app",                   // Dashlane
            "com.lastpass.lastpass",              // LastPass
            "org.keepassxc.keepassxc_browser",    // KeePassXC
            "com.honey.app",                      // Honey
            "com.malwarebytes.browserguard",      // Malwarebytes
            "com.docker.desktop",                 // Docker Desktop
            "com.tampermonkey.host",              // Tampermonkey
        ]

        let fm = FileManager.default

        for (path, browser) in hostDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: path) else { continue }

            for entry in entries where entry.hasSuffix(".json") {
                let manifestPath = "\(path)/\(entry)"
                guard let data = fm.contents(atPath: manifestPath),
                      let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

                let hostName = (manifest["name"] as? String) ?? entry.replacingOccurrences(of: ".json", with: "")
                let binaryPath = manifest["path"] as? String ?? ""
                if knownLegit.contains(hostName) { continue }

                // Resolve relative binary paths against the manifest's directory
                let resolvedBinary: String = binaryPath.hasPrefix("/")
                    ? binaryPath
                    : "\(path)/\(binaryPath)"

                let binaryExists = fm.fileExists(atPath: resolvedBinary)
                let inSuspiciousLocation = resolvedBinary.hasPrefix("/tmp") ||
                    resolvedBinary.hasPrefix("/private/tmp") ||
                    resolvedBinary.hasPrefix("/var/tmp") ||
                    resolvedBinary.split(separator: "/").contains { $0.hasPrefix(".") && $0 != ".cargo" && $0 != ".local" }

                let severity: Severity = inSuspiciousLocation ? .high :
                    (binaryExists ? .medium : .low)

                findings.append(Finding(
                    severity: severity, category: .suspiciousFile,
                    title: "\(browser) native messaging host registered: \(hostName)",
                    detail: "Manifest: \(manifestPath) → binary: \(resolvedBinary)" +
                        (inSuspiciousLocation ? " — binary in temp/hidden directory" : "") +
                        (binaryExists ? "" : " — binary missing"),
                    path: manifestPath,
                    remediation: "Verify which extension installed this host — remove the manifest if you don't recognize it: rm \"\(manifestPath)\""
                ))
            }
        }
    }

    // MARK: - Recent Package Installs
    //
    // /Library/Receipts/InstallHistory.plist (and /var/db/receipts) record every .pkg
    // installed on the system. Recent unsigned/non-Apple installs are often the breadcrumb
    // for an initial-access compromise — particularly the "fake update" pattern.

    private func scanRecentPackageInstalls(findings: inout [Finding], errors: inout [String]) {
        let plistPath = "/Library/Receipts/InstallHistory.plist"
        guard let data = FileManager.default.contents(atPath: plistPath),
              let list = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [[String: Any]]
        else { return }

        let now = Date()
        let cutoff = now.addingTimeInterval(-30 * 86400)  // last 30 days

        // Trusted package source names from Apple / common vendor installers.
        let trustedNamePrefixes: [String] = [
            "macOS", "Safari", "iOS", "iPad", "iPhone",
            "XProtect", "Gatekeeper", "MRT", "Xcode",
            "Command Line Tools", "Rosetta",
        ]
        let trustedProcessNames: Set<String> = [
            "softwareupdated",
            "com.apple.SoftwareUpdate",
            "Installer",  // mac App Store / system installer
            "App Store",
            "system_installd",
            "appstoreagent",
            "storeagent",
        ]

        var recentSuspicious: [(name: String, process: String, date: Date)] = []

        for entry in list {
            guard let date = entry["date"] as? Date, date >= cutoff,
                  let name = entry["displayName"] as? String else { continue }
            let process = (entry["processName"] as? String) ?? "unknown"

            // Apple-issued / store-issued packages are routine. Anything else gets a closer look.
            if trustedProcessNames.contains(process) { continue }
            if trustedNamePrefixes.contains(where: { name.hasPrefix($0) }) { continue }

            recentSuspicious.append((name: name, process: process, date: date))
        }

        // Cap output — the receipts list can get long on dev machines.
        for entry in recentSuspicious.suffix(20) {
            let dayFmt = DateFormatter()
            dayFmt.dateFormat = "yyyy-MM-dd"
            findings.append(Finding(
                severity: .low, category: .suspiciousFile,
                title: "Recent non-Apple package install: \(entry.name)",
                detail: "Installed \(dayFmt.string(from: entry.date)) by \(entry.process) — .pkg installers run preinstall/postinstall scripts as root",
                path: plistPath,
                remediation: "Verify this install was intentional. If not, the package's receipts are under /var/db/receipts/<id>.*"
            ))
        }
    }

    // MARK: - APFS Snapshots
    //
    // `tmutil listlocalsnapshots /` lists Time Machine local snapshots, which Time Machine
    // creates and rotates automatically. A snapshot that isn't named with TM's standard prefix
    // (`com.apple.TimeMachine.<date>`) was created manually — possibly to roll back changes
    // after compromise, or to stash data before exfiltration.

    private func scanAPFSSnapshots(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/tmutil", arguments: ["listlocalsnapshots", "/"], timeout: 10)
        guard result.success else { return }

        for rawLine in result.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("Snapshots for disk") { continue }

            // Time Machine snapshots all start with this label.
            if line.contains("com.apple.TimeMachine.") { continue }

            findings.append(Finding(
                severity: .medium, category: .suspiciousFile,
                title: "Non–Time-Machine APFS snapshot found",
                detail: "Snapshot: \(line) — APFS snapshots outside Time Machine's naming convention are rare and can be used to hide files",
                path: nil,
                remediation: "Inspect, then delete if not yours: tmutil deletelocalsnapshots <snapshot-id>"
            ))
        }
    }
}
