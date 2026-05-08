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

        // 6. Check for apps with Gatekeeper quarantine attribute stripped
        progress?.update("checking for Gatekeeper bypass attempts")
        scanQuarantineStripping(findings: &findings, errors: &errors)

        // 7. Check Privileged Helper Tools — root daemons installed by apps
        progress?.update("checking privileged helper tools")
        scanPrivilegedHelpers(findings: &findings, errors: &errors)

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

    // MARK: - Gatekeeper Quarantine Stripping
    //
    // macOS attaches a `com.apple.quarantine` extended attribute to anything downloaded
    // by a Gatekeeper-aware app (Safari, Mail, Messages, AirDrop, App Store, etc).
    // That xattr is what makes Gatekeeper enforce notarization on first launch.
    //
    // A common 2024-2025 install trick — used by AMOS-style stealers and ClickFix campaigns —
    // is to ship a DMG plus a script that runs `xattr -dr com.apple.quarantine /Applications/Foo.app`,
    // silently bypassing Gatekeeper. Recently-installed third-party apps that have NO quarantine
    // xattr at all are the tell.

    private func scanQuarantineStripping(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        let appDirs = ["/Applications", "\(ShellRunner.realUserHome)/Applications"]
        let now = Date()

        for dir in appDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".app") {
                let appPath = "\(dir)/\(entry)"

                // Only flag apps installed in the last 30 days — old apps legitimately lose their xattr
                // over time (backups, OS migrations strip it). Recent installs are the interesting case.
                guard let attrs = try? fm.attributesOfItem(atPath: appPath),
                      let modDate = attrs[.modificationDate] as? Date else { continue }
                let daysOld = Calendar.current.dateComponents([.day], from: modDate, to: now).day ?? 999
                guard daysOld <= 30 else { continue }

                // Apple-signed apps shipping with the OS aren't downloaded — skip them.
                let infoPlistPath = "\(appPath)/Contents/Info.plist"
                if let data = fm.contents(atPath: infoPlistPath),
                   let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                   let bundleId = plist["CFBundleIdentifier"] as? String,
                   bundleId.hasPrefix("com.apple.") { continue }

                // Ask xattr whether the quarantine flag is present.
                let xattrCheck = ShellRunner.run("/usr/bin/xattr",
                                                 arguments: ["-p", "com.apple.quarantine", appPath],
                                                 timeout: 3)
                let hasQuarantine = xattrCheck.success
                if hasQuarantine { continue }

                // Apps installed via App Store / pkg installers also legitimately have no quarantine.
                // We can't perfectly tell those apart, so call this MEDIUM — informational, not alarming —
                // but call out the 30-day install window so the user can decide.
                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "Recently installed app missing Gatekeeper quarantine flag",
                    detail: "App: \(entry), installed ~\(daysOld) day(s) ago — could indicate `xattr -d com.apple.quarantine` was run to bypass Gatekeeper",
                    path: appPath,
                    remediation: "If you didn't install this from the App Store or a pkg installer, treat the app as untrusted and verify its source"
                ))
            }
        }
    }

    // MARK: - Privileged Helper Tools
    //
    // /Library/PrivilegedHelperTools holds root-running launch daemons that apps register
    // via SMJobBless. Legitimate examples: 1Password, Docker, virtualization tools.
    // Spyware sometimes installs its own helper here so that it can act as root without
    // the user re-authenticating. Anything from an unknown signing identity should be reviewed.

    private func scanPrivilegedHelpers(findings: inout [Finding], errors: inout [String]) {
        let helperDir = "/Library/PrivilegedHelperTools"
        let fm = FileManager.default
        guard fm.fileExists(atPath: helperDir),
              let entries = try? fm.contentsOfDirectory(atPath: helperDir) else { return }

        // Common, well-known helpers we don't bother surfacing.
        let knownPrefixes: [String] = [
            "com.apple.",
            "com.docker.",
            "com.1password.",
            "com.agilebits.",
            "com.parallels.",
            "com.vmware.",
            "com.crashlytics.",
            "com.adobe.",
            "com.microsoft.",
            "com.google.keystone.",
            "com.brave.",
            "org.virtualbox.",
            "com.objective-see.",   // LuLu, KnockKnock, etc.
            "com.crowdstrike.",
            "com.sentinelone.",
            "com.malwarebytes.",
            "com.jamf.",
            "com.tailscale.",
        ]

        for entry in entries where !entry.hasPrefix(".") {
            let path = "\(helperDir)/\(entry)"

            // The filename is the bundle id of the helper (e.g. com.foo.helper).
            if knownPrefixes.contains(where: { entry.hasPrefix($0) }) { continue }

            // Spyware-mimicked Apple helpers fail this test — they look like com.apple.* but
            // aren't really Apple. The SpywareSignature heuristic catches these.
            if SpywareSignature.isFakeAppleBundleId(entry) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Fake-Apple privileged helper installed",
                    detail: "Helper: \(entry) — this name impersonates an Apple service but isn't a real Apple helper",
                    path: path,
                    remediation: "Inspect, then remove: sudo rm \"\(path)\" and sudo launchctl bootout system/\(entry)"
                ))
                continue
            }

            // Look up the helper's code signature to surface the team identifier when present.
            let codesign = ShellRunner.run("/usr/bin/codesign",
                                           arguments: ["-dv", "--verbose=4", path],
                                           timeout: 5)
            // codesign writes to stderr by default.
            let combined = codesign.stderr + codesign.stdout
            let teamLine = combined.split(separator: "\n").first { $0.contains("TeamIdentifier=") }
            let teamId = teamLine.map { String($0).replacingOccurrences(of: "TeamIdentifier=", with: "")
                                                  .trimmingCharacters(in: .whitespaces) } ?? "unknown"

            findings.append(Finding(
                severity: .medium, category: .persistence,
                title: "Privileged helper from unknown vendor",
                detail: "Helper: \(entry), Team: \(teamId) — runs as root, registered via SMJobBless",
                path: path,
                remediation: "If you don't recognize the vendor, remove: sudo rm \"\(path)\" and sudo launchctl bootout system/\(entry)"
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
