import Foundation

public final class SystemIntegrityScanner: Scanner {
    public let name = "System Integrity Scan"
    public init() {}

    private let fdaRiskApps: Set<String> = [
        "com.apple.Terminal", "com.googlecode.iterm2",
        "net.kovidgoyal.kitty", "com.microsoft.VSCode",
        "com.sublimetext.4", "com.sublimetext.3",
    ]

    private let whitelistedFDAApps: Set<String> = [
        "com.apple.systempreferences", "com.apple.finder",
        "com.apple.dt.Xcode",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        // 1. SIP status
        progress?.update("checking SIP status")
        checkSIPStatus(findings: &findings, errors: &errors)

        // 2. TCC bypass indicators
        progress?.update("checking for TCC bypass indicators")
        checkMountedDMGs(findings: &findings, errors: &errors)

        progress?.update("checking Full Disk Access grants")
        checkFullDiskAccess(findings: &findings, errors: &errors)

        progress?.update("checking for hardlinked binaries")
        checkHardlinkedBinaries(findings: &findings, errors: &errors)

        // 3. Gatekeeper status
        progress?.update("checking Gatekeeper status")
        checkGatekeeperStatus(findings: &findings, errors: &errors)

        // 4. XProtect health
        progress?.update("checking XProtect status")
        checkXProtectHealth(findings: &findings, errors: &errors)

        // 5. macOS version freshness — unpatched OSes accumulate publicly-disclosed CVEs.
        progress?.update("checking macOS version")
        checkOSVersionFreshness(findings: &findings, errors: &errors)

        // 6. Quarantine event database — apps that bypassed Gatekeeper leave no quarantine
        //    entry. We flag recently-added launchable bundles that are missing the xattr.
        progress?.update("checking quarantine bypass")
        checkQuarantineBypass(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - SIP Status

    private func checkSIPStatus(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/csrutil", arguments: ["status"], timeout: 5)

        guard result.success || !result.stdout.isEmpty else {
            errors.append("Could not check SIP status")
            return
        }

        let output = result.stdout + result.stderr
        if output.contains("disabled") {
            findings.append(Finding(
                severity: .high, category: .systemIntegrity,
                title: "System Integrity Protection is DISABLED",
                detail: "SIP disabled — system is vulnerable to TCC bypass, kernel-level spyware, and rootkits",
                path: nil,
                remediation: "Reboot into Recovery Mode (Cmd+R at startup) and run: csrutil enable"
            ))
        } else if output.contains("custom configuration") || output.contains("Custom Configuration") {
            findings.append(Finding(
                severity: .medium, category: .systemIntegrity,
                title: "System Integrity Protection has custom configuration",
                detail: "SIP is partially disabled — some protections may be missing",
                path: nil,
                remediation: "Reboot into Recovery Mode and run: csrutil enable (to restore full protection)"
            ))
        }
        // If enabled, no finding needed
    }

    // MARK: - Mounted DMGs (TCC bypass vector)

    private func checkMountedDMGs(findings: inout [Finding], errors: inout [String]) {
        // Check for DMG files in temp directories
        let suspiciousDirs = ["/tmp", "/private/tmp", "/var/tmp"]
        let fm = FileManager.default

        for dir in suspiciousDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for file in contents where file.lowercased().hasSuffix(".dmg") {
                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "DMG file in temp directory (potential TCC bypass vector)",
                    detail: "DMG images in temp dirs can be used to bypass TCC restrictions",
                    path: "\(dir)/\(file)",
                    remediation: "Investigate and remove if not expected: rm \"\(dir)/\(file)\""
                ))
            }
        }

        // Check for unusual mount points
        let mountResult = ShellRunner.run("/sbin/mount", timeout: 5)
        if mountResult.success {
            let lines = mountResult.stdout.split(separator: "\n")
            for line in lines {
                let lineStr = String(line)
                // Look for disk images mounted outside /Volumes
                if lineStr.contains("disk image") || lineStr.contains(".dmg") {
                    if !lineStr.contains("/Volumes/") {
                        findings.append(Finding(
                            severity: .medium, category: .systemIntegrity,
                            title: "Disk image mounted in unusual location",
                            detail: String(lineStr.prefix(200)),
                            path: nil,
                            remediation: "Investigate this mounted disk image"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Full Disk Access Grants

    private func checkFullDiskAccess(findings: inout [Finding], errors: inout [String]) {
        // Query TCC for Full Disk Access grants
        let userHome = ShellRunner.realUserHome
        let tccPaths = [
            "\(userHome)/Library/Application Support/com.apple.TCC/TCC.db",
            "/Library/Application Support/com.apple.TCC/TCC.db",
        ]

        for tccPath in tccPaths {
            let tempPath = "/tmp/anti-spy-si-tcc-\(UUID().uuidString).db"
            let copyResult = ShellRunner.run("/bin/cp", arguments: [tccPath, tempPath])
            let queryPath = copyResult.success ? tempPath : tccPath
            defer { try? FileManager.default.removeItem(atPath: tempPath) }

            let query = "SELECT client FROM access WHERE service = 'kTCCServiceSystemPolicyAllFiles' AND auth_value = 2;"
            let result = ShellRunner.run("/usr/bin/sqlite3", arguments: ["-separator", "|", queryPath, query])

            guard result.success && !result.stdout.isEmpty else { continue }

            let clients = result.stdout.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }
            for client in clients where !client.isEmpty {
                if client.hasPrefix("com.apple.") || whitelistedFDAApps.contains(client) { continue }

                if fdaRiskApps.contains(client) {
                    findings.append(Finding(
                        severity: .low, category: .systemIntegrity,
                        title: "Terminal/IDE has Full Disk Access",
                        detail: "Client: \(client) — could be leveraged by malware for TCC bypass",
                        path: nil,
                        remediation: "This is often needed for development, but be aware of the risk"
                    ))
                } else {
                    // Check against known spyware
                    if let sig = SpywareSignature.match(bundleId: client) {
                        findings.append(Finding(
                            severity: .high, category: .systemIntegrity,
                            title: "Known spyware has Full Disk Access: \(sig.name)",
                            detail: "Client: \(client) — has unrestricted access to all files",
                            path: nil,
                            remediation: "Revoke immediately in System Settings > Privacy & Security > Full Disk Access"
                        ))
                    } else {
                        findings.append(Finding(
                            severity: .medium, category: .systemIntegrity,
                            title: "Non-standard app has Full Disk Access",
                            detail: "Client: \(client) — has unrestricted access to all files including TCC database",
                            path: nil,
                            remediation: "Verify in System Settings > Privacy & Security > Full Disk Access"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Hardlinked Binaries (TCC bypass technique)

    private func checkHardlinkedBinaries(findings: inout [Finding], errors: inout [String]) {
        let tempDirs = ["/tmp", "/private/tmp", "/var/tmp"]
        let fm = FileManager.default

        for dir in tempDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for file in contents {
                let filePath = "\(dir)/\(file)"

                // Check link count
                guard let attrs = try? fm.attributesOfItem(atPath: filePath),
                      let linkCount = attrs[.referenceCount] as? Int,
                      linkCount > 1 else { continue }

                // Check if it's a Mach-O binary
                guard let fh = FileHandle(forReadingAtPath: filePath) else { continue }
                let header = fh.readData(ofLength: 4)
                fh.closeFile()
                guard header.count == 4 else { continue }

                let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
                let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
                guard machoMagics.contains(magic) else { continue }

                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "Hardlinked binary in temp directory",
                    detail: "File: \(file), Link count: \(linkCount) — hardlinks to TCC-protected binaries can bypass restrictions",
                    path: filePath,
                    remediation: "Investigate: ls -li \"\(filePath)\" and remove if suspicious"
                ))
            }
        }
    }

    // MARK: - Gatekeeper Status

    private func checkGatekeeperStatus(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/spctl", arguments: ["--status"], timeout: 5)
        let output = result.stdout + result.stderr

        if output.contains("disabled") {
            findings.append(Finding(
                severity: .high, category: .systemIntegrity,
                title: "Gatekeeper is DISABLED",
                detail: "Gatekeeper disabled — unsigned and unnotarized apps can run without warning",
                path: nil,
                remediation: "Re-enable: sudo spctl --master-enable"
            ))
        }
    }

    // MARK: - XProtect Health Check

    private func checkXProtectHealth(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default

        // Check XProtect bundle exists and get version
        let xprotectPaths = [
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
            "/System/Library/CoreServices/XProtect.bundle",
        ]
        var xprotectFound = false

        for xpPath in xprotectPaths {
            let plistPath = "\(xpPath)/Contents/Info.plist"
            guard fm.fileExists(atPath: plistPath),
                  let data = fm.contents(atPath: plistPath),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { continue }

            xprotectFound = true
            let version = plist["CFBundleShortVersionString"] as? String ?? "unknown"

            // Check how old the XProtect definitions are
            if let attrs = try? fm.attributesOfItem(atPath: plistPath),
               let modDate = attrs[.modificationDate] as? Date {
                let daysSinceUpdate = Calendar.current.dateComponents([.day], from: modDate, to: Date()).day ?? 0

                if daysSinceUpdate > 30 {
                    findings.append(Finding(
                        severity: .medium, category: .systemIntegrity,
                        title: "XProtect definitions are \(daysSinceUpdate) days old",
                        detail: "Version: \(version), Last updated: \(formatDate(modDate))",
                        path: xpPath,
                        remediation: "Update macOS: System Settings > General > Software Update"
                    ))
                }
            }
            break
        }

        if !xprotectFound {
            findings.append(Finding(
                severity: .high, category: .systemIntegrity,
                title: "XProtect not found",
                detail: "macOS built-in malware protection is missing",
                path: nil,
                remediation: "Reinstall macOS or run Software Update"
            ))
        }

        // Check XProtect Remediator (MRT replacement on Ventura+)
        let xprPaths = [
            "/Library/Apple/System/Library/CoreServices/XProtect.app",
        ]
        for xprPath in xprPaths {
            if fm.fileExists(atPath: xprPath) {
                // Check last scan time
                if let attrs = try? fm.attributesOfItem(atPath: xprPath),
                   let modDate = attrs[.modificationDate] as? Date {
                    let daysSinceUpdate = Calendar.current.dateComponents([.day], from: modDate, to: Date()).day ?? 0
                    if daysSinceUpdate > 60 {
                        findings.append(Finding(
                            severity: .medium, category: .systemIntegrity,
                            title: "XProtect Remediator is \(daysSinceUpdate) days old",
                            detail: "Last updated: \(formatDate(modDate))",
                            path: xprPath,
                            remediation: "Update macOS: System Settings > General > Software Update"
                        ))
                    }
                }
            }
        }
    }

    private func formatDate(_ date: Date) -> String {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd"
        return fmt.string(from: date)
    }

    // MARK: - macOS Version Freshness

    /// Minimum macOS versions per major release that contain critical security fixes.
    /// Each entry: (major, minimum-patch-level-with-known-critical-fixes, "well-known CVE label").
    /// We don't try to track every CVE — only the ones Apple has marked as "actively exploited".
    private let minimumSafeVersions: [(major: Int, minor: Int, advisory: String)] = [
        // Sonoma 14.x — CVE-2024-23225 (kernel, actively exploited) patched in 14.4
        (14, 4, "CVE-2024-23225 (Sonoma kernel, actively exploited)"),
        // Ventura 13.x — CVE-2024-23225 in 13.6.5
        (13, 7, "Ventura security responses through 13.7"),
        // Monterey 12.x — Apple stopped shipping fixes in late 2024
        (12, 7, "Monterey (unsupported since late 2024 — upgrade strongly recommended)"),
    ]

    private func checkOSVersionFreshness(findings: inout [Finding], errors: inout [String]) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let major = v.majorVersion
        let minor = v.minorVersion

        // macOS < 12 (Big Sur and earlier) — fully unsupported, won't receive any new fixes.
        if major < 12 {
            findings.append(Finding(
                severity: .high, category: .systemIntegrity,
                title: "macOS \(major).\(minor) is end-of-life",
                detail: "Apple no longer ships security updates for macOS \(major) — every newly-disclosed CVE remains unpatched",
                path: nil,
                remediation: "Upgrade to a supported macOS release: System Settings > General > Software Update"
            ))
            return
        }

        // Match against the minimum-safe table.
        if let entry = minimumSafeVersions.first(where: { $0.major == major }) {
            if minor < entry.minor {
                let isOlderMajor = major < 14
                findings.append(Finding(
                    severity: isOlderMajor ? .high : .medium,
                    category: .systemIntegrity,
                    title: "macOS \(major).\(minor) is missing critical security updates",
                    detail: "Behind minimum recommended patch level (\(major).\(entry.minor)) — \(entry.advisory)",
                    path: nil,
                    remediation: "Update macOS: System Settings > General > Software Update"
                ))
            }
        }

        // Even the latest known major (15, 16, …) — flag if the patch-level looks stale by date.
        // Apple cuts a point release roughly every 1-2 months; >180 days with no patch means
        // either the user disabled updates or a recent release is missing.
        let kernPath = "/System/Library/Kernels/kernel"
        if let attrs = try? FileManager.default.attributesOfItem(atPath: kernPath),
           let modDate = attrs[.modificationDate] as? Date {
            let days = Calendar.current.dateComponents([.day], from: modDate, to: Date()).day ?? 0
            if days > 180 {
                findings.append(Finding(
                    severity: .medium, category: .systemIntegrity,
                    title: "Kernel hasn't been patched in \(days) days",
                    detail: "Last system update appears to be \(formatDate(modDate)) — recent macOS updates may be available",
                    path: nil,
                    remediation: "Check for updates: System Settings > General > Software Update"
                ))
            }
        }
    }

    // MARK: - Quarantine Bypass

    private func checkQuarantineBypass(findings: inout [Finding], errors: inout [String]) {
        // Every file downloaded via a browser or AirDrop is tagged com.apple.quarantine.
        // Stealers commonly strip this xattr with `xattr -d` to bypass Gatekeeper on first run.
        // Recently-installed .app bundles in /Applications without the xattr — and without
        // an Apple/known signature — are worth surfacing.
        let fm = FileManager.default
        let appDirs = ["/Applications", "\(ShellRunner.realUserHome)/Applications"]

        let cutoffDays: TimeInterval = 30
        let cutoff = Date(timeIntervalSinceNow: -cutoffDays * 86400)
        var flagged = 0

        for dir in appDirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            // Pre-filter to recently-modified .app bundles only — avoids spctl-spamming on a
            // freshly-installed Mac where every app's mtime is recent.
            let recentApps = contents
                .filter { $0.hasSuffix(".app") }
                .compactMap { entry -> (String, Date)? in
                    let appPath = "\(dir)/\(entry)"
                    guard let attrs = try? fm.attributesOfItem(atPath: appPath),
                          let modDate = attrs[.modificationDate] as? Date,
                          modDate > cutoff else { return nil }
                    return (appPath, modDate)
                }
                .sorted(by: { $0.1 > $1.1 })  // newest first
                .prefix(20)  // hard cap on spctl calls

            for (appPath, _) in recentApps {
                let entry = URL(fileURLWithPath: appPath).lastPathComponent
                let xattr = ShellRunner.run("/usr/bin/xattr", arguments: ["-p", "com.apple.quarantine", appPath], timeout: 3)
                let hasQuarantine = xattr.success && !xattr.stdout.isEmpty
                let spctl = ShellRunner.run("/usr/sbin/spctl", arguments: ["-a", "-vv", appPath], timeout: 5)
                let isAppleSigned = spctl.stderr.contains("source=Apple")
                let isAccepted = spctl.stderr.contains("accepted")

                if !hasQuarantine && !isAppleSigned && !isAccepted {
                    findings.append(Finding(
                        severity: .medium, category: .systemIntegrity,
                        title: "Recently installed app missing quarantine attribute",
                        detail: "\(entry) installed within the last \(Int(cutoffDays)) days but has no quarantine xattr and isn't Apple-signed — possible Gatekeeper bypass",
                        path: appPath,
                        remediation: "Verify the app's origin: spctl -a -vv \"\(appPath)\" — remove if unfamiliar"
                    ))
                    flagged += 1
                    if flagged >= 5 { return }
                }
            }
        }
    }
}
