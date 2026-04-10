import Foundation

final class SystemIntegrityScanner: Scanner {
    let name = "System Integrity Scan"

    private let fdaRiskApps: Set<String> = [
        "com.apple.Terminal", "com.googlecode.iterm2",
        "net.kovidgoyal.kitty", "com.microsoft.VSCode",
        "com.sublimetext.4", "com.sublimetext.3",
    ]

    private let whitelistedFDAApps: Set<String> = [
        "com.apple.systempreferences", "com.apple.finder",
        "com.apple.dt.Xcode",
    ]

    func scan(progress: Spinner? = nil) -> ScanResult {
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
}
