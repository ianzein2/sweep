import Foundation

/// Hunts for actual evidence of spying: stored screenshots, keystroke logs,
/// screen recordings, and processes actively writing surveillance data.
public final class EvidenceScanner: Scanner {
    public let name = "Evidence Scan"
    public init() {}

    private let imageExtensions: Set<String> = ["png", "jpg", "jpeg", "bmp", "tiff", "tif", "webp"]
    private let videoExtensions: Set<String> = ["mp4", "mov", "avi", "mkv", "m4v"]

    private let skipDirs: Set<String> = [
        ".Trash", ".git", "node_modules", ".npm", ".cache",
        "DerivedData", ".build", "Caches", "WebKit", "Safari",
        "Google", "Firefox", "BraveSoftware", "Microsoft Edge",
        "com.apple.Safari", "com.apple.mail", "Photos Library.photoslibrary",
    ]

    /// Known legitimate app directories whose hidden files are NOT spyware.
    /// Files like .claude.json, .config inside these are normal.
    private let knownAppPaths: [String] = [
        "21st-desktop", "claude-sessions", "Claude",
        "com.apple.", "com.microsoft.", "com.google.",
        "Electron", "Code", "VSCode", "Slack", "Discord",
        "iTerm2", "Homebrew", "docker", "JetBrains",
        "Arc", "Brave Browser", "Chromium", "Opera",
        "Raycast", "Alfred", "1Password",
        "obs-studio", "Loom", "Descript",
        "Steam", "Epic", "Unity",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        // 1. Find processes with open file handles to suspicious files RIGHT NOW
        progress?.update("checking open file handles")
        scanOpenFileHandles(findings: &findings, errors: &errors)

        // 2. Find recently written screenshot-like image files in hidden/unusual places
        progress?.update("hunting for stored screenshots")
        scanForStoredScreenshots(home: home, findings: &findings, errors: &errors, progress: progress)

        // 3. Find keystroke log files — text files being appended to regularly
        progress?.update("hunting for keystroke logs")
        scanForKeystrokeLogs(home: home, findings: &findings, errors: &errors, progress: progress)

        // 4. Find screen recording files in hidden locations
        progress?.update("hunting for screen recordings")
        scanForScreenRecordings(home: home, findings: &findings, errors: &errors)

        // 5. Check for data exfiltration staging directories
        progress?.update("checking exfiltration paths")
        scanForExfiltration(home: home, findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Open File Handles (what's being written RIGHT NOW)

    private func scanOpenFileHandles(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/sbin/lsof", arguments: [
            "-w", "+c", "0"
        ], timeout: 20)

        guard result.success && !result.stdout.isEmpty else { return }

        let targetExtensions: Set<String> = [
            "png", "jpg", "jpeg", "log", "txt", "dat", "db", "sqlite", "bmp", "tiff", "mp4", "mov"
        ]

        let lines = result.stdout.split(separator: "\n")
        var matchCount = 0
        for line in lines {
            if matchCount >= 50 { break }
            let lineStr = String(line)

            // Filter for write/read-write file descriptors
            let parts = lineStr.split(separator: " ", maxSplits: 8, omittingEmptySubsequences: true)
            guard parts.count >= 9 else { continue }
            let fdField = String(parts[3])
            guard fdField.hasSuffix("w") || fdField.hasSuffix("u") else { continue }

            let filePath = String(parts.last ?? "")
            guard !filePath.contains("/dev/"),
                  !filePath.contains("/System/"),
                  !filePath.contains("com.apple.") else { continue }

            let ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
            guard targetExtensions.contains(ext) else { continue }

            matchCount += 1
            let processName = String(parts[0])

            // Skip known safe processes
            if processName.hasPrefix("com.apple.") { continue }
            if ["Finder", "mds", "mds_stores", "mdworker", "Spotlight",
                "quicklookd", "Preview", "Photos", "screencaptureui",
                "ScreenshotMonitor"].contains(processName) { continue }

            // Is the file in a hidden directory?
            let isHidden = filePath.split(separator: "/").contains { $0.hasPrefix(".") }
            // Is it in a temp or unusual location?
            let isSuspiciousPath = filePath.hasPrefix("/tmp") || filePath.hasPrefix("/private/tmp") ||
                                   filePath.hasPrefix("/var/tmp") || isHidden

            guard isSuspiciousPath else { continue }

            let ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
            if imageExtensions.contains(ext) {
                findings.append(Finding(
                    severity: .high, category: .screenCapture,
                    title: "Process actively writing image to hidden/temp location",
                    detail: "Process: \(processName), writing: \(filePath)",
                    path: filePath,
                    remediation: "This may be active screenshot capture — investigate \(processName) immediately"
                ))
            } else if ["log", "txt", "dat"].contains(ext) {
                findings.append(Finding(
                    severity: .high, category: .keylogging,
                    title: "Process actively writing log/data to hidden/temp location",
                    detail: "Process: \(processName), writing: \(filePath)",
                    path: filePath,
                    remediation: "This may be active keystroke logging — investigate \(processName) immediately"
                ))
            }
        }
    }

    // MARK: - Stored Screenshots in Hidden Places

    private func scanForStoredScreenshots(home: String, findings: inout [Finding], errors: inout [String], progress: ScanProgress?) {
        // Spyware stores screenshots in hidden directories, not ~/Desktop
        // Look for clusters of image files in unusual places
        let searchRoots = [
            "\(home)/Library/Application Support",
            "\(home)/Library",
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "/private/var/tmp",
            "\(home)/.local",
            "\(home)/.config",
        ]

        for root in searchRoots {
            let fm = FileManager.default
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey, .isRegularFileKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            var dirImageCounts: [String: (count: Int, totalSize: Int, newest: Date, examples: [String])] = [:]
            var filesProcessed = 0
            let maxFiles = 100_000

            for case let url as URL in enumerator {
                filesProcessed += 1
                if filesProcessed > maxFiles { break }
                if enumerator.level > 4 {
                    enumerator.skipDescendants()
                    continue
                }
                let dirName = url.deletingLastPathComponent().lastPathComponent
                if skipDirs.contains(dirName) {
                    enumerator.skipDescendants()
                    continue
                }

                // Skip known legitimate app directories
                if isKnownAppPath(url.path) { continue }

                let ext = url.pathExtension.lowercased()
                guard imageExtensions.contains(ext) else { continue }

                guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
                      let size = values.fileSize,
                      size > 50_000  // > 50KB — skip tiny icons/thumbnails
                else { continue }

                let parentDir = url.deletingLastPathComponent().path
                let modDate = values.contentModificationDate ?? Date.distantPast

                var entry = dirImageCounts[parentDir] ?? (count: 0, totalSize: 0, newest: .distantPast, examples: [])
                entry.count += 1
                entry.totalSize += size
                if modDate > entry.newest { entry.newest = modDate }
                if entry.examples.count < 3 { entry.examples.append(url.lastPathComponent) }
                dirImageCounts[parentDir] = entry
            }

            // Flag directories with suspicious image clusters
            for (dir, info) in dirImageCounts {
                // A hidden directory with multiple screenshots is very suspicious
                let isHidden = dir.split(separator: "/").contains { $0.hasPrefix(".") }
                let isTemp = dir.hasPrefix("/tmp") || dir.hasPrefix("/private/tmp") || dir.hasPrefix("/var/tmp")
                let isRecent = info.newest.timeIntervalSinceNow > -86400 * 7  // within last 7 days

                if info.count >= 3 && (isHidden || isTemp) {
                    let sizeMB = String(format: "%.1f", Double(info.totalSize) / 1_000_000)
                    let age = formatAge(info.newest)
                    findings.append(Finding(
                        severity: .high, category: .screenCapture,
                        title: "\(info.count) screenshot-like images in hidden directory",
                        detail: "Total: \(sizeMB)MB, newest: \(age), examples: \(info.examples.joined(separator: ", "))",
                        path: dir,
                        remediation: "Inspect: ls -la \"\(dir)\" — this looks like stored screenshot captures"
                    ))
                } else if info.count >= 5 && isRecent {
                    let sizeMB = String(format: "%.1f", Double(info.totalSize) / 1_000_000)
                    let age = formatAge(info.newest)
                    findings.append(Finding(
                        severity: .medium, category: .screenCapture,
                        title: "\(info.count) recent screenshots in unusual location",
                        detail: "Total: \(sizeMB)MB, newest: \(age), examples: \(info.examples.joined(separator: ", "))",
                        path: dir,
                        remediation: "Check if you recognize these files"
                    ))
                }
            }
        }
    }

    // MARK: - Keystroke Logs

    private func scanForKeystrokeLogs(home: String, findings: inout [Finding], errors: inout [String], progress: ScanProgress?) {
        // Keystroke loggers write to text/log/dat files, often appending continuously.
        // Look for: recently modified text files in hidden dirs, files with "key" in the name,
        // files growing over time, files with high line counts in unusual places.

        let searchPaths = [
            "\(home)/Library/Application Support",
            "\(home)/Library/Logs",
            "\(home)/.local",
            "\(home)/.config",
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "/var/log",
        ]

        let suspiciousNames = [
            "keylog", "keystroke", "keypress", "keyboard", "typelog",
            "inputlog", "keycapture", "keyrecord", "klog", "keys.log",
            "keys.txt", "typed.txt", "input.log", "input.txt",
        ]

        let logExtensions: Set<String> = ["log", "txt", "dat", "csv"]

        for root in searchPaths {
            let fm = FileManager.default
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey, .isRegularFileKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            var filesProcessed = 0
            let maxFiles = 100_000

            for case let url as URL in enumerator {
                filesProcessed += 1
                if filesProcessed > maxFiles { break }
                if enumerator.level > 4 {
                    enumerator.skipDescendants()
                    continue
                }
                let dirName = url.deletingLastPathComponent().lastPathComponent
                if skipDirs.contains(dirName) {
                    enumerator.skipDescendants()
                    continue
                }

                let ext = url.pathExtension.lowercased()
                let filename = url.lastPathComponent.lowercased()

                // Skip known legitimate app directories
                if isKnownAppPath(url.path) { continue }

                // Check for suspicious filenames regardless of extension
                for pattern in suspiciousNames {
                    if filename.contains(pattern) {
                        let isHidden = url.path.split(separator: "/").contains { $0.hasPrefix(".") }
                        findings.append(Finding(
                            severity: isHidden ? .high : .medium,
                            category: .keylogging,
                            title: "Potential keystroke log file: \(url.lastPathComponent)",
                            detail: "Matches pattern: \"\(pattern)\"",
                            path: url.path,
                            remediation: "Inspect: cat \"\(url.path)\" | head -20"
                        ))
                        break
                    }
                }

                // In hidden directories, check for recently modified log/text files
                guard logExtensions.contains(ext) else { continue }
                let isHidden = url.path.split(separator: "/").contains { $0.hasPrefix(".") }
                guard isHidden else { continue }

                guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
                      let size = values.fileSize, size > 1000,  // > 1KB
                      let modDate = values.contentModificationDate,
                      modDate.timeIntervalSinceNow > -86400 * 3  // modified in last 3 days
                else { continue }

                let sizeFmt = size > 1_000_000
                    ? String(format: "%.1fMB", Double(size) / 1_000_000)
                    : String(format: "%.1fKB", Double(size) / 1000)
                let age = formatAge(modDate)

                findings.append(Finding(
                    severity: .medium, category: .keylogging,
                    title: "Recently modified log in hidden directory",
                    detail: "Size: \(sizeFmt), modified: \(age)",
                    path: url.path,
                    remediation: "Inspect: head -20 \"\(url.path)\""
                ))
            }
        }
    }

    // MARK: - Screen Recordings in Hidden Places

    private func scanForScreenRecordings(home: String, findings: inout [Finding], errors: inout [String]) {
        let searchRoots = [
            "\(home)/Library/Application Support",
            "\(home)/.local",
            "\(home)/.config",
            "/tmp", "/private/tmp", "/var/tmp",
        ]

        for root in searchRoots {
            let fm = FileManager.default
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 3 {
                    enumerator.skipDescendants()
                    continue
                }
                let dirName = url.deletingLastPathComponent().lastPathComponent
                if skipDirs.contains(dirName) {
                    enumerator.skipDescendants()
                    continue
                }

                if isKnownAppPath(url.path) { continue }

                let ext = url.pathExtension.lowercased()
                guard videoExtensions.contains(ext) else { continue }
                let isHidden = url.path.split(separator: "/").contains { $0.hasPrefix(".") }
                guard isHidden else { continue }

                guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
                      let size = values.fileSize, size > 500_000  // > 500KB
                else { continue }

                let sizeMB = String(format: "%.1fMB", Double(size) / 1_000_000)
                let age = values.contentModificationDate.map { formatAge($0) } ?? "unknown"

                findings.append(Finding(
                    severity: .high, category: .screenCapture,
                    title: "Video file in hidden directory: \(url.lastPathComponent)",
                    detail: "Size: \(sizeMB), modified: \(age)",
                    path: url.path,
                    remediation: "This may be a screen recording — inspect: open \"\(url.path)\""
                ))
            }
        }
    }

    // MARK: - Data Exfiltration Staging

    private func scanForExfiltration(home: String, findings: inout [Finding], errors: inout [String]) {
        // Spyware often stages captured data before uploading.
        // Look for: zip/tar files in hidden dirs, unusual network-related config files.
        let archiveExtensions: Set<String> = ["zip", "tar", "gz", "tgz", "rar", "7z"]

        let stagingPaths = [
            "\(home)/Library/Application Support",
            "/tmp", "/private/tmp", "/var/tmp",
        ]

        for root in stagingPaths {
            let fm = FileManager.default
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 3 {
                    enumerator.skipDescendants()
                    continue
                }
                let dirName = url.deletingLastPathComponent().lastPathComponent
                if skipDirs.contains(dirName) {
                    enumerator.skipDescendants()
                    continue
                }

                if isKnownAppPath(url.path) { continue }

                let ext = url.pathExtension.lowercased()
                guard archiveExtensions.contains(ext) else { continue }
                let isHidden = url.path.split(separator: "/").contains { $0.hasPrefix(".") }
                guard isHidden else { continue }

                guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
                      let size = values.fileSize, size > 100_000,
                      let modDate = values.contentModificationDate,
                      modDate.timeIntervalSinceNow > -86400 * 7  // last 7 days
                else { continue }

                let sizeMB = String(format: "%.1fMB", Double(size) / 1_000_000)

                findings.append(Finding(
                    severity: .medium, category: .suspiciousFile,
                    title: "Recent archive in hidden directory: \(url.lastPathComponent)",
                    detail: "Size: \(sizeMB), modified: \(formatAge(modDate))",
                    path: url.path,
                    remediation: "May be staged exfiltration data — inspect contents"
                ))
            }
        }
    }

    // MARK: - Helpers

    /// Check if a file path belongs to a known legitimate application
    private func isKnownAppPath(_ path: String) -> Bool {
        let components = path.split(separator: "/").map(String.init)
        return knownAppPaths.contains { known in
            components.contains { component in
                component == known || component.hasPrefix(known)
            }
        }
    }

    private func formatAge(_ date: Date) -> String {
        let seconds = -date.timeIntervalSinceNow
        if seconds < 3600 { return "\(Int(seconds / 60))m ago" }
        if seconds < 86400 { return "\(Int(seconds / 3600))h ago" }
        return "\(Int(seconds / 86400))d ago"
    }
}
