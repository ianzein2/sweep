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

        // 6. Check for crypto wallet / browser credential theft — the signature payload
        //    of AMOS-family infostealers (2023-2025).
        progress?.update("checking crypto wallet / credential theft")
        scanForCredentialTheft(home: home, findings: &findings, errors: &errors)

        // 7. Check for ransomware artifacts — macOS ransomware (macOS.NotLockBit,
        //    EvilQuest 2025 variants) drops ransom notes and renames files with marker extensions.
        progress?.update("checking for ransomware artifacts")
        scanForRansomwareArtifacts(home: home, findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Open File Handles (what's being written RIGHT NOW)

    private func scanOpenFileHandles(findings: inout [Finding], errors: inout [String]) {
        // Find processes writing to image or log files in hidden/unusual locations
        // lsof +D is too slow. Use lsof with write mode filter.
        let result = ShellRunner.run("/bin/sh", arguments: [
            "-c",
            """
            lsof -w +c 0 2>/dev/null | awk '$4 ~ /[0-9]+w/ || $4 ~ /[0-9]+u/' | \
            grep -iE '\\.(png|jpg|jpeg|log|txt|dat|db|sqlite|bmp|tiff|mp4|mov)$' | \
            grep -v '/dev/' | grep -v '/System/' | grep -v 'com.apple.' | \
            head -50
            """
        ], timeout: 20)

        guard result.success && !result.stdout.isEmpty else { return }

        let lines = result.stdout.split(separator: "\n")
        for line in lines {
            let parts = String(line).split(separator: " ", maxSplits: 8, omittingEmptySubsequences: true)
            guard parts.count >= 9 else { continue }
            let processName = String(parts[0])
            let filePath = String(parts.last ?? "")

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

            // Track image clusters per directory
            var dirImageCounts: [String: (count: Int, totalSize: Int, newest: Date, examples: [String])] = [:]

            for case let url as URL in enumerator {
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

            for case let url as URL in enumerator {
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

    // MARK: - Credential / Crypto Wallet Theft

    /// Filenames/paths that modern macOS infostealers (AMOS, Banshee, Poseidon, Realst, etc.)
    /// explicitly target. Finding copies of these files staged in /tmp or hidden directories
    /// is strong evidence of an active stealer campaign on the machine.
    private let walletFingerprints: [(label: String, marker: String)] = [
        ("MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn"),   // Chromium extension dir
        ("Phantom",  "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
        ("Coinbase Wallet", "hnfanknocfeofbddgcijnmhnfnkdnaad"),
        ("Ronin",    "fnjhmkhhmkbjkkabndcnnogagogbneec"),
        ("TronLink", "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
        ("Exodus",   "Exodus"),
        ("Electrum", ".electrum"),
        ("Atomic Wallet", "Atomic"),
        ("Ledger Live", "Ledger Live"),
        ("Trezor Suite", "@trezor"),
        ("Keplr",    "dmkamcknogkgcdfhhbddcghachkejeap"),
    ]

    /// Browser credential stores AMOS-family stealers copy.
    private let browserCredStoreNames: Set<String> = [
        "Login Data", "Web Data", "Cookies", "Local State",
        "key4.db", "logins.json", "cookies.sqlite",  // Firefox
        "Keychains", "login.keychain-db",            // macOS keychain copies
    ]

    private func scanForCredentialTheft(home: String, findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        let searchRoots = ["/tmp", "/private/tmp", "/var/tmp",
                           "\(home)/Library/Application Support",
                           "\(home)/.local",
                           "\(home)/.config"]

        // Allowed locations where these files SHOULD appear. Anything outside is suspect.
        let legitRoots: [String] = [
            "\(home)/Library/Application Support/Google/Chrome",
            "\(home)/Library/Application Support/BraveSoftware",
            "\(home)/Library/Application Support/Microsoft Edge",
            "\(home)/Library/Application Support/Chromium",
            "\(home)/Library/Application Support/Arc",
            "\(home)/Library/Application Support/Firefox",
            "\(home)/Library/Application Support/com.operasoftware.Opera",
            "\(home)/Library/Keychains",
            "/Library/Keychains",
        ]

        for root in searchRoots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 5 {
                    enumerator.skipDescendants()
                    continue
                }
                let filePath = url.path

                // A copy of a browser credential store outside of its legitimate browser directory
                // is high-confidence stealer evidence.
                let filename = url.lastPathComponent
                if browserCredStoreNames.contains(filename) {
                    let inLegitPath = legitRoots.contains(where: { filePath.hasPrefix($0) })
                    if !inLegitPath {
                        // Only flag if the file is non-trivially sized (real credential stores are at least a few KB)
                        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
                        if size > 512 {
                            findings.append(Finding(
                                severity: .high, category: .suspiciousFile,
                                title: "Browser credential store copied to non-browser location",
                                detail: "File \"\(filename)\" at \(filePath) — infostealers (AMOS, Banshee, Poseidon) copy these files before uploading them",
                                path: filePath,
                                remediation: "Rotate browser-saved passwords and investigate the process that created this file"
                            ))
                        }
                    }
                }

                // Crypto wallet references staged outside of the wallet's real location
                for fingerprint in walletFingerprints {
                    if filename.contains(fingerprint.marker) || filePath.contains("/\(fingerprint.marker)/") {
                        // A wallet extension dir inside /tmp or a hidden dir = staged for theft.
                        let isStaging = filePath.hasPrefix("/tmp") || filePath.hasPrefix("/private/tmp") ||
                                        filePath.hasPrefix("/var/tmp") ||
                                        filePath.split(separator: "/").contains(where: {
                                            let s = String($0)
                                            return s.hasPrefix(".") && s != ".local" && s != ".config"
                                        })
                        if isStaging {
                            findings.append(Finding(
                                severity: .high, category: .suspiciousFile,
                                title: "Crypto wallet files staged in unusual location",
                                detail: "\(fingerprint.label) data found at \(filePath) — stealers stage wallet data here before exfiltration",
                                path: filePath,
                                remediation: "Move funds to a new wallet and investigate the process that placed this file"
                            ))
                            break
                        }
                    }
                }
            }
        }

        // Watch for active invocations of `security dump-keychain` — a stealer hallmark.
        // Looking at currently-running processes is cheaper than parsing log history.
        let psResult = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,comm,args"], timeout: 5)
        if psResult.success {
            for line in psResult.stdout.split(separator: "\n") {
                let lineStr = String(line)
                if lineStr.contains("security") && lineStr.contains("dump-keychain") {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Process dumping the macOS keychain",
                        detail: "Active: \(String(lineStr.prefix(160)))",
                        path: nil,
                        remediation: "Identify the calling process and kill it — `security dump-keychain -d` extracts stored passwords"
                    ))
                }
            }
        }
    }

    // MARK: - Ransomware Artifact Detection

    /// File extensions appended by known macOS / cross-platform ransomware families.
    /// We deliberately keep this list short and high-confidence — generic extensions like
    /// ".lock" or ".key" are too noisy on a dev machine.
    private let ransomwareExtensions: Set<String> = [
        "encrypted", "nslocked", "notlockbit", "crypted", "evilquest",
        "thiefquest", "lockbit", "abyss", "lokis", "darkside_mac",
        "crystalransom", "crystalrans0m", "shelbylocked", "tsunamilock",
    ]

    /// Filenames characteristic of ransom-note drops. We require the file to contain at least
    /// one ransom-style keyword to avoid flagging a legitimate "README.txt".
    private let ransomNoteFilenames: [String] = [
        "READ_ME_FOR_DECRYPT", "HOW_TO_DECRYPT", "DECRYPT_INSTRUCTIONS",
        "RESTORE_FILES", "RECOVERY", "RECOVER_FILES", "RANSOM_NOTE",
        "YOUR_FILES_ARE_ENCRYPTED", "HOW_TO_RECOVER", "DECRYPT_NOTE",
        "NotLockBit_README", "EvilQuest_README", "RansomNote",
    ]

    /// Phrases nearly always present in a real ransom note — used to confirm a candidate.
    private let ransomNoteKeywords: [String] = [
        "your files have been encrypted", "your files are encrypted",
        "bitcoin", "monero", "decryption key", "pay the ransom",
        "to decrypt your files", "send us", "wallet address",
        "tor browser", ".onion", "ransomware", "encrypted with",
    ]

    private func scanForRansomwareArtifacts(home: String, findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default

        // Where ransomware tends to drop notes — user-visible directories first, then known landing spots.
        let noteSearchRoots = [
            "\(home)/Desktop",
            "\(home)/Documents",
            "\(home)/Downloads",
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "/private/var/tmp",
        ]

        // Used to bound the work: we cap scans to top-level + one directory deep so this stays fast
        // even on Documents folders with thousands of files.
        for root in noteSearchRoots {
            guard fm.fileExists(atPath: root) else { continue }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
                options: [.skipsPackageDescendants]
            ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 2 {
                    enumerator.skipDescendants()
                    continue
                }
                let dirName = url.deletingLastPathComponent().lastPathComponent
                if skipDirs.contains(dirName) {
                    enumerator.skipDescendants()
                    continue
                }

                let filename = url.lastPathComponent
                let ext = url.pathExtension.lowercased()

                // 1. Filename has a known ransomware extension.
                if ransomwareExtensions.contains(ext) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "File with ransomware extension: .\(ext)",
                        detail: "File: \(filename) — extension is associated with known macOS ransomware",
                        path: url.path,
                        remediation: "Disconnect from the network and restore from backup — do NOT pay the ransom"
                    ))
                    continue
                }

                // 2. Filename matches a ransom-note pattern AND the body contains ransom keywords.
                let nameUpper = filename.uppercased()
                let nameMatches = ransomNoteFilenames.contains { nameUpper.contains($0.uppercased()) }
                guard nameMatches else { continue }

                // Only confirm if the file body looks like a real ransom note.
                let attrs = try? url.resourceValues(forKeys: [.fileSizeKey])
                let size = attrs?.fileSize ?? 0
                guard size > 50 && size < 200_000 else { continue }  // bound: real notes are 100B - 50KB

                guard let content = try? String(contentsOf: url, encoding: .utf8) else { continue }
                let lower = content.lowercased()
                let hitKeyword = ransomNoteKeywords.first { lower.contains($0) }
                guard let kw = hitKeyword else { continue }

                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Possible ransom note found: \(filename)",
                    detail: "Contains keyword \"\(kw)\" — strong indicator of an encryption attack in progress",
                    path: url.path,
                    remediation: "Disconnect from the network and restore from backup — do NOT pay the ransom. " +
                                 "If this Mac is encrypted, contact a security professional before powering it off."
                ))
            }
        }

        // 3. Bulk-rename detection: look for clusters of files in Documents/Desktop where the
        //    rename happened all within a short window. This is what mass encryption looks like
        //    from the user's filesystem POV.
        detectBulkEncryptionPattern(home: home, findings: &findings)
    }

    private func detectBulkEncryptionPattern(home: String, findings: inout [Finding]) {
        let fm = FileManager.default
        let dirsToCheck = ["\(home)/Documents", "\(home)/Desktop", "\(home)/Downloads"]

        for dir in dirsToCheck {
            guard fm.fileExists(atPath: dir),
                  let enumerator = fm.enumerator(
                    at: URL(fileURLWithPath: dir),
                    includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
                    options: [.skipsPackageDescendants]
                  ) else { continue }

            var ransomExtCount = 0
            var examples: [String] = []

            for case let url as URL in enumerator {
                if enumerator.level > 3 {
                    enumerator.skipDescendants()
                    continue
                }
                let ext = url.pathExtension.lowercased()
                guard ransomwareExtensions.contains(ext) else { continue }

                ransomExtCount += 1
                if examples.count < 3 { examples.append(url.lastPathComponent) }
                // Bound work — if we found a lot, that's already a finding.
                if ransomExtCount > 100 { break }
            }

            if ransomExtCount >= 5 {
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Bulk file encryption pattern in \(URL(fileURLWithPath: dir).lastPathComponent)",
                    detail: "\(ransomExtCount) files with ransomware extensions — examples: \(examples.joined(separator: ", "))",
                    path: dir,
                    remediation: "Disconnect from the network immediately. Do NOT power off — the encryption process may still hold the key in memory. " +
                                 "Image the disk and contact a security professional."
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
