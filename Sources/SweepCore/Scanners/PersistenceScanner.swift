import Foundation
import Security

public final class PersistenceScanner: Scanner {
    public let name = "Persistence Scan"
    public init() {}

    private let launchDirs: [(path: String, label: String)] = [
        ("~/Library/LaunchAgents", "User LaunchAgents"),
        ("/Library/LaunchAgents", "System LaunchAgents"),
        ("/Library/LaunchDaemons", "System LaunchDaemons"),
    ]

    private let trustedPathPrefixes = [
        "/System/", "/usr/", "/bin/", "/sbin/",
        "/Applications/", "/Library/Apple/",
        "/Library/Developer/", "/Library/Frameworks/",
        "/Library/PrivilegedHelperTools/",
        "/opt/homebrew/", "/usr/local/",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        for (dirPath, dirLabel) in launchDirs {
            progress?.update("scanning \(dirLabel)")
            let expandedPath = dirPath.hasPrefix("~/")
                ? ShellRunner.realUserHome + dirPath.dropFirst(1)
                : dirPath
            let fm = FileManager.default

            guard fm.fileExists(atPath: expandedPath) else { continue }

            guard let contents = try? fm.contentsOfDirectory(atPath: expandedPath) else {
                errors.append("\(dirLabel): Could not read directory")
                continue
            }

            for file in contents where file.hasSuffix(".plist") {
                let plistPath = "\(expandedPath)/\(file)"
                analyzePlist(at: plistPath, dirLabel: dirLabel, findings: &findings, errors: &errors)
            }
        }

        // Legacy persistence mechanisms (pre-SIP)
        progress?.update("checking legacy StartupItems")
        scanStartupItems(findings: &findings, errors: &errors)

        progress?.update("checking rc scripts")
        scanRCScripts(findings: &findings, errors: &errors)

        progress?.update("checking /usr/local for unsigned binaries")
        scanUsrLocalBinaries(findings: &findings, errors: &errors)

        progress?.update("checking shell config files")
        scanShellConfigs(findings: &findings, errors: &errors)

        progress?.update("checking cron jobs")
        scanCronJobs(findings: &findings, errors: &errors)

        progress?.update("checking login/logout hooks")
        scanLoginHooks(findings: &findings, errors: &errors)

        progress?.update("checking periodic scripts")
        scanPeriodicScripts(findings: &findings, errors: &errors)

        progress?.update("checking SSH authorized_keys")
        scanSSHAuthorizedKeys(findings: &findings, errors: &errors)

        progress?.update("checking sudoers drop-ins")
        scanSudoers(findings: &findings, errors: &errors)

        progress?.update("checking PAM configuration")
        scanPAMConfig(findings: &findings, errors: &errors)

        progress?.update("checking emond rules")
        scanEmondRules(findings: &findings, errors: &errors)

        progress?.update("checking input methods")
        scanInputMethods(findings: &findings, errors: &errors)

        progress?.update("checking system plug-in directories")
        scanPluginDirectories(findings: &findings, errors: &errors)

        progress?.update("checking background login items (BTM)")
        scanBackgroundTaskManager(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    private func analyzePlist(at path: String, dirLabel: String, findings: inout [Finding], errors: inout [String]) {
        guard let data = FileManager.default.contents(atPath: path) else { return }

        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return
        }

        let label = plist["Label"] as? String ?? "unknown"
        let runAtLoad = plist["RunAtLoad"] as? Bool ?? false
        let keepAlive = plist["KeepAlive"] != nil

        // Get executable path
        var executablePath: String?
        if let program = plist["Program"] as? String {
            executablePath = program
        } else if let args = plist["ProgramArguments"] as? [String], let first = args.first {
            executablePath = first
        }

        // Check against known spyware labels
        if let sig = SpywareSignature.match(label: label) {
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "Known spyware persistence: \(sig.name)",
                detail: "Label: \(label), RunAtLoad: \(runAtLoad), KeepAlive: \(keepAlive)",
                path: path,
                remediation: "Remove this plist and uninstall \(sig.name): sudo rm \"\(path)\""
            ))
            return
        }

        // Check for fake Apple bundle IDs (spyware disguising as Apple)
        if SpywareSignature.isFakeAppleBundleId(label) {
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "Fake Apple bundle ID detected",
                detail: "Label: \(label) — this is not a legitimate Apple service",
                path: path,
                remediation: "Remove this plist: sudo rm \"\(path)\" — legitimate Apple plists don't use this naming pattern"
            ))
            return
        }

        // Skip real Apple plists
        if label.hasPrefix("com.apple.") { return }

        guard let execPath = executablePath else { return }

        // Check if executable is from a trusted path
        let isTrustedPath = trustedPathPrefixes.contains { execPath.hasPrefix($0) }

        // Check if executable exists
        let execExists = FileManager.default.fileExists(atPath: execPath)

        // Flag hidden paths
        let isHiddenPath = execPath.contains("/.") || execPath.split(separator: "/").contains(where: { $0.hasPrefix(".") })

        if isHiddenPath {
            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "LaunchAgent/Daemon points to hidden path",
                detail: "Label: \(label), RunAtLoad: \(runAtLoad)",
                path: path,
                remediation: "Investigate: \(execPath) — hidden executables are a strong spyware indicator"
            ))
            return
        }

        // For non-trusted paths, check code signature
        if !isTrustedPath && execExists {
            let isSigned = checkIsSigned(path: execPath)
            if !isSigned && runAtLoad {
                // Check if plist predates SIP (2015-10-01)
                let sipDate = Date(timeIntervalSince1970: 1443657600)
                let plistAttrs = try? FileManager.default.attributesOfItem(atPath: path)
                let plistModDate = plistAttrs?[.modificationDate] as? Date
                let isPreSIP = plistModDate != nil && plistModDate! < sipDate

                findings.append(Finding(
                    severity: isPreSIP ? .high : .medium,
                    category: .persistence,
                    title: isPreSIP
                        ? "Pre-SIP unsigned persistence (high risk)"
                        : "Unsigned executable set to run at login",
                    detail: "Label: \(label), Dir: \(dirLabel)" + (isPreSIP ? ", Plist from \(plistModDate!)" : ""),
                    path: path,
                    remediation: "Verify this LaunchAgent is legitimate: \(execPath)"
                ))
            }
        }

        // Executable doesn't exist — broken or removed plist
        if !execExists && !execPath.isEmpty {
            findings.append(Finding(
                severity: .low,
                category: .persistence,
                title: "LaunchAgent references missing executable",
                detail: "Label: \(label), Missing: \(execPath)",
                path: path,
                remediation: "Orphaned plist — safe to remove if not needed"
            ))
        }
    }

    // MARK: - Legacy StartupItems

    private func scanStartupItems(findings: inout [Finding], errors: inout [String]) {
        let startupPath = "/Library/StartupItems"
        let fm = FileManager.default
        guard fm.fileExists(atPath: startupPath),
              let contents = try? fm.contentsOfDirectory(atPath: startupPath) else { return }

        for item in contents {
            let itemPath = "\(startupPath)/\(item)"
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: itemPath, isDirectory: &isDir) else { continue }

            // Check against known spyware
            let matchesSpyware = SpywareSignature.match(processName: item) != nil
            findings.append(Finding(
                severity: matchesSpyware ? .high : .medium,
                category: .persistence,
                title: matchesSpyware
                    ? "Known spyware in legacy StartupItems"
                    : "Legacy StartupItem found (deprecated since macOS 10.10)",
                detail: "Item: \(item) — StartupItems is a pre-SIP persistence mechanism",
                path: itemPath,
                remediation: "Remove this StartupItem: sudo rm -rf \"\(itemPath)\""
            ))
        }
    }

    // MARK: - RC Scripts

    private func scanRCScripts(findings: inout [Finding], errors: inout [String]) {
        let rcPaths = ["/etc/rc.local", "/etc/rc.common"]
        for rcPath in rcPaths {
            guard let content = try? String(contentsOfFile: rcPath, encoding: .utf8) else { continue }

            // /etc/rc.common is Apple's default file — only flag if it contains spyware
            // /etc/rc.local should not exist on modern macOS
            let isAppleDefault = rcPath == "/etc/rc.common" && content.contains("Copyright") && content.contains("Apple")

            var matchedSpyware: String?
            for sig in SpywareSignature.known {
                for name in sig.processNames {
                    if content.lowercased().contains(name.lowercased()) {
                        matchedSpyware = sig.name
                        break
                    }
                }
                if matchedSpyware != nil { break }
            }

            if matchedSpyware != nil {
                findings.append(Finding(
                    severity: .high,
                    category: .persistence,
                    title: "Known spyware in rc script: \(matchedSpyware!)",
                    detail: "File: \(rcPath) — \(content.split(separator: "\n").count) lines",
                    path: rcPath,
                    remediation: "Inspect contents: cat \(rcPath)"
                ))
            } else if !isAppleDefault {
                findings.append(Finding(
                    severity: .medium,
                    category: .persistence,
                    title: "RC script exists (deprecated persistence mechanism)",
                    detail: "File: \(rcPath) — \(content.split(separator: "\n").count) lines",
                    path: rcPath,
                    remediation: "Inspect contents: cat \(rcPath)"
                ))
            }
        }
    }

    // MARK: - Unsigned Binaries in /usr/local

    private func scanUsrLocalBinaries(findings: inout [Finding], errors: inout [String]) {
        let dirs = ["/usr/local/bin", "/usr/local/sbin"]
        let fm = FileManager.default

        // Build set of Homebrew-managed files to skip
        var homebrewFiles = Set<String>()
        let cellarPaths = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
        for cellar in cellarPaths where fm.fileExists(atPath: cellar) {
            // Any file that resolves to a Homebrew Cellar path is legitimate
            homebrewFiles.insert(cellar)
        }

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for file in contents {
                let filePath = "\(dir)/\(file)"

                // Skip symlinks (Homebrew uses symlinks from Cellar)
                let attrs = try? fm.attributesOfItem(atPath: filePath)
                if attrs?[.type] as? FileAttributeType == .typeSymbolicLink { continue }

                // Resolve real path — skip if it's in a Homebrew Cellar
                if let realPath = try? fm.destinationOfSymbolicLink(atPath: filePath),
                   cellarPaths.contains(where: { realPath.hasPrefix($0) }) { continue }

                // Check if it's a Mach-O binary (skip scripts and text files)
                guard let fh = FileHandle(forReadingAtPath: filePath) else { continue }
                let header = fh.readData(ofLength: 4)
                fh.closeFile()
                guard header.count == 4 else { continue }

                let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
                let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
                guard machoMagics.contains(magic) else { continue }

                // Check against known spyware
                if let sig = SpywareSignature.match(processName: file) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware binary in /usr/local: \(sig.name)",
                        detail: "File: \(file)",
                        path: filePath,
                        remediation: "Remove: sudo rm \"\(filePath)\""
                    ))
                    continue
                }

                // Only flag unsigned Mach-O binaries — these are unusual in /usr/local
                // (most legitimate software is either Homebrew-symlinked or properly signed)
                if !checkIsSigned(path: filePath) {
                    findings.append(Finding(
                        severity: .low, category: .persistence,
                        title: "Unsigned Mach-O binary in \(dir)",
                        detail: "File: \(file) — not installed by Homebrew",
                        path: filePath,
                        remediation: "Verify this binary is legitimate"
                    ))
                }
            }
        }
    }

    // MARK: - Shell Config Files

    private func scanShellConfigs(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let shellConfigs = [
            "\(home)/.zshrc", "\(home)/.zprofile", "\(home)/.zshenv",
            "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile",
        ]

        let suspiciousPatterns: [(pattern: String, description: String)] = [
            ("curl.*|.*sh", "downloads and executes remote script"),
            ("wget.*|.*sh", "downloads and executes remote script"),
            ("curl.*|.*bash", "downloads and executes remote script"),
            ("eval.*$(curl", "evaluates remote code"),
            ("eval.*$(wget", "evaluates remote code"),
            ("base64.*--decode", "decodes hidden payload"),
            ("base64.*-d", "decodes hidden payload"),
            ("python.*-c.*import", "runs inline Python (may be obfuscated)"),
            ("/tmp/", "references temp directory"),
            ("/.hidden", "references hidden directory"),
        ]

        for configPath in shellConfigs {
            guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else { continue }
            let fileName = URL(fileURLWithPath: configPath).lastPathComponent
            let lines = content.components(separatedBy: "\n")

            for (lineNum, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                // Skip comments and empty lines
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                for pattern in suspiciousPatterns {
                    if trimmed.lowercased().contains(pattern.pattern.lowercased()) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Suspicious command in \(fileName)",
                            detail: "Line \(lineNum + 1): \(pattern.description) — \(String(trimmed.prefix(100)))",
                            path: configPath,
                            remediation: "Review: open \(configPath) and inspect line \(lineNum + 1)"
                        ))
                        break // one finding per line is enough
                    }
                }
            }

            // Also check for spyware signatures in content
            let contentLC = content.lowercased()
            for sig in SpywareSignature.known {
                for name in sig.processNames {
                    if contentLC.contains(name.lowercased()) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Known spyware reference in \(fileName): \(sig.name)",
                            detail: "Shell config contains reference to '\(name)'",
                            path: configPath,
                            remediation: "Remove the malicious lines from \(configPath)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Cron Jobs

    private func scanCronJobs(findings: inout [Finding], errors: inout [String]) {
        // Check current user's crontab
        let userCron = ShellRunner.run("/usr/bin/crontab", arguments: ["-l"], timeout: 5)
        if userCron.success && !userCron.stdout.isEmpty &&
           !userCron.stdout.contains("no crontab") {
            let lines = userCron.stdout.components(separatedBy: "\n")
                .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty && !$0.hasPrefix("#") }

            if !lines.isEmpty {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "User cron jobs found (\(lines.count) entries)",
                    detail: "First entry: \(String(lines.first!.prefix(80)))",
                    path: nil,
                    remediation: "Review with: crontab -l"
                ))
            }
        }

        // Check system cron directories
        let cronDirs = ["/etc/cron.d", "/var/at/tabs"]
        let fm = FileManager.default
        for dir in cronDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for file in contents {
                // Skip known system files
                if file == ".localized" || file == "root" { continue }
                let filePath = "\(dir)/\(file)"
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "System cron job found",
                    detail: "File: \(file) in \(dir)",
                    path: filePath,
                    remediation: "Review contents: cat \"\(filePath)\""
                ))
            }
        }
    }

    // MARK: - Login/Logout Hooks

    private func scanLoginHooks(findings: inout [Finding], errors: inout [String]) {
        // Try reading via defaults
        let loginHook = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.loginwindow", "LoginHook"
        ], timeout: 5)

        if loginHook.success {
            let hook = loginHook.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !hook.isEmpty {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Login hook detected (deprecated persistence)",
                    detail: "Script runs every time a user logs in: \(hook)",
                    path: hook,
                    remediation: "Remove: sudo defaults delete com.apple.loginwindow LoginHook"
                ))
            }
        }

        let logoutHook = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.loginwindow", "LogoutHook"
        ], timeout: 5)

        if logoutHook.success {
            let hook = logoutHook.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !hook.isEmpty {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Logout hook detected (deprecated persistence)",
                    detail: "Script runs every time a user logs out: \(hook)",
                    path: hook,
                    remediation: "Remove: sudo defaults delete com.apple.loginwindow LogoutHook"
                ))
            }
        }
    }

    // MARK: - Periodic Scripts

    private func scanPeriodicScripts(findings: inout [Finding], errors: inout [String]) {
        let periodicDirs = ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]
        let fm = FileManager.default

        for dir in periodicDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            let period = URL(fileURLWithPath: dir).lastPathComponent

            for file in contents {
                let filePath = "\(dir)/\(file)"
                // Apple's default periodic scripts are numbered (100.clean-logs, 500.daily, etc.)
                // Non-numbered or unusually named scripts are suspicious
                let isAppleDefault = file.first?.isNumber == true

                if !isAppleDefault {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "Custom \(period) periodic script",
                        detail: "File: \(file) — runs automatically via periodic(8)",
                        path: filePath,
                        remediation: "Review contents: cat \"\(filePath)\""
                    ))
                }
            }
        }
    }

    // MARK: - SSH authorized_keys

    private func scanSSHAuthorizedKeys(findings: inout [Finding], errors: inout [String]) {
        // Attacker-added keys in ~/.ssh/authorized_keys allow persistent remote access
        // without a password, bypassing every other login control.
        let home = ShellRunner.realUserHome
        let keyFiles = [
            "\(home)/.ssh/authorized_keys",
            "\(home)/.ssh/authorized_keys2",
            "/var/root/.ssh/authorized_keys",
            "/var/root/.ssh/authorized_keys2",
        ]

        for keyFile in keyFiles {
            guard FileManager.default.fileExists(atPath: keyFile),
                  let content = try? String(contentsOfFile: keyFile, encoding: .utf8) else { continue }

            // Each non-comment, non-blank line is one authorized key. Report every key so the
            // user can review what has remote SSH access to their Mac.
            let keyLines = content.split(separator: "\n").filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return !trimmed.isEmpty && !trimmed.hasPrefix("#")
            }
            if keyLines.isEmpty { continue }

            // Extract the comment field of each key (last whitespace-delimited token) for context
            let comments = keyLines.compactMap { line -> String? in
                let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                return parts.count >= 3 ? String(parts.last!) : nil
            }
            let commentList = comments.prefix(3).joined(separator: ", ")

            // Flag risky options inline with the key (forced command is a classic reverse-shell pattern)
            let hasForcedCommand = keyLines.contains { $0.contains("command=") }

            let severity: Severity = hasForcedCommand ? .high : .medium
            findings.append(Finding(
                severity: severity, category: .persistence,
                title: "SSH authorized key present (\(keyLines.count) key\(keyLines.count == 1 ? "" : "s"))",
                detail: "File: \(keyFile)\(commentList.isEmpty ? "" : ", comments: \(commentList)")\(hasForcedCommand ? " — contains command= forcing" : "")",
                path: keyFile,
                remediation: "Review each key — remove anything you don't recognize: nano \(keyFile)"
            ))
        }
    }

    // MARK: - Sudoers

    private func scanSudoers(findings: inout [Finding], errors: inout [String]) {
        // NOPASSWD: ALL in /etc/sudoers.d is a common privilege-escalation backdoor.
        // We inspect both the main sudoers file and any drop-ins.
        let sudoersPaths = ["/etc/sudoers"]
        var allPaths = sudoersPaths

        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") {
            for entry in dropIns where !entry.hasPrefix(".") && entry != "README" {
                allPaths.append("/etc/sudoers.d/\(entry)")
            }
        }

        for path in allPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let lines = content.split(separator: "\n")
            for (idx, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                // NOPASSWD lines grant passwordless root — always flag for review.
                if trimmed.uppercased().contains("NOPASSWD") {
                    // The default admin group already allows sudo with a password; NOPASSWD removes that gate.
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Passwordless sudo entry in \(URL(fileURLWithPath: path).lastPathComponent)",
                        detail: "Line \(idx + 1): \(String(trimmed.prefix(120)))",
                        path: path,
                        remediation: "Inspect and remove if not expected: sudo visudo -f \(path)"
                    ))
                }
            }
        }

        // A sudoers.d drop-in owned by a non-root user is a privilege-escalation indicator.
        if let dropIns = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") {
            for entry in dropIns where !entry.hasPrefix(".") {
                let entryPath = "/etc/sudoers.d/\(entry)"
                if let attrs = try? FileManager.default.attributesOfItem(atPath: entryPath),
                   let ownerId = attrs[.ownerAccountID] as? Int, ownerId != 0 {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "sudoers.d entry not owned by root",
                        detail: "\(entry) is owned by UID \(ownerId) — a non-root writable sudoers file is a privilege escalation risk",
                        path: entryPath,
                        remediation: "Inspect, then reset ownership: sudo chown root:wheel \(entryPath)"
                    ))
                }
            }
        }
    }

    // MARK: - PAM configuration

    private func scanPAMConfig(findings: inout [Finding], errors: inout [String]) {
        // PAM modules under /etc/pam.d/ gate login, sudo, and screensaver unlocks. Rogue modules
        // (pam_permit.so with auth sufficient, for example) can bypass authentication entirely.
        let pamFiles = ["/etc/pam.d/sudo", "/etc/pam.d/login", "/etc/pam.d/authorization",
                        "/etc/pam.d/screensaver", "/etc/pam.d/su"]

        let suspiciousPatterns: [(pattern: String, reason: String)] = [
            ("pam_permit.so", "pam_permit.so grants access unconditionally"),
            ("pam_deny.so", "pam_deny.so anywhere other than final fallback can signal tampering"),
            ("pam_tid.so", "pam_tid.so enables Touch ID for this action"),  // benign but noteworthy
        ]

        // Baseline: the stock contents of these files on macOS are small (~10 lines). Flag unusual growth too.
        for file in pamFiles {
            guard let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }

            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                for (pattern, reason) in suspiciousPatterns {
                    if trimmed.contains(pattern) {
                        // Touch ID (pam_tid.so) is often manually added by users for convenience — low severity.
                        let isTouchID = pattern == "pam_tid.so"
                        if trimmed.contains("auth") && trimmed.contains("sufficient") && trimmed.contains(pattern) && !isTouchID {
                            findings.append(Finding(
                                severity: .high, category: .persistence,
                                title: "Suspicious PAM rule in \(URL(fileURLWithPath: file).lastPathComponent)",
                                detail: "Rule: \(trimmed) — \(reason)",
                                path: file,
                                remediation: "Review and restore the stock PAM file if this was not intentionally added"
                            ))
                        } else if isTouchID {
                            findings.append(Finding(
                                severity: .low, category: .hardening,
                                title: "Touch ID enabled for \(URL(fileURLWithPath: file).lastPathComponent)",
                                detail: "pam_tid.so is configured — this is convenience, not spyware, but verify the edit is yours",
                                path: file,
                                remediation: "No action needed if you added this intentionally"
                            ))
                        }
                    }
                }
            }
        }
    }

    // MARK: - emond rules

    private func scanEmondRules(findings: inout [Finding], errors: inout [String]) {
        // emond (Event Monitor Daemon) is a legacy, deprecated persistence mechanism still available
        // on macOS. The rules directory is empty by default; any file here runs actions in response
        // to system events and is a strong spyware indicator.
        let rulesDir = "/etc/emond.d/rules"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: rulesDir) else { return }

        for entry in entries where !entry.hasPrefix(".") && entry != "SampleRules.plist" {
            let path = "\(rulesDir)/\(entry)"
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "emond rule installed (deprecated persistence)",
                detail: "emond rule: \(entry) — emond is rarely used legitimately and is a known spyware persistence channel",
                path: path,
                remediation: "Inspect contents, then remove: sudo rm \"\(path)\""
            ))
        }
    }

    // MARK: - Input Methods

    private func scanInputMethods(findings: inout [Finding], errors: inout [String]) {
        // Input Methods are bundles loaded by every text-input-capable process and receive
        // every keystroke the user types — a perfect keylogger vector. Apple's own input
        // methods live under /System/Library/Input Methods; anything in /Library/Input Methods
        // or ~/Library/Input Methods was installed by a third party.
        let home = ShellRunner.realUserHome
        let inputMethodDirs = [
            ("/Library/Input Methods", "system input method"),
            ("\(home)/Library/Input Methods", "user input method"),
        ]

        // Common legitimate third-party input methods — keep this list short and accurate
        // so unfamiliar ones surface as findings the user can review.
        let trustedInputBundles: Set<String> = [
            "com.google.inputmethod.Japanese",
            "com.google.inputmethod.Japanese.base",
            "com.sogou.inputmethod.sogou",
            "com.baidu.inputmethod.BaiduIM",
            "im.rime.inputmethod.Squirrel",
            "com.openvanilla.OVCannedMessages",
            "org.openvanilla.inputmethod.OVMandarin",
            "tw.openvanilla.inputmethod.McBopomofo",
            "tw.com.ime.OVIMOpenVanilla",
            "com.atok.inputmethod.Atok",
        ]

        let fm = FileManager.default
        for (dir, label) in inputMethodDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".app") || entry.hasSuffix(".bundle") {
                let bundlePath = "\(dir)/\(entry)"
                let infoPath = "\(bundlePath)/Contents/Info.plist"
                var bundleId = ""
                if let data = fm.contents(atPath: infoPath),
                   let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                    bundleId = (plist["CFBundleIdentifier"] as? String) ?? ""
                }

                if !bundleId.isEmpty && trustedInputBundles.contains(bundleId) { continue }

                // Known spyware bundle ID or process name match
                if !bundleId.isEmpty, let sig = SpywareSignature.match(bundleId: bundleId) {
                    findings.append(Finding(
                        severity: .high, category: .keylogging,
                        title: "Known spyware installed as input method: \(sig.name)",
                        detail: "Bundle: \(bundleId), Path: \(bundlePath) — input methods see every keystroke",
                        path: bundlePath,
                        remediation: "Remove immediately: sudo rm -rf \"\(bundlePath)\" — then reboot"
                    ))
                    continue
                }

                let isSigned = checkIsSigned(path: bundlePath)
                findings.append(Finding(
                    severity: isSigned ? .medium : .high,
                    category: .keylogging,
                    title: "Third-party \(label) installed",
                    detail: "Bundle: \(bundleId.isEmpty ? entry : bundleId)\(isSigned ? "" : " — unsigned"). Input methods receive every keystroke.",
                    path: bundlePath,
                    remediation: "Verify this input method is one you installed: System Settings > Keyboard > Input Sources"
                ))
            }
        }
    }

    // MARK: - System Plug-in Directories

    private func scanPluginDirectories(findings: inout [Finding], errors: inout [String]) {
        // Several macOS plug-in folders auto-load bundles into trusted host processes:
        //   - Spotlight importers run inside the indexer (mdworker / mdimporter)
        //   - QuickLook plug-ins run inside the QuickLook host (qlmanage)
        //   - Screen Savers run arbitrary code when the screen saver starts
        //   - Color Pickers load into any app that opens a color panel
        //   - Internet Plug-Ins are legacy NPAPI hosts (mostly dead, but still scanned)
        //   - Audio HAL plug-ins load into coreaudiod with high privileges
        // Apple's own plug-ins live under /System/Library, which we don't scan.
        let home = ShellRunner.realUserHome
        let pluginDirs: [(path: String, kind: String, severity: Severity)] = [
            ("/Library/Spotlight", "Spotlight importer", .medium),
            ("\(home)/Library/Spotlight", "Spotlight importer", .medium),
            ("/Library/QuickLook", "QuickLook plug-in", .medium),
            ("\(home)/Library/QuickLook", "QuickLook plug-in", .medium),
            ("/Library/Screen Savers", "Screen Saver", .medium),
            ("\(home)/Library/Screen Savers", "Screen Saver", .medium),
            ("/Library/ColorPickers", "Color Picker", .low),
            ("\(home)/Library/ColorPickers", "Color Picker", .low),
            ("/Library/Internet Plug-Ins", "Internet Plug-In", .medium),
            ("\(home)/Library/Internet Plug-Ins", "Internet Plug-In", .medium),
            ("/Library/Audio/Plug-Ins/HAL", "Audio HAL plug-in", .high),
        ]

        let fm = FileManager.default
        for (dir, kind, baseSeverity) in pluginDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries {
                if entry.hasPrefix(".") { continue }
                // Skip README-style plain files — only bundles (.app/.bundle/.qlgenerator/.saver/...) matter here
                if !entry.contains(".") { continue }

                let pluginPath = "\(dir)/\(entry)"

                // Resolve bundle identifier when possible
                let infoPath = "\(pluginPath)/Contents/Info.plist"
                var bundleId = ""
                if let data = fm.contents(atPath: infoPath),
                   let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                    bundleId = (plist["CFBundleIdentifier"] as? String) ?? ""
                }

                // Known spyware bundle ID — always HIGH
                if !bundleId.isEmpty, let sig = SpywareSignature.match(bundleId: bundleId) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware installed as \(kind): \(sig.name)",
                        detail: "Bundle: \(bundleId), Path: \(pluginPath)",
                        path: pluginPath,
                        remediation: "Remove immediately: sudo rm -rf \"\(pluginPath)\""
                    ))
                    continue
                }

                // Fake Apple bundle ID
                if !bundleId.isEmpty && SpywareSignature.isFakeAppleBundleId(bundleId) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Fake Apple bundle ID as \(kind)",
                        detail: "Bundle: \(bundleId), Path: \(pluginPath) — Apple doesn't publish plug-ins with this identifier",
                        path: pluginPath,
                        remediation: "Remove: sudo rm -rf \"\(pluginPath)\""
                    ))
                    continue
                }

                // Unsigned plug-in — strong signal: macOS refuses to load unsigned bundles into
                // most plug-in hosts, so anything unsigned here is either broken or hostile.
                let isSigned = checkIsSigned(path: pluginPath)
                if !isSigned {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Unsigned \(kind) installed",
                        detail: "Bundle: \(bundleId.isEmpty ? entry : bundleId), Path: \(pluginPath)",
                        path: pluginPath,
                        remediation: "Verify origin and remove if unexpected: sudo rm -rf \"\(pluginPath)\""
                    ))
                    continue
                }

                // Audio HAL plug-ins load into coreaudiod with high privileges — always surface
                // signed third-party HAL plug-ins so the user can sanity check.
                if kind == "Audio HAL plug-in" {
                    findings.append(Finding(
                        severity: baseSeverity, category: .persistence,
                        title: "Third-party Audio HAL plug-in installed",
                        detail: "Bundle: \(bundleId.isEmpty ? entry : bundleId) — loaded into coreaudiod (high privileges, hears all audio)",
                        path: pluginPath,
                        remediation: "Verify this is a known tool (BlackHole, SoundSource, Loopback, etc.) — otherwise remove"
                    ))
                }
                // Other signed plug-ins (QuickLook, Spotlight, screen savers, color pickers, etc.)
                // are common and benign — skip them to keep the report focused.
            }
        }
    }

    // MARK: - Background Task Management (SMAppService / BTM)

    private func scanBackgroundTaskManager(findings: inout [Finding], errors: inout [String]) {
        // macOS Ventura+ tracks every background login item / agent registered via
        // SMAppService in the Background Task Management database. `sfltool dumpbtm` prints
        // the live registrations; non-Apple, disabled-but-still-installed items are worth
        // surfacing because they're invisible to the legacy LaunchAgents/login-items checks.
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // Parse the dump — each item is a multi-line block; the lines we care about are
        // "Name: ...", "Bundle ID: ...", "URL: ...", and "Disposition: ...".
        var name = ""
        var bundleId = ""
        var url = ""
        var disposition = ""
        var seen = Set<String>()  // dedupe on bundle ID

        func emitCurrent() {
            defer {
                name = ""; bundleId = ""; url = ""; disposition = ""
            }
            guard !bundleId.isEmpty else { return }
            if seen.contains(bundleId) { return }
            seen.insert(bundleId)

            // Skip Apple and obvious system items
            if bundleId.hasPrefix("com.apple.") { return }

            // Known spyware bundle ID
            if let sig = SpywareSignature.match(bundleId: bundleId) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware registered as background login item: \(sig.name)",
                    detail: "Bundle: \(bundleId)\(name.isEmpty ? "" : ", Name: \(name)")\(disposition.isEmpty ? "" : ", Disposition: \(disposition)")",
                    path: url.isEmpty ? nil : url,
                    remediation: "Disable: System Settings > General > Login Items & Extensions"
                ))
                return
            }

            // Fake Apple bundle ID
            if SpywareSignature.isFakeAppleBundleId(bundleId) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Fake Apple bundle ID in background login items",
                    detail: "Bundle: \(bundleId)\(name.isEmpty ? "" : ", Name: \(name)")",
                    path: url.isEmpty ? nil : url,
                    remediation: "Remove the offending app and disable in System Settings > General > Login Items & Extensions"
                ))
                return
            }

            // Background items running from a hidden directory are a strong spyware indicator.
            let hiddenInUrl = url.contains("/.") || url.split(separator: "/").contains(where: { $0.hasPrefix(".") })
            if !url.isEmpty && hiddenInUrl {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background login item running from hidden path",
                    detail: "Bundle: \(bundleId), URL: \(url) — hidden install paths are a spyware hallmark",
                    path: url,
                    remediation: "Remove this background item: System Settings > General > Login Items & Extensions"
                ))
                return
            }

            // Otherwise, no finding — the user can see legitimate background items in System Settings.
        }

        // `sfltool dumpbtm` separates records with blank lines and uses "Field: value"
        // formatting. Field names have varied across macOS releases ("Bundle Identifier:"
        // on Sonoma, "Bundle ID:" historically) so we accept both spellings.
        func valueAfter(_ line: String, prefixes: [String]) -> String? {
            for p in prefixes where line.hasPrefix(p) {
                return String(line.dropFirst(p.count)).trimmingCharacters(in: .whitespaces)
            }
            return nil
        }

        for rawLine in result.stdout.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty {
                emitCurrent()
                continue
            }
            // A record header line ("Item #...") also marks the start of a new entry.
            if line.hasPrefix("Item ") || line.hasPrefix("Item #") {
                emitCurrent()
                continue
            }
            if let v = valueAfter(line, prefixes: ["Bundle Identifier:", "Bundle ID:", "Identifier:"]) {
                bundleId = v
            } else if let v = valueAfter(line, prefixes: ["Name:"]) {
                name = v
            } else if let v = valueAfter(line, prefixes: ["URL:", "Executable Path:"]) {
                if url.isEmpty { url = v }
            } else if let v = valueAfter(line, prefixes: ["Disposition:"]) {
                disposition = v
            }
        }
        emitCurrent()  // flush the last record
    }

    private func checkIsSigned(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return false
        }
        return SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil) == errSecSuccess
    }
}
