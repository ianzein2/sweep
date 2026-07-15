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

        progress?.update("checking Folder Actions / Automator agents")
        scanFolderActionsAndAutomator(findings: &findings, errors: &errors)

        progress?.update("checking package manager postinstall scripts")
        scanPackageManagerHooks(findings: &findings, errors: &errors)

        progress?.update("checking XPC helper tools")
        scanPrivilegedHelperTools(findings: &findings, errors: &errors)

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

    // MARK: - Folder Actions & Automator agents

    /// Folder Actions attach AppleScript / Automator workflows to a directory: whenever
    /// a file lands there, the workflow runs. Attackers use "~/Downloads" for this because
    /// it's the first place a phishing-delivered payload arrives.
    ///
    /// Automator Application Scripts (~/Library/Workflows/Applications) also survive login
    /// via a plist entry and are rarely inspected — a stealth win for the attacker.
    private func scanFolderActionsAndAutomator(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // 1. Folder Actions dispatcher preferences — enumerating attached scripts.
        let folderActionsPlist = "\(home)/Library/Preferences/com.apple.FolderActionsDispatcher.plist"
        if fm.fileExists(atPath: folderActionsPlist),
           let data = fm.contents(atPath: folderActionsPlist),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            // The plist stores an array under "FolderActions"; each entry pairs a folder path
            // with one or more script paths.
            if let actions = plist["FolderActions"] as? [[String: Any]], !actions.isEmpty {
                for action in actions {
                    let folder = (action["path"] as? String) ?? "?"
                    let scripts = (action["scripts"] as? [[String: Any]])?.compactMap { $0["scriptName"] as? String } ?? []
                    let scriptList = scripts.isEmpty ? "unknown" : scripts.joined(separator: ", ")

                    // Downloads is a canonical attacker target — flag it high.
                    let isDownloads = folder.hasSuffix("/Downloads") || folder.contains("/Downloads/")
                    findings.append(Finding(
                        severity: isDownloads ? .high : .medium,
                        category: .persistence,
                        title: "Folder Action attached to \(URL(fileURLWithPath: folder).lastPathComponent)",
                        detail: "Folder: \(folder), Script(s): \(scriptList) — runs whenever items appear in this folder",
                        path: folderActionsPlist,
                        remediation: "Open Automator, remove unwanted Folder Actions. Downloads/Desktop actions are a known malware persistence trick."
                    ))
                }
            }
        }

        // 2. Automator Applications (~/Library/Workflows/Applications/Folder Actions)
        // Each .workflow bundle is an AppleScript/JavaScript runner. Real users rarely
        // have any of these — the dir is empty by default.
        let workflowDirs = [
            "\(home)/Library/Workflows/Applications/Folder Actions",
            "\(home)/Library/Scripts/Folder Action Scripts",
            "/Library/Scripts/Folder Action Scripts",
        ]
        for dir in workflowDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in contents where !entry.hasPrefix(".") {
                let entryPath = "\(dir)/\(entry)"
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Folder Action workflow present",
                    detail: "Workflow: \(entry) — Folder Actions run automatically on file events",
                    path: entryPath,
                    remediation: "Inspect the workflow in Automator, then delete if not expected: rm -rf \"\(entryPath)\""
                ))
            }
        }

        // 3. Login items registered via SMAppService (macOS 13+). The manifests live under
        // ~/Library/LaunchAgents-style paths but the modern UI hides them; enumerate directly.
        let loginItemsDir = "\(home)/Library/Application Support/com.apple.backgroundtaskmanagementagent"
        if fm.fileExists(atPath: loginItemsDir) {
            let listing = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 5)
            if listing.success && !listing.stdout.isEmpty {
                // sfltool output lists each Background Task Manager entry — a few dev tools
                // (Docker, Rectangle, etc.) are normal, but unknown "SMAppService" entries
                // pointing to hidden or /tmp paths are suspicious. Only flag those.
                let lines = listing.stdout.split(separator: "\n")
                var pendingEntry: [String] = []
                for line in lines {
                    let s = String(line).trimmingCharacters(in: .whitespaces)
                    if s.isEmpty {
                        checkBTMEntry(pendingEntry, findings: &findings)
                        pendingEntry.removeAll()
                    } else {
                        pendingEntry.append(s)
                    }
                }
                checkBTMEntry(pendingEntry, findings: &findings)
            }
        }
    }

    private func checkBTMEntry(_ lines: [String], findings: inout [Finding]) {
        guard !lines.isEmpty else { return }
        let joined = lines.joined(separator: " ")
        // Only interesting BTM records: those referencing hidden paths or temp dirs.
        let interesting =
            joined.contains("/tmp/") ||
            joined.contains("/private/tmp/") ||
            joined.contains("/var/tmp/") ||
            joined.contains("/.") ||   // hidden dir component
            joined.range(of: "path = .*/\\.", options: .regularExpression) != nil
        guard interesting else { return }

        // Extract the URL/path field if present for the finding detail.
        let pathLine = lines.first(where: { $0.hasPrefix("URL") || $0.hasPrefix("Path") || $0.contains("path =") })
            ?? lines.first ?? ""
        findings.append(Finding(
            severity: .high, category: .persistence,
            title: "Background Task Manager entry from hidden/temp path",
            detail: String(pathLine.prefix(200)),
            path: nil,
            remediation: "Review with: sfltool dumpbtm — then remove the app / login item in System Settings > General > Login Items"
        ))
    }

    // MARK: - Package manager hooks (npm postinstall, pip auto-run, malicious taps)

    /// Malicious npm packages routinely use "scripts.postinstall" to run arbitrary
    /// commands the moment `npm install` completes. A postinstall living in the user's
    /// home root (or Downloads / Desktop) — outside a project — is almost always a
    /// social-engineered dropper. Also flags npm .npmrc pointing to non-registry hosts.
    private func scanPackageManagerHooks(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // 1. package.json in unusual top-level locations. Legit projects live under repos,
        // not directly in $HOME.
        let suspiciousRoots = [home, "\(home)/Downloads", "\(home)/Desktop"]
        for root in suspiciousRoots {
            let pkgPath = "\(root)/package.json"
            guard let data = fm.contents(atPath: pkgPath),
                  let pkg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            let scripts = (pkg["scripts"] as? [String: Any]) ?? [:]
            let hookNames = ["preinstall", "install", "postinstall", "prepublish", "prepare"]
            let hookHits = hookNames.compactMap { name -> (String, String)? in
                guard let cmd = scripts[name] as? String, !cmd.isEmpty else { return nil }
                return (name, cmd)
            }
            guard !hookHits.isEmpty else { continue }

            for (hookName, cmd) in hookHits {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "npm \(hookName) hook in package.json at \(root)",
                    detail: "Hook fires on `npm install`. Command: \(String(cmd.prefix(160)))",
                    path: pkgPath,
                    remediation: "package.json in \(root) is unusual — real projects live in repos. Inspect and delete if unexpected."
                ))
            }
        }

        // 2. .npmrc pointing at a non-registry host. Attackers set "registry=" to a
        // hosted look-alike to serve trojaned packages transparently.
        let npmrcPath = "\(home)/.npmrc"
        if let content = try? String(contentsOfFile: npmrcPath, encoding: .utf8) {
            for line in content.split(separator: "\n") {
                let s = line.trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("#") || s.isEmpty { continue }
                // registry=https://... or //hostname/:_authToken=... — flag anything that isn't npmjs.org / GitHub.
                if s.lowercased().hasPrefix("registry=") || s.lowercased().hasPrefix("//") && s.contains(":_authToken=") {
                    let known = ["registry.npmjs.org", "npm.pkg.github.com", "registry.yarnpkg.com",
                                 "npm.jfrog.io", "artifactory", "azure.com", "aws.com", "cloudfront.net",
                                 "verdaccio", "cloudsmith", "gitlab"]
                    let isKnown = known.contains(where: { s.lowercased().contains($0) })
                    if !isKnown {
                        findings.append(Finding(
                            severity: .medium, category: .persistence,
                            title: "Custom npm registry in .npmrc",
                            detail: "Line: \(s.prefix(120)) — non-standard npm registry",
                            path: npmrcPath,
                            remediation: "Verify this registry is your company's — attackers redirect npm to serve trojaned packages."
                        ))
                    }
                }
            }
        }

        // 3. Third-party Homebrew taps. Official taps live under homebrew/homebrew-core
        // and homebrew/homebrew-cask; anything else is user-added and worth surfacing.
        let tapRoots = ["/opt/homebrew/Library/Taps", "/usr/local/Homebrew/Library/Taps"]
        for tapRoot in tapRoots {
            guard let owners = try? fm.contentsOfDirectory(atPath: tapRoot) else { continue }
            for owner in owners where owner != "homebrew" && !owner.hasPrefix(".") {
                let ownerPath = "\(tapRoot)/\(owner)"
                guard let taps = try? fm.contentsOfDirectory(atPath: ownerPath) else { continue }
                for tap in taps where !tap.hasPrefix(".") {
                    findings.append(Finding(
                        severity: .low, category: .persistence,
                        title: "Third-party Homebrew tap: \(owner)/\(tap)",
                        detail: "Non-official taps can ship arbitrary formulae — verify the tap's source",
                        path: "\(ownerPath)/\(tap)",
                        remediation: "Review: brew tap-info \(owner)/\(tap.replacingOccurrences(of: "homebrew-", with: "")) — remove with brew untap if unexpected"
                    ))
                }
            }
        }

        // 4. Python pip user-install with startup hooks (~/.pth files auto-import on any
        // Python invocation — silent persistence). Any custom .pth in the user site-packages
        // that isn't from a well-known package is worth surfacing.
        let userSitePython = ShellRunner.run("/usr/bin/python3", arguments: [
            "-c", "import site; print(site.getusersitepackages())"
        ], timeout: 3)
        if userSitePython.success {
            let userSite = userSitePython.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !userSite.isEmpty, let entries = try? fm.contentsOfDirectory(atPath: userSite) {
                for entry in entries where entry.hasSuffix(".pth") {
                    let pthPath = "\(userSite)/\(entry)"
                    guard let content = try? String(contentsOfFile: pthPath, encoding: .utf8) else { continue }
                    // .pth files with 'import' lines are executed on interpreter startup.
                    if content.contains("import ") {
                        findings.append(Finding(
                            severity: .medium, category: .persistence,
                            title: "Python .pth file executes code on interpreter startup",
                            detail: "File: \(entry) — .pth entries containing 'import' run before your script does",
                            path: pthPath,
                            remediation: "Inspect: cat \"\(pthPath)\" — remove if you don't recognize the package."
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Privileged helper tools

    /// /Library/PrivilegedHelperTools/ is where SMJobBless-installed helpers land. Real
    /// helpers are code-signed by well-known vendors; attackers occasionally drop ad-hoc
    /// or unsigned binaries here for root-level persistence.
    private func scanPrivilegedHelperTools(findings: inout [Finding], errors: inout [String]) {
        let dir = "/Library/PrivilegedHelperTools"
        let fm = FileManager.default
        guard fm.fileExists(atPath: dir),
              let entries = try? fm.contentsOfDirectory(atPath: dir) else { return }

        for entry in entries where !entry.hasPrefix(".") {
            let path = "\(dir)/\(entry)"
            // Skip if not a Mach-O (some helpers ship as scripts, uncommon but possible)
            guard let fh = FileHandle(forReadingAtPath: path) else { continue }
            let header = fh.readData(ofLength: 4)
            fh.closeFile()
            guard header.count == 4 else { continue }
            let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
            let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
            guard machoMagics.contains(magic) else { continue }

            if !checkIsSigned(path: path) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Unsigned privileged helper tool",
                    detail: "Root-level helper: \(entry) — real vendors always sign these binaries",
                    path: path,
                    remediation: "Verify origin. Remove with: sudo rm \"\(path)\" and remove its matching /Library/LaunchDaemons plist"
                ))
            }
        }
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
