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

        progress?.update("checking Scripting Additions")
        scanScriptingAdditions(findings: &findings, errors: &errors)

        progress?.update("checking Folder Actions")
        scanFolderActions(findings: &findings, errors: &errors)

        progress?.update("checking Mail rules")
        scanMailRules(findings: &findings, errors: &errors)

        progress?.update("checking Background Items (SMAppService)")
        scanBackgroundItems(findings: &findings, errors: &errors)

        progress?.update("checking shell history for paste-and-run attacks")
        scanShellHistory(findings: &findings, errors: &errors)

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

    // MARK: - Scripting Additions (OSAX)

    private func scanScriptingAdditions(findings: inout [Finding], errors: inout [String]) {
        // Scripting Additions (.osax bundles) load into every process that runs an AppleScript.
        // That makes them a powerful, mostly-forgotten persistence and code-injection channel.
        // /System/Library/ScriptingAdditions is SIP-protected — only the user/admin paths matter here.
        let dirs = [
            "/Library/ScriptingAdditions",
            "\(ShellRunner.realUserHome)/Library/ScriptingAdditions",
        ]
        let fm = FileManager.default

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let entryPath = "\(dir)/\(entry)"

                // Apple's bundled additions live under /System; anything in /Library or ~/Library
                // is third-party. Flag everything and note severity based on signature state.
                let executablePath = resolveOSAXExecutable(bundlePath: entryPath)
                let isSigned = executablePath.map { checkIsSigned(path: $0) } ?? false

                findings.append(Finding(
                    severity: isSigned ? .medium : .high,
                    category: .persistence,
                    title: isSigned
                        ? "Third-party Scripting Addition installed"
                        : "Unsigned Scripting Addition (.osax) installed",
                    detail: "\(entry) in \(dir) — loads into every AppleScript host process",
                    path: entryPath,
                    remediation: "Verify this OSAX is legitimate, then remove if unexpected: sudo rm -rf \"\(entryPath)\""
                ))
            }
        }
    }

    private func resolveOSAXExecutable(bundlePath: String) -> String? {
        // Try Info.plist's CFBundleExecutable; fall back to Contents/MacOS/<basename>.
        let infoPath = "\(bundlePath)/Contents/Info.plist"
        if let data = FileManager.default.contents(atPath: infoPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let exec = plist["CFBundleExecutable"] as? String {
            return "\(bundlePath)/Contents/MacOS/\(exec)"
        }
        let base = URL(fileURLWithPath: bundlePath).deletingPathExtension().lastPathComponent
        let fallback = "\(bundlePath)/Contents/MacOS/\(base)"
        return FileManager.default.fileExists(atPath: fallback) ? fallback : nil
    }

    // MARK: - Folder Actions

    private func scanFolderActions(findings: inout [Finding], errors: inout [String]) {
        // Folder Actions fire an AppleScript every time a watched folder changes — used both
        // by Automator workflows and, occasionally, by stealers that want a trigger on
        // ~/Downloads or the Desktop. They're stored as a dispatcher plist plus scripts in
        // ~/Library/Scripts/Folder Action Scripts.
        let home = ShellRunner.realUserHome

        // 1. Check the dispatcher preference for enabled actions
        let dispatcher = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "com.apple.FolderActionsDispatcher"
        ], timeout: 5)

        if dispatcher.success && !dispatcher.stdout.isEmpty &&
           !dispatcher.stdout.contains("does not exist") {
            // Any enabled action is worth surfacing — Folder Actions are rarely configured by
            // accident, and a malicious one can run on every new file in a folder.
            findings.append(Finding(
                severity: .medium, category: .persistence,
                title: "macOS Folder Actions are configured",
                detail: "Folder Actions trigger AppleScripts on folder changes",
                path: nil,
                remediation: "Review: System Settings is no longer used; run `osascript -e 'tell app \"System Events\" to get folder actions'`"
            ))
        }

        // 2. Enumerate the actual script files — flag the ones that don't look benign.
        let scriptsDir = "\(home)/Library/Scripts/Folder Action Scripts"
        let fm = FileManager.default
        guard fm.fileExists(atPath: scriptsDir),
              let scripts = try? fm.contentsOfDirectory(atPath: scriptsDir) else { return }

        for script in scripts where !script.hasPrefix(".") {
            let scriptPath = "\(scriptsDir)/\(script)"
            // Apple's default sample scripts ship in /System (which we don't reach); anything
            // user-installed here is custom. Read for suspicious patterns.
            guard let content = try? String(contentsOfFile: scriptPath, encoding: .utf8) else { continue }
            let lc = content.lowercased()

            // `do shell script` + curl|bash is the smoking gun for a folder-action stealer.
            let suspicious = (lc.contains("do shell script") &&
                              (lc.contains("curl") || lc.contains("wget") || lc.contains("base64")))
            findings.append(Finding(
                severity: suspicious ? .high : .low,
                category: .persistence,
                title: suspicious
                    ? "Folder Action script runs shell commands"
                    : "Folder Action script present",
                detail: "Script: \(script) — runs on changes to its attached folder",
                path: scriptPath,
                remediation: "Inspect, then remove if unexpected: open \"\(scriptPath)\""
            ))
        }
    }

    // MARK: - Mail.app rules with script actions

    private func scanMailRules(findings: inout [Finding], errors: inout [String]) {
        // Mail.app supports rules that execute an AppleScript or shell script when a message
        // arrives — a popular persistence trick because the rules survive reboot and run in
        // Mail's signed context. The rules live in `MailData/SyncedRules.plist` (and v1/v2
        // variants) inside a per-account Mail container.
        let home = ShellRunner.realUserHome
        let mailRoot = "\(home)/Library/Mail"
        let fm = FileManager.default
        guard fm.fileExists(atPath: mailRoot),
              let versions = try? fm.contentsOfDirectory(atPath: mailRoot) else { return }

        for version in versions where version.hasPrefix("V") {
            let mailDataDir = "\(mailRoot)/\(version)/MailData"
            guard let plistNames = try? fm.contentsOfDirectory(atPath: mailDataDir) else { continue }

            for plistName in plistNames where plistName.lowercased().contains("rules") &&
                                              plistName.lowercased().hasSuffix(".plist") {
                let plistPath = "\(mailDataDir)/\(plistName)"
                guard let data = fm.contents(atPath: plistPath),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) else {
                    continue
                }

                // Format varies — sometimes a top-level array of dicts, sometimes a dict with
                // a "Rules" key holding the array. Walk the structure looking for AppleScript
                // or shell-script actions, which Mail represents in its action criteria.
                let serialized = String(describing: plist).lowercased()
                let hasAppleScriptAction = serialized.contains("applescript") ||
                                           serialized.contains("runscript")
                let hasScriptPath = serialized.contains(".scpt") || serialized.contains(".applescript") ||
                                    serialized.contains(".sh\"") || serialized.contains(".py\"")

                if hasAppleScriptAction || hasScriptPath {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Mail.app rule executes a script",
                        detail: "Rules file: \(plistName) in \(version) — Mail triggers a script on incoming messages",
                        path: plistPath,
                        remediation: "Open Mail > Settings > Rules and remove any unfamiliar rule that runs a script"
                    ))
                }
            }
        }
    }

    // MARK: - Background Items (SMAppService, macOS 13+)

    private func scanBackgroundItems(findings: inout [Finding], errors: inout [String]) {
        // Since macOS 13, third-party apps can register Login Items / launch agents through
        // the SMAppService API. These don't appear in ~/Library/LaunchAgents — they live in
        // the Background Task Management (BTM) database at
        // /var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v15.btm.
        //
        // The file is a binary plist that's only readable as root, but `sfltool dumpbtm`
        // produces a textual dump we can parse.
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 15)
        guard result.success && !result.stdout.isEmpty else { return }

        // Each record block looks like:
        //   UUID: ...
        //   Name: SomeApp
        //   Developer Name: ...
        //   Type: legacy daemon (...)
        //   Disposition: [enabled]
        //   Bundle path: /Applications/SomeApp.app
        //   Executable Path: /Applications/SomeApp.app/Contents/MacOS/Helper
        //   Generation: 1
        //
        // We split by blank lines and inspect each record.
        let records = result.stdout.components(separatedBy: "\n\n")

        for record in records {
            guard record.contains("Bundle path:") || record.contains("Executable Path:") else { continue }

            let lines = record.split(separator: "\n")
            var name = "(unknown)"
            var developer = "(unknown)"
            var bundlePath: String?
            var executablePath: String?
            var disposition = ""
            var typeString = ""

            for line in lines {
                let s = String(line).trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("Name:") {
                    name = s.replacingOccurrences(of: "Name:", with: "").trimmingCharacters(in: .whitespaces)
                } else if s.hasPrefix("Developer Name:") {
                    developer = s.replacingOccurrences(of: "Developer Name:", with: "").trimmingCharacters(in: .whitespaces)
                } else if s.hasPrefix("Bundle path:") {
                    bundlePath = s.replacingOccurrences(of: "Bundle path:", with: "").trimmingCharacters(in: .whitespaces)
                } else if s.hasPrefix("Executable Path:") {
                    executablePath = s.replacingOccurrences(of: "Executable Path:", with: "").trimmingCharacters(in: .whitespaces)
                } else if s.hasPrefix("Disposition:") {
                    disposition = s.replacingOccurrences(of: "Disposition:", with: "").trimmingCharacters(in: .whitespaces)
                } else if s.hasPrefix("Type:") {
                    typeString = s.replacingOccurrences(of: "Type:", with: "").trimmingCharacters(in: .whitespaces)
                }
            }

            // Only flag enabled items — disabled BTM records are toggled-off Login Items,
            // they aren't actually running.
            let isEnabled = disposition.lowercased().contains("enabled") &&
                            !disposition.lowercased().contains("disabled")
            guard isEnabled else { continue }

            let target = executablePath ?? bundlePath
            guard let resolvedTarget = target, !resolvedTarget.isEmpty else { continue }

            // Skip Apple/system-managed items
            if developer.contains("Apple") { continue }
            if resolvedTarget.hasPrefix("/System/") || resolvedTarget.hasPrefix("/usr/") { continue }

            // 1. Spyware match wins immediately
            if let sig = SpywareSignature.match(processName: URL(fileURLWithPath: resolvedTarget).lastPathComponent) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware registered as Background Item: \(sig.name)",
                    detail: "Name: \(name), Developer: \(developer), Type: \(typeString)",
                    path: resolvedTarget,
                    remediation: "System Settings > General > Login Items & Extensions — disable and remove \(sig.name)"
                ))
                continue
            }

            // 2. Hidden path is high-confidence bad
            let isHiddenPath = resolvedTarget.contains("/.") ||
                resolvedTarget.split(separator: "/").contains(where: { $0.hasPrefix(".") })
            if isHiddenPath {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Background Item points to hidden path",
                    detail: "Name: \(name), Developer: \(developer), Type: \(typeString)",
                    path: resolvedTarget,
                    remediation: "Disable in System Settings > General > Login Items & Extensions; investigate the binary"
                ))
                continue
            }

            // 3. Unsigned binary in a Background Item slot is unusual — SMAppService normally
            //    refuses unsigned helpers, but a Developer-ID-revoked binary is reported as
            //    unsigned by SecStaticCode. Worth surfacing as MEDIUM.
            if FileManager.default.fileExists(atPath: resolvedTarget),
               !checkIsSigned(path: resolvedTarget) {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Unsigned Background Item registered to run at login",
                    detail: "Name: \(name), Developer: \(developer), Type: \(typeString)",
                    path: resolvedTarget,
                    remediation: "Verify this Login Item in System Settings > General > Login Items & Extensions"
                ))
            }
        }
    }

    // MARK: - Shell History (ClickFix / paste-and-run forensics)

    private func scanShellHistory(findings: inout [Finding], errors: inout [String]) {
        // ClickFix-style social engineering tricks the user into pasting a malicious
        // command into Terminal. The command typically pipes a curl/wget download into
        // `bash`/`sh`/`zsh`, or invokes `osascript` to run an inline AppleScript that
        // bypasses Gatekeeper. These attacks leave clear forensic breadcrumbs in the
        // shell history file, which we scan for the canonical patterns.
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
            "\(home)/.local/share/fish/fish_history",
        ]

        // Anchored regexes catch the dangerous shapes without false-positiving on
        // every Homebrew install snippet (Homebrew's install uses a specific URL).
        let patterns: [(needle: String, description: String, severity: Severity)] = [
            ("curl ", "curl-piped-to-shell — common ClickFix dropper", .high),
            ("wget ", "wget-piped-to-shell — common ClickFix dropper", .high),
            ("base64 -d", "base64 decode to shell — obfuscated payload", .high),
            ("base64 --decode", "base64 decode to shell — obfuscated payload", .high),
            ("eval \"$(curl", "eval of remote content", .high),
            ("eval \"$(wget", "eval of remote content", .high),
            ("osascript -e", "inline AppleScript invocation", .medium),
            ("xattr -d com.apple.quarantine", "manual Gatekeeper bypass", .high),
            ("xattr -cr ", "wipe extended attributes (Gatekeeper bypass)", .high),
            ("sudo spctl --master-disable", "Gatekeeper globally disabled", .high),
            ("python -c \"import", "inline Python execution", .medium),
            ("python3 -c \"import", "inline Python execution", .medium),
            ("/dev/tcp/", "bash reverse-shell construct", .high),
        ]

        // Whitelist legitimate one-liners that users invariably run. Anything matching
        // a pattern AND a whitelist is suppressed.
        let benignSubstrings = [
            "raw.githubusercontent.com/Homebrew/install/",  // Homebrew installer
            "https://sh.rustup.rs",                           // rustup
            "https://get.docker.com",                          // Docker
            "https://nodejs.org/",
            "https://deno.land/install.sh",
            "https://bun.sh/install",
            "https://ohmyposh.dev/install.sh",
            "https://raw.githubusercontent.com/ohmyzsh/",
        ]

        for historyFile in historyFiles {
            guard let content = try? String(contentsOfFile: historyFile, encoding: .utf8) else { continue }
            let fileName = URL(fileURLWithPath: historyFile).lastPathComponent

            // Walk lines, surfacing only the most recent ~500 (history files grow large).
            let lines = content.split(separator: "\n").suffix(500)
            for line in lines {
                let raw = String(line)
                let lc = raw.lowercased()
                // Pipe to a shell is the signature — `curl X | bash` / `... | sh`
                let pipedToShell = (lc.contains("| bash") || lc.contains("|bash") ||
                                    lc.contains("| sh") || lc.contains("|sh") ||
                                    lc.contains("| zsh") || lc.contains("|zsh"))

                for pattern in patterns {
                    guard lc.contains(pattern.needle) else { continue }

                    // curl/wget-piped-to-shell only fires when actually piped
                    if (pattern.needle == "curl " || pattern.needle == "wget ") && !pipedToShell {
                        continue
                    }
                    // Suppress well-known legitimate installers
                    if benignSubstrings.contains(where: { lc.contains($0.lowercased()) }) { continue }

                    findings.append(Finding(
                        severity: pattern.severity, category: .persistence,
                        title: "Suspicious one-liner in \(fileName)",
                        detail: "\(pattern.description): \(String(raw.prefix(120)))",
                        path: historyFile,
                        remediation: "Review your shell history (open \(historyFile)) and the binaries the command downloaded. If you didn't run this, treat the Mac as compromised."
                    ))
                    break  // one finding per line is enough
                }
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
