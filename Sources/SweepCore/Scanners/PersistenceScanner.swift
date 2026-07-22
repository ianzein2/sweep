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

        progress?.update("checking Background Task Management (BTM)")
        scanBackgroundTaskManagement(findings: &findings, errors: &errors)

        progress?.update("checking QuickLook plugins")
        scanQuickLookPlugins(findings: &findings, errors: &errors)

        progress?.update("checking Spotlight importers")
        scanSpotlightImporters(findings: &findings, errors: &errors)

        progress?.update("checking shell hook functions")
        scanShellHookFunctions(findings: &findings, errors: &errors)

        progress?.update("checking global npm packages")
        scanGlobalNodePackages(findings: &findings, errors: &errors)

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

    // MARK: - Background Task Management (BTM)

    /// macOS 13+ tracks every background item, login item, LaunchAgent and SMAppService in a
    /// unified database ("Background Task Management"). `sfltool dumpbtm` is the canonical way
    /// to enumerate it. Attacker-installed helpers persisted via SMAppService (modern login
    /// items) show up here even when they don't drop a plist under LaunchAgents.
    private func scanBackgroundTaskManagement(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/sfltool", arguments: ["dumpbtm"], timeout: 15)
        // `sfltool dumpbtm` exists on macOS 13+; on older systems it exits non-zero. That's fine.
        guard result.success, !result.stdout.isEmpty else { return }

        // The output is a series of `Record #N:` blocks separated by blank lines. Parse them and
        // flag records whose executable path is outside a trusted prefix, missing on disk, or
        // matches a known spyware family.
        struct BTMRecord {
            var name: String = ""
            var developer: String = ""
            var teamId: String = ""
            var type: String = ""
            var url: String = ""
            var executablePath: String = ""
            var identifier: String = ""
        }

        var records: [BTMRecord] = []
        var current = BTMRecord()

        for rawLine in result.stdout.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.hasPrefix("Record #") {
                if !current.identifier.isEmpty || !current.executablePath.isEmpty || !current.name.isEmpty {
                    records.append(current)
                }
                current = BTMRecord()
                continue
            }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let colon = trimmed.range(of: ":") else { continue }
            let key = trimmed[..<colon.lowerBound].trimmingCharacters(in: .whitespaces).lowercased()
            let value = trimmed[colon.upperBound...].trimmingCharacters(in: .whitespaces)

            switch key {
            case "name":                    current.name = value
            case "developer name":          current.developer = value
            case "team identifier":         current.teamId = value
            case "type":                    current.type = value
            case "url":                     current.url = value
            case "executable path":         current.executablePath = value
            case "identifier":              current.identifier = value
            default: break
            }
        }
        if !current.identifier.isEmpty || !current.executablePath.isEmpty || !current.name.isEmpty {
            records.append(current)
        }

        let fm = FileManager.default
        for rec in records {
            let execPath = extractPath(fromURL: rec.url) ?? rec.executablePath

            // Match against the spyware database first — a hit here is HIGH regardless of path.
            let urlLast = URL(string: rec.url)?.lastPathComponent ?? ""
            let sigMatch = SpywareSignature.match(label: rec.identifier)
                ?? SpywareSignature.match(processName: rec.name)
                ?? (urlLast.isEmpty ? nil : SpywareSignature.match(processName: urlLast))
            if let sig = sigMatch {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Known spyware in Background Task Management: \(sig.name)",
                    detail: "Identifier: \(rec.identifier), name: \(rec.name), path: \(execPath)",
                    path: execPath.isEmpty ? nil : execPath,
                    remediation: "Remove: sfltool remove-item \"\(rec.identifier)\" — then uninstall \(sig.name)"
                ))
                continue
            }

            // A record with no team identifier that isn't in a trusted path is worth investigating.
            // Apple's own helpers always have team ID `APPLE` (or blank for legacy Apple items in
            // /System). Third-party ad-hoc-signed helpers are the norm for spyware.
            guard !execPath.isEmpty else { continue }
            let isTrusted = trustedPathPrefixes.contains { execPath.hasPrefix($0) }
                || execPath.hasPrefix("/System/")
            if isTrusted { continue }

            // Missing executable = a stale record; low signal but useful for cleanup.
            if !fm.fileExists(atPath: execPath) {
                findings.append(Finding(
                    severity: .low, category: .persistence,
                    title: "BTM record references missing executable",
                    detail: "Name: \(rec.name), identifier: \(rec.identifier), path: \(execPath)",
                    path: execPath,
                    remediation: "Orphan BTM entry — remove: sfltool remove-item \"\(rec.identifier)\""
                ))
                continue
            }

            // Ad-hoc-signed (no team ID) third-party BTM items are the modern equivalent of an
            // unsigned LaunchAgent. Not automatically malicious, but worth surfacing.
            let noTeamId = rec.teamId.isEmpty || rec.teamId == "-" || rec.teamId.lowercased() == "none"
            if noTeamId {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Ad-hoc-signed background item registered with the system",
                    detail: "Name: \(rec.name), type: \(rec.type), identifier: \(rec.identifier), path: \(execPath)",
                    path: execPath,
                    remediation: "Verify this item is expected in System Settings > General > Login Items & Extensions"
                ))
            }
        }
    }

    /// `Executable Path:` isn't always populated — sometimes only `URL:` is. This pulls
    /// the file path out of a `file:///...` URL.
    private func extractPath(fromURL urlString: String) -> String? {
        guard let url = URL(string: urlString), url.isFileURL else { return nil }
        return url.path
    }

    // MARK: - QuickLook plugins

    /// QuickLook plugins run inside `QuickLookUIService` whenever Finder previews a file. A
    /// malicious `.qlgenerator` can execute code the first time the user taps space on a file.
    /// The plugin directories are otherwise unmonitored, so this is a well-known but often-missed
    /// persistence channel.
    private func scanQuickLookPlugins(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            "/Library/QuickLook",
            "\(home)/Library/QuickLook",
        ]
        let fm = FileManager.default

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".qlgenerator") {
                let path = "\(dir)/\(entry)"
                let signed = checkIsSigned(path: path)
                findings.append(Finding(
                    severity: signed ? .low : .medium, category: .persistence,
                    title: "QuickLook plugin installed" + (signed ? " (signed)" : " (unsigned)"),
                    detail: "\(entry) in \(dir) — code runs when Finder previews a matching file type",
                    path: path,
                    remediation: signed
                        ? "Legitimate if you installed it (BetterZip, QLColorCode, etc.) — otherwise remove: sudo rm -rf \"\(path)\""
                        : "Unsigned QuickLook plugins are rare — inspect and remove if not expected: sudo rm -rf \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Spotlight importers

    /// Spotlight importers (`.mdimporter` bundles) are loaded by `mdworker` for every indexed
    /// file. A malicious importer gets code execution on the fanout of the entire filesystem.
    private func scanSpotlightImporters(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            "/Library/Spotlight",
            "\(home)/Library/Spotlight",
        ]
        let fm = FileManager.default

        for dir in dirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".mdimporter") {
                let path = "\(dir)/\(entry)"
                let signed = checkIsSigned(path: path)
                findings.append(Finding(
                    severity: signed ? .low : .high, category: .persistence,
                    title: "Third-party Spotlight importer installed" + (signed ? " (signed)" : " (unsigned)"),
                    detail: "\(entry) in \(dir) — loaded by mdworker for every indexed file of the type it claims",
                    path: path,
                    remediation: signed
                        ? "Legitimate importers ship with apps like Adobe/Office — otherwise remove: sudo rm -rf \"\(path)\""
                        : "Unsigned Spotlight importers are almost never legitimate — remove: sudo rm -rf \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Shell hook functions

    /// zsh (and bash via traps) supports a set of hook function arrays that fire on every prompt,
    /// directory change, or command. Attackers register a function name here so their code runs
    /// implicitly without the shell config containing a `curl | sh` line — evading the pattern
    /// scan in `scanShellConfigs`.
    private func scanShellHookFunctions(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let configs = [
            "\(home)/.zshrc", "\(home)/.zprofile", "\(home)/.zshenv", "\(home)/.zlogin",
            "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile",
        ]

        // The zsh hook arrays. Any assignment or `+=` to one of these registers code to run at
        // that lifecycle point. `add-zsh-hook` is the modern registration form.
        let zshHookArrays = [
            "chpwd_functions", "precmd_functions", "preexec_functions",
            "periodic_functions", "zshaddhistory_functions", "zshexit_functions",
        ]

        for path in configs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let name = URL(fileURLWithPath: path).lastPathComponent

            for (idx, rawLine) in content.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                let line = String(rawLine).trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }

                // Direct assignment to hook arrays or use of add-zsh-hook.
                let mentionsHook = zshHookArrays.contains { line.contains($0) }
                    || line.contains("add-zsh-hook")
                // Bash: traps on DEBUG or ERR run before every command / on any error.
                let mentionsBashTrap = line.hasPrefix("trap ")
                    && (line.contains("DEBUG") || line.contains("ERR") || line.contains("EXIT"))
                // PROMPT_COMMAND is bash's equivalent of precmd_functions.
                let mentionsPromptCmd = line.hasPrefix("PROMPT_COMMAND=")
                    || line.hasPrefix("export PROMPT_COMMAND=")

                guard mentionsHook || mentionsBashTrap || mentionsPromptCmd else { continue }

                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Shell hook function registered in \(name)",
                    detail: "Line \(idx + 1): \(String(line.prefix(120))) — runs on every prompt / cd / command",
                    path: path,
                    remediation: "Review: nano \(path) — legitimate uses exist (Oh My Zsh, direnv, starship) but hooks are also used to hide keyloggers"
                ))
            }
        }
    }

    // MARK: - Global npm / pnpm / yarn packages

    /// The DPRK "Contagious Interview" campaign delivers BeaverTail and InvisibleFerret via
    /// malicious npm packages that developers install globally during fake job interviews.
    /// A short IOC list is worth checking; any hit is HIGH.
    private func scanGlobalNodePackages(findings: inout [Finding], errors: inout [String]) {
        // Package names publicly reported as part of the DPRK npm supply-chain campaigns
        // (Contagious Interview, "Phantom Circuit", 2024-2025). Substrings, so a versioned name
        // still matches.
        let maliciousPackageMarkers: [String] = [
            "beavertail", "invisibleferret",
            "solana-transaction-toolkit", "solana-stealer", "solana-token-transfer",
            "pumpfun-bundler", "raydium-sniper",
            "eslint-config-airbnb-typescriptx",   // typosquat of airbnb config
            "node-hide-console-window",           // frequently trojanized
            "electron-notifications-fix",         // reported dropper name
            "web3-solidity-toolkit",              // matches a 2025 dropper
        ]

        // Candidate global directories to inspect. We look at directory listings rather than
        // invoking `npm list -g` — that's slow and won't work if npm isn't on PATH under the
        // scanner's environment.
        let home = ShellRunner.realUserHome
        let candidates = [
            "/opt/homebrew/lib/node_modules",
            "/usr/local/lib/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.nvm/versions/node",     // holds nodeVXX/lib/node_modules
            "\(home)/Library/pnpm/global",
            "\(home)/.yarn/global/node_modules",
        ]

        let fm = FileManager.default

        // Recursively look one or two levels deep for `node_modules/<pkg>` and `@scope/<pkg>`
        // directory names — enough to catch scoped packages.
        func inspect(_ dir: String, depth: Int) {
            guard depth <= 3, fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { return }
            for entry in entries {
                let sub = "\(dir)/\(entry)"
                let entryLower = entry.lowercased()

                if let marker = maliciousPackageMarkers.first(where: { entryLower.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Globally installed npm package matches known-malicious pattern",
                        detail: "\(entry) at \(sub) — matches \"\(marker)\" (DPRK Contagious Interview / typosquat family)",
                        path: sub,
                        remediation: "Uninstall immediately: npm rm -g \"\(entry)\" — then rotate any wallet, browser, and SSH credentials"
                    ))
                    continue
                }

                // Recurse into scoped-package dirs (starts with @) and nvm's per-version dir.
                if entry.hasPrefix("@") || dir.contains(".nvm/versions/node") {
                    inspect(sub, depth: depth + 1)
                }
            }
        }

        for base in candidates { inspect(base, depth: 0) }
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
