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

        // Newer persistence vectors used by 2024-2025 macOS malware
        progress?.update("checking QuickLook plugins")
        scanQuickLookPlugins(findings: &findings, errors: &errors)

        progress?.update("checking Spotlight importers")
        scanSpotlightImporters(findings: &findings, errors: &errors)

        progress?.update("checking Mail bundles")
        scanMailBundles(findings: &findings, errors: &errors)

        progress?.update("checking screen savers")
        scanScreenSavers(findings: &findings, errors: &errors)

        progress?.update("checking Internet Plug-Ins")
        scanInternetPlugins(findings: &findings, errors: &errors)

        progress?.update("checking Application Scripts")
        scanApplicationScripts(findings: &findings, errors: &errors)

        progress?.update("checking hidden user accounts")
        scanHiddenUsers(findings: &findings, errors: &errors)

        progress?.update("checking login window banner")
        scanLoginWindowBanner(findings: &findings, errors: &errors)

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

    private func checkIsSigned(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return false
        }
        return SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil) == errSecSuccess
    }

    // MARK: - QuickLook plugins
    //
    // QuickLook generators are loaded by qlmanage / Finder when previewing files. A malicious
    // .qlgenerator runs in the user's context the first time any file of its supported UTI is
    // previewed — a stealthy persistence vector and a classic XCSSET-family technique.

    private func scanQuickLookPlugins(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            ("\(home)/Library/QuickLook", "User"),
            ("/Library/QuickLook", "System"),
        ]
        let fm = FileManager.default

        for (dir, scope) in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".qlgenerator") {
                let path = "\(dir)/\(entry)"
                let isSigned = checkIsSigned(path: path)
                findings.append(Finding(
                    severity: isSigned ? .medium : .high, category: .persistence,
                    title: "\(scope) QuickLook plugin installed: \(entry)",
                    detail: "QuickLook generators run when Finder previews a matching file — \(isSigned ? "signed" : "UNSIGNED") plugin in a non-Apple location",
                    path: path,
                    remediation: "Verify the plugin is legitimate, or remove: rm -rf \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Spotlight importer plugins
    //
    // Spotlight importers (.mdimporter bundles) are loaded by mds/mdworker to extract metadata
    // from files. A rogue importer runs in mdworker's context whenever a matching file is indexed
    // — broadly equivalent to a user-context backdoor that auto-runs against new downloads.

    private func scanSpotlightImporters(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            ("\(home)/Library/Spotlight", "User"),
            ("/Library/Spotlight", "System"),
        ]
        let fm = FileManager.default

        for (dir, scope) in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".mdimporter") {
                let path = "\(dir)/\(entry)"
                let isSigned = checkIsSigned(path: path)
                findings.append(Finding(
                    severity: isSigned ? .medium : .high, category: .persistence,
                    title: "\(scope) Spotlight importer installed: \(entry)",
                    detail: "Spotlight importers run inside mdworker whenever a matching file is indexed — \(isSigned ? "signed" : "UNSIGNED")",
                    path: path,
                    remediation: "Inspect contents and remove if not from a recognized vendor: rm -rf \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Mail bundles
    //
    // ~/Library/Mail/Bundles holds plugins that load inside Mail.app — they can read every
    // message, intercept compose actions, and exfiltrate attachments. Apple has progressively
    // restricted these, but rogue bundles still get installed when a user is tricked into
    // re-enabling unsigned plugins.

    private func scanMailBundles(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            "\(home)/Library/Mail/Bundles",
            "/Library/Mail/Bundles",
            // Per-version directories used by Apple over the years
            "\(home)/Library/Mail/V8/Bundles",
            "\(home)/Library/Mail/V9/Bundles",
            "\(home)/Library/Mail/V10/Bundles",
        ]
        let fm = FileManager.default

        for dir in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".mailbundle") || entry.hasSuffix(".bundle") {
                let path = "\(dir)/\(entry)"
                let isSigned = checkIsSigned(path: path)
                findings.append(Finding(
                    severity: isSigned ? .medium : .high, category: .persistence,
                    title: "Mail bundle installed: \(entry)",
                    detail: "Mail bundles run inside Mail.app and can read every message and attachment — \(isSigned ? "signed" : "UNSIGNED")",
                    path: path,
                    remediation: "Remove if not deliberately installed (very few legitimate Mail plugins exist on modern macOS): rm -rf \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Screen Savers
    //
    // .saver bundles execute arbitrary code from /System/Library/Frameworks/ScreenSaver.framework
    // whenever the screen saver runs. A signed .saver is normal; an unsigned one — or one that
    // matches a spyware signature — is a clean persistence channel.

    private func scanScreenSavers(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            ("\(home)/Library/Screen Savers", "User"),
            ("/Library/Screen Savers", "System"),
        ]
        let fm = FileManager.default

        for (dir, scope) in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".saver") {
                let path = "\(dir)/\(entry)"
                let isSigned = checkIsSigned(path: path)
                if !isSigned {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "\(scope) screen saver is unsigned: \(entry)",
                        detail: "Screen savers run arbitrary code whenever the system idles — unsigned .saver in user-writable location",
                        path: path,
                        remediation: "Remove if not deliberately installed: rm -rf \"\(path)\""
                    ))
                }
            }
        }
    }

    // MARK: - Internet Plug-Ins
    //
    // /Library/Internet Plug-Ins and ~/Library/Internet Plug-Ins used to host browser NPAPI
    // plugins. Browsers no longer load these, but the directories are still scanned by some
    // apps (and by attackers as a quiet drop site for follow-on payloads). Any non-Apple file
    // here is at least worth surfacing.

    private func scanInternetPlugins(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let dirs = [
            "\(home)/Library/Internet Plug-Ins",
            "/Library/Internet Plug-Ins",
        ]
        let fm = FileManager.default

        // Older Apple plug-ins that may still appear and are not a concern
        let allowed: Set<String> = [
            "JavaAppletPlugin.plugin", "QuickTime Plugin.plugin",
            "Default Browser.plugin",
            ".DS_Store", "Disabled Plug-Ins",
        ]

        for dir in dirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where !entry.hasPrefix(".") {
                if allowed.contains(entry) { continue }
                if !(entry.hasSuffix(".plugin") || entry.hasSuffix(".webplugin") || entry.hasSuffix(".bundle")) { continue }

                let path = "\(dir)/\(entry)"
                let isSigned = checkIsSigned(path: path)
                findings.append(Finding(
                    severity: isSigned ? .low : .medium, category: .persistence,
                    title: "Non-standard Internet Plug-In: \(entry)",
                    detail: "Modern browsers no longer load NPAPI plug-ins — files dropped here often go unnoticed (\(isSigned ? "signed" : "UNSIGNED"))",
                    path: path,
                    remediation: "Remove if not recognized: rm -rf \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Application Scripts
    //
    // ~/Library/Application Scripts/<bundle id>/ holds scripts that an app can invoke via
    // NSUserAppleScriptTask — a sandbox-friendly way for an app to run AppleScript on the
    // user's behalf. The XCSSET family and AMOS v3+ drop AppleScript payloads here under
    // legitimate-looking Apple bundle IDs (com.apple.notes, com.apple.mail).

    private func scanApplicationScripts(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let root = "\(home)/Library/Application Scripts"
        let fm = FileManager.default

        guard let bundleDirs = try? fm.contentsOfDirectory(atPath: root) else { return }

        // Apple system bundle IDs that frequently get abused — scripts here for these are
        // suspicious because Apple rarely ships them.
        let appleBundlesToFlag: Set<String> = [
            "com.apple.notes", "com.apple.mail", "com.apple.systempreferences",
            "com.apple.dt.Xcode", "com.apple.finder", "com.apple.iCal",
        ]

        for bundleDir in bundleDirs where !bundleDir.hasPrefix(".") {
            let dir = "\(root)/\(bundleDir)"
            guard let scripts = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            let isFlaggedApple = appleBundlesToFlag.contains(bundleDir)

            for script in scripts where !script.hasPrefix(".") {
                let extLower = (script as NSString).pathExtension.lowercased()
                guard ["scpt", "applescript", "sh", "py", "rb", "js"].contains(extLower) else { continue }
                let path = "\(dir)/\(script)"

                // Inspect plain-text scripts for download/exec patterns; .scpt is binary
                var hasSuspiciousContent = false
                if extLower != "scpt",
                   let content = try? String(contentsOfFile: path, encoding: .utf8) {
                    let lower = content.lowercased()
                    if (lower.contains("curl ") || lower.contains("wget ") || lower.contains("nscurl")) &&
                       (lower.contains("|sh") || lower.contains("| sh") || lower.contains("eval ") || lower.contains("base64")) {
                        hasSuspiciousContent = true
                    }
                    if lower.contains("do shell script") || lower.contains("osascript -e") {
                        hasSuspiciousContent = true
                    }
                }

                let severity: Severity = hasSuspiciousContent ? .high : (isFlaggedApple ? .high : .medium)
                findings.append(Finding(
                    severity: severity, category: .persistence,
                    title: isFlaggedApple
                        ? "Application Script in Apple bundle directory: \(bundleDir)"
                        : "Application Script installed: \(bundleDir)/\(script)",
                    detail: "Script: \(script)" +
                        (hasSuspiciousContent ? " — contains shell/download patterns" : "") +
                        (isFlaggedApple ? " — Apple bundles very rarely ship NSUserAppleScriptTask scripts (XCSSET/AMOS pattern)" : ""),
                    path: path,
                    remediation: "Inspect: cat \"\(path)\" — then remove if it isn't from an app you trust"
                ))
            }
        }
    }

    // MARK: - Hidden Local User Accounts
    //
    // A common privilege-escalation backdoor: create a local user with UID < 500 so the macOS
    // login window hides it by default. dscl(1) is the only reliable way to enumerate every
    // local account regardless of UID or "IsHidden" flag.

    private func scanHiddenUsers(findings: inout [Finding], errors: inout [String]) {
        // List every local user record (Open Directory queries /Local/Default)
        let result = ShellRunner.run("/usr/bin/dscl", arguments: [".", "list", "/Users", "UniqueID"], timeout: 10)
        guard result.success else { return }

        // Known macOS system accounts we expect to see (UID < 500). Any UID < 500 not in this
        // list is hidden from the login window and worth surfacing.
        let knownSystemAccounts: Set<String> = [
            "_amavisd", "_analyticsd", "_appinstalld", "_appleevents", "_applepay",
            "_appowner", "_appserver", "_appstore", "_ard", "_assetcache",
            "_astris", "_atsserver", "_avbdeviced", "_biome", "_calendar",
            "_ces", "_clamav", "_cmiodalassistants", "_coreaudiod", "_coremediaiod",
            "_ctkd", "_cvmsroot", "_cvs", "_cyrus", "_darwindaemon", "_devdocs",
            "_devicemgr", "_diskimagesiod", "_displaypolicyd", "_distnote",
            "_dovecot", "_dovenull", "_driverkit", "_eppc", "_findmydevice",
            "_fpsd", "_ftp", "_fud", "_gamecontrollerd", "_geod", "_hidd",
            "_iconservices", "_installassistant", "_installcoordinationd", "_installer",
            "_jabber", "_kadmin_admin", "_kadmin_changepw", "_knowledgegraphd",
            "_krb_anonymous", "_krb_changepw", "_krb_kadmin", "_krb_kerberos",
            "_krb_krbtgt", "_krbtgt", "_launchservicesd", "_lda", "_locationd",
            "_logd", "_lp", "_mailman", "_mbsetupuser", "_mcxalr", "_mdnsresponder",
            "_mobileasset", "_mysql", "_nbcd", "_netbios", "_netstatistics",
            "_networkd", "_nfsd", "_notification_proxy", "_nsurlsessiond",
            "_nsurlstoraged", "_ondemand", "_oahd", "_opendirectoryd", "_pcastagentd",
            "_postfix", "_postgres", "_qtss", "_reportmemoryexception", "_rmd",
            "_sandbox", "_screensaver", "_scsd", "_securityagent", "_serialnumberd",
            "_signaturedirectory", "_softwareupdate", "_spotlight", "_sshd", "_svn",
            "_taskgated", "_teamsserver", "_terastrust", "_timed", "_timezone",
            "_tokend", "_trustd", "_trustevaluationagent", "_unknown", "_update_sharing",
            "_usbmuxd", "_uucp", "_warmd", "_webauthserver", "_windowserver",
            "_wireless", "_wwwproxy", "_xserverdocs", "daemon", "nobody", "root",
        ]

        for rawLine in result.stdout.split(separator: "\n") {
            // Each row is "username  UID"; tokens may be tab- or space-separated.
            let parts = String(rawLine).components(separatedBy: CharacterSet.whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 2, let uid = Int(parts.last!) else { continue }
            let user = parts[0]

            // Hide-from-login is the classic indicator: UID below 500 (legacy) or 501 (Big Sur+).
            let isHidden = uid >= 0 && uid < 501 && !knownSystemAccounts.contains(user)
            if !isHidden { continue }

            // Check admin group membership — hidden + admin is the backdoor pattern.
            let admin = ShellRunner.run("/usr/bin/dseditgroup", arguments: ["-o", "checkmember", "-m", user, "admin"], timeout: 5)
            let isAdmin = admin.stdout.lowercased().contains("yes \(user.lowercased()) is a member")

            findings.append(Finding(
                severity: isAdmin ? .high : .medium, category: .persistence,
                title: isAdmin
                    ? "Hidden admin user account: \(user) (UID \(uid))"
                    : "Hidden local user account: \(user) (UID \(uid))",
                detail: "User does not appear at the login window because UID < 501 — " +
                    (isAdmin ? "and is a member of the admin group (full root-via-sudo)" : "non-Apple system account"),
                path: nil,
                remediation: "Inspect and remove if not yours: sudo dscl . -delete /Users/\(user)"
            ))
        }
    }

    // MARK: - Login Window Banner / Message
    //
    // /Library/Preferences/com.apple.loginwindow.plist supports LoginwindowText (banner above
    // the login prompt). MacRansom-style attackers set this to demand payment; legitimate
    // organizations sometimes use it for compliance banners. Either way, the user should know
    // it's there.

    private func scanLoginWindowBanner(findings: inout [Finding], errors: inout [String]) {
        let result = ShellRunner.run("/usr/bin/defaults", arguments: [
            "read", "/Library/Preferences/com.apple.loginwindow", "LoginwindowText"
        ], timeout: 5)
        guard result.success else { return }
        let text = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }

        let lower = text.lowercased()
        let ransomKeywords = ["bitcoin", "btc", "ransom", "decrypt", "encrypted",
                              "monero", "xmr", "pay ", "wallet"]
        let isRansomLike = ransomKeywords.contains { lower.contains($0) }
        findings.append(Finding(
            severity: isRansomLike ? .high : .low, category: .persistence,
            title: isRansomLike
                ? "Login window message contains ransom-like keywords"
                : "Custom login window banner is set",
            detail: "Text: \(String(text.prefix(160)))",
            path: "/Library/Preferences/com.apple.loginwindow.plist",
            remediation: isRansomLike
                ? "Investigate immediately, then clear: sudo defaults delete /Library/Preferences/com.apple.loginwindow LoginwindowText"
                : "If not your organization's banner, clear: sudo defaults delete /Library/Preferences/com.apple.loginwindow LoginwindowText"
        ))
    }
}
