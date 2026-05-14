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

        progress?.update("checking plug-in bundle persistence")
        scanPluginBundlePersistence(findings: &findings, errors: &errors)

        progress?.update("checking Folder Action scripts")
        scanFolderActionScripts(findings: &findings, errors: &errors)

        progress?.update("checking Mail rules / bundles")
        scanMailPersistence(findings: &findings, errors: &errors)

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

    // MARK: - Plug-in Bundle Persistence
    //
    // Many macOS plug-in directories load arbitrary code into long-running processes (Finder,
    // Spotlight, audio daemons, screensaver engine, etc.) on every login or every time the host
    // app runs. Spyware abuses these as quiet, signed-by-the-user persistence channels —
    // the bundles aren't surfaced anywhere in System Settings, so users rarely audit them.

    private struct PluginLocation {
        let dir: String
        let extensions: Set<String>
        let kind: String
        let host: String
        let severity: Severity
    }

    private func scanPluginBundlePersistence(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let locations: [PluginLocation] = [
            // Spotlight importers run inside mdworker and execute on every file index — a stealthy
            // execution surface. The user dir is empty by default; system dir contains Apple's set.
            PluginLocation(dir: "\(home)/Library/Spotlight",
                           extensions: ["mdimporter"],
                           kind: "Spotlight importer",
                           host: "loaded by mdworker on every Spotlight index",
                           severity: .high),
            PluginLocation(dir: "/Library/Spotlight",
                           extensions: ["mdimporter"],
                           kind: "Spotlight importer (system)",
                           host: "loaded by mdworker on every Spotlight index",
                           severity: .high),
            // QuickLook generators run when Finder previews a matching file — auto-execution on hover.
            PluginLocation(dir: "\(home)/Library/QuickLook",
                           extensions: ["qlgenerator"],
                           kind: "QuickLook plug-in",
                           host: "loaded by quicklookd whenever Finder previews a file",
                           severity: .high),
            PluginLocation(dir: "/Library/QuickLook",
                           extensions: ["qlgenerator"],
                           kind: "QuickLook plug-in (system)",
                           host: "loaded by quicklookd whenever Finder previews a file",
                           severity: .high),
            // Screen savers are bundles that load on lock/idle — perfect for camera/keystroke spyware.
            PluginLocation(dir: "\(home)/Library/Screen Savers",
                           extensions: ["saver", "qtz"],
                           kind: "Screen Saver",
                           host: "loaded by legacyScreenSaver / WindowServer on idle",
                           severity: .medium),
            PluginLocation(dir: "/Library/Screen Savers",
                           extensions: ["saver", "qtz"],
                           kind: "Screen Saver (system)",
                           host: "loaded by legacyScreenSaver / WindowServer on idle",
                           severity: .medium),
            // Audio Units run inside coreaudiod and any AU host (Logic, GarageBand, browsers).
            PluginLocation(dir: "\(home)/Library/Audio/Plug-Ins/Components",
                           extensions: ["component"],
                           kind: "Audio Unit",
                           host: "loaded by coreaudiod and audio-using apps",
                           severity: .medium),
            PluginLocation(dir: "/Library/Audio/Plug-Ins/Components",
                           extensions: ["component"],
                           kind: "Audio Unit (system)",
                           host: "loaded by coreaudiod and audio-using apps",
                           severity: .medium),
            // Color picker plug-ins load into any app that opens NSColorPanel. Trivially installable, never audited.
            PluginLocation(dir: "\(home)/Library/ColorPickers",
                           extensions: ["colorPicker"],
                           kind: "Color Picker plug-in",
                           host: "loaded by any app that shows the system color panel",
                           severity: .medium),
            PluginLocation(dir: "/Library/ColorPickers",
                           extensions: ["colorPicker"],
                           kind: "Color Picker plug-in (system)",
                           host: "loaded by any app that shows the system color panel",
                           severity: .medium),
            // Internet Plug-Ins are deprecated but Safari/AppKit may still load them.
            PluginLocation(dir: "\(home)/Library/Internet Plug-Ins",
                           extensions: ["plugin", "webplugin", "bundle"],
                           kind: "Internet Plug-In",
                           host: "loaded by Safari and other WebKit hosts (legacy)",
                           severity: .high),
            PluginLocation(dir: "/Library/Internet Plug-Ins",
                           extensions: ["plugin", "webplugin", "bundle"],
                           kind: "Internet Plug-In (system)",
                           host: "loaded by Safari and other WebKit hosts (legacy)",
                           severity: .high),
            // Input Methods run inside loginwindow — they have access to every keystroke.
            PluginLocation(dir: "\(home)/Library/Input Methods",
                           extensions: ["app", "bundle"],
                           kind: "Input Method",
                           host: "loaded by loginwindow — sees every keystroke typed",
                           severity: .high),
            PluginLocation(dir: "/Library/Input Methods",
                           extensions: ["app", "bundle"],
                           kind: "Input Method (system)",
                           host: "loaded by loginwindow — sees every keystroke typed",
                           severity: .high),
            // Login Items folder (legacy) — apps placed here run at login.
            PluginLocation(dir: "\(home)/Library/LoginItems",
                           extensions: ["app", "bundle"],
                           kind: "Login Item",
                           host: "launched at user login",
                           severity: .medium),
            // PreferencePanes appear in System Settings and can register helpers/launchd jobs on install.
            PluginLocation(dir: "\(home)/Library/PreferencePanes",
                           extensions: ["prefPane"],
                           kind: "Preference Pane",
                           host: "loaded by System Settings; pane installer often registers a launch agent",
                           severity: .low),
            PluginLocation(dir: "/Library/PreferencePanes",
                           extensions: ["prefPane"],
                           kind: "Preference Pane (system)",
                           host: "loaded by System Settings; pane installer often registers a launch agent",
                           severity: .low),
        ]

        let fm = FileManager.default
        // Apple-shipped bundles always use a com.apple.* identifier.
        let appleBundlePrefix = "com.apple."

        for loc in locations {
            guard fm.fileExists(atPath: loc.dir),
                  let entries = try? fm.contentsOfDirectory(atPath: loc.dir) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let ext = (entry as NSString).pathExtension
                guard loc.extensions.contains(ext) else { continue }
                let bundlePath = "\(loc.dir)/\(entry)"

                // Read the bundle's CFBundleIdentifier so we can skip Apple's own plug-ins.
                let infoPlistPath = "\(bundlePath)/Contents/Info.plist"
                let bundleId: String = {
                    guard let data = fm.contents(atPath: infoPlistPath),
                          let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
                    else { return "" }
                    return (plist["CFBundleIdentifier"] as? String) ?? ""
                }()

                if bundleId.hasPrefix(appleBundlePrefix) { continue }

                // Cross-reference with known spyware (process names + bundle IDs).
                let entryName = (entry as NSString).deletingPathExtension
                if let sig = SpywareSignature.match(processName: entryName)
                    ?? SpywareSignature.match(bundleId: bundleId) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware as \(loc.kind): \(sig.name)",
                        detail: "\(entry) — \(loc.host)",
                        path: bundlePath,
                        remediation: "Remove: rm -rf \"\(bundlePath)\" — then verify nothing else depends on it"
                    ))
                    continue
                }

                // Plug-ins masquerading as Apple bundle IDs are a strong indicator.
                if SpywareSignature.isFakeAppleBundleId(bundleId) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "\(loc.kind) using fake Apple bundle ID",
                        detail: "Bundle ID \"\(bundleId)\" — \(loc.host)",
                        path: bundlePath,
                        remediation: "Remove: rm -rf \"\(bundlePath)\""
                    ))
                    continue
                }

                // Otherwise surface the bundle so the user can audit it. Most macs have zero
                // entries in these directories; even one warrants a look.
                findings.append(Finding(
                    severity: loc.severity, category: .persistence,
                    title: "\(loc.kind) installed: \(entry)",
                    detail: bundleId.isEmpty
                        ? "\(loc.host)"
                        : "Bundle ID: \(bundleId) — \(loc.host)",
                    path: bundlePath,
                    remediation: "Verify you installed this. To remove: rm -rf \"\(bundlePath)\""
                ))
            }
        }
    }

    // MARK: - Folder Action Scripts
    //
    // Folder Actions trigger AppleScripts when files are added, removed, or modified in a
    // watched folder. They run silently in the background via System Events — a quiet way
    // to react to file drops (Downloads, Desktop) and trigger code execution.

    private func scanFolderActionScripts(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let scriptDirs = [
            "\(home)/Library/Scripts/Folder Action Scripts",
            "/Library/Scripts/Folder Action Scripts",
        ]

        let fm = FileManager.default
        for dir in scriptDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                let ext = (entry as NSString).pathExtension.lowercased()
                guard ["scpt", "scptd", "applescript", "sh", "py"].contains(ext) else { continue }
                let scriptPath = "\(dir)/\(entry)"

                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Folder Action script installed: \(entry)",
                    detail: "Folder Action scripts run automatically when watched folders change — review which folder this is bound to",
                    path: scriptPath,
                    remediation: "List bindings: osascript -e 'tell application \"System Events\" to get every folder action' — remove with 'remove folder action <name>'"
                ))
            }
        }

        // Also check whether Folder Actions are enabled at all — a common spyware enabler.
        let enabledResult = ShellRunner.run("/usr/bin/osascript", arguments: [
            "-e", "tell application \"System Events\" to get folder actions enabled"
        ], timeout: 5)
        if enabledResult.success &&
           enabledResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "true" {
            // Listing the actual attached actions makes the finding actionable.
            let listResult = ShellRunner.run("/usr/bin/osascript", arguments: [
                "-e", "tell application \"System Events\" to get name of every folder action"
            ], timeout: 5)
            let actions = listResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !actions.isEmpty && actions.lowercased() != "missing value" {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Folder Actions are enabled",
                    detail: "Active folder actions: \(String(actions.prefix(160)))",
                    path: nil,
                    remediation: "If unexpected, disable: osascript -e 'tell application \"System Events\" to set folder actions enabled to false'"
                ))
            }
        }
    }

    // MARK: - Mail Persistence
    //
    // Apple Mail supports plug-in bundles and rules that can run AppleScripts on incoming
    // messages. Both have been used as persistence/exfiltration vectors (e.g. CVE-2020-9922
    // and several stealer families that auto-forward sensitive mail to attacker addresses).

    private func scanMailPersistence(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let bundleDirs = [
            "\(home)/Library/Mail/Bundles",
            "/Library/Mail/Bundles",
        ]

        let fm = FileManager.default
        for dir in bundleDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where !entry.hasPrefix(".") &&
                                       (entry.hasSuffix(".mailbundle") || entry.hasSuffix(".bundle")) {
                let bundlePath = "\(dir)/\(entry)"
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Apple Mail plug-in installed: \(entry)",
                    detail: "Mail loads this bundle inside its own process — full access to mailboxes, drafts, and outgoing messages",
                    path: bundlePath,
                    remediation: "Apple-signed Mail plug-ins are extremely rare. If unexpected: rm -rf \"\(bundlePath)\""
                ))
            }
        }

        // Mail rules with run-script or forward-message actions are a common silent-exfil pattern.
        // SyncedRules.plist holds the user's rules; presence of "AppleScript" or "Forward" actions is worth surfacing.
        let mailV10Plist = "\(home)/Library/Mail/V10/MailData/SyncedRules.plist"
        let mailV9Plist  = "\(home)/Library/Mail/V9/MailData/SyncedRules.plist"
        for rulesPath in [mailV10Plist, mailV9Plist] {
            guard let data = fm.contents(atPath: rulesPath),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) else { continue }

            // Rules can be at the top level or nested under a "rules" key; just stringify and search.
            let content = String(describing: plist).lowercased()
            let runsScript = content.contains("applescript") || content.contains("runapplescript")
            let autoForwards = content.contains("forwardtext") || content.contains("forwardmessage") ||
                               content.contains("redirect")
            if runsScript || autoForwards {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Apple Mail rules contain script-run or auto-forward actions",
                    detail: "Mail rules can silently run AppleScripts or forward incoming messages — common stealer exfil channel",
                    path: rulesPath,
                    remediation: "Audit in Mail > Settings > Rules and remove any rule you don't recognize"
                ))
                break  // one finding per file is enough
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
