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

        progress?.update("checking plug-in persistence points")
        scanPluginPersistence(findings: &findings, errors: &errors)

        progress?.update("checking AppleScript / Automator persistence")
        scanAppleScriptPersistence(findings: &findings, errors: &errors)

        progress?.update("checking clipboard monitoring")
        scanClipboardMonitoring(findings: &findings, errors: &errors)

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

    // MARK: - Plug-in Persistence Points

    /// macOS loads third-party bundles out of well-known plug-in directories. Malware has used
    /// every one of these as persistence at some point — QuickLook generators execute whenever
    /// Finder previews a file, Spotlight importers run as mdworker_shared inherits them, and
    /// Audio Units get loaded by almost every creative app on the system.
    private func scanPluginPersistence(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        struct PluginDir {
            let path: String
            let ext: String?  // file extension to match, nil = any bundle
            let kind: String
            let detail: String
        }

        let pluginDirs: [PluginDir] = [
            // QuickLook generators run when Finder previews a file — silent auto-execution vector
            PluginDir(path: "\(home)/Library/QuickLook", ext: "qlgenerator",
                      kind: "QuickLook generator",
                      detail: "QuickLook generators execute code whenever Finder previews a matching file type"),
            PluginDir(path: "/Library/QuickLook", ext: "qlgenerator",
                      kind: "QuickLook generator",
                      detail: "QuickLook generators execute code whenever Finder previews a matching file type"),
            // Spotlight importers are loaded by mdworker_shared during indexing
            PluginDir(path: "\(home)/Library/Spotlight", ext: "mdimporter",
                      kind: "Spotlight importer",
                      detail: "Spotlight importers are loaded by mdworker_shared and run during indexing"),
            PluginDir(path: "/Library/Spotlight", ext: "mdimporter",
                      kind: "Spotlight importer",
                      detail: "Spotlight importers are loaded by mdworker_shared and run during indexing"),
            // Audio Units load into every audio host (GarageBand, Logic, etc.)
            PluginDir(path: "\(home)/Library/Audio/Plug-Ins/Components", ext: "component",
                      kind: "Audio Unit plug-in",
                      detail: "Audio Units load into any audio host app and can run arbitrary code"),
            PluginDir(path: "/Library/Audio/Plug-Ins/Components", ext: "component",
                      kind: "Audio Unit plug-in",
                      detail: "Audio Units load into any audio host app and can run arbitrary code"),
            // Screen Savers run when the lock screen activates
            PluginDir(path: "\(home)/Library/Screen Savers", ext: "saver",
                      kind: "Screen Saver",
                      detail: "Screen savers are bundles with executable code that run on idle"),
            PluginDir(path: "/Library/Screen Savers", ext: "saver",
                      kind: "Screen Saver",
                      detail: "Screen savers are bundles with executable code that run on idle"),
            // Input Methods run with the user's session — a classic keylogger position
            PluginDir(path: "\(home)/Library/Input Methods", ext: nil,
                      kind: "Input Method",
                      detail: "Input methods run with every user session and can capture keystrokes"),
            PluginDir(path: "/Library/Input Methods", ext: nil,
                      kind: "Input Method",
                      detail: "Input methods run with every user session and can capture keystrokes"),
            // Keyboard Layouts — .bundle with executable code can hijack keyboard input
            PluginDir(path: "\(home)/Library/Keyboard Layouts", ext: "bundle",
                      kind: "Keyboard Layout bundle",
                      detail: "Keyboard layout bundles with code are unusual and can intercept input"),
            PluginDir(path: "/Library/Keyboard Layouts", ext: "bundle",
                      kind: "Keyboard Layout bundle",
                      detail: "Keyboard layout bundles with code are unusual and can intercept input"),
            // Legacy Internet Plug-Ins — still loaded by Safari for older tech
            PluginDir(path: "\(home)/Library/Internet Plug-Ins", ext: nil,
                      kind: "Internet Plug-In",
                      detail: "Internet plug-ins are legacy but still loaded by Safari on launch"),
            PluginDir(path: "/Library/Internet Plug-Ins", ext: nil,
                      kind: "Internet Plug-In",
                      detail: "Internet plug-ins are legacy but still loaded by Safari on launch"),
            // PreferencePanes — loaded by System Settings
            PluginDir(path: "\(home)/Library/PreferencePanes", ext: "prefPane",
                      kind: "Preference Pane",
                      detail: "PreferencePanes are loaded by System Settings and run code"),
            PluginDir(path: "/Library/PreferencePanes", ext: "prefPane",
                      kind: "Preference Pane",
                      detail: "PreferencePanes are loaded by System Settings and run code"),
            // Color Pickers — loaded by any app showing a color picker
            PluginDir(path: "\(home)/Library/ColorPickers", ext: "colorPicker",
                      kind: "Color Picker plug-in",
                      detail: "Color Picker bundles load into every app that opens a color panel"),
            PluginDir(path: "/Library/ColorPickers", ext: "colorPicker",
                      kind: "Color Picker plug-in",
                      detail: "Color Picker bundles load into every app that opens a color panel"),
            // Contextual menu items (legacy, but still loadable)
            PluginDir(path: "\(home)/Library/Contextual Menu Items", ext: "plugin",
                      kind: "Contextual Menu plug-in",
                      detail: "Contextual Menu plug-ins extend right-click menus and can run on activation"),
            PluginDir(path: "/Library/Contextual Menu Items", ext: "plugin",
                      kind: "Contextual Menu plug-in",
                      detail: "Contextual Menu plug-ins extend right-click menus and can run on activation"),
            // Dock Tile plug-ins
            PluginDir(path: "/Library/DockTiles", ext: "docktileplugin",
                      kind: "Dock Tile plug-in",
                      detail: "Dock Tile plug-ins run inside the Dock process"),
            // CUPS filter / backend — less common but well-documented persistence for root malware
            PluginDir(path: "/usr/libexec/cups/filter", ext: nil,
                      kind: "CUPS filter",
                      detail: "CUPS filters run as root during printing and have been abused by macOS malware"),
            PluginDir(path: "/usr/libexec/cups/backend", ext: nil,
                      kind: "CUPS backend",
                      detail: "CUPS backends run as root when a print job is dispatched"),
        ]

        for pd in pluginDirs {
            guard fm.fileExists(atPath: pd.path),
                  let contents = try? fm.contentsOfDirectory(atPath: pd.path) else { continue }

            for entry in contents where !entry.hasPrefix(".") {
                // Skip entries that don't match the expected extension when one is specified.
                if let ext = pd.ext, !entry.hasSuffix("." + ext) { continue }
                let bundlePath = "\(pd.path)/\(entry)"

                // Known CUPS defaults — Apple ships a long list of filters/backends; skip those
                // by checking if the file is inside a signed system location already.
                if pd.path.hasPrefix("/usr/libexec/cups/") {
                    // Skip common Apple-shipped filter names
                    let appleCupsDefaults: Set<String> = [
                        "commandtops", "pstops", "cgbannertopdf", "cgpdftopdf",
                        "cgpdftops", "cgpdftoraster", "cgtexttopdf", "pdftops",
                        "pictwpstops", "rastertodymo", "rastertoescpx", "rastertohp",
                        "rastertopdf", "rastertopwg", "rastertoepson", "rastertopcl",
                        "usb", "ipp", "lpd", "socket", "http", "https", "mdns",
                        "bluetooth", "dnssd", "rastertobrlaser", "hpcups",
                    ]
                    if appleCupsDefaults.contains(entry) { continue }
                }

                let bundleId = readBundleIdentifier(at: bundlePath)

                // Apple-shipped plug-ins often carry Apple bundle IDs — trust those.
                if let bid = bundleId, bid.hasPrefix("com.apple.") { continue }

                // Check against known spyware by bundle ID
                if let bid = bundleId, let sig = SpywareSignature.match(bundleId: bid) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Known spyware installed as \(pd.kind): \(sig.name)",
                        detail: "Bundle: \(bundleId ?? "unknown"), Path: \(bundlePath)",
                        path: bundlePath,
                        remediation: "Remove: sudo rm -rf \"\(bundlePath)\" — then remove \(sig.name)"
                    ))
                    continue
                }

                // Flag unsigned plug-ins outright — every one of these extension points has been
                // used by malware, and legitimate third-party plug-ins are almost always signed.
                let isSigned = checkIsSigned(path: bundlePath)
                if !isSigned {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Unsigned \(pd.kind) installed",
                        detail: "\(pd.detail). Bundle: \(bundleId ?? entry)",
                        path: bundlePath,
                        remediation: "Verify this plug-in is expected. Remove if not: rm -rf \"\(bundlePath)\""
                    ))
                } else {
                    // Signed but third-party plug-ins in these paths warrant a look — they auto-load.
                    findings.append(Finding(
                        severity: .low, category: .persistence,
                        title: "Third-party \(pd.kind) installed",
                        detail: "\(pd.detail). Bundle: \(bundleId ?? entry)",
                        path: bundlePath,
                        remediation: "Verify this plug-in is expected — it auto-loads at runtime"
                    ))
                }
            }
        }
    }

    private func readBundleIdentifier(at path: String) -> String? {
        let infoPlistCandidates = [
            "\(path)/Contents/Info.plist",
            "\(path)/Info.plist",
        ]
        for plistPath in infoPlistCandidates {
            guard let data = FileManager.default.contents(atPath: plistPath),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            else { continue }
            if let id = plist["CFBundleIdentifier"] as? String { return id }
        }
        return nil
    }

    // MARK: - AppleScript / Automator Persistence

    /// LaunchAgents pointing at osascript or an Automator workflow are a common stealth tactic:
    /// the plist looks innocuous, and the actual malicious behaviour lives in a separate script
    /// or workflow file that's easy to overlook. FrigidStealer (2025) uses exactly this pattern.
    private func scanAppleScriptPersistence(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        let home = ShellRunner.realUserHome

        // 1. Folder Actions — AppleScripts that run when a folder's contents change.
        //    They're rare in legitimate setups; any entry here deserves a look.
        let folderActionsPath = "\(home)/Library/Workflows/Applications/Folder Actions"
        if let entries = try? fm.contentsOfDirectory(atPath: folderActionsPath) {
            for entry in entries where !entry.hasPrefix(".") {
                let path = "\(folderActionsPath)/\(entry)"
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Folder Action workflow installed",
                    detail: "Folder Actions run AppleScript/shell code when a folder's contents change: \(entry)",
                    path: path,
                    remediation: "Review contents, then remove if unexpected: rm -rf \"\(path)\""
                ))
            }
        }

        // 2. User-installed macOS Services — .workflow bundles that attach to the Services menu
        //    and can also run on keyboard shortcuts.
        let servicesPath = "\(home)/Library/Services"
        if let entries = try? fm.contentsOfDirectory(atPath: servicesPath) {
            for entry in entries where !entry.hasPrefix(".") && entry.hasSuffix(".workflow") {
                let path = "\(servicesPath)/\(entry)"
                // Skip obvious user-created workflows by checking if the file is signed — users
                // typically don't sign their own workflows, so unsigned is fine here.
                // But an unsigned .workflow that's been recently modified and has shell actions
                // is worth surfacing.
                let wfScript = "\(path)/Contents/document.wflow"
                guard let data = fm.contents(atPath: wfScript),
                      let text = String(data: data, encoding: .utf8) else { continue }
                let suspicious = ["curl ", "wget ", "bash -c", "sh -c", "osascript",
                                  "base64 --decode", "base64 -d", "nc ", "/tmp/",
                                  "python -c", "python3 -c", "perl -e"]
                if suspicious.contains(where: { text.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Services workflow runs shell / network commands",
                        detail: "Workflow: \(entry) — contains remote-exec style commands",
                        path: path,
                        remediation: "Review: cat \"\(wfScript)\" — remove if unexpected"
                    ))
                }
            }
        }

        // 3. LaunchAgents whose ProgramArguments invoke osascript / an .scpt file — a favourite
        //    pattern for FrigidStealer, AdLoad and AppleScript-first stealers.
        for (dirPath, dirLabel) in launchDirs {
            let expanded = dirPath.hasPrefix("~/") ? home + String(dirPath.dropFirst(1)) : dirPath
            guard let entries = try? fm.contentsOfDirectory(atPath: expanded) else { continue }
            for file in entries where file.hasSuffix(".plist") {
                let plistPath = "\(expanded)/\(file)"
                guard let data = fm.contents(atPath: plistPath),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
                else { continue }

                let label = plist["Label"] as? String ?? "unknown"
                // Skip Apple's own plists
                if label.hasPrefix("com.apple.") { continue }

                var args: [String] = []
                if let program = plist["Program"] as? String { args = [program] }
                if let pa = plist["ProgramArguments"] as? [String] { args = pa }
                guard !args.isEmpty else { continue }

                let joined = args.joined(separator: " ")
                let isOsa = args.first?.hasSuffix("/osascript") == true || joined.contains("osascript")
                let runsScpt = args.contains(where: { $0.hasSuffix(".scpt") || $0.hasSuffix(".applescript") })
                let runsShellPipe = (joined.contains("curl ") || joined.contains("wget ")) &&
                    (joined.contains("| sh") || joined.contains("| bash") ||
                     joined.contains("|sh") || joined.contains("|bash"))

                if isOsa || runsScpt {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "LaunchAgent invokes AppleScript",
                        detail: "Label: \(label), Dir: \(dirLabel), Args: \(String(joined.prefix(120)))",
                        path: plistPath,
                        remediation: "Review the script it runs, then remove the plist if unexpected: sudo rm \"\(plistPath)\""
                    ))
                } else if runsShellPipe {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "LaunchAgent pipes remote content into a shell",
                        detail: "Label: \(label), Dir: \(dirLabel), Args: \(String(joined.prefix(120)))",
                        path: plistPath,
                        remediation: "This is the canonical curl-into-shell downloader pattern — remove: sudo rm \"\(plistPath)\""
                    ))
                }
            }
        }
    }

    // MARK: - Clipboard Monitoring

    /// Clipboard hijackers replace wallet addresses and steal copied secrets. They typically
    /// persist as LaunchAgents that poll `pbpaste` or hook NSPasteboard. Legitimate clipboard
    /// tools (Alfred, Raycast, Paste.app, Copy'em) are whitelisted.
    private func scanClipboardMonitoring(findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        let home = ShellRunner.realUserHome

        let legitClipboardLabels: Set<String> = [
            "com.runningwithcrayons.Alfred",
            "com.raycast.macos",
            "com.fiplab.clipboard",
            "com.apple.pasteboard",
            "com.maxel.PasteApp",
            "com.sindresorhus.Pasta",
            "com.flexibits.Clipy",
        ]

        for (dirPath, _) in launchDirs {
            let expanded = dirPath.hasPrefix("~/") ? home + String(dirPath.dropFirst(1)) : dirPath
            guard let entries = try? fm.contentsOfDirectory(atPath: expanded) else { continue }
            for file in entries where file.hasSuffix(".plist") {
                let plistPath = "\(expanded)/\(file)"
                guard let data = fm.contents(atPath: plistPath),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
                else { continue }

                let label = plist["Label"] as? String ?? "unknown"
                if label.hasPrefix("com.apple.") { continue }
                if legitClipboardLabels.contains(where: { label.hasPrefix($0) }) { continue }

                var args: [String] = []
                if let program = plist["Program"] as? String { args = [program] }
                if let pa = plist["ProgramArguments"] as? [String] { args = pa }
                let joined = args.joined(separator: " ")

                // Direct references to pbpaste / NSPasteboard in a launch agent are uncommon —
                // legitimate clipboard managers hook the API via their own frameworks.
                let pollsClipboard = joined.contains("pbpaste") || joined.contains("pbcopy")
                // KeepAlive + short StartInterval polling a clipboard-reading script is the
                // classic crypto-drainer pattern.
                let startInterval = plist["StartInterval"] as? Int ?? 0
                let fastPoll = startInterval > 0 && startInterval < 30

                if pollsClipboard {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "LaunchAgent polls the clipboard",
                        detail: "Label: \(label), Args: \(String(joined.prefix(120)))" +
                            (fastPoll ? ", StartInterval: \(startInterval)s (fast polling)" : ""),
                        path: plistPath,
                        remediation: "Clipboard polling is the standard pattern for crypto-address swappers — remove: rm \"\(plistPath)\""
                    ))
                }
            }
        }
    }
}
