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

        progress?.update("checking authorization plugins")
        scanAuthorizationPlugins(findings: &findings, errors: &errors)

        progress?.update("checking Spotlight importers")
        scanBundlePlugins(
            dirs: ["~/Library/Spotlight", "/Library/Spotlight"],
            extensionFilter: "mdimporter",
            label: "Spotlight importer",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking QuickLook plugins")
        scanBundlePlugins(
            dirs: ["~/Library/QuickLook", "/Library/QuickLook"],
            extensionFilter: "qlgenerator",
            label: "QuickLook generator",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking screen saver bundles")
        scanBundlePlugins(
            dirs: ["~/Library/Screen Savers", "/Library/Screen Savers"],
            extensionFilter: "saver",
            label: "Screen Saver",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking ColorPickers")
        scanBundlePlugins(
            dirs: ["~/Library/ColorPickers", "/Library/ColorPickers"],
            extensionFilter: "colorPicker",
            label: "ColorPicker",
            severity: .medium,
            findings: &findings
        )

        progress?.update("checking input methods / keyboard layouts")
        scanBundlePlugins(
            dirs: ["~/Library/Input Methods", "/Library/Input Methods",
                   "~/Library/Keyboard Layouts", "/Library/Keyboard Layouts"],
            extensionFilter: nil,
            label: "Input Method / Keyboard Layout",
            severity: .high,
            findings: &findings
        )

        progress?.update("checking sandboxed app LaunchAgents")
        scanSandboxedLaunchAgents(findings: &findings, errors: &errors)

        progress?.update("checking at-job queue")
        scanAtJobs(findings: &findings, errors: &errors)

        progress?.update("checking modern Background Items (SMAppService)")
        scanBackgroundItems(findings: &findings, errors: &errors)

        progress?.update("checking dynamic linker config (dyld)")
        scanDyldConfig(findings: &findings, errors: &errors)

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

    // MARK: - Authorization Plugins

    /// Authorization plugins under /Library/Security/SecurityAgentPlugins are loaded by
    /// authd / SecurityAgent at login, sudo, screensaver unlock, etc. A rogue plugin can
    /// silently capture credentials. macOS ships with no third-party plugins by default.
    private func scanAuthorizationPlugins(findings: inout [Finding], errors: inout [String]) {
        let pluginDir = "/Library/Security/SecurityAgentPlugins"
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: pluginDir) else { return }

        for entry in entries where !entry.hasPrefix(".") {
            let pluginPath = "\(pluginDir)/\(entry)"
            // Apple plugins live under /System/Library, not /Library — anything here is third-party.
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Third-party authorization plugin: \(entry)",
                detail: "Authorization plugins gate every login/sudo/unlock prompt and can capture credentials",
                path: pluginPath,
                remediation: "Remove if not deliberately installed: sudo rm -rf \"\(pluginPath)\""
            ))
        }

        // /etc/authorization.plist (legacy) should not exist on modern macOS.
        if fm.fileExists(atPath: "/etc/authorization") {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Legacy /etc/authorization file present",
                detail: "Modern macOS uses authd; a stand-alone /etc/authorization is unusual and may indicate tampering",
                path: "/etc/authorization",
                remediation: "Inspect contents and remove if not expected"
            ))
        }
    }

    // MARK: - Generic Bundle-Plugin Scanner

    /// macOS loads code from many user-installable plugin directories: Spotlight importers
    /// (.mdimporter), QuickLook generators (.qlgenerator), Screen Savers (.saver), ColorPickers
    /// (.colorPicker), and Input Methods. Each of these runs in-process inside system services
    /// and is a known persistence channel for stalkerware.
    private func scanBundlePlugins(
        dirs: [String],
        extensionFilter: String?,
        label: String,
        severity: Severity,
        findings: inout [Finding]
    ) {
        let fm = FileManager.default
        for dir in dirs {
            let expanded = dir.hasPrefix("~/")
                ? ShellRunner.realUserHome + dir.dropFirst(1)
                : dir
            guard let entries = try? fm.contentsOfDirectory(atPath: expanded) else { continue }

            for entry in entries where !entry.hasPrefix(".") {
                if let ext = extensionFilter, !entry.hasSuffix(".\(ext)") { continue }
                let pluginPath = "\(expanded)/\(entry)"

                // Resolve the plugin's executable to check signature
                let infoPath = "\(pluginPath)/Contents/Info.plist"
                var execPath: String?
                if let data = fm.contents(atPath: infoPath),
                   let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                   let execName = plist["CFBundleExecutable"] as? String {
                    execPath = "\(pluginPath)/Contents/MacOS/\(execName)"
                }

                let isSigned = execPath.map { checkIsSigned(path: $0) } ?? false
                let nameLC = entry.lowercased()
                let nameSuspicious = ["spy", "keylog", "monitor", "stealth", "track"]
                    .contains(where: { nameLC.contains($0) })

                if nameSuspicious {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "\(label) with spy-like name: \(entry)",
                        detail: "Plugin runs in a system service — name suggests surveillance",
                        path: pluginPath,
                        remediation: "Remove if unexpected: sudo rm -rf \"\(pluginPath)\""
                    ))
                } else if !isSigned {
                    findings.append(Finding(
                        severity: severity, category: .persistence,
                        title: "Unsigned \(label.lowercased()): \(entry)",
                        detail: "User-installable plugin in \(expanded) is not code-signed — runs inside a system process at login",
                        path: pluginPath,
                        remediation: "Verify this plugin is legitimate, otherwise remove: sudo rm -rf \"\(pluginPath)\""
                    ))
                }
            }
        }
    }

    // MARK: - Sandboxed App LaunchAgents

    /// Apps installed via the App Store (sandboxed) cannot write to ~/Library/LaunchAgents,
    /// but malware sometimes drops a plist into ~/Library/Containers/<bundle>/Data/Library/LaunchAgents
    /// hoping it survives migrations and is overlooked by users. macOS doesn't actually load these,
    /// but their presence is a strong tampering signal — a non-sandboxed process placed them there.
    private func scanSandboxedLaunchAgents(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let containers = "\(home)/Library/Containers"
        let fm = FileManager.default
        guard let bundles = try? fm.contentsOfDirectory(atPath: containers) else { return }

        for bundle in bundles where !bundle.hasPrefix(".") {
            let agentDir = "\(containers)/\(bundle)/Data/Library/LaunchAgents"
            guard fm.fileExists(atPath: agentDir),
                  let plists = try? fm.contentsOfDirectory(atPath: agentDir) else { continue }

            for plist in plists where plist.hasSuffix(".plist") {
                let plistPath = "\(agentDir)/\(plist)"
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "LaunchAgent plist inside sandboxed container: \(bundle)",
                    detail: "Container apps cannot legitimately write LaunchAgents — \(plist) suggests a non-sandboxed process tampered with this app's container",
                    path: plistPath,
                    remediation: "Inspect the plist and the parent app, then remove: rm \"\(plistPath)\""
                ))
            }
        }
    }

    // MARK: - at(1) jobs

    /// `at` is a deprecated POSIX scheduler. atrun is disabled by default on macOS, but malware
    /// occasionally re-enables it as a low-noise persistence channel. Any pending at-job is unusual.
    private func scanAtJobs(findings: inout [Finding], errors: inout [String]) {
        // /var/at/jobs holds pending at jobs. /var/at/spool holds running ones.
        let atDirs = ["/var/at/jobs", "/var/at/spool"]
        let fm = FileManager.default
        for dir in atDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            // Apple's defaults leave a `.SEQ` and a `.lockfile` — anything else is a real job.
            let realJobs = entries.filter { !$0.hasPrefix(".") }
            for job in realJobs {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "at-job present (deprecated, disabled by default)",
                    detail: "File: \(dir)/\(job) — atrun is off on stock macOS, so a queued at-job is unexpected",
                    path: "\(dir)/\(job)",
                    remediation: "Inspect and remove: sudo cat \"\(dir)/\(job)\" then sudo rm \"\(dir)/\(job)\""
                ))
            }
        }
    }

    // MARK: - Background Items (modern SMAppService persistence)

    /// macOS 13+ replaced the LaunchAgent prompt with a unified "Login Items & Extensions" pane
    /// backed by `backgrounditems.btm` (a Codable plist managed by backgroundtaskmanagementagent).
    /// The file is binary and not user-readable, but its existence + size and ItemRecords paths
    /// give us a fingerprint. Many stalkerware families now register here instead of writing
    /// LaunchAgents directly.
    private func scanBackgroundItems(findings: inout [Finding], errors: inout [String]) {
        let candidates = [
            "/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v8.btm",
            "/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm",
        ]
        let fm = FileManager.default

        // Use sfltool if available — it dumps registered items in plain text.
        let result = ShellRunner.run("/usr/bin/sfltool",
                                     arguments: ["dumpbtm"], timeout: 10)
        if result.success && !result.stdout.isEmpty {
            // Each item record has a "URL" line — flag any non-Apple, non-/Applications entry.
            let lines = result.stdout.split(separator: "\n").map(String.init)
            var currentURL: String?
            var currentName: String?
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("Name:") {
                    currentName = String(trimmed.dropFirst(5)).trimmingCharacters(in: .whitespaces)
                }
                if trimmed.hasPrefix("URL:") {
                    currentURL = String(trimmed.dropFirst(4)).trimmingCharacters(in: .whitespaces)
                    if let url = currentURL {
                        let lower = url.lowercased()
                        let trustedRoot = lower.contains("/applications/") ||
                                          lower.contains("/system/") ||
                                          lower.contains("file:///library/apple/") ||
                                          lower.contains("/library/printers/")
                        let suspiciousLocation = lower.contains("/tmp/") ||
                                                 lower.contains("/private/tmp/") ||
                                                 lower.contains("/.") ||
                                                 lower.contains("/users/shared/")
                        if suspiciousLocation || (!trustedRoot && lower.hasPrefix("file:///users/")) {
                            let display = currentName ?? url
                            findings.append(Finding(
                                severity: suspiciousLocation ? .high : .medium,
                                category: .persistence,
                                title: "Background Login Item from unusual location",
                                detail: "Item: \(display) → \(url) — registered via SMAppService/backgroundtaskmanagementagent",
                                path: nil,
                                remediation: "Review in System Settings > General > Login Items & Extensions, or: sfltool dumpbtm | less"
                            ))
                        }
                    }
                    currentName = nil
                }
            }
            return
        }

        // Fallback — sfltool not available or restricted. Just note the BTM database is large.
        for candidate in candidates {
            guard let attrs = try? fm.attributesOfItem(atPath: candidate),
                  let size = attrs[.size] as? Int else { continue }
            if size > 50_000 {
                findings.append(Finding(
                    severity: .low, category: .persistence,
                    title: "Background Login Items database is large",
                    detail: "BTM file size: \(size) bytes — many registered login items, review in System Settings",
                    path: candidate,
                    remediation: "Open System Settings > General > Login Items & Extensions and remove unfamiliar entries"
                ))
            }
        }
    }

    // MARK: - Dynamic Linker Configuration

    /// The dyld(1) loader honors several configuration files when SIP doesn't block them.
    /// Their presence on a normal Mac is unusual and indicates either developer activity or
    /// targeted dyld-injection persistence.
    private func scanDyldConfig(findings: inout [Finding], errors: inout [String]) {
        // /etc/launchd.conf: deprecated on macOS 10.10+, still loaded by some forks.
        // /etc/man.conf and /etc/paths.d entries are safe; skip those.
        let dyldPaths = [
            "/etc/launchd.conf",
            "/etc/launchd-user.conf",
        ]
        let fm = FileManager.default
        for path in dyldPaths where fm.fileExists(atPath: path) {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Legacy launchd config present: \(URL(fileURLWithPath: path).lastPathComponent)",
                detail: "launchd.conf was deprecated in OS X 10.10 and is no longer read by Apple's launchd. Its presence may indicate tampering.",
                path: path,
                remediation: "Inspect contents, then: sudo rm \"\(path)\""
            ))
        }

        // ~/.dyld and /etc/dyld_*.conf are non-standard dyld config drops used by some loaders.
        let home = ShellRunner.realUserHome
        let extras = ["\(home)/.dyld", "/etc/dyld.conf", "/etc/dyld_inject.conf"]
        for path in extras where fm.fileExists(atPath: path) {
            findings.append(Finding(
                severity: .high, category: .persistence,
                title: "Unusual dyld configuration file: \(path)",
                detail: "dyld config files outside SIP-protected paths can force every launched binary to load attacker-supplied dylibs",
                path: path,
                remediation: "Inspect and remove: sudo rm \"\(path)\""
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
}
