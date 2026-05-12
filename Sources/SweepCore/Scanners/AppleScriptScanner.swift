import Foundation

/// Detects AppleScript / `osascript` abuse — the dominant initial-access and
/// credential-harvesting vector used by modern macOS infostealers (AMOS, Banshee,
/// Poseidon, Cthulhu, Realst) and DPRK families (BeaverTail, NimDoor, FlexibleFerret).
///
/// Most of these families ship a single compiled `.scpt` that pops a fake
/// "type your password" dialog via `display dialog` and pipes the result to
/// `do shell script ... with administrator privileges`. The script itself is then
/// staged in /tmp, /var/tmp, or a hidden dir under ~/Library; persistence
/// is usually a Folder Action or a Launch Agent that re-invokes osascript.
public final class AppleScriptScanner: Scanner {
    public let name = "AppleScript Scan"
    public init() {}

    /// Strings that, when present inside a `.scpt`/`.applescript` source, strongly
    /// indicate a credential-grabbing or stealer-style payload. Compiled scripts
    /// (binary AEScript) still embed these literals readable via `osadecompile`,
    /// but a `strings` pass over the raw bytes is fast and good enough for IOCs.
    private let stealerPhrases: [(needle: String, reason: String)] = [
        ("display dialog \"macOS needs", "fake macOS password prompt"),
        ("display dialog \"System Preferences", "fake System Preferences prompt"),
        ("display dialog \"Please enter your password", "fake password prompt"),
        ("display dialog \"To allow", "fake permission prompt"),
        ("with hidden answer", "captures a password into a variable"),
        ("with administrator privileges", "elevates to root via the user"),
        ("do shell script \"curl", "downloads and runs remote code"),
        ("do shell script \"wget", "downloads and runs remote code"),
        ("do shell script \"osascript -e", "nested osascript (obfuscation)"),
        ("do shell script \"echo .* | base64", "decodes a hidden payload"),
        ("security find-generic-password", "reads keychain secrets"),
        ("security dump-keychain", "dumps the keychain"),
        ("security 2>&1 > /dev/null", "redirects security output (hiding theft)"),
        ("metaMask", "targets MetaMask wallet"),
        ("Exodus.app", "targets Exodus wallet"),
        ("Keychains/login.keychain-db", "copies the login keychain"),
        ("Local State", "copies Chromium master key"),
    ]

    /// Locations under which legitimate macOS / homebrew / app-bundle AppleScripts live.
    /// Anything outside these — especially compiled .scpt files in /tmp — is suspect.
    private let legitScriptRoots: [String] = [
        "/System/", "/Library/Application Support/iLifeAssetManagement/",
        "/Library/Scripts/",
        "/Applications/", "/usr/", "/opt/homebrew/", "/usr/local/",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        // 1. Compiled / source AppleScripts staged in temp or hidden dirs.
        progress?.update("scanning for staged AppleScripts")
        scanStagedScripts(home: home, findings: &findings, errors: &errors)

        // 2. Folder Action scripts — runs when a target dir is modified.
        progress?.update("checking Folder Actions")
        scanFolderActions(home: home, findings: &findings, errors: &errors)

        // 3. Launch Agents that invoke osascript / AppleScript directly.
        progress?.update("checking osascript launch agents")
        scanOsascriptLaunchAgents(findings: &findings, errors: &errors)

        // 4. Login Item .app bundles that are actually script applets.
        progress?.update("checking script applets in login items")
        scanScriptApplets(home: home, findings: &findings, errors: &errors)

        // 5. Running osascript processes that look like fake password prompts.
        progress?.update("checking running osascript processes")
        scanRunningOsascript(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - 1. Staged scripts

    private func scanStagedScripts(home: String, findings: inout [Finding], errors: inout [String]) {
        let stagingRoots = [
            "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp",
            "\(home)/Library/Application Support",
            "\(home)/Library/Caches",
            "\(home)/.local", "\(home)/.config",
        ]

        let scriptExtensions: Set<String> = ["scpt", "applescript", "scptd"]

        let fm = FileManager.default
        for root in stagingRoots {
            guard fm.fileExists(atPath: root),
                  let enumerator = fm.enumerator(
                    at: URL(fileURLWithPath: root),
                    includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey, .isRegularFileKey],
                    options: [.skipsPackageDescendants]
                  ) else { continue }

            for case let url as URL in enumerator {
                if enumerator.level > 5 {
                    enumerator.skipDescendants()
                    continue
                }
                let ext = url.pathExtension.lowercased()
                guard scriptExtensions.contains(ext) else { continue }

                // Real apps ship their own .scpt under their bundle — skip those.
                if isInsideAppBundle(url.path) { continue }

                let isHidden = url.path.split(separator: "/").contains { $0.hasPrefix(".") }
                let isTemp = url.path.hasPrefix("/tmp") || url.path.hasPrefix("/private/tmp") ||
                             url.path.hasPrefix("/var/tmp") || url.path.hasPrefix("/private/var/tmp")

                // A compiled or source AppleScript anywhere in /tmp is essentially never legitimate.
                // In ~/Library, only the hidden-dir variant is suspicious.
                guard isTemp || isHidden else { continue }

                let scanResult = scanScriptContent(at: url.path)
                let modDate = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                    .contentModificationDate

                if let phrase = scanResult.matchedPhrase {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Malicious-looking AppleScript staged in \(isTemp ? "temp" : "hidden") directory",
                        detail: "File: \(url.lastPathComponent) — \(phrase.reason)" +
                            (modDate.map { ", modified \(formatAge($0))" } ?? ""),
                        path: url.path,
                        remediation: "Inspect with: osadecompile \"\(url.path)\" — delete after review"
                    ))
                } else {
                    // No known phrase, but presence alone is unusual — stealers sometimes
                    // ship custom obfuscated scripts that wouldn't match the phrase list.
                    findings.append(Finding(
                        severity: isTemp ? .medium : .low,
                        category: .suspiciousFile,
                        title: "AppleScript in unexpected location: \(url.lastPathComponent)",
                        detail: "Path: \(url.path)" + (modDate.map { ", modified \(formatAge($0))" } ?? ""),
                        path: url.path,
                        remediation: "Decompile and review: osadecompile \"\(url.path)\""
                    ))
                }
            }
        }
    }

    // MARK: - 2. Folder Actions (osascript persistence)

    private func scanFolderActions(home: String, findings: inout [Finding], errors: inout [String]) {
        // Folder Actions hook scripts to filesystem events without LaunchAgents.
        // They live in ~/Library/Workflows/Applications/Folder Actions/ and the binding
        // is recorded in ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist.
        let dispatcherPlist = "\(home)/Library/Preferences/com.apple.FolderActionsDispatcher.plist"
        if let data = FileManager.default.contents(atPath: dispatcherPlist),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            // We don't enumerate every binding — just flag that any are present, since
            // Folder Actions are an extremely rare legitimate user feature.
            let enabled = (plist["FolderActionsEnabled"] as? Bool) ?? false
            if enabled {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Folder Actions dispatcher is enabled",
                    detail: "Scripts can be triggered automatically when target folders are modified",
                    path: dispatcherPlist,
                    remediation: "Review in Script Editor > File > Folder Actions Setup, or disable: defaults write com.apple.FolderActionsDispatcher FolderActionsEnabled -bool false"
                ))
            }
        }

        // Any user-added scripts in the Folder Actions directory are unusual; stock macOS
        // ships ~10 scripts under /Library/Scripts/Folder Action Scripts/ but the user
        // directory is empty by default.
        let userFolderActionsDir = "\(home)/Library/Scripts/Folder Action Scripts"
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: userFolderActionsDir) {
            for entry in entries where !entry.hasPrefix(".") {
                let path = "\(userFolderActionsDir)/\(entry)"
                let scanResult = scanScriptContent(at: path)
                if let phrase = scanResult.matchedPhrase {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Folder Action script contains suspicious payload",
                        detail: "Script: \(entry) — \(phrase.reason)",
                        path: path,
                        remediation: "Remove via Script Editor > Folder Actions Setup, then delete: rm \"\(path)\""
                    ))
                } else {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "Custom Folder Action script present",
                        detail: "Script: \(entry) — Folder Actions are a stealthy persistence channel",
                        path: path,
                        remediation: "Verify you added this script intentionally"
                    ))
                }
            }
        }
    }

    // MARK: - 3. LaunchAgent / LaunchDaemon plists that invoke osascript

    private func scanOsascriptLaunchAgents(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let launchDirs = [
            "\(home)/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]

        let fm = FileManager.default
        for dir in launchDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries where entry.hasSuffix(".plist") {
                let path = "\(dir)/\(entry)"
                guard let data = fm.contents(atPath: path),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { continue }

                let label = plist["Label"] as? String ?? entry
                if label.hasPrefix("com.apple.") { continue }

                // Gather every arg into a single string for keyword matching.
                var allArgs: [String] = []
                if let program = plist["Program"] as? String { allArgs.append(program) }
                if let args = plist["ProgramArguments"] as? [String] { allArgs.append(contentsOf: args) }
                let joined = allArgs.joined(separator: " ")
                let lower = joined.lowercased()

                let invokesOsascript = lower.contains("osascript") ||
                                       lower.contains("/usr/bin/osa") ||
                                       lower.contains("automator") && lower.contains("workflow")
                guard invokesOsascript else { continue }

                // osascript -e with `do shell script` is the canonical eval-on-launch pattern.
                let hasInlineShell = lower.contains("-e") &&
                    (lower.contains("do shell script") || lower.contains("display dialog") ||
                     lower.contains("system events"))

                findings.append(Finding(
                    severity: hasInlineShell ? .high : .medium,
                    category: .persistence,
                    title: hasInlineShell
                        ? "LaunchAgent runs inline AppleScript on every login"
                        : "LaunchAgent invokes osascript",
                    detail: "Label: \(label), Command: \(String(joined.prefix(160)))",
                    path: path,
                    remediation: "Review the plist and remove if not intentional: cat \"\(path)\""
                ))
            }
        }
    }

    // MARK: - 4. Script applets disguised as apps

    private func scanScriptApplets(home: String, findings: inout [Finding], errors: inout [String]) {
        // Script applets (.app bundles built by Script Editor / osacompile) have a
        // recognizable structure: Contents/Resources/Scripts/main.scpt and
        // CFBundleExecutable = "applet". They masquerade as regular apps but their entire
        // payload is an AppleScript that can do arbitrary `do shell script` calls.
        //
        // We focus on applets that have registered themselves as Login Items via
        // ~/Library/LaunchAgents (caught above) or are sitting in unusual locations
        // like /tmp or ~/Downloads.
        let suspiciousAppRoots = [
            "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp",
            "\(home)/Downloads",
            "\(home)/Library/Application Support",
        ]

        let fm = FileManager.default
        for root in suspiciousAppRoots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

            for entry in entries where entry.hasSuffix(".app") {
                let appPath = "\(root)/\(entry)"
                let scriptPath = "\(appPath)/Contents/Resources/Scripts/main.scpt"
                let infoPlist = "\(appPath)/Contents/Info.plist"

                guard fm.fileExists(atPath: scriptPath) else { continue }

                // Is the bundle executable the AppleScript runtime (`applet`)?
                var isApplet = false
                if let data = fm.contents(atPath: infoPlist),
                   let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                   let exec = plist["CFBundleExecutable"] as? String {
                    isApplet = exec == "applet" || exec == "droplet"
                }
                guard isApplet else { continue }

                let scanResult = scanScriptContent(at: scriptPath)
                let inTemp = root.hasPrefix("/tmp") || root.hasPrefix("/private/tmp") ||
                             root.hasPrefix("/var/tmp")

                let severity: Severity = scanResult.matchedPhrase != nil ? .high
                    : inTemp ? .high : .medium

                let detail: String
                if let phrase = scanResult.matchedPhrase {
                    detail = "Bundle: \(entry) — \(phrase.reason)"
                } else {
                    detail = "Bundle: \(entry) in \(root) — Script-based .app in an unusual location"
                }

                findings.append(Finding(
                    severity: severity, category: .suspiciousFile,
                    title: "AppleScript applet disguised as an .app bundle",
                    detail: detail,
                    path: appPath,
                    remediation: "Decompile: osadecompile \"\(scriptPath)\" — delete the .app if not yours"
                ))
            }
        }
    }

    // MARK: - 5. Running osascript with stealer-flavored args

    private func scanRunningOsascript(findings: inout [Finding], errors: inout [String]) {
        // ps -axo args lets us see the full -e payload passed to osascript at launch.
        let result = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,comm,args"], timeout: 5)
        guard result.success else { return }

        let lines = result.stdout.split(separator: "\n")
        let myPid = "\(ProcessInfo.processInfo.processIdentifier)"
        let realHome = ShellRunner.realUserHome

        for line in lines {
            let lineStr = String(line)
            guard lineStr.contains("osascript") else { continue }
            // Skip ourselves (parent app may legitimately spawn osascript).
            if lineStr.contains(myPid) { continue }
            // Skip osadecompile/Script Editor invocations
            if lineStr.contains("osadecompile") { continue }

            let lower = lineStr.lowercased()

            // Highest-confidence: literal credential-prompt phrasing in argv.
            let promptPhrases = [
                "type your password", "macos needs", "system preferences",
                "please enter your password", "to allow", "system update needs",
            ]
            let hasFakePrompt = promptPhrases.contains(where: { lower.contains($0) })
            let stealsKeychain = lower.contains("security") &&
                (lower.contains("dump-keychain") || lower.contains("find-generic-password"))
            let downloadsAndRuns = (lower.contains("curl ") || lower.contains("wget ")) &&
                (lower.contains("| sh") || lower.contains("|sh") ||
                 lower.contains("| bash") || lower.contains("|bash"))

            // Note: osascript invocations referencing /tmp or hidden paths in the user's
            // home are also a stealer hallmark.
            let pointsAtTemp = lower.contains("/tmp/") || lower.contains("/var/tmp/")
            let pointsAtHidden = lineStr.contains(realHome + "/.") &&
                !lineStr.contains(realHome + "/.config") &&
                !lineStr.contains(realHome + "/.cache")

            guard hasFakePrompt || stealsKeychain || downloadsAndRuns ||
                  pointsAtTemp || pointsAtHidden else { continue }

            // Pull PID for kill suggestion.
            let parts = lineStr.trimmingCharacters(in: .whitespaces)
                .split(separator: " ", omittingEmptySubsequences: true)
            let pid = parts.first.map(String.init) ?? "?"

            var reason = ""
            if hasFakePrompt { reason = "displays a fake macOS password prompt" }
            else if stealsKeychain { reason = "is dumping the keychain" }
            else if downloadsAndRuns { reason = "downloads and pipes code to a shell" }
            else if pointsAtTemp { reason = "is running a script from a temp directory" }
            else { reason = "is running a script from a hidden directory" }

            findings.append(Finding(
                severity: .high, category: .suspiciousProcess,
                title: "Suspicious osascript invocation in progress",
                detail: "PID \(pid) — \(reason). Args: \(String(lineStr.prefix(200)))",
                path: nil,
                remediation: "Investigate immediately: ps -o args= -p \(pid) — then kill if unexpected: kill \(pid)"
            ))
        }
    }

    // MARK: - Helpers

    private struct ScriptScanResult {
        let matchedPhrase: (needle: String, reason: String)?
    }

    /// Scan a script file for stealer fingerprints. Works on both source `.applescript`
    /// and compiled `.scpt` because we read raw bytes — compiled scripts embed literals.
    private func scanScriptContent(at path: String) -> ScriptScanResult {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path),
                                   options: [.mappedIfSafe]) else {
            return ScriptScanResult(matchedPhrase: nil)
        }
        // Cap reads to 2MB — real stealer payloads are kilobytes.
        let bytes = data.prefix(2_000_000)
        // Try UTF-8 first, fall back to lossy ASCII for compiled scripts (binary AEScript).
        let raw = String(data: bytes, encoding: .utf8) ??
                  String(data: bytes, encoding: .ascii) ?? ""
        let lower = raw.lowercased()
        for phrase in stealerPhrases where lower.contains(phrase.needle.lowercased()) {
            return ScriptScanResult(matchedPhrase: phrase)
        }
        return ScriptScanResult(matchedPhrase: nil)
    }

    /// Treat a path as legitimate if any of its parents is one of `legitScriptRoots`.
    private func isInsideAppBundle(_ path: String) -> Bool {
        // Application bundles legitimately embed `.scpt` files. Everything inside
        // an .app under a trusted prefix is considered legitimate.
        for root in legitScriptRoots where path.hasPrefix(root) {
            if path.contains(".app/") { return true }
        }
        return false
    }

    private func formatAge(_ date: Date) -> String {
        let seconds = -date.timeIntervalSinceNow
        if seconds < 3600 { return "\(Int(seconds / 60))m ago" }
        if seconds < 86400 { return "\(Int(seconds / 3600))h ago" }
        return "\(Int(seconds / 86400))d ago"
    }
}
