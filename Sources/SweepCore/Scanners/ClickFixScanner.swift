import Foundation

/// Detects indicators of "ClickFix" / "FakeCAPTCHA" / "Paste and Run" social-engineering attacks
/// that surged in 2024-2025. A fake CAPTCHA page copies a malicious shell command to the
/// clipboard and instructs the user to paste it into Terminal or the Cmd+Space "Run" prompt.
/// Payloads typically use `curl | sh`, base64-decoded eval, or osascript stagers.
public final class ClickFixScanner: Scanner {
    public let name = "ClickFix / Social Engineering Scan"
    public init() {}

    /// Regex-lite substring patterns commonly seen in ClickFix payloads. Case-insensitive.
    private let payloadPatterns: [(pattern: String, description: String)] = [
        ("curl -s ", "curl piped to a shell — remote-execute pattern"),
        ("curl -sso", "curl -sSo | sh — remote-execute pattern"),
        ("curl -fssl", "curl -fsSL | sh — remote-execute pattern"),
        ("wget -q ", "wget piped to shell"),
        ("| bash", "pipes remote output into bash"),
        ("| sh", "pipes remote output into sh"),
        ("| zsh", "pipes remote output into zsh"),
        ("base64 -d", "base64 decode — often used to smuggle payloads"),
        ("base64 --decode", "base64 decode — often used to smuggle payloads"),
        ("eval \"$(", "runtime eval of dynamic content"),
        ("eval $(", "runtime eval of dynamic content"),
        ("osascript -e ", "AppleScript one-liner — ClickFix payload channel"),
        ("do shell script", "AppleScript executing a shell command"),
        ("/tmp/update", "known ClickFix drop path"),
        ("/tmp/install", "known ClickFix drop path"),
        ("systemupdate.sh", "fake macOS update script"),
        ("macos-update", "fake macOS update binary"),
    ]

    /// Files that are almost always malicious to have in ~/Downloads. These extensions run
    /// arbitrary code as soon as the user double-clicks and dismisses Gatekeeper.
    private let riskyExecutableExtensions: Set<String> = ["command", "tool"]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning shell history for paste-and-run patterns")
        scanShellHistory(findings: &findings, errors: &errors)

        progress?.update("checking Downloads for risky executables")
        scanDownloadsForCommandFiles(findings: &findings, errors: &errors)

        progress?.update("checking clipboard-driven osascript activity")
        scanRecentOsascriptStagers(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Shell history

    private func scanShellHistory(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.sh_history",
            "\(home)/.local/share/fish/fish_history",
        ]

        for path in historyFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lines = content.components(separatedBy: "\n")

            // Zsh writes lines as `: <epoch>:0;<command>` when EXTENDED_HISTORY is on.
            // Strip the metadata prefix so pattern-matching sees the actual command.
            var commands: [(Int, String)] = []
            for (idx, raw) in lines.enumerated() {
                var line = raw
                if line.hasPrefix(": "), let semi = line.firstIndex(of: ";") {
                    line = String(line[line.index(after: semi)...])
                }
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty {
                    commands.append((idx + 1, trimmed))
                }
            }

            var loggedForFile = Set<String>()  // dedupe on pattern per file
            for (lineNum, cmd) in commands {
                let lower = cmd.lowercased()
                for entry in payloadPatterns {
                    guard lower.contains(entry.pattern) else { continue }
                    // Filter obvious dev-tool false positives on the highest-noise patterns.
                    if entry.pattern == "| sh" || entry.pattern == "| bash" {
                        // A user typing `brew install`-like commands isn't ClickFix. Only flag
                        // when the pipe is preceded by an HTTP fetch on the same line.
                        if !(lower.contains("curl ") || lower.contains("wget ") ||
                             lower.contains("http://") || lower.contains("https://")) {
                            continue
                        }
                    }
                    if loggedForFile.contains(entry.pattern) { continue }
                    loggedForFile.insert(entry.pattern)

                    let severity: Severity = entry.pattern.hasPrefix("/tmp/") ||
                                             entry.pattern.contains("update") ||
                                             entry.pattern.contains("do shell") ? .high : .medium
                    findings.append(Finding(
                        severity: severity, category: .suspiciousProcess,
                        title: "ClickFix-style command in shell history",
                        detail: "Line \(lineNum) of \(URL(fileURLWithPath: path).lastPathComponent) — " +
                            "\(entry.description). Command: \(String(cmd.prefix(140)))",
                        path: path,
                        remediation: "Review \(path). If you didn't run this, treat the Mac as potentially compromised: change passwords, rotate app-specific and API tokens, and inspect ~/.n2, /tmp, and LaunchAgents."
                    ))
                    break
                }
            }
        }
    }

    // MARK: - Downloads folder scan

    private func scanDownloadsForCommandFiles(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let downloads = "\(home)/Downloads"
        let fm = FileManager.default

        guard fm.fileExists(atPath: downloads),
              let entries = try? fm.contentsOfDirectory(atPath: downloads) else { return }

        for name in entries {
            let path = "\(downloads)/\(name)"
            let ext = URL(fileURLWithPath: name).pathExtension.lowercased()
            guard riskyExecutableExtensions.contains(ext) else { continue }

            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let modDate = attrs[.modificationDate] as? Date else { continue }

            // Only surface files younger than 30 days — a `.command` sitting there for years is
            // usually the user's own script; recent ones align with active social-engineering campaigns.
            guard modDate.timeIntervalSinceNow > -86400 * 30 else { continue }

            findings.append(Finding(
                severity: .medium, category: .suspiciousFile,
                title: "Recent .\(ext) file in Downloads",
                detail: "File: \(name) — .command / .tool files auto-execute in Terminal when double-clicked. " +
                    "ClickFix pages often drop these instead of pasting commands.",
                path: path,
                remediation: "Do not double-click. Inspect first: cat \"\(path)\" — delete if unrecognized."
            ))
        }
    }

    // MARK: - Recent osascript stagers

    /// Look for currently-running osascript processes whose command line reveals the classic
    /// "do shell script with administrator privileges" stager pattern. Amos-family variants use
    /// this to elicit a password prompt after a ClickFix paste.
    private func scanRecentOsascriptStagers(findings: inout [Finding], errors: inout [String]) {
        let ps = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,command"], timeout: 5)
        guard ps.success else { return }

        for line in ps.stdout.split(separator: "\n") {
            let lineStr = String(line)
            // We look for osascript invocations that contain shell-script or curl one-liners.
            guard lineStr.contains("osascript") else { continue }
            let lower = lineStr.lowercased()
            let interesting = lower.contains("do shell script") ||
                              lower.contains("curl ") || lower.contains("wget ") ||
                              lower.contains("base64") || lower.contains("| sh") ||
                              lower.contains("administrator privileges")
            guard interesting else { continue }

            let trimmed = lineStr.trimmingCharacters(in: .whitespaces)
            let pid = trimmed.split(separator: " ", maxSplits: 1).first.map(String.init) ?? "?"

            findings.append(Finding(
                severity: .high, category: .suspiciousProcess,
                title: "osascript running a shell/network stager",
                detail: "PID \(pid): \(String(trimmed.prefix(200)))",
                path: nil,
                remediation: "Kill and investigate: kill \(pid); then check ~/.n2/, /tmp/, LaunchAgents"
            ))
        }
    }
}
