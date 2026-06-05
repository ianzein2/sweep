import Foundation

/// Detects evidence that the user pasted or ran malicious shell one-liners.
///
/// "ClickFix" / "pastejacking" / fake-CAPTCHA attacks (2024-2025) trick users into copying
/// an obfuscated command to the clipboard and pasting it into Terminal, which then drops a
/// macOS stealer (AMOS, Atomic, FrigidStealer, etc.). The command itself usually survives
/// in shell history — even if the malware later cleans up its dropped files. This scanner
/// surfaces those entries so the user knows what they ran.
public final class ShellHistoryScanner: Scanner {
    public let name = "Shell History Scan"
    public init() {}

    /// Patterns that strongly indicate a drive-by paste — high severity.
    /// Each is a substring match against a single history line (already lowercased).
    private let highSeverityPatterns: [(pattern: String, label: String)] = [
        // Canonical "curl | sh" / "wget | sh" drop-and-run
        ("curl ", "curl piped to a shell"),  // refined further by pipeCheck
        ("wget ", "wget piped to a shell"),
        // base64 -> shell — the obfuscation signature of AMOS-family payloads
        ("base64 -d | sh", "base64-decoded payload piped to shell"),
        ("base64 -d | bash", "base64-decoded payload piped to bash"),
        ("base64 --decode | sh", "base64-decoded payload piped to shell"),
        ("base64 --decode | bash", "base64-decoded payload piped to bash"),
        ("echo \"", "echo-then-pipe-to-shell pattern"),  // refined by pipeCheck
        // AppleScript invoking shell — the AMOS payload delivery vector
        ("osascript -e 'do shell script", "osascript invoking shell"),
        ("osascript -e \"do shell script", "osascript invoking shell"),
        // /tmp drop + execute
        ("chmod +x /tmp/", "made a /tmp file executable"),
        ("chmod 777 /tmp/", "made a /tmp file world-executable"),
        ("chmod +x /private/tmp/", "made a /tmp file executable"),
        // python/python3 -c with import — common stealer staging
        ("python -c \"import", "inline Python launcher"),
        ("python3 -c \"import", "inline Python launcher"),
        ("python -c 'import", "inline Python launcher"),
        ("python3 -c 'import", "inline Python launcher"),
        // eval $(curl ...)
        ("eval $(curl", "eval of remote curl output"),
        ("eval `curl", "eval of remote curl output"),
        ("eval $(wget", "eval of remote wget output"),
        // DYLD_INSERT_LIBRARIES used inline
        ("dyld_insert_libraries=", "DYLD library injection"),
        // launchctl load of a /tmp plist — common backdoor install
        ("launchctl load /tmp/", "loading a launchd job from /tmp"),
        ("launchctl load /private/tmp/", "loading a launchd job from /tmp"),
        // xattr -d on a downloaded binary (clearing quarantine to dodge Gatekeeper)
        ("xattr -d com.apple.quarantine", "removing Gatekeeper quarantine"),
        ("xattr -dr com.apple.quarantine", "removing Gatekeeper quarantine"),
        // spctl bypass
        ("spctl --master-disable", "disabling Gatekeeper system-wide"),
        // killing security tools
        ("sudo killall xprotect", "killing XProtect"),
        // disabling SIP/Gatekeeper-style hardening
        ("csrutil disable", "disabling System Integrity Protection"),
    ]

    /// Patterns worth flagging at medium severity — common in both legit dev workflows
    /// and malware. Surface them so the user can confirm.
    private let mediumSeverityPatterns: [(pattern: String, label: String)] = [
        ("nc -e ", "netcat with -e (reverse shell capability)"),
        ("ncat -e ", "ncat with -e (reverse shell capability)"),
        ("/dev/tcp/", "bash /dev/tcp redirection (reverse shell)"),
        ("mkfifo /tmp/", "FIFO in /tmp (often used for reverse shells)"),
        // ssh-copy-id from non-standard hosts — possible attacker installing access
        // Suppress here; it's too noisy. Left as comment to document intent.
    ]

    /// Hostnames seen in late-2024/2025 ClickFix campaigns. Substring match.
    private let knownClickFixDomains: [String] = [
        // Documented in Proofpoint / Sekoia / Malwarebytes write-ups of FrigidStealer and AMOS lures
        "robotrcaptcha", "captcha-verify", "humansverify", "iam-not-robot",
        "i-am-human", "verifyhuman", "cfcaptcha", "ray-id-",
        "browser-update-fix", "fixbrowser", "browserfix",
        "macshield", "macsafety", "applesupport-helpdesk",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
            "\(home)/.fish_history",
        ]

        progress?.update("scanning shell history for ClickFix / paste attacks")

        for path in historyFiles {
            guard FileManager.default.fileExists(atPath: path),
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let fileName = URL(fileURLWithPath: path).lastPathComponent
            scanHistoryContent(content, fileName: fileName, path: path, findings: &findings)
        }

        // Also inspect /var/log/asl/ or `log show` last day for a defaults write to LoginItems
        // that came from Terminal — a common malware trick. Cheap to do.
        progress?.update("checking recent Terminal activity for persistence writes")
        scanForRecentPersistenceCommands(findings: &findings)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: [],
            duration: Date().timeIntervalSince(start)
        )
    }

    private func scanHistoryContent(_ content: String, fileName: String, path: String,
                                    findings: inout [Finding]) {
        let lines = content.components(separatedBy: "\n")

        // zsh extended history prefixes each line with ": <epoch>:<duration>;<cmd>"
        // Strip that so the pattern matchers see just the command.
        let stripped = lines.map { line -> String in
            if line.hasPrefix(": "), let semi = line.firstIndex(of: ";") {
                return String(line[line.index(after: semi)...])
            }
            return line
        }

        var seenPatterns = Set<String>()  // dedupe per-file

        for (idx, raw) in stripped.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            let lower = trimmed.lowercased()

            // ClickFix domain detection runs first — when the host matches a known lure
            // the whole command is "high" no matter what shape it takes.
            if let kw = knownClickFixDomains.first(where: { lower.contains($0) }) {
                let key = "clickfix:\(kw)"
                if !seenPatterns.contains(key) {
                    seenPatterns.insert(key)
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "ClickFix-style domain in shell history (\(fileName))",
                        detail: "Line \(idx + 1) contains \"\(kw)\" — \(truncate(trimmed))",
                        path: path,
                        remediation: "If you pasted a command from a CAPTCHA / browser-update prompt, treat this Mac as compromised: rotate keychain passwords, then run a full scan"
                    ))
                }
                continue
            }

            // High-severity pattern matches
            for entry in highSeverityPatterns {
                guard lower.contains(entry.pattern) else { continue }

                // For "curl " / "wget " / "echo " we only care if they pipe into a shell.
                let needsPipeCheck = entry.pattern == "curl " ||
                                     entry.pattern == "wget " ||
                                     entry.pattern == "echo \""
                if needsPipeCheck && !isPipingToShell(lower) { continue }

                let key = "high:\(entry.pattern)"
                if seenPatterns.contains(key) { break }
                seenPatterns.insert(key)

                findings.append(Finding(
                    severity: .high, category: .suspiciousProcess,
                    title: "Suspicious command in \(fileName): \(entry.label)",
                    detail: "Line \(idx + 1): \(truncate(trimmed))",
                    path: path,
                    remediation: "Review the full command — if you don't recognize it, you may have pasted a malicious payload from a fake CAPTCHA / update prompt. Inspect with: grep -n '\(escapeForGrep(entry.pattern))' \"\(path)\""
                ))
                break  // one finding per line
            }

            // Medium-severity pattern matches
            for entry in mediumSeverityPatterns {
                guard lower.contains(entry.pattern) else { continue }
                let key = "medium:\(entry.pattern)"
                if seenPatterns.contains(key) { break }
                seenPatterns.insert(key)

                findings.append(Finding(
                    severity: .medium, category: .suspiciousProcess,
                    title: "Reverse-shell-shaped command in \(fileName)",
                    detail: "Line \(idx + 1): \(entry.label) — \(truncate(trimmed))",
                    path: path,
                    remediation: "Confirm you ran this intentionally (security testing). Otherwise treat as compromise indicator."
                ))
                break
            }
        }
    }

    /// A command pipes to a shell if it contains `| sh`, `| bash`, `| zsh`, or `| /bin/sh` etc.
    private func isPipingToShell(_ line: String) -> Bool {
        let needles = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh",
                       "| /bin/sh", "| /bin/bash", "| /bin/zsh",
                       "|/bin/sh", "|/bin/bash", "|/bin/zsh"]
        return needles.contains(where: { line.contains($0) })
    }

    private func truncate(_ s: String, maxLen: Int = 140) -> String {
        if s.count <= maxLen { return s }
        return String(s.prefix(maxLen)) + "…"
    }

    /// Single-quotes the pattern so the remediation grep is safe to copy-paste.
    private func escapeForGrep(_ s: String) -> String {
        return s.replacingOccurrences(of: "'", with: "'\"'\"'")
    }

    // MARK: - Recent Persistence Commands

    /// Looks at the unified log for the last 24h for shell-spawned `defaults write` /
    /// `launchctl load` / `chflags hidden` invocations — classic ClickFix follow-ups.
    /// Querying the log is cheaper than parsing every shell history file but only catches
    /// commands run via login shells in that window.
    private func scanForRecentPersistenceCommands(findings: inout [Finding]) {
        let predicate = "process == \"Terminal\" OR process == \"iTerm2\" OR process == \"WezTerm\" OR process == \"kitty\" OR process == \"Alacritty\""
        let result = ShellRunner.run("/usr/bin/log", arguments: [
            "show", "--last", "1d", "--style", "compact",
            "--predicate", predicate,
        ], timeout: 8)
        guard result.success, !result.stdout.isEmpty else { return }

        let watchedSubcommands: [(needle: String, label: String)] = [
            ("LoginHook", "writing a LoginHook"),
            ("LogoutHook", "writing a LogoutHook"),
            ("launchctl load", "loading a launchd job"),
            ("chflags hidden", "hiding a file with chflags"),
        ]

        // We only emit one finding per match needle to avoid spamming on duplicate log lines.
        var seen = Set<String>()
        for line in result.stdout.split(separator: "\n") {
            let lineStr = String(line)
            for sub in watchedSubcommands where lineStr.contains(sub.needle) {
                if seen.contains(sub.needle) { continue }
                seen.insert(sub.needle)
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Terminal recently used to modify persistence: \(sub.label)",
                    detail: "Recent log line: \(truncate(lineStr.trimmingCharacters(in: .whitespaces)))",
                    path: nil,
                    remediation: "If you didn't run this in the last 24h, investigate — this is a ClickFix follow-up shape. Review with: log show --last 1d --predicate 'process == \"Terminal\"' | grep \(sub.needle)"
                ))
            }
        }
    }
}
