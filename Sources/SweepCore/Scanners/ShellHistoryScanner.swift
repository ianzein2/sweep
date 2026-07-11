import Foundation

/// Scans shell history for pasted-command attacks — the dominant macOS delivery vector
/// of 2024-2026 (ClickFix / FakeCAPTCHA / FakeUpdate). A malicious website copies a shell
/// command into the clipboard and instructs the victim to paste it into Terminal. If the
/// victim did, the command lands in the shell's history file — where we can find it after
/// the fact even if the malware itself has already cleaned up.
///
/// This scanner does NOT execute anything from history; it only reads history files that
/// the shell writes on every command.
public final class ShellHistoryScanner: Scanner {
    public let name = "Shell History Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning zsh / bash history")
        scanZshBashHistory(findings: &findings, errors: &errors)

        progress?.update("scanning fish history")
        scanFishHistory(findings: &findings, errors: &errors)

        progress?.update("scanning python / node REPL history")
        scanReplHistory(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Detection patterns

    /// Regex-free substring patterns. Each is a strong indicator on its own, and all are
    /// case-insensitive at match time. Anchoring by literal substring keeps the scanner
    /// fast on multi-megabyte history files.
    private struct ClickFixPattern {
        let substrings: [String]
        let severity: Severity
        let title: String
        let detail: String
    }

    /// Patterns ordered from highest confidence to lowest. Multi-substring rules require
    /// ALL substrings on the same line to fire — that keeps the false-positive rate low.
    private var patterns: [ClickFixPattern] {
        [
            // curl | sh with a suspicious top-level domain is the canonical ClickFix payload
            ClickFixPattern(
                substrings: ["curl", "| sh"],
                severity: .high,
                title: "curl piped straight to sh in shell history",
                detail: "Downloading remote code and executing it in one step — the canonical ClickFix payload"
            ),
            ClickFixPattern(
                substrings: ["curl", "|sh"],
                severity: .high,
                title: "curl piped straight to sh in shell history",
                detail: "Downloading remote code and executing it in one step"
            ),
            ClickFixPattern(
                substrings: ["curl", "| bash"],
                severity: .high,
                title: "curl piped to bash in shell history",
                detail: "Downloading remote code and executing it in one step"
            ),
            ClickFixPattern(
                substrings: ["curl", "|bash"],
                severity: .high,
                title: "curl piped to bash in shell history",
                detail: "Downloading remote code and executing it in one step"
            ),
            ClickFixPattern(
                substrings: ["curl", "| zsh"],
                severity: .high,
                title: "curl piped to zsh in shell history",
                detail: "Downloading remote code and executing it in one step"
            ),
            ClickFixPattern(
                substrings: ["wget", "| sh"],
                severity: .high,
                title: "wget piped straight to sh in shell history",
                detail: "Downloading remote code and executing it in one step"
            ),
            ClickFixPattern(
                substrings: ["wget", "| bash"],
                severity: .high,
                title: "wget piped to bash in shell history",
                detail: "Downloading remote code and executing it in one step"
            ),
            // Base64 payloads decoded straight into a shell — DPRK / AMOS campaigns rely on this.
            ClickFixPattern(
                substrings: ["base64", "-d", "| sh"],
                severity: .high,
                title: "Base64-decoded payload piped to sh",
                detail: "A base64 blob decoded straight into a shell is a classic obfuscated dropper"
            ),
            ClickFixPattern(
                substrings: ["base64", "--decode", "| bash"],
                severity: .high,
                title: "Base64-decoded payload piped to bash",
                detail: "A base64 blob decoded straight into a shell is a classic obfuscated dropper"
            ),
            ClickFixPattern(
                substrings: ["base64", "-d", "|bash"],
                severity: .high,
                title: "Base64-decoded payload piped to bash",
                detail: "A base64 blob decoded straight into a shell is a classic obfuscated dropper"
            ),
            // AMOS / Poseidon variants prompt for the login password via AppleScript.
            ClickFixPattern(
                substrings: ["osascript", "display dialog", "password"],
                severity: .high,
                title: "AppleScript password prompt in shell history",
                detail: "AMOS and its clones display a fake password dialog to harvest the login password"
            ),
            // eval $(curl ...) — one-liner remote code execution
            ClickFixPattern(
                substrings: ["eval", "$(curl"],
                severity: .high,
                title: "eval of a remote curl in shell history",
                detail: "Evaluating a remote script inline — no artifact on disk, hard to audit"
            ),
            ClickFixPattern(
                substrings: ["eval", "$(wget"],
                severity: .high,
                title: "eval of a remote wget in shell history",
                detail: "Evaluating a remote script inline"
            ),
            // Explicit FakeCAPTCHA / "verify you're human" strings observed in real payloads
            ClickFixPattern(
                substrings: ["verify_human"],
                severity: .high,
                title: "\"verify_human\" ClickFix marker in shell history",
                detail: "This filename is used by ClickFix / FakeCAPTCHA drops — you likely pasted a command from a malicious site"
            ),
            ClickFixPattern(
                substrings: ["captcha_verify"],
                severity: .high,
                title: "\"captcha_verify\" ClickFix marker in shell history",
                detail: "This filename is used by ClickFix / FakeCAPTCHA drops"
            ),
            ClickFixPattern(
                substrings: ["mshta"],
                severity: .high,
                title: "mshta reference in shell history",
                detail: "mshta is a Windows LOLBin often copied by attackers into cross-platform ClickFix payloads — its presence here suggests a botched paste from a Windows-targeted campaign"
            ),
            // Downloading executables to /tmp and running them
            ClickFixPattern(
                substrings: ["chmod", "+x", "/tmp/"],
                severity: .medium,
                title: "chmod +x on a /tmp binary",
                detail: "Making a temp-directory file executable is a common dropper step"
            ),
            // Recovery of a keychain / SSH key via unusual commands
            ClickFixPattern(
                substrings: ["security", "dump-keychain"],
                severity: .high,
                title: "security dump-keychain in shell history",
                detail: "Dumping the login keychain extracts every stored password — you would not do this by accident"
            ),
            ClickFixPattern(
                substrings: ["dd", "if=/dev/", "of=/dev/"],
                severity: .medium,
                title: "Raw disk copy in shell history",
                detail: "A dd from one device to another can indicate offline disk imaging"
            ),
        ]
    }

    // MARK: - Zsh / Bash history

    private func scanZshBashHistory(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.sh_history",
            "\(home)/.history",
        ]

        for file in historyFiles {
            guard FileManager.default.fileExists(atPath: file) else { continue }
            guard let content = try? String(contentsOfFile: file, encoding: .utf8) else {
                // zsh writes an extended history format that isn't always valid UTF-8 — try latin1 as a fallback.
                guard let data = FileManager.default.contents(atPath: file),
                      let latin = String(data: data, encoding: .isoLatin1) else { continue }
                scanContent(latin, file: file, findings: &findings)
                continue
            }
            scanContent(content, file: file, findings: &findings)
        }
    }

    // MARK: - Fish history

    private func scanFishHistory(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let file = "\(home)/.local/share/fish/fish_history"
        guard FileManager.default.fileExists(atPath: file),
              let content = try? String(contentsOfFile: file, encoding: .utf8) else { return }
        // fish stores YAML-ish entries: `- cmd: ...`. Substring matching still works.
        scanContent(content, file: file, findings: &findings)
    }

    // MARK: - Python / Node REPL history

    private func scanReplHistory(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // .python_history / .node_repl_history rarely contain shell commands, but Python's
        // os.system("curl … | sh") is a real pattern in DPRK Contagious Interview payloads.
        let files = [
            "\(home)/.python_history",
            "\(home)/.node_repl_history",
            "\(home)/.psql_history",
        ]
        for file in files {
            guard FileManager.default.fileExists(atPath: file),
                  let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
            scanContent(content, file: file, findings: &findings)
        }
    }

    // MARK: - Core matching

    private func scanContent(_ content: String, file: String, findings: inout [Finding]) {
        // Cap the number of findings per file — one confirmed ClickFix paste is enough to alert.
        // Duplicating the same hit dozens of times just spams the report.
        var reported = Set<String>()
        let lines = content.split(separator: "\n", omittingEmptySubsequences: false)

        // Hoist patterns and pre-lowercased substrings out of the per-line loop.
        // Otherwise we'd rebuild the pattern list and re-lowercase every substring
        // for every line of a potentially multi-megabyte history file.
        let compiledPatterns: [(pattern: ClickFixPattern, lowered: [String])] = patterns.map {
            ($0, $0.substrings.map { s in s.lowercased() })
        }

        for (lineNum, rawLine) in lines.enumerated() {
            let line = String(rawLine)
            // Zsh extended history prefixes each command with ": <ts>:<duration>;". Strip it
            // so the match is against the actual command text.
            let command: String = {
                if line.hasPrefix(":") {
                    if let semi = line.firstIndex(of: ";") {
                        return String(line[line.index(after: semi)...])
                    }
                }
                return line
            }()
            let lowered = command.lowercased()
            if lowered.count < 6 { continue }

            for entry in compiledPatterns {
                let pattern = entry.pattern
                if entry.lowered.allSatisfy({ lowered.contains($0) }) {
                    let dedupeKey = pattern.title + "|" + file
                    if reported.contains(dedupeKey) { break }
                    reported.insert(dedupeKey)

                    let snippet = String(command.trimmingCharacters(in: .whitespaces).prefix(140))
                    findings.append(Finding(
                        severity: pattern.severity,
                        category: .suspiciousProcess,
                        title: pattern.title,
                        detail: "\(pattern.detail) — line \(lineNum + 1) of \(URL(fileURLWithPath: file).lastPathComponent): \(snippet)",
                        path: file,
                        remediation: "Inspect: grep -n \"\(pattern.substrings.first ?? "")\" \(file) — if you did not run this, rotate keychain / SSH / browser passwords and investigate the source of the paste"
                    ))
                    break
                }
            }
        }
    }
}
