import Foundation

/// Detects traces of ClickFix / paste-and-run attacks, where a user is tricked
/// (via a fake CAPTCHA, "verification" dialog, or captured OS prompt) into
/// pasting an attacker-supplied command into Terminal.
///
/// These commands leave forensic evidence in shell history even when the payload
/// they downloaded is long gone. The 2024-2025 wave of AMOS, Atomic, Odyssey,
/// and DPRK-linked infostealer campaigns depend almost entirely on this vector,
/// so shell-history hunting complements the process/persistence scanners: it can
/// surface a compromise that already ran and cleaned itself up.
public final class ShellHistoryScanner: Scanner {
    public let name = "Shell History Scan"
    public init() {}

    // A pattern is (regex-like substring test, human description, severity).
    // We intentionally keep this as case-insensitive substring matching rather
    // than a regex engine — history lines are already lowercased when checked,
    // and substring hits are faster with fewer false-positive regex traps.
    private struct HistoryPattern {
        let needle: String
        let description: String
        let severity: Severity
        let category: FindingCategory
    }

    private let patterns: [HistoryPattern] = [
        // Classic ClickFix — pipe a downloaded script into a shell
        HistoryPattern(
            needle: "curl", description: "downloads content with curl", severity: .low,
            category: .persistence),  // upgraded below when combined with sh/bash
        // Direct remote script execution
        HistoryPattern(
            needle: "bash -c \"$(curl", description: "runs a remote script via curl-pipe-bash — canonical ClickFix pattern",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "bash -c \"$(wget", description: "runs a remote script via wget-pipe-bash",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "sh -c \"$(curl", description: "runs a remote script via curl-pipe-sh",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "| bash", description: "pipes command output into bash — remote-code-exec risk",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "| sh", description: "pipes command output into sh — remote-code-exec risk",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "|sh", description: "pipes command output into sh (no space) — remote-code-exec risk",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "|bash", description: "pipes command output into bash (no space) — remote-code-exec risk",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "eval \"$(curl", description: "evaluates the output of a curl download",
            severity: .high, category: .suspiciousProcess),

        // Fake password prompts (Atomic Stealer / AMOS staple)
        HistoryPattern(
            needle: "osascript -e 'display dialog", description: "AppleScript display dialog — used by stealers to fake password prompts",
            severity: .medium, category: .suspiciousProcess),
        HistoryPattern(
            needle: "with administrator privileges", description: "AppleScript privilege escalation — often used to run malware as root",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "do shell script", description: "AppleScript shell execution — a stealer/dropper hallmark",
            severity: .medium, category: .suspiciousProcess),

        // Direct keychain / credential exfiltration attempts
        HistoryPattern(
            needle: "security dump-keychain", description: "keychain dump attempt — extracts stored passwords",
            severity: .high, category: .permission),
        HistoryPattern(
            needle: "security find-generic-password -w", description: "keychain password extraction attempt",
            severity: .high, category: .permission),
        HistoryPattern(
            needle: "security find-internet-password -w", description: "keychain internet-password extraction attempt",
            severity: .high, category: .permission),

        // Security-bypass commands (rarely typed by legit users outside recovery)
        HistoryPattern(
            needle: "csrutil disable", description: "SIP disable attempt — hostile without Recovery Mode",
            severity: .high, category: .systemIntegrity),
        HistoryPattern(
            needle: "spctl --master-disable", description: "Gatekeeper disable attempt",
            severity: .high, category: .systemIntegrity),
        HistoryPattern(
            needle: "spctl --global-disable", description: "Gatekeeper disable attempt (macOS 15+ flag)",
            severity: .high, category: .systemIntegrity),
        HistoryPattern(
            needle: "xattr -d com.apple.quarantine", description: "quarantine-attribute strip — bypasses Gatekeeper on downloaded file",
            severity: .medium, category: .systemIntegrity),
        HistoryPattern(
            needle: "xattr -c ", description: "extended-attribute clear — often used to strip quarantine",
            severity: .low, category: .systemIntegrity),
        HistoryPattern(
            needle: "nvram boot-args", description: "boot-args tampering — allows kernel-level bypasses",
            severity: .high, category: .systemIntegrity),

        // Payload staging directories used by AMOS-family droppers
        HistoryPattern(
            needle: "chmod +x /tmp/", description: "makes a /tmp file executable — common dropper step",
            severity: .medium, category: .suspiciousFile),
        HistoryPattern(
            needle: "chmod 755 /tmp/", description: "makes a /tmp file executable — common dropper step",
            severity: .medium, category: .suspiciousFile),

        // Base64-encoded shell (obfuscation)
        HistoryPattern(
            needle: "base64 -d | sh", description: "base64 decode piped into a shell — obfuscation",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "base64 -d | bash", description: "base64 decode piped into a shell — obfuscation",
            severity: .high, category: .suspiciousProcess),
        HistoryPattern(
            needle: "base64 --decode | sh", description: "base64 decode piped into a shell — obfuscation",
            severity: .high, category: .suspiciousProcess),

        // TCC-database tampering
        HistoryPattern(
            needle: "tccutil reset", description: "TCC permissions reset — attackers wipe privacy prompts to re-request",
            severity: .medium, category: .permission),

        // Explicit SSH backdoor setup
        HistoryPattern(
            needle: ">> ~/.ssh/authorized_keys", description: "SSH key append — persistent remote-access backdoor",
            severity: .high, category: .persistence),
        HistoryPattern(
            needle: ">>~/.ssh/authorized_keys", description: "SSH key append — persistent remote-access backdoor",
            severity: .high, category: .persistence),
    ]

    /// URLs whose presence in a curl/wget history line boosts severity even when
    /// the destination shell is unclear. Sourced from public reporting on AMOS,
    /// FerretDPRK, and ClickFix landing infrastructure.
    private let knownMaliciousDomains: [String] = [
        "install-mac.com", "macfixerx.com", "macos-install.com",
        "brew-install.com", "install-brew.sh", "installer-mac.com",
        "hxxps://", // deliberately-defanged links copy-pasted from advisories
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        let historyFiles: [(path: String, label: String)] = [
            ("\(home)/.zsh_history", "zsh history"),
            ("\(home)/.bash_history", "bash history"),
            ("\(home)/.local/share/fish/fish_history", "fish history"),
            ("\(home)/.history", "shell history"),
            ("/var/root/.zsh_history", "root zsh history"),
            ("/var/root/.bash_history", "root bash history"),
        ]

        for (path, label) in historyFiles {
            progress?.update("scanning \(label)")
            scanHistoryFile(path: path, label: label, findings: &findings, errors: &errors)
        }

        // Also scan zsh session snapshots — zsh writes per-session .zsh_history-like
        // files under ~/.zsh_sessions when share-history isn't set.
        let sessionsDir = "\(home)/.zsh_sessions"
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: sessionsDir) {
            progress?.update("scanning zsh session snapshots")
            for entry in entries where entry.hasSuffix(".history") || entry.hasSuffix(".historyfile") {
                scanHistoryFile(path: "\(sessionsDir)/\(entry)",
                                label: "zsh session \(entry)",
                                findings: &findings, errors: &errors)
            }
        }

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    private func scanHistoryFile(path: String, label: String, findings: inout [Finding], errors: inout [String]) {
        guard FileManager.default.fileExists(atPath: path),
              let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }

        // Age gate: history files are append-only, so ancient entries drown out recent
        // attacks. We inspect only the tail of the file — enough to catch a recent
        // ClickFix while ignoring years-old shell one-liners the user forgot about.
        let allLines = content.components(separatedBy: "\n")
        let tail = Array(allLines.suffix(2000))

        // Deduplicate: a ClickFix line often gets re-entered when the user rebuilds
        // their history from multiple shells. Report each unique line once per file.
        var reportedNeedles = Set<String>()

        for rawLine in tail {
            // zsh extended history has a ": <timestamp>:<duration>;<command>" prefix — strip it.
            var line = rawLine
            if line.hasPrefix(":") {
                if let semicolon = line.firstIndex(of: ";") {
                    line = String(line[line.index(after: semicolon)...])
                }
            }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            let lower = trimmed.lowercased()

            // Skip lines that are clearly package-manager installers (`brew install …`)
            // rather than raw curl-pipe-bash. These are the biggest false-positive source.
            if lower.hasPrefix("brew install") || lower.hasPrefix("brew upgrade")
                || lower.hasPrefix("brew reinstall") || lower.hasPrefix("brew list") { continue }

            for pattern in patterns {
                guard lower.contains(pattern.needle.lowercased()) else { continue }
                if reportedNeedles.contains(pattern.needle) { continue }
                reportedNeedles.insert(pattern.needle)

                // Boost severity if the same history line also references a known malicious domain
                var severity = pattern.severity
                for domain in knownMaliciousDomains {
                    if lower.contains(domain.lowercased()) && severity < .high {
                        severity = .high
                        break
                    }
                }

                // Suppress standalone curl matches — too noisy on their own. We only
                // want the *combined* piped-into-shell pattern to land.
                if pattern.needle == "curl" && severity == .low { break }

                findings.append(Finding(
                    severity: severity,
                    category: pattern.category,
                    title: "Suspicious command in \(label)",
                    detail: "\(pattern.description) — `\(String(trimmed.prefix(140)))`",
                    path: path,
                    remediation: "Review: tail -n 200 \(path) — if unexpected, treat this Mac as potentially compromised"
                ))
                break  // one finding per line is enough
            }
        }
    }
}
