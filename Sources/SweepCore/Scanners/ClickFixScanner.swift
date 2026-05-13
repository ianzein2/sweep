import Foundation

/// Detects evidence of "ClickFix" / "FakeCAPTCHA" / fake-terminal-paste social engineering
/// attacks that exploded as a delivery vector for macOS infostealers in late 2024 and 2025.
///
/// The attack tricks a user into copying a one-liner from a malicious page (a fake
/// "verify you are human" prompt or fake browser-update banner) and pasting it into
/// Terminal. The payload is almost always a `curl ... | sh` / `osascript -e ...`
/// command that pulls down stage-two malware (AMOS, Banshee, FrigidStealer, Poseidon,
/// Cuckoo, etc.).
///
/// Because the user opens Terminal themselves, the action leaves no LaunchAgent, plist,
/// or process tree to find by the time Sweep runs. The forensic remnants live in:
///   1. Shell history files (~/.zsh_history, ~/.bash_history) — usually still there.
///   2. Terminal's saved-state files (recent commands echoed back on relaunch).
///   3. /tmp scripts that were downloaded but already executed.
///   4. AppleScript transient files left in /private/tmp/.
public final class ClickFixScanner: Scanner {
    public let name = "ClickFix / Fake Terminal Paste Scan"
    public init() {}

    // Highly specific IOC patterns. Each entry is a substring (lowercased) and a short
    // description that goes into the finding. Patterns are conservative — we want to
    // strongly hint at "user pasted an attack one-liner" rather than catch every curl.
    private let pastePatterns: [(pattern: String, description: String, severity: Severity)] = [
        // Direct download-and-execute one-liners (very high confidence)
        ("curl -fsso", "curl downloading and piping a script to a shell — classic drop-and-run", .high),
        ("curl -sso", "curl downloading and piping a script to a shell", .high),
        ("curl -ssl", "curl downloading silently — often paired with | sh", .high),
        ("curl -o-", "curl outputting to stdout — typically piped to sh / bash", .high),
        ("curl -sl", "curl silent download — usually piped to a shell", .high),
        ("wget -q -o -", "wget silent download to stdout — usually piped to a shell", .high),
        // The single most-reused AMOS / Atomic Stealer one-liner (osascript prompt for password)
        ("osascript -e 'display dialog \"macos needs to access", "AMOS/Atomic Stealer password-prompt one-liner", .high),
        ("osascript -e \"display dialog \\\"macos needs to access", "AMOS-style password-prompt one-liner", .high),
        ("display dialog \"macos\" default answer", "Fake macOS password prompt via AppleScript", .high),
        ("with hidden answer", "AppleScript password prompt — common stealer pattern when combined with shell exec", .medium),
        // ClickFix-specific phrases observed in delivered commands (Feb-Aug 2025 reports)
        ("clearfake", "ClearFake / ClickFix campaign indicator", .high),
        ("fakeupdate", "FakeUpdate / SocGholish-style delivery indicator", .high),
        // Shell-history poisoning + remote code combos
        ("base64 --decode | sh", "base64-decoded payload piped to a shell", .high),
        ("base64 -d | sh", "base64-decoded payload piped to a shell", .high),
        ("eval \"$(curl", "shell `eval` of remote curl content — drop-and-run pattern", .high),
        ("eval $(curl", "shell `eval` of remote curl content", .high),
        ("python3 -c \"import urllib", "inline Python that fetches a remote URL — common stealer stager", .high),
        ("python -c \"import urllib", "inline Python that fetches a remote URL", .high),
        // Pseudo-CAPTCHA / "Verify you are human" framing
        ("verify you are a human", "ClickFix fake-CAPTCHA framing text", .high),
        ("verify you are human", "ClickFix fake-CAPTCHA framing text", .high),
        ("i am not a robot", "ClickFix fake-CAPTCHA framing text", .high),
        ("ctrl-v then enter", "ClickFix instruction text echoed into the shell", .high),
    ]

    private let trustedHomebrewCurlPrefixes: [String] = [
        "/bin/bash -c \"$(curl -fsssl https://raw.githubusercontent.com/homebrew/install/",
        "/bin/bash -c \"$(curl -fssl https://raw.githubusercontent.com/homebrew/install/",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("scanning shell histories")
        scanShellHistories(findings: &findings, errors: &errors)

        progress?.update("scanning Terminal saved state")
        scanTerminalSavedState(findings: &findings, errors: &errors)

        progress?.update("scanning recent /tmp scripts")
        scanRecentTmpScripts(findings: &findings, errors: &errors)

        progress?.update("scanning quarantine-bypass downloads")
        scanQuarantineBypass(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Shell histories

    private func scanShellHistories(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
            "\(home)/.local/share/fish/fish_history",
        ]

        for histPath in historyFiles {
            guard let content = try? String(contentsOfFile: histPath, encoding: .utf8) else { continue }
            // zsh extended history is encoded as `: epoch:0;command\n` — strip leading metadata
            let lines = content.split(separator: "\n").map(String.init)

            for (idx, rawLine) in lines.enumerated() {
                // Strip zsh extended-history prefix: `: 1700000000:0;`
                var line = rawLine
                if line.hasPrefix(": ") {
                    if let semi = line.range(of: ";") {
                        line = String(line[semi.upperBound...])
                    }
                }
                let lower = line.lowercased()
                guard !lower.isEmpty else { continue }

                // Suppress the Homebrew install line — it's the world's most common curl|bash
                if trustedHomebrewCurlPrefixes.contains(where: { lower.hasPrefix($0) }) { continue }

                for entry in pastePatterns {
                    if lower.contains(entry.pattern) {
                        let snippet = String(line.prefix(140)).replacingOccurrences(of: "\n", with: " ")
                        findings.append(Finding(
                            severity: entry.severity,
                            category: .suspiciousProcess,
                            title: "Possible ClickFix / fake-terminal-paste in shell history",
                            detail: "File: \(filenameOnly(histPath)), line \(idx + 1) — \(entry.description). Snippet: \(snippet)",
                            path: histPath,
                            remediation: "Review the entry: grep -n -F '\(snippet.prefix(40))' \(histPath) — if you don't recognize it, treat the Mac as compromised: rotate browser passwords, move crypto funds, and run a full scan again"
                        ))
                        break  // one finding per line is enough
                    }
                }
            }
        }
    }

    // MARK: - Terminal saved state

    private func scanTerminalSavedState(findings: inout [Finding], errors: inout [String]) {
        // Terminal.app keeps a transient window snapshot in
        // ~/Library/Saved Application State/com.apple.Terminal.savedState/ . The
        // `windows.plist` file inside often contains the most recent window's text buffer,
        // including a freshly-pasted command, even after the history file has been cleared.
        let home = ShellRunner.realUserHome
        let savedStates = [
            "\(home)/Library/Saved Application State/com.apple.Terminal.savedState",
            "\(home)/Library/Saved Application State/com.googlecode.iterm2.savedState",
        ]

        for stateDir in savedStates {
            guard FileManager.default.fileExists(atPath: stateDir) else { continue }
            let windowsPlist = "\(stateDir)/windows.plist"
            guard let data = FileManager.default.contents(atPath: windowsPlist) else { continue }

            // The plist contains binary text; do a simple substring search against the
            // raw bytes for the most distinctive IOC strings. This avoids parsing
            // Apple's NSKeyedArchiver format.
            let text = String(data: data, encoding: .isoLatin1) ?? ""
            let lower = text.lowercased()

            let stateIOCs: [(String, String)] = [
                ("verify you are a human",
                 "ClickFix fake-CAPTCHA prompt text"),
                ("display dialog \"macos needs to access",
                 "AMOS-family password-prompt one-liner"),
                ("curl -fsso",
                 "curl drop-and-run one-liner"),
                ("base64 --decode | sh",
                 "base64-decoded payload piped to a shell"),
            ]

            for (ioc, desc) in stateIOCs where lower.contains(ioc) {
                findings.append(Finding(
                    severity: .high,
                    category: .suspiciousProcess,
                    title: "ClickFix indicator in Terminal saved state",
                    detail: "\(desc) — found in \(filenameOnly(stateDir))",
                    path: windowsPlist,
                    remediation: "Quit Terminal, then delete the saved state: rm -rf \"\(stateDir)\". Treat the Mac as compromised and rotate browser passwords."
                ))
                break
            }
        }
    }

    // MARK: - Recently-modified /tmp scripts

    private func scanRecentTmpScripts(findings: inout [Finding], errors: inout [String]) {
        // ClickFix payloads almost always land a temporary `.sh`, `.command`, `.scpt`, or
        // `AppleScript-*.scpt` file in /private/tmp before executing it. The file lingers
        // because the stealer rarely cleans up after itself.
        let tmpDirs = ["/tmp", "/private/tmp", "/var/tmp"]
        let fm = FileManager.default
        let now = Date()

        let suspiciousExtensions: Set<String> = ["sh", "command", "scpt", "applescript", "py", "pl"]
        let suspiciousNameFragments = ["update", "install", "verify", "captcha", "fix",
                                       "applescript-", "fakeupdate", "browser_update"]

        for dir in tmpDirs {
            guard fm.fileExists(atPath: dir),
                  let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in contents {
                let fullPath = "\(dir)/\(entry)"
                let ext = URL(fileURLWithPath: entry).pathExtension.lowercased()
                let nameLC = entry.lowercased()

                // Must look interesting on extension OR name
                let extMatch = suspiciousExtensions.contains(ext)
                let nameMatch = suspiciousNameFragments.contains(where: { nameLC.contains($0) })
                guard extMatch || nameMatch else { continue }

                // Must be a regular file
                guard let attrs = try? fm.attributesOfItem(atPath: fullPath),
                      (attrs[.type] as? FileAttributeType) == .typeRegular else { continue }

                // Modified within the last 14 days = recent ClickFix delivery window
                guard let modDate = attrs[.modificationDate] as? Date,
                      now.timeIntervalSince(modDate) < 14 * 86400 else { continue }

                // Read the first ~2KB to look for IOC text
                let head = readHead(of: fullPath, bytes: 2048)
                let headLower = head.lowercased()

                var matchedDesc: String?
                if headLower.contains("display dialog") && headLower.contains("with hidden answer") {
                    matchedDesc = "AppleScript with hidden-answer password prompt (AMOS family)"
                } else if headLower.contains("curl") && (headLower.contains("| sh") || headLower.contains("|sh") || headLower.contains("| bash")) {
                    matchedDesc = "shell script that pipes a curl download into a shell"
                } else if headLower.contains("base64") && (headLower.contains("--decode") || headLower.contains(" -d ")) {
                    matchedDesc = "script that base64-decodes a payload"
                } else if extMatch && nameMatch {
                    matchedDesc = "recently-written script with attack-related name and extension"
                }

                guard let desc = matchedDesc else { continue }

                let ageHours = Int(now.timeIntervalSince(modDate) / 3600)
                findings.append(Finding(
                    severity: .high,
                    category: .suspiciousFile,
                    title: "Suspicious dropped script in \(dir)",
                    detail: "File: \(entry), age: \(ageHours)h — \(desc)",
                    path: fullPath,
                    remediation: "Inspect, then remove: cat \"\(fullPath)\" — if you didn't put it there, delete and rotate credentials"
                ))
            }
        }
    }

    // MARK: - Quarantine-bypass downloads (xattr stripping)

    private func scanQuarantineBypass(findings: inout [Finding], errors: inout [String]) {
        // ClickFix payloads delivered via curl/wget never have the com.apple.quarantine xattr,
        // so they bypass Gatekeeper. We can spot them indirectly by looking for fresh Mach-O
        // binaries in ~/Downloads, /private/tmp, and ~/Library/Caches that are missing the
        // quarantine attribute despite being recent.
        let home = ShellRunner.realUserHome
        let scanDirs = [
            "\(home)/Downloads",
            "/private/tmp",
            "/tmp",
            "\(home)/Library/Caches",
        ]
        let fm = FileManager.default
        let now = Date()
        var flagged = 0

        for dir in scanDirs {
            guard fm.fileExists(atPath: dir),
                  let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for entry in entries.prefix(200) {
                if flagged >= 5 { return }  // cap so we don't spam the report
                let path = "\(dir)/\(entry)"

                guard let attrs = try? fm.attributesOfItem(atPath: path),
                      (attrs[.type] as? FileAttributeType) == .typeRegular,
                      let modDate = attrs[.modificationDate] as? Date,
                      now.timeIntervalSince(modDate) < 7 * 86400,
                      let size = attrs[.size] as? Int, size > 4096 else { continue }

                // Must be Mach-O
                guard let fh = FileHandle(forReadingAtPath: path) else { continue }
                let header = fh.readData(ofLength: 4)
                fh.closeFile()
                guard header.count == 4 else { continue }
                let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
                let machoMagics: Set<UInt32> = [0xFEEDFACF, 0xFEEDFACE, 0xBEBAFECA, 0xCAFEBABE]
                guard machoMagics.contains(magic) else { continue }

                // Check for the quarantine xattr — present on legitimate browser downloads
                let xattrResult = ShellRunner.run("/usr/bin/xattr", arguments: [path], timeout: 3)
                guard xattrResult.success else { continue }
                let hasQuarantine = xattrResult.stdout.contains("com.apple.quarantine")

                if !hasQuarantine {
                    let ageHours = Int(now.timeIntervalSince(modDate) / 3600)
                    findings.append(Finding(
                        severity: .medium,
                        category: .suspiciousFile,
                        title: "Recent Mach-O binary without Gatekeeper quarantine flag",
                        detail: "File: \(entry) (\(size / 1024) KB, age \(ageHours)h) — was not downloaded by a browser. Common after curl/wget delivery in a ClickFix attack.",
                        path: path,
                        remediation: "If you didn't curl this yourself, delete it and investigate: file \"\(path)\""
                    ))
                    flagged += 1
                }
            }
        }
    }

    // MARK: - Helpers

    private func readHead(of path: String, bytes: Int) -> String {
        guard let fh = FileHandle(forReadingAtPath: path) else { return "" }
        defer { fh.closeFile() }
        let data = fh.readData(ofLength: bytes)
        return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) ?? ""
    }

    private func filenameOnly(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent
    }
}
