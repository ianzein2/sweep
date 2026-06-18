import Foundation

/// Catches modern attack vectors that target developer machines and that the signature-based
/// scanners miss: ClickFix / fake-CAPTCHA paste attacks, malicious npm postinstall hooks,
/// known-compromised packages, cryptominer processes, and untrusted Homebrew taps.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking shell history for ClickFix indicators")
        scanShellHistoryForClickFix(findings: &findings, errors: &errors)

        progress?.update("auditing globally installed npm packages")
        scanGlobalNpmPackages(findings: &findings, errors: &errors)

        progress?.update("checking for known-compromised packages")
        scanKnownCompromisedPackages(findings: &findings, errors: &errors)

        progress?.update("checking for cryptominer processes")
        scanCryptominers(findings: &findings, errors: &errors)

        progress?.update("auditing Homebrew taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("checking developer pipe-to-shell exposure")
        scanRecentPipeToShell(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - ClickFix / fake-CAPTCHA paste detection
    //
    // ClickFix (also marketed as "FileFix") attacks were the dominant initial-access technique
    // in 2024-2025. A malicious site convinces the victim to paste a payload into the Terminal
    // (or Spotlight → Terminal). The pasted command typically combines `osascript -e 'do shell
    // script ...'` with base64 decoding or a `curl <attacker domain> | bash` one-liner. Once
    // pasted and run, the command leaves a footprint in the shell history — that's what we hunt.

    /// High-confidence indicators of a ClickFix-style paste payload. Each entry matches on
    /// composition (two substrings together) so single-substring false positives — like a
    /// developer who legitimately runs `osascript -e ...` for an automation — don't fire.
    /// Each match is treated as HIGH severity.
    private struct PastePattern {
        let trigger: [String]   // any of these must appear in the line to begin matching
        let require: [String]   // any of these must also appear (empty = no further requirement)
        let reason: String
    }

    private static let clickFixCompositePatterns: [PastePattern] = [
        // The canonical macOS ClickFix payload: osascript that runs an AppleScript that itself
        // runs a shell command. Almost never legitimate from interactive shell history.
        PastePattern(
            trigger: ["osascript"], require: ["do shell script"],
            reason: "osascript + AppleScript `do shell script` pasted into the shell — the canonical macOS ClickFix payload"
        ),
        // base64-decoded shell payload — heavily used by ClickFix and Cuckoo-family droppers.
        PastePattern(
            trigger: ["base64 -d", "base64 --decode", "base64 -D"],
            require: ["| sh", "| bash", "|sh", "|bash", "| zsh", "|zsh"],
            reason: "base64 decode piped into a shell — common ClickFix / fake-CAPTCHA payload shape"
        ),
        // Inline Python that decodes and execs a payload.
        PastePattern(
            trigger: ["python3 -c", "python -c", "python2 -c"],
            require: ["exec(base64", "exec(__import__"],
            reason: "Python inline exec of obfuscated payload — ClickFix loader"
        ),
        // Reverse shell shapes.
        PastePattern(
            trigger: ["bash -i", "sh -i", "zsh -i"], require: ["/dev/tcp/"],
            reason: "Interactive bash with /dev/tcp redirection — reverse shell"
        ),
        PastePattern(
            trigger: ["nc -e", "ncat -e", "/bin/nc -e"], require: [],
            reason: "netcat invoked with -e (command execution) — reverse shell"
        ),
        // curl/wget piped into a shell as the contents of an `eval` or `bash -c "$(…)"`.
        PastePattern(
            trigger: ["bash -c \"$(curl", "bash -c \"$(wget", "sh -c \"$(curl", "sh -c \"$(wget"],
            require: [],
            reason: "bash -c \"$(curl …)\" pattern — pasted remote-command-execution dropper"
        ),
    ]

    /// Suspicious domains seen in ClickFix payloads in 2024-2025 IOC dumps and in Lazarus
    /// "Contagious Interview" droppers. Matching is substring-only to catch subdomains.
    private static let suspiciousPasteDomains: [String] = [
        // ClickFix infra reported by Proofpoint / ANY.RUN 2024-2025
        ".click.fix", "clickfix.", "fakecaptcha.",
        // Contagious Interview / fake-recruiter npm droppers
        "ipcheck.cloud", "npmaudit.org", "skillquestionnaire",
        // Frequently abused short-link / file-host domains in copy-paste lures
        "transfer.sh/", "tmpfiles.org/", "anonfiles.", "filebin.net/",
    ]

    private func scanShellHistoryForClickFix(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.history",
        ]

        for path in historyFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            var matched = Set<String>()
            for rawLine in content.split(separator: "\n") {
                let line = String(rawLine)
                let lower = line.lowercased()
                guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { continue }

                for pattern in Self.clickFixCompositePatterns {
                    // A `trigger` substring must hit; if there are `require` substrings, one
                    // of them must hit too. Empty `require` means the trigger is self-sufficient.
                    let triggered = pattern.trigger.contains { lower.contains($0.lowercased()) }
                    guard triggered else { continue }
                    if !pattern.require.isEmpty {
                        let required = pattern.require.contains { lower.contains($0.lowercased()) }
                        guard required else { continue }
                    }

                    let key = "\(path):\(pattern.reason)"
                    if matched.contains(key) { continue }
                    matched.insert(key)

                    // Strip zsh extended history prefix ": 1696942000:0;<cmd>" so the snippet
                    // surfaces what the user actually ran.
                    let snippet = trimZshHistoryPrefix(line)
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Shell history contains ClickFix-style payload",
                        detail: "\(pattern.reason) — \(String(snippet.prefix(180)))",
                        path: path,
                        remediation: "If you don't recognize this command, treat your Mac as potentially compromised: rotate browser-saved passwords, check Activity Monitor for unknown processes, and review LaunchAgents."
                    ))
                }

                for domain in Self.suspiciousPasteDomains {
                    guard lower.contains(domain) else { continue }
                    let key = "\(path):domain:\(domain)"
                    if matched.contains(key) { continue }
                    matched.insert(key)

                    let snippet = trimZshHistoryPrefix(line)
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Shell history references known ClickFix / dropper domain",
                        detail: "Domain match: \(domain) — \(String(snippet.prefix(180)))",
                        path: path,
                        remediation: "Inspect the surrounding history with: tail -100 \(path) — and revoke any credentials the command could have touched."
                    ))
                }
            }
        }
    }

    /// zsh writes extended history lines as `: 1696942000:0;<cmd>`. Strip that envelope so the
    /// detail surfaces the actual command rather than the timestamp prefix.
    private func trimZshHistoryPrefix(_ line: String) -> String {
        guard line.hasPrefix(": ") else { return line }
        if let sep = line.range(of: ";") {
            return String(line[sep.upperBound...])
        }
        return line
    }

    // MARK: - Global npm postinstall audit
    //
    // The shai-hulud-style worms of 2024-2025 spread through globally installed npm packages
    // whose `postinstall` script downloads and runs additional code. Even when the package
    // itself isn't on a known-bad list, a postinstall that does `curl … | sh` or decodes a
    // base64 blob is reason enough to surface it.

    private static let npmPostinstallRedFlags: [(needle: String, reason: String)] = [
        ("curl ", "postinstall downloads a remote payload"),
        ("wget ", "postinstall downloads a remote payload"),
        ("| sh", "postinstall pipes output into a shell"),
        ("| bash", "postinstall pipes output into bash"),
        ("eval(", "postinstall evaluates dynamic code"),
        ("Buffer.from(", "postinstall reconstructs an obfuscated payload"),
        ("child_process", "postinstall spawns a child process"),
        ("node -e", "postinstall runs an inline node script"),
        ("base64", "postinstall touches base64 encoded data"),
    ]

    private func scanGlobalNpmPackages(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Candidate global-install directories across npm, pnpm, yarn, volta, asdf, nvm.
        var roots = [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.npm/lib/node_modules",
            "\(home)/.config/yarn/global/node_modules",
            "\(home)/.local/share/pnpm/global",
            "\(home)/.volta/tools/image/packages",
        ]

        // nvm: each Node version has its own global node_modules dir.
        let nvmRoot = "\(home)/.nvm/versions/node"
        if let versions = try? fm.contentsOfDirectory(atPath: nvmRoot) {
            for v in versions {
                roots.append("\(nvmRoot)/\(v)/lib/node_modules")
            }
        }

        for root in roots {
            guard fm.fileExists(atPath: root),
                  let topLevel = try? fm.contentsOfDirectory(atPath: root) else { continue }

            for entry in topLevel where !entry.hasPrefix(".") {
                // Scoped packages live one directory deeper: @scope/pkg.
                if entry.hasPrefix("@") {
                    guard let scoped = try? fm.contentsOfDirectory(atPath: "\(root)/\(entry)") else { continue }
                    for sub in scoped where !sub.hasPrefix(".") {
                        inspectNpmPackage(at: "\(root)/\(entry)/\(sub)",
                                          displayName: "\(entry)/\(sub)",
                                          findings: &findings)
                    }
                } else {
                    inspectNpmPackage(at: "\(root)/\(entry)",
                                      displayName: entry,
                                      findings: &findings)
                }
            }
        }
    }

    private func inspectNpmPackage(at path: String, displayName: String, findings: inout [Finding]) {
        let packageJsonPath = "\(path)/package.json"
        guard let data = FileManager.default.contents(atPath: packageJsonPath),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let scripts = json["scripts"] as? [String: Any] ?? [:]
        // Lifecycle hooks that fire on install / publish — the realistic infection surface.
        let lifecycleHooks = ["preinstall", "install", "postinstall", "prepare", "preprepare", "prepublish"]

        for hook in lifecycleHooks {
            guard let command = scripts[hook] as? String, !command.isEmpty else { continue }
            let lower = command.lowercased()

            var reasons: [String] = []
            for redFlag in Self.npmPostinstallRedFlags where lower.contains(redFlag.needle.lowercased()) {
                reasons.append(redFlag.reason)
            }

            // node-gyp rebuild is the legitimate native-module case and is overwhelmingly the
            // most common reason for a non-empty install hook. Don't flag it on its own.
            let isOnlyGyp = lower.contains("node-gyp") && reasons.count <= 1 && lower.contains("rebuild")
            if reasons.isEmpty || isOnlyGyp { continue }

            let severity: Severity = reasons.count >= 2 ? .high : .medium
            findings.append(Finding(
                severity: severity, category: .suspiciousProcess,
                title: "Global npm package \(displayName) has suspicious \(hook) hook",
                detail: "Hook fires on install: \(reasons.joined(separator: "; ")) — command: \(String(command.prefix(160)))",
                path: packageJsonPath,
                remediation: "If you didn't intentionally install \(displayName), uninstall it: npm uninstall -g \(displayName)"
            ))
        }
    }

    // MARK: - Known compromised / typosquat packages
    //
    // Each entry is a package name observed in a published supply-chain compromise (Socket.dev,
    // GitHub Security Advisories, npm security alerts, 2023-2025). Presence on disk doesn't
    // prove the user installed the malicious version — but it's a strong enough lead to surface.

    /// Package names tied to published supply-chain compromises (npm advisories, Socket.dev /
    /// Phylum / ReversingLabs reports, 2024-2025). We deliberately keep this list short and
    /// well-sourced — broader heuristics live in the postinstall-hook audit above.
    private static let knownMaliciousNpmPackages: Set<String> = [
        // Shai-Hulud worm (September 2024) — propagated through compromised maintainer accounts.
        "shai-hulud",
        // Typosquats of popular packages reported by Socket.dev (2024-2025).
        "eslint-config-prettier-extended", "eslint-prettier-config",
        // BeaverTail / "Contagious Interview" DPRK npm droppers reported by Phylum & Palo Alto
        // Unit 42. These names appear in fake-recruiter coding-challenge repos.
        "node-helper-tools", "coding-challenge-helper",
        "react-native-shared-data", "react-native-debugger-tools",
    ]

    private func scanKnownCompromisedPackages(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        // Walk a fixed set of plausible install locations to a shallow depth. We're not trying
        // to enumerate every node_modules directory on the system — just the obvious globals
        // plus the developer's working directories one level deep.
        let searchRoots = [
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            "\(home)/.npm-global/lib/node_modules",
            "\(home)/.local/share/pnpm/global",
            "\(home)/node_modules",
            "\(home)/Projects",
            "\(home)/Code",
            "\(home)/Developer",
            "\(home)/src",
            "\(home)/work",
        ]

        for root in searchRoots {
            guard fm.fileExists(atPath: root),
                  let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

            // Direct top-level match (the install dir itself).
            for entry in entries {
                if Self.knownMaliciousNpmPackages.contains(entry) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Known-compromised npm package found: \(entry)",
                        detail: "Package \(entry) appears in published supply-chain compromise reports",
                        path: "\(root)/\(entry)",
                        remediation: "Remove the package and rotate any credentials that were available to the shell during install: rm -rf \"\(root)/\(entry)\""
                    ))
                }
            }

            // One-level descent into project directories: look for a project's node_modules.
            for entry in entries where !entry.hasPrefix(".") {
                let projectModules = "\(root)/\(entry)/node_modules"
                guard let nm = try? fm.contentsOfDirectory(atPath: projectModules) else { continue }
                for pkg in nm where Self.knownMaliciousNpmPackages.contains(pkg) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousFile,
                        title: "Known-compromised npm package in project tree: \(pkg)",
                        detail: "Package \(pkg) found in project \(entry)",
                        path: "\(projectModules)/\(pkg)",
                        remediation: "Remove from package.json and re-install with lockfile audit: cd \"\(root)/\(entry)\" && npm audit --omit=dev"
                    ))
                }
            }
        }
    }

    // MARK: - Cryptominer detection
    //
    // Most cryptominers don't bother hiding the process name; flagging well-known miner binaries
    // is the highest-signal, lowest-noise check we can do. We use the kinfo-style `ps` listing
    // because it's already used elsewhere in the codebase and works without root.

    private static let knownMinerNames: Set<String> = [
        "xmrig", "xmr-stak", "xmr-stak-cpu", "xmr-stak-amd", "xmr-stak-nvidia",
        "minerd", "cpuminer", "ccminer", "ccminer-cryptonight",
        "ethminer", "phoenixminer", "lolMiner", "t-rex", "trex",
        "nanominer", "nbminer", "teamredminer", "gminer",
        "monero-miner", "moneroocean", "cryptonight",
        "minergate", "minergate-cli", "ezil", "ravencoin-miner",
        // 2024 stealer payloads sometimes drop "kdevtmpfsi" / "kinsing" on macOS too.
        "kdevtmpfsi", "kinsing",
    ]

    /// Known crypto-mining pool hostnames. Connections here from anything but a dev sandbox
    /// are a strong unauthorized-mining signal.
    private static let knownMiningPoolDomains: [String] = [
        "moneroocean.stream", "supportxmr.com", "minexmr.com", "nanopool.org",
        "ethermine.org", "f2pool.com", "2miners.com", "hashvault.pro",
        "minergate.com", "xmrpool.eu", "pool.minexmr.com", "mining-dutch.nl",
    ]

    private func scanCryptominers(findings: inout [Finding], errors: inout [String]) {
        // 1. Process names. `ps -axo pid,comm,args` is portable and quick.
        let psResult = ShellRunner.run("/bin/ps", arguments: ["-axo", "pid,comm,args"], timeout: 5)
        if psResult.success {
            var reported = Set<String>()
            for rawLine in psResult.stdout.split(separator: "\n") {
                let line = String(rawLine)
                let lower = line.lowercased()
                for miner in Self.knownMinerNames where lower.contains(miner.lowercased()) {
                    // Require a word-boundary-ish check so "trex" doesn't match every "tRex" string.
                    let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                    let comm = parts.count >= 2 ? String(parts[1]) : ""
                    let argsBlob = parts.count >= 3 ? parts[2...].map(String.init).joined(separator: " ") : ""
                    let isMatch = comm.lowercased().contains(miner)
                        || argsBlob.lowercased().contains("/\(miner)")
                        || argsBlob.lowercased().contains(" \(miner) ")
                    guard isMatch else { continue }

                    let pid = parts.first.map(String.init) ?? "?"
                    let key = "\(miner):\(pid)"
                    if reported.contains(key) { continue }
                    reported.insert(key)

                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "Cryptominer process detected: \(miner)",
                        detail: "PID \(pid) running known mining binary — \(String(line.prefix(160)))",
                        path: nil,
                        remediation: "If this isn't intentional mining: kill \(pid) — then find the LaunchAgent that started it."
                    ))
                }
            }
        }

        // 2. Active connections to known mining pools. `lsof -i` is broader than we need but is
        //    the only no-root way to enumerate sockets system-wide.
        let lsofResult = ShellRunner.run("/usr/sbin/lsof",
                                         arguments: ["-i", "-n", "-P", "+c", "0", "-w"], timeout: 10)
        guard lsofResult.success, !lsofResult.stdout.isEmpty else { return }

        var poolReported = Set<String>()
        for line in lsofResult.stdout.split(separator: "\n") {
            let lineStr = String(line).lowercased()
            for pool in Self.knownMiningPoolDomains where lineStr.contains(pool) {
                if poolReported.contains(pool) { continue }
                poolReported.insert(pool)
                findings.append(Finding(
                    severity: .high, category: .networkActivity,
                    title: "Connection to known cryptocurrency mining pool",
                    detail: "Pool: \(pool) — line: \(String(line).trimmingCharacters(in: .whitespaces).prefix(160))",
                    path: nil,
                    remediation: "Identify the local process with: lsof -i | grep \(pool) — then kill and remove its persistence."
                ))
            }
        }
    }

    // MARK: - Homebrew tap audit
    //
    // Adding a Homebrew tap is the developer equivalent of trusting a software vendor. Most users
    // intentionally tap a handful of well-known orgs (homebrew/*, the cask repos). Anything else
    // is worth a quick "did you mean to do this?" prompt.

    private static let trustedBrewTaps: Set<String> = [
        "homebrew/core", "homebrew/cask", "homebrew/cask-fonts", "homebrew/cask-versions",
        "homebrew/services", "homebrew/bundle", "homebrew/cask-drivers",
        "homebrew/command-not-found",
        // Frequently used first-party taps maintained by major projects.
        "hashicorp/tap", "mongodb/brew", "minio/stable", "aws/tap",
        "azure/functions", "github/gh", "cloudflare/cloudflare",
        "vmware-tanzu/carvel", "fluxcd/tap", "argoproj/tap",
        "homebrew-ffmpeg/ffmpeg", "homebrew/cask-fonts",
        "homeport/tap",
    ]

    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // Look directly at the tap directories on disk — works even if `brew` isn't on PATH for
        // the user that ran sweep.
        let tapRoots = ["/opt/homebrew/Library/Taps", "/usr/local/Homebrew/Library/Taps"]
        let fm = FileManager.default

        for root in tapRoots {
            guard fm.fileExists(atPath: root),
                  let orgs = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for org in orgs where !org.hasPrefix(".") {
                guard let repos = try? fm.contentsOfDirectory(atPath: "\(root)/\(org)") else { continue }
                for repo in repos where !repo.hasPrefix(".") {
                    // Tap layout on disk uses "homebrew-<name>" — translate to the canonical "org/name".
                    let name = repo.hasPrefix("homebrew-") ? String(repo.dropFirst("homebrew-".count)) : repo
                    let tapId = "\(org)/\(name)"
                    if Self.trustedBrewTaps.contains(tapId.lowercased()) { continue }
                    if org.lowercased() == "homebrew" { continue }

                    findings.append(Finding(
                        severity: .low, category: .suspiciousFile,
                        title: "Third-party Homebrew tap installed",
                        detail: "Tap: \(tapId) — formulas from this tap run with your privileges during `brew install`",
                        path: "\(root)/\(org)/\(repo)",
                        remediation: "If you didn't intentionally tap this, remove it: brew untap \(tapId)"
                    ))
                }
            }
        }
    }

    // MARK: - Recent pipe-to-shell installer use
    //
    // `curl … | sh` isn't malware by itself — it's how a lot of legit projects publish installers —
    // but it's worth surfacing recent uses so the user can mentally cross-check what they ran.
    // We only flag uses against domains outside a small allowlist of well-known installer hosts.

    private static let trustedInstallerDomains: [String] = [
        "sh.rustup.rs", "rustup.rs", "get.docker.com",
        "raw.githubusercontent.com/Homebrew", "brew.sh",
        "deb.nodesource.com", "rpm.nodesource.com",
        "get.helm.sh", "starship.rs/install.sh",
        "install.python-poetry.org", "pyenv.run",
        "fnm.vercel.app", "get.volta.sh",
        "ohmyz.sh", "raw.githubusercontent.com/ohmyzsh",
        "raw.githubusercontent.com/oh-my-fish",
        "fly.io/install.sh", "ollama.com/install.sh",
        "deno.land/install.sh", "bun.sh/install",
    ]

    private func scanRecentPipeToShell(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let historyFiles = ["\(home)/.zsh_history", "\(home)/.bash_history"]

        for path in historyFiles {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            var reported = Set<String>()
            for rawLine in content.split(separator: "\n") {
                let line = String(rawLine)
                let lower = line.lowercased()
                let hasFetch = lower.contains("curl ") || lower.contains("wget ")
                guard hasFetch else { continue }
                let hasPipeShell = lower.contains("| sh")
                    || lower.contains("|sh")
                    || lower.contains("| bash")
                    || lower.contains("|bash")
                    || lower.contains("| zsh")
                guard hasPipeShell else { continue }

                // Extract a single URL token for context and the trust check.
                let url = extractFirstURL(from: line) ?? ""
                let isTrusted = Self.trustedInstallerDomains.contains { url.lowercased().contains($0) }
                if isTrusted { continue }
                if reported.contains(url) { continue }
                reported.insert(url)

                let snippet = trimZshHistoryPrefix(line)
                findings.append(Finding(
                    severity: .medium, category: .suspiciousProcess,
                    title: "Shell history piped a remote script to a shell",
                    detail: "URL: \(url.isEmpty ? "(unparseable)" : url) — \(String(snippet.prefix(160)))",
                    path: path,
                    remediation: "Verify the publisher before running curl|sh installers. If unfamiliar, inspect what got installed and clean up."
                ))
            }
        }
    }

    private func extractFirstURL(from line: String) -> String? {
        guard let range = line.range(of: "http") else { return nil }
        let tail = line[range.lowerBound...]
        let urlEnd = tail.firstIndex(where: { $0 == " " || $0 == "\"" || $0 == "'" || $0 == "|" })
            ?? tail.endIndex
        return String(tail[..<urlEnd])
    }
}
