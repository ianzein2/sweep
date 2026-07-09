import Foundation

/// Detects developer-toolchain supply-chain risks: auto-loaded interpreter startup files,
/// hijacked package registries, and untrusted Homebrew taps.
///
/// Software supply-chain attacks against developers have exploded in 2024-2025 — the "Contagious
/// Interview" DPRK campaign, npm/PyPI typosquatting waves, and the December 2024 Cyberhaven
/// browser-extension compromise all rely on one thing: they only need to run on the developer's
/// Mac once. Anything auto-executed by their interpreter or package manager is a jackpot for
/// attackers.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply-Chain Scan"
    public init() {}

    // Patterns that suggest remote-code-execution payloads inside auto-loaded interpreter files.
    private let suspiciousExecPatterns: [(pattern: String, description: String)] = [
        ("subprocess",     "spawns external processes"),
        ("os.system",      "invokes the shell"),
        ("os.popen",       "opens a subprocess pipe"),
        ("exec(",          "runs dynamically-constructed code"),
        ("eval(",          "evaluates dynamically-constructed code"),
        ("urllib.request", "downloads over HTTP"),
        ("requests.get",   "downloads over HTTP"),
        ("socket.socket",  "opens a raw network socket"),
        ("base64.b64decode", "decodes hidden payloads"),
        ("marshal.loads",  "unmarshals code objects (obfuscation)"),
        ("compile(",       "compiles dynamic code at import"),
        ("pty.spawn",      "spawns a pseudo-terminal (shell backdoor)"),
        ("__import__(",    "dynamically imports (evasion technique)"),
    ]

    // Known good/expected registries — anything else is worth surfacing.
    private let trustedNpmRegistries: Set<String> = [
        "https://registry.npmjs.org/",
        "https://registry.npmjs.org",
        "https://registry.yarnpkg.com/",
        "https://registry.yarnpkg.com",
    ]

    private let trustedPipIndexes: Set<String> = [
        "https://pypi.org/simple/",
        "https://pypi.org/simple",
        "https://pypi.python.org/simple/",
        "https://pypi.python.org/simple",
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking Python startup files")
        checkPythonStartupFiles(findings: &findings, errors: &errors)

        progress?.update("checking Ruby REPL configs")
        checkRubyStartupFiles(findings: &findings, errors: &errors)

        progress?.update("checking Node/npm configuration")
        checkNpmConfig(findings: &findings, errors: &errors)

        progress?.update("checking pip / Python index")
        checkPipConfig(findings: &findings, errors: &errors)

        progress?.update("checking Cargo registry")
        checkCargoConfig(findings: &findings, errors: &errors)

        progress?.update("checking Homebrew taps")
        checkHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("checking git hooks / credential helpers")
        checkGitConfig(findings: &findings, errors: &errors)

        progress?.update("checking direnv / .envrc files")
        checkDirenvFiles(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Python startup files

    private func checkPythonStartupFiles(findings: inout [Finding], errors: inout [String]) {
        // `sitecustomize.py` / `usercustomize.py` run automatically on every Python import.
        // A stealer only needs one line here to survive every future virtualenv and system Python.
        let home = ShellRunner.realUserHome
        let fm = FileManager.default

        var candidates: [String] = [
            "\(home)/.pythonrc",
            "\(home)/.pythonrc.py",
            "\(home)/.pdbrc",
            "\(home)/.pdbrc.py",
        ]

        // The user's PYTHONSTARTUP env var, if set, points to a file that runs before every REPL session
        if let startupFile = ProcessInfo.processInfo.environment["PYTHONSTARTUP"] {
            candidates.append(startupFile)
        }

        // usercustomize.py in the per-user site-packages runs on every python invocation
        let siteResult = ShellRunner.run("/bin/sh", arguments: [
            "-c", "python3 -c 'import site; print(site.getusersitepackages())' 2>/dev/null"
        ], timeout: 5)
        if siteResult.success {
            let userSite = siteResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !userSite.isEmpty {
                candidates.append("\(userSite)/usercustomize.py")
                candidates.append("\(userSite)/sitecustomize.py")
            }
        }

        for file in candidates {
            guard fm.fileExists(atPath: file),
                  let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }

            // The mere presence of usercustomize/sitecustomize.py is itself worth surfacing —
            // most users don't have one, and Python runs it on every invocation.
            let baseName = URL(fileURLWithPath: file).lastPathComponent
            let isImplicit = baseName == "usercustomize.py" || baseName == "sitecustomize.py"

            let contentLC = content.lowercased()
            var matched: [String] = []
            for (pattern, description) in suspiciousExecPatterns {
                if contentLC.contains(pattern.lowercased()) {
                    matched.append(description)
                }
            }

            if !matched.isEmpty {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Python startup file executes suspicious operations",
                    detail: "File: \(baseName) — \(matched.joined(separator: ", ")). Runs on every Python invocation.",
                    path: file,
                    remediation: "Inspect and clean: \(file)"
                ))
            } else if isImplicit {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Implicit Python startup file present",
                    detail: "\(baseName) runs automatically on every Python launch — verify contents",
                    path: file,
                    remediation: "Inspect: cat \"\(file)\""
                ))
            }
        }
    }

    // MARK: - Ruby REPL / startup files

    private func checkRubyStartupFiles(findings: inout [Finding], errors: inout [String]) {
        // .irbrc / .pryrc are executed by the Ruby REPL on startup. .rvmrc / .ruby-version
        // are auto-loaded by rvm/rbenv shell hooks.
        let home = ShellRunner.realUserHome
        let files = [
            "\(home)/.irbrc",
            "\(home)/.pryrc",
            "\(home)/.gemrc",
        ]

        for file in files {
            guard let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
            let contentLC = content.lowercased()

            // Backticks / IO.popen / system in a Ruby REPL config is a solid RCE indicator
            let rubyExecPatterns: [(String, String)] = [
                ("system(",   "invokes the shell"),
                ("`",         "backtick shell execution"),
                ("io.popen",  "opens a subprocess pipe"),
                ("exec(",     "replaces the process"),
                ("eval(",     "evaluates dynamic code"),
                ("open('http", "downloads over HTTP"),
                ("net::http", "makes network requests"),
                ("net::https", "makes network requests"),
            ]

            for (pattern, description) in rubyExecPatterns where contentLC.contains(pattern) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Ruby REPL config contains suspicious code",
                    detail: "File: \(URL(fileURLWithPath: file).lastPathComponent) — \(description)",
                    path: file,
                    remediation: "Inspect: cat \"\(file)\""
                ))
                break
            }
        }
    }

    // MARK: - npm configuration

    private func checkNpmConfig(findings: inout [Finding], errors: inout [String]) {
        // A tampered ~/.npmrc can redirect every `npm install` to a hostile registry — package
        // typosquats or malicious clones then land during any subsequent install.
        let home = ShellRunner.realUserHome
        let npmrcPaths = [
            "\(home)/.npmrc",
            "/etc/npmrc",
            "/usr/local/etc/npmrc",
            "/opt/homebrew/etc/npmrc",
        ]

        for path in npmrcPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix(";") || trimmed.hasPrefix("#") { continue }

                let lower = trimmed.lowercased()
                if lower.hasPrefix("registry=") || lower.contains(":registry=") {
                    let value = trimmed
                        .replacingOccurrences(of: "registry=", with: "")
                        .replacingOccurrences(of: " ", with: "")
                    let url = value.split(separator: "=").last.map { String($0) } ?? value
                    if !trustedNpmRegistries.contains(where: { url.hasPrefix($0) }) &&
                       !url.hasPrefix("http://localhost") &&
                       !url.hasPrefix("http://127.0.0.1") {
                        findings.append(Finding(
                            severity: .medium, category: .networkActivity,
                            title: "Non-standard npm registry configured",
                            detail: "Registry: \(url) — replaces the default npmjs.org. Malicious registries can serve typosquatted or backdoored packages.",
                            path: path,
                            remediation: "If this is an internal corporate registry, ignore. Otherwise reset: npm config delete registry"
                        ))
                    }
                }
                // Ignore-scripts=false + globally-set unsafe-perm=true is the "auto-run postinstall as root" combo
                if lower.hasPrefix("unsafe-perm=true") && path == "/etc/npmrc" {
                    findings.append(Finding(
                        severity: .medium, category: .hardening,
                        title: "npm global config allows unsafe postinstall scripts",
                        detail: "unsafe-perm=true — root-level `npm install -g` will run any package's postinstall as root",
                        path: path,
                        remediation: "Remove or set unsafe-perm=false"
                    ))
                }
            }
        }
    }

    // MARK: - pip / Python package index

    private func checkPipConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let pipPaths = [
            "\(home)/.pip/pip.conf",
            "\(home)/Library/Application Support/pip/pip.conf",
            "\(home)/.config/pip/pip.conf",
            "/etc/pip.conf",
        ]

        for path in pipPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("[") { continue }

                let lower = trimmed.lowercased()
                // Match "index-url = https://..." or "extra-index-url = https://..."
                if lower.hasPrefix("index-url") || lower.hasPrefix("extra-index-url") {
                    let value = trimmed
                        .split(separator: "=", maxSplits: 1)
                        .last
                        .map { String($0).trimmingCharacters(in: .whitespaces) } ?? ""
                    if value.isEmpty { continue }

                    let isTrusted = trustedPipIndexes.contains(where: { value.hasPrefix($0) })
                    let isLocal = value.hasPrefix("http://localhost") || value.hasPrefix("http://127.0.0.1")
                    if !isTrusted && !isLocal {
                        // "extra-index-url" is especially dangerous — pip will prefer whichever mirror
                        // has the highest version, so a malicious mirror advertising v99.0 of `requests`
                        // wins over PyPI's real 2.31.
                        let isExtra = lower.hasPrefix("extra-index-url")
                        findings.append(Finding(
                            severity: isExtra ? .high : .medium,
                            category: .networkActivity,
                            title: isExtra
                                ? "pip extra-index-url is a typosquatting attack surface"
                                : "pip is configured to use a non-standard index",
                            detail: "URL: \(value) — pip will fetch packages from here" +
                                (isExtra ? ". \"extra-index-url\" lets whichever mirror advertises the highest version win, which is how the 2023-2024 dependency-confusion attacks worked." : ""),
                            path: path,
                            remediation: "If this is your corporate index, ignore. Otherwise remove from \(path)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Cargo (Rust) registry

    private func checkCargoConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let cargoPaths = [
            "\(home)/.cargo/config.toml",
            "\(home)/.cargo/config",
        ]

        for path in cargoPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Look for [source.crates-io] replaced-with = "..." — this reroutes the default
            // crates.io index to a mirror. Legitimate for enterprise mirrors; also the mechanism
            // for a supply-chain redirect.
            let contentLC = content.lowercased()
            if contentLC.contains("[source.crates-io]") && contentLC.contains("replace-with") {
                findings.append(Finding(
                    severity: .medium, category: .networkActivity,
                    title: "Cargo replaces the default crates.io registry",
                    detail: "config.toml points crates-io at a mirror — verify the destination.",
                    path: path,
                    remediation: "Inspect: cat \"\(path)\""
                ))
            }
        }
    }

    // MARK: - Homebrew taps

    private func checkHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // Third-party taps ship arbitrary Ruby that runs at install time. A single `brew install`
        // from a compromised tap is remote code execution.
        let brewPaths = [
            "/opt/homebrew/bin/brew",       // Apple silicon
            "/usr/local/bin/brew",          // Intel
        ]
        let brew = brewPaths.first { FileManager.default.fileExists(atPath: $0) }
        guard let brewBin = brew else { return }

        let result = ShellRunner.run(brewBin, arguments: ["tap"], timeout: 10)
        guard result.success else { return }

        // Homebrew ships its own core taps under "homebrew/*". Other common vendor taps have
        // large legitimate followings — but they are not required to be safe.
        let trustedTapPrefixes = ["homebrew/"]
        let taps = result.stdout
            .split(separator: "\n")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        for tap in taps {
            let isTrusted = trustedTapPrefixes.contains { tap.hasPrefix($0) }
            if !isTrusted {
                findings.append(Finding(
                    severity: .low, category: .persistence,
                    title: "Third-party Homebrew tap installed",
                    detail: "Tap: \(tap) — installs from this tap run arbitrary Ruby code from a repo you don't necessarily control",
                    path: nil,
                    remediation: "If you don't recognize it: brew untap \(tap)"
                ))
            }
        }
    }

    // MARK: - Git config: hooks, credential helpers, and evil aliases

    private func checkGitConfig(findings: inout [Finding], errors: inout [String]) {
        // Global git config can define aliases that shell out — running `git status` could then
        // fire off an exfil script. Similarly, credential.helper=store leaves plaintext creds on disk.
        let home = ShellRunner.realUserHome
        let gitConfigPaths = [
            "\(home)/.gitconfig",
            "\(home)/.config/git/config",
            "/etc/gitconfig",
        ]

        for path in gitConfigPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let lines = content.split(separator: "\n")
            var inAliasSection = false

            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { continue }

                if trimmed.hasPrefix("[") {
                    inAliasSection = trimmed.lowercased().contains("[alias]")
                    continue
                }

                // Any alias that starts with "!" runs an arbitrary shell command. That's normal
                // for legitimate helpers, but downloads/curls in an alias are a smell.
                if inAliasSection && trimmed.contains("=") {
                    let value = trimmed.split(separator: "=", maxSplits: 1).last.map { String($0) } ?? ""
                    let vLower = value.lowercased()
                    if vLower.contains("!") &&
                       (vLower.contains("curl") || vLower.contains("wget") ||
                        vLower.contains("nc ") || vLower.contains("/dev/tcp")) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Git alias downloads or executes remote code",
                            detail: "Alias in \(path): \(trimmed.prefix(100))",
                            path: path,
                            remediation: "Inspect and remove: git config --global --unset alias.<name>"
                        ))
                    }
                }

                // credential.helper=store keeps plaintext credentials in ~/.git-credentials
                if trimmed.lowercased().contains("helper") && trimmed.lowercased().contains("= store") {
                    findings.append(Finding(
                        severity: .low, category: .hardening,
                        title: "Git stores credentials in plaintext",
                        detail: "credential.helper=store keeps plaintext tokens in ~/.git-credentials — readable by any process running as you",
                        path: path,
                        remediation: "Switch to osxkeychain: git config --global credential.helper osxkeychain"
                    ))
                }

                // core.hooksPath pointing outside the repo is unusual — attackers use it to
                // route every `git commit` through their script.
                if trimmed.lowercased().hasPrefix("hookspath") ||
                   trimmed.lowercased().hasPrefix("core.hookspath") {
                    let value = trimmed.split(separator: "=", maxSplits: 1).last.map {
                        String($0).trimmingCharacters(in: .whitespaces)
                    } ?? ""
                    if !value.isEmpty {
                        findings.append(Finding(
                            severity: .medium, category: .persistence,
                            title: "Global git hooksPath configured",
                            detail: "hooksPath = \(value) — every `git` action in every repo runs hooks from this path",
                            path: path,
                            remediation: "Verify this is your own setup. Remove: git config --global --unset core.hooksPath"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - direnv .envrc files in developer paths

    private func checkDirenvFiles(findings: inout [Finding], errors: inout [String]) {
        // direnv auto-executes any `.envrc` when you `cd` into a directory. A malicious
        // `.envrc` in a downloaded repo can pop a shell the moment the user opens a terminal there.
        // We can only surface stuck-around .envrc files under common dev roots.
        let home = ShellRunner.realUserHome
        let searchRoots = [
            "\(home)/Downloads",
            "\(home)/tmp",
            "\(home)/Desktop",
        ]

        for root in searchRoots {
            let result = ShellRunner.run("/usr/bin/find", arguments: [
                root, "-maxdepth", "4", "-name", ".envrc", "-type", "f"
            ], timeout: 5)
            guard result.success && !result.stdout.isEmpty else { continue }

            let files = result.stdout
                .split(separator: "\n")
                .map { String($0).trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
                .prefix(10)

            for file in files {
                // Only flag if the file references shell exec / downloads
                guard let content = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
                let contentLC = content.lowercased()
                if contentLC.contains("curl ") || contentLC.contains("wget ") ||
                   contentLC.contains("eval ") || contentLC.contains("/dev/tcp") ||
                   contentLC.contains("base64 -d") || contentLC.contains("base64 --decode") {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: ".envrc in Downloads/Desktop downloads or executes code",
                        detail: "File: \(file) — direnv-hooked shells will run this when you cd into the directory",
                        path: file,
                        remediation: "Inspect before allowing: cat \"\(file)\""
                    ))
                }
            }
        }
    }
}
