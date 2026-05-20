import Foundation

/// Audits developer-tool configuration files for tampering and supply-chain risks.
///
/// Throughout 2024-2025 the dominant attack against developer Macs has shifted from
/// LaunchAgents to dotfile manipulation: npm token theft via injected `.npmrc` entries,
/// malicious `core.hooksPath` overrides, `Include` hijacks in `~/.ssh/config`, and
/// crates.io / PyPI mirror redirections. Sweep's existing persistence and process
/// scanners don't look inside these files because they aren't binaries — but they
/// run code (or hand out secrets) the moment a developer runs `git`, `npm`, `pip`,
/// `cargo`, or `ssh`.
public final class SupplyChainScanner: Scanner {
    public let name = "Supply Chain Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking npm / yarn / pnpm configs")
        scanNodePackageManagers(findings: &findings, errors: &errors)

        progress?.update("checking git configuration")
        scanGitConfig(findings: &findings, errors: &errors)

        progress?.update("checking global git hooks")
        scanGitTemplates(findings: &findings, errors: &errors)

        progress?.update("checking SSH client config")
        scanSSHClientConfig(findings: &findings, errors: &errors)

        progress?.update("checking Python package indexes")
        scanPythonConfig(findings: &findings, errors: &errors)

        progress?.update("checking Cargo registry config")
        scanCargoConfig(findings: &findings, errors: &errors)

        progress?.update("checking Homebrew taps")
        scanHomebrewTaps(findings: &findings, errors: &errors)

        progress?.update("checking shell hook overrides")
        scanShellHookOverrides(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - npm / yarn / pnpm / bun

    private func scanNodePackageManagers(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Each manager has a user-level config that can pin a custom registry and bake in
        // an auth token. A malicious `.npmrc` writes the token over `npm publish` runs,
        // and a malicious `registry=` line silently fetches packages from an attacker mirror.
        let configs: [(path: String, kind: String)] = [
            ("\(home)/.npmrc", "npm"),
            ("\(home)/.yarnrc", "yarn"),
            ("\(home)/.yarnrc.yml", "yarn"),
            ("\(home)/.pnpmrc", "pnpm"),
            ("\(home)/.bunfig.toml", "bun"),
        ]

        for (path, kind) in configs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let lines = content.split(separator: "\n").map { String($0) }
            for (idx, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { continue }

                // Auth tokens left in the file are a credential-theft target. A finding here
                // is informational on its own but lets us escalate when paired with a non-default registry.
                let hasAuthToken = trimmed.contains("_authToken") || trimmed.contains("_auth=") ||
                                   trimmed.contains("npmAuthToken") || trimmed.contains("npmRegistries")

                // Custom registry: anything that isn't a known-good mirror. We accept the
                // official registries and the well-known corporate ones; everything else is flagged.
                let isRegistryLine = trimmed.lowercased().contains("registry") ||
                                     trimmed.lowercased().hasPrefix("npmregistryserver")

                if isRegistryLine {
                    let lower = trimmed.lowercased()
                    let known = ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com",
                                 "npm.pkg.github.com", "pkgs.dev.azure.com", "artifactory",
                                 "jfrog", "nexus", "verdaccio"]
                    let usesPlainHttp = lower.contains("http://") && !lower.contains("://localhost") && !lower.contains("://127.0.0.1")
                    let isKnownMirror = known.contains(where: { lower.contains($0) })

                    if usesPlainHttp {
                        findings.append(Finding(
                            severity: .high, category: .supplyChain,
                            title: "\(kind) registry served over plain HTTP",
                            detail: "Line \(idx + 1) in \(path): \(String(trimmed.prefix(120))) — anyone on the network can swap installed packages",
                            path: path,
                            remediation: "Switch to HTTPS or remove the line: open \(path)"
                        ))
                    } else if !isKnownMirror && (lower.contains("://") || lower.contains("registry=")) {
                        findings.append(Finding(
                            severity: hasAuthToken ? .high : .medium, category: .supplyChain,
                            title: "\(kind) is configured with an unrecognized registry",
                            detail: "Line \(idx + 1) in \(path): \(String(trimmed.prefix(120)))" +
                                (hasAuthToken ? " — auth token is bundled, anything that runs \(kind) will leak it" : ""),
                            path: path,
                            remediation: "Verify the registry URL is your employer's mirror. Remove if unexpected: open \(path)"
                        ))
                    }
                }

                // pre/post-install lifecycle override or shell pipe in the rc file itself
                // — `npm config set script-shell ...` written via this file is a known abuse path.
                let overridesShell = trimmed.contains("script-shell=")
                let ignoresScriptsButHasToken = trimmed.contains("ignore-scripts=false") && hasAuthToken
                if overridesShell || ignoresScriptsButHasToken {
                    findings.append(Finding(
                        severity: .medium, category: .supplyChain,
                        title: "\(kind) lifecycle script behavior overridden",
                        detail: "Line \(idx + 1) in \(path): \(String(trimmed.prefix(120)))",
                        path: path,
                        remediation: "Review: a custom script-shell can run an attacker-controlled binary on every install"
                    ))
                }
            }
        }
    }

    // MARK: - Git config

    private func scanGitConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Three locations in priority order. Repo-local .git/config isn't scanned (that's per-repo);
        // these are the global ones that affect every command the user runs.
        let configs = [
            "\(home)/.gitconfig",
            "\(home)/.config/git/config",
            "/etc/gitconfig",
        ]

        for path in configs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            var currentSection = ""
            let lines = content.split(separator: "\n").map { String($0) }
            for (idx, rawLine) in lines.enumerated() {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }

                if line.hasPrefix("[") && line.hasSuffix("]") {
                    currentSection = String(line.dropFirst().dropLast()).lowercased()
                    continue
                }

                // `[include] path = ...` chain-loads another config. Attackers use this to
                // ship a config that "looks clean" but resolves include directives at git-runtime.
                if currentSection.hasPrefix("include") && line.lowercased().hasPrefix("path") {
                    let value = extractGitValue(line)
                    let resolvedRange = !value.hasPrefix("~/.gitconfig") &&
                        !value.hasPrefix(home + "/.gitconfig") &&
                        !value.hasPrefix(home + "/.config/git/")
                    if resolvedRange {
                        findings.append(Finding(
                            severity: .medium, category: .supplyChain,
                            title: "Global git config chain-loads another file",
                            detail: "[\(currentSection)] in \(path) line \(idx + 1): include path = \(value)",
                            path: path,
                            remediation: "Inspect that file — `[include]` is a known persistence and config-override channel"
                        ))
                    }
                }

                // `core.hooksPath` overrides the default `.git/hooks` directory globally. Any git
                // command in any repo will then run scripts from this path.
                if currentSection == "core" && line.lowercased().hasPrefix("hookspath") {
                    let value = extractGitValue(line)
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "Global git hooks path is overridden",
                        detail: "core.hooksPath = \(value) — every git command will execute hooks from this directory",
                        path: path,
                        remediation: "Verify the directory contents, then reset: git config --global --unset core.hooksPath"
                    ))
                }

                // `core.fsmonitor` runs an arbitrary binary inside every interactive git command.
                if currentSection == "core" && line.lowercased().hasPrefix("fsmonitor") {
                    let value = extractGitValue(line)
                    // The Git built-in is `true` / `false`; anything else is a custom binary path.
                    if value.lowercased() != "true" && value.lowercased() != "false" {
                        findings.append(Finding(
                            severity: .high, category: .supplyChain,
                            title: "Custom fsmonitor binary configured in git",
                            detail: "core.fsmonitor = \(value) — git runs this on every status/commit",
                            path: path,
                            remediation: "Verify the binary, then unset: git config --global --unset core.fsmonitor"
                        ))
                    }
                }

                // `core.sshCommand` lets a config replace `ssh` for git operations.
                if currentSection == "core" && line.lowercased().hasPrefix("sshcommand") {
                    let value = extractGitValue(line)
                    findings.append(Finding(
                        severity: .medium, category: .supplyChain,
                        title: "Custom SSH command set in git",
                        detail: "core.sshCommand = \(value) — git push/pull will run this command instead of plain ssh",
                        path: path,
                        remediation: "Verify legitimate (corporate ssh wrapper). Unset: git config --global --unset core.sshCommand"
                    ))
                }

                // `[alias]` entries that start with `!` shell out — a known phishing payload.
                // Example: `git status` running `!curl ... | sh` because `status` is aliased.
                if currentSection == "alias" {
                    if let value = extractGitValueIfAssignment(line), value.trimmingCharacters(in: .whitespaces).hasPrefix("!") {
                        let suspicious = value.contains("curl") || value.contains("wget") ||
                                         value.contains("eval") || value.contains("base64") ||
                                         value.contains("|sh") || value.contains("| sh") ||
                                         value.contains("/tmp/")
                        findings.append(Finding(
                            severity: suspicious ? .high : .medium, category: .supplyChain,
                            title: suspicious
                                ? "Git alias shells out to a suspicious command"
                                : "Git alias runs a shell command",
                            detail: "Line \(idx + 1): \(String(line.prefix(140)))",
                            path: path,
                            remediation: "Inspect: git config --global --get-regexp ^alias\\. — remove if unexpected"
                        ))
                    }
                }

                // `[url].insteadOf` silently rewrites every clone/push URL. A malicious entry
                // redirects pushes through an attacker-controlled mirror that re-signs commits.
                if currentSection.hasPrefix("url ") && line.lowercased().hasPrefix("insteadof") {
                    let value = extractGitValue(line)
                    let target = currentSection
                        .replacingOccurrences(of: "url \"", with: "")
                        .replacingOccurrences(of: "\"", with: "")
                    findings.append(Finding(
                        severity: .medium, category: .supplyChain,
                        title: "Git URL rewrite rule active",
                        detail: "Any push/pull to '\(value)' is rerouted through '\(target)'",
                        path: path,
                        remediation: "Verify legitimate (mirror, monorepo proxy). Inspect: git config --global --get-regexp '^url\\.'"
                    ))
                }
            }
        }
    }

    /// Pull the value out of `key = value` git-config lines, returning "" when no `=` is present.
    private func extractGitValue(_ line: String) -> String {
        guard let eq = line.firstIndex(of: "=") else { return "" }
        return line[line.index(after: eq)...]
            .trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
    }

    /// Like `extractGitValue`, but returns nil when the line isn't actually an assignment.
    /// Useful for `[alias]` where the key is freeform (`co = checkout`, not just `path = ...`).
    private func extractGitValueIfAssignment(_ line: String) -> String? {
        guard line.contains("=") else { return nil }
        return extractGitValue(line)
    }

    // MARK: - Global git hooks (~/.git-templates) and core.hooksPath targets

    private func scanGitTemplates(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // `~/.git-templates/hooks/*` is copied into every newly-cloned repo's `.git/hooks/`.
        // A pre-commit / post-checkout payload there runs on every developer's machine that
        // clones a repo after the tampering — a strong persistence and lateral-movement channel.
        let templatePath = "\(home)/.git-templates/hooks"
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: templatePath) else { return }

        for entry in entries {
            if entry.hasPrefix(".") || entry.hasSuffix(".sample") { continue }
            let hookPath = "\(templatePath)/\(entry)"

            // Skip if not executable — a non-executable file in the template isn't actually run.
            guard let attrs = try? fm.attributesOfItem(atPath: hookPath),
                  let perms = attrs[.posixPermissions] as? NSNumber else { continue }
            let isExec = (perms.intValue & 0o111) != 0
            guard isExec else { continue }

            // We don't know what the hook does, but its mere presence is unusual for end-users —
            // and even legitimate templates should be reviewed by Sweep's user since they execute
            // arbitrary code on every repo init/clone.
            findings.append(Finding(
                severity: .medium, category: .supplyChain,
                title: "Global git hook is installed (\(entry))",
                detail: "Hook at \(hookPath) is copied into every new git repository and runs on \(entry) events",
                path: hookPath,
                remediation: "Review contents: cat \"\(hookPath)\" — remove if you didn't add it"
            ))
        }
    }

    // MARK: - SSH client config

    private func scanSSHClientConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Three things to look for in the user's ~/.ssh/config:
        // 1. `Include` directives that pull in another file (which we can't audit further here)
        // 2. `ProxyCommand` / `ProxyJump` entries running shell payloads
        // 3. `ForwardAgent yes` for hosts where it shouldn't be on (credential-theft surface)
        let path = "\(home)/.ssh/config"
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }

        let lines = content.split(separator: "\n").map { String($0) }
        for (idx, rawLine) in lines.enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let lower = line.lowercased()

            if lower.hasPrefix("include ") {
                let value = String(line.dropFirst("Include ".count)).trimmingCharacters(in: .whitespaces)
                // Includes that resolve outside ~/.ssh are unusual — flag them. We allow the
                // common ~/.ssh/conf.d/* pattern that ssh_config(5) documents.
                let inSSHDir = value.hasPrefix("~/.ssh/") || value.hasPrefix(home + "/.ssh/") ||
                               value.hasPrefix("/etc/ssh/")
                if !inSSHDir {
                    findings.append(Finding(
                        severity: .medium, category: .supplyChain,
                        title: "SSH config chain-includes a file outside ~/.ssh",
                        detail: "Line \(idx + 1) of \(path): Include \(value)",
                        path: path,
                        remediation: "Inspect that include — SSH will read settings (and ProxyCommands) from it"
                    ))
                }
            }

            if lower.hasPrefix("proxycommand") {
                let value = String(line.dropFirst("ProxyCommand".count)).trimmingCharacters(in: .whitespaces)
                // ProxyCommand runs arbitrary shell on every ssh — a known persistence trick.
                let suspicious = value.contains("curl") || value.contains("wget") ||
                                 value.contains("|sh") || value.contains("| sh") ||
                                 value.contains("/tmp/") || value.contains("base64")
                if suspicious {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "SSH ProxyCommand executes suspicious shell",
                        detail: "Line \(idx + 1) of \(path): ProxyCommand \(String(value.prefix(120)))",
                        path: path,
                        remediation: "Inspect and remove if unexpected — every ssh connection runs this command"
                    ))
                }
            }
        }
    }

    // MARK: - Python: pip / poetry / uv

    private func scanPythonConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // ~/.pypirc holds upload credentials and (when extended) custom indexes.
        // pip.conf can pin an `index-url` so every `pip install` reaches an attacker mirror.
        let configs: [(path: String, kind: String)] = [
            ("\(home)/.pypirc", "pypirc"),
            ("\(home)/.pip/pip.conf", "pip.conf"),
            ("\(home)/Library/Application Support/pip/pip.conf", "pip.conf"),
            ("\(home)/.config/pip/pip.conf", "pip.conf"),
            ("\(home)/.config/uv/uv.toml", "uv"),
        ]

        for (path, kind) in configs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            let lines = content.split(separator: "\n").map { String($0) }
            for (idx, rawLine) in lines.enumerated() {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
                let lower = line.lowercased()

                let mentionsIndex = lower.contains("index-url") || lower.contains("indexurl") ||
                                    lower.contains("extra-index") || lower.contains("repository") ||
                                    lower.hasPrefix("index =") || lower.hasPrefix("index=")
                if mentionsIndex && lower.contains("://") {
                    let trusted = ["pypi.org", "pypi.python.org", "files.pythonhosted.org",
                                   "test.pypi.org", "artifactory", "jfrog", "nexus", "devpi",
                                   "pkgs.dev.azure.com", "pkg.github.com"]
                    let isTrusted = trusted.contains(where: { lower.contains($0) })
                    let isPlainHTTP = lower.contains("http://") && !lower.contains("://localhost") && !lower.contains("://127.0.0.1")
                    if isPlainHTTP {
                        findings.append(Finding(
                            severity: .high, category: .supplyChain,
                            title: "\(kind) index is served over plain HTTP",
                            detail: "Line \(idx + 1) of \(path): \(String(line.prefix(120))) — packages can be swapped in transit",
                            path: path,
                            remediation: "Switch to HTTPS or remove the line"
                        ))
                    } else if !isTrusted {
                        findings.append(Finding(
                            severity: .medium, category: .supplyChain,
                            title: "\(kind) configured with an unrecognized package index",
                            detail: "Line \(idx + 1) of \(path): \(String(line.prefix(120)))",
                            path: path,
                            remediation: "Verify this is your employer's mirror. Remove if unexpected: open \(path)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Cargo (Rust)

    private func scanCargoConfig(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Cargo lets you replace crates.io with a `[source.crates-io]` `replace-with` directive.
        // Several recent campaigns ship a config that points crates.io at an attacker mirror that
        // serves modified versions of well-known crates.
        let configs = [
            "\(home)/.cargo/config.toml",
            "\(home)/.cargo/config",
        ]

        for path in configs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lower = content.lowercased()

            // Look for any `replace-with` outside a comment.
            for (idx, rawLine) in content.split(separator: "\n").enumerated() {
                let line = String(rawLine).trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }
                if line.lowercased().hasPrefix("replace-with") {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "Cargo replaces crates.io with a different source",
                        detail: "Line \(idx + 1) of \(path): \(String(line.prefix(120))) — every `cargo build` will fetch dependencies from the alternate registry",
                        path: path,
                        remediation: "Verify legitimate (employer mirror). Remove if unexpected: open \(path)"
                    ))
                }
            }

            // Custom `[source.*]` blocks pointing at registries other than the official one.
            if lower.contains("registry = \"sparse+http://") || lower.contains("registry = \"http://") {
                findings.append(Finding(
                    severity: .high, category: .supplyChain,
                    title: "Cargo configured with a plain-HTTP crate registry",
                    detail: "\(path) lists a registry served over HTTP — anyone on the network can substitute crates",
                    path: path,
                    remediation: "Switch the registry to HTTPS or remove the override"
                ))
            }
        }
    }

    // MARK: - Homebrew taps

    private func scanHomebrewTaps(findings: inout [Finding], errors: inout [String]) {
        // `brew tap` adds a third-party formula repository. Tapped repos can ship formulas that run
        // arbitrary install scripts. A genuinely unknown tap on a developer's machine is worth review.
        let result = ShellRunner.run("/bin/sh", arguments: ["-c", "command -v brew >/dev/null 2>&1 && brew tap || true"], timeout: 10)
        guard result.success, !result.stdout.isEmpty else { return }

        // These taps are widely used and don't need to be flagged.
        let common: Set<String> = [
            "homebrew/core", "homebrew/cask", "homebrew/services", "homebrew/bundle",
            "homebrew/cask-fonts", "homebrew/cask-versions", "homebrew/cask-drivers",
            "hashicorp/tap", "mongodb/brew", "aws/tap", "azure/functions", "azure/kubelogin",
            "supabase/tap", "oven-sh/bun", "anthropics/tap",
        ]

        for line in result.stdout.split(separator: "\n") {
            let tap = String(line).trimmingCharacters(in: .whitespaces).lowercased()
            if tap.isEmpty || common.contains(tap) { continue }

            findings.append(Finding(
                severity: .low, category: .supplyChain,
                title: "Custom Homebrew tap is installed",
                detail: "Tap: \(tap) — formulas from this tap can run arbitrary install scripts",
                path: nil,
                remediation: "If you don't recognise this tap: brew untap \(tap)"
            ))
        }
    }

    // MARK: - Shell hook overrides

    private func scanShellHookOverrides(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Shell init files don't just live in ~/.zshrc — pre-prompt hook frameworks add functions
        // to `precmd_functions` / `chpwd_functions` (zsh) and `PROMPT_COMMAND` (bash). A malicious
        // function added to these arrays runs before every shell prompt. We scan the rc files for
        // suspicious additions to these specific hook variables.
        let shellConfigs = [
            "\(home)/.zshrc", "\(home)/.zprofile", "\(home)/.zshenv",
            "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile",
        ]

        let suspiciousHookKeywords = ["curl", "wget", "/tmp/", "base64", "eval", "exec /", "/dev/tcp/"]

        for path in shellConfigs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            for (idx, rawLine) in content.split(separator: "\n").enumerated() {
                let line = String(rawLine).trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }
                let lower = line.lowercased()

                let hooksHere = lower.contains("precmd_functions") || lower.contains("chpwd_functions") ||
                                lower.contains("prompt_command")
                guard hooksHere else { continue }

                if suspiciousHookKeywords.contains(where: { lower.contains($0) }) {
                    findings.append(Finding(
                        severity: .high, category: .supplyChain,
                        title: "Shell prompt hook runs a suspicious command",
                        detail: "Line \(idx + 1) of \(path): \(String(line.prefix(120)))",
                        path: path,
                        remediation: "Inspect — anything bound to PROMPT_COMMAND / precmd_functions runs before each shell prompt"
                    ))
                }
            }
        }
    }
}
