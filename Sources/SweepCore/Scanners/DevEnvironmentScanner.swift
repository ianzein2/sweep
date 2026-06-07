import Foundation

/// Detects tampering of developer-environment configuration — a vector that exploded in
/// 2024–2025 with the DPRK "Contagious Interview" / BeaverTail campaigns, malicious npm/PyPI
/// post-install scripts, and supply-chain compromises of common dev tools.
///
/// Most users running Sweep are developers; an attacker who flips one line in `.gitconfig`,
/// `~/.ssh/config`, or `.npmrc` can run arbitrary code during a `git pull` or `npm install`
/// without ever touching launchd, browser extensions, or any of the classic persistence
/// channels the other scanners cover.
public final class DevEnvironmentScanner: Scanner {
    public let name = "Dev Environment Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        progress?.update("checking SSH configuration")
        scanSSHConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking SSH daemon configuration")
        scanSSHDConfig(findings: &findings, errors: &errors)

        progress?.update("checking Git configuration")
        scanGitConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking npm / Node config")
        scanNpmConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking Python / pip config")
        scanPythonConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking cloud credentials")
        scanCloudCredentials(home: home, findings: &findings, errors: &errors)

        progress?.update("checking editor auto-task abuse")
        scanEditorWorkspaceTasks(home: home, findings: &findings, errors: &errors)

        progress?.update("checking direnv / .envrc files")
        scanEnvrcFiles(home: home, findings: &findings, errors: &errors)

        progress?.update("checking shell history for credential dumps")
        scanShellHistoryAnomalies(home: home, findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - SSH client config

    /// `~/.ssh/config` settings an attacker can use to silently MITM your git/server traffic:
    ///   - ProxyCommand → run arbitrary shell on every `ssh ...` invocation
    ///   - LocalCommand + PermitLocalCommand → run after a session opens
    ///   - Host * with non-default IdentityFile/UserKnownHostsFile → swap your keys/trust
    private func scanSSHConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let sshConfig = "\(home)/.ssh/config"
        guard let content = try? String(contentsOfFile: sshConfig, encoding: .utf8) else { return }

        let lines = content.components(separatedBy: "\n")
        var sawPermitLocal = false

        for (idx, raw) in lines.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let lower = line.lowercased()

            // ProxyCommand piping through shell utilities can replace your keys/known_hosts
            // or simply tee your traffic. Legitimate uses (corp SSO/Teleport) exist, so flag
            // explicitly for review rather than auto-remediate.
            if lower.hasPrefix("proxycommand") {
                let isObvious = lower.contains("curl") || lower.contains("wget") ||
                                lower.contains("/tmp/") || lower.contains("base64") ||
                                lower.contains("nc ") || lower.contains("ncat")
                findings.append(Finding(
                    severity: isObvious ? .high : .medium, category: .persistence,
                    title: "SSH ProxyCommand configured in ~/.ssh/config",
                    detail: "Line \(idx + 1): \(String(line.prefix(120))) — every SSH connection runs this command",
                    path: sshConfig,
                    remediation: "Verify this is your corporate SSO/bastion (Teleport, gcloud, ssm). Otherwise remove — attackers use ProxyCommand to MITM git/server traffic."
                ))
            }

            if lower.hasPrefix("permitlocalcommand") && lower.contains("yes") {
                sawPermitLocal = true
            }

            if lower.hasPrefix("localcommand") && sawPermitLocal {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "SSH LocalCommand executes on every connection",
                    detail: "Line \(idx + 1): \(String(line.prefix(120)))",
                    path: sshConfig,
                    remediation: "Remove unless intentional — LocalCommand runs locally after each successful SSH session"
                ))
            }

            // IdentityAgent override pointing somewhere odd is how attackers proxy your private keys.
            if lower.hasPrefix("identityagent") {
                let value = line.split(separator: " ", maxSplits: 1).dropFirst().first.map(String.init) ?? ""
                let legit = value.contains("1password") || value.contains("Bitwarden") ||
                            value.contains("com.apple.") || value.contains("/Library/Group Containers/")
                if !legit && !value.contains("$SSH_AUTH_SOCK") && !value.isEmpty {
                    findings.append(Finding(
                        severity: .medium, category: .persistence,
                        title: "SSH IdentityAgent points to non-standard socket",
                        detail: "Line \(idx + 1): \(line)",
                        path: sshConfig,
                        remediation: "Verify this socket — a rogue agent can sign requests with your private keys without your consent"
                    ))
                }
            }
        }

        // World-writable ~/.ssh is a classic privilege-escalation gift
        let sshDir = "\(home)/.ssh"
        if let attrs = try? FileManager.default.attributesOfItem(atPath: sshDir),
           let posix = attrs[.posixPermissions] as? Int, (posix & 0o002) != 0 {
            findings.append(Finding(
                severity: .high, category: .hardening,
                title: "~/.ssh directory is world-writable",
                detail: "Permissions: \(String(posix, radix: 8)) — anyone on this Mac can drop authorized_keys",
                path: sshDir,
                remediation: "Run: chmod 700 \"\(sshDir)\""
            ))
        }
    }

    // MARK: - SSH daemon (sshd) config

    /// If the user has Remote Login enabled, several sshd_config knobs decide how exposed they are.
    /// macOS 13+ ships with a hardened default — these flags catch drift.
    private func scanSSHDConfig(findings: inout [Finding], errors: inout [String]) {
        let candidates = ["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
        for path in candidates {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Only relevant when sshd is actually accepting connections
            let listening = ShellRunner.run("/bin/sh", arguments: [
                "-c", "lsof -i :22 -nP 2>/dev/null | grep -i LISTEN | head -1"
            ], timeout: 3)
            let sshOn = listening.success && !listening.stdout.isEmpty

            let lines = content.components(separatedBy: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }

            func value(of key: String) -> String? {
                for line in lines where line.lowercased().hasPrefix(key.lowercased() + " ") ||
                                         line.lowercased() == key.lowercased() {
                    return line.split(separator: " ", maxSplits: 1).dropFirst().first.map { String($0).trimmingCharacters(in: .whitespaces) }
                }
                return nil
            }

            if sshOn {
                if value(of: "PermitRootLogin")?.lowercased() == "yes" {
                    findings.append(Finding(
                        severity: .high, category: .hardening,
                        title: "sshd_config allows root SSH login",
                        detail: "PermitRootLogin yes — root can SSH in directly with a password",
                        path: path,
                        remediation: "Set: PermitRootLogin no (or prohibit-password) in \(path) and restart sshd"
                    ))
                }
                if value(of: "PasswordAuthentication")?.lowercased() == "yes" {
                    findings.append(Finding(
                        severity: .medium, category: .hardening,
                        title: "sshd_config allows password authentication",
                        detail: "PasswordAuthentication yes — attackers can brute-force; key-based auth is safer",
                        path: path,
                        remediation: "Set: PasswordAuthentication no after confirming all users have SSH keys enrolled"
                    ))
                }
                if value(of: "PermitEmptyPasswords")?.lowercased() == "yes" {
                    findings.append(Finding(
                        severity: .high, category: .hardening,
                        title: "sshd_config permits empty passwords",
                        detail: "PermitEmptyPasswords yes — users with blank passwords can SSH in",
                        path: path,
                        remediation: "Set: PermitEmptyPasswords no immediately"
                    ))
                }
            }
            break
        }
    }

    // MARK: - Git config

    /// Three git-config primitives can give an attacker code execution at every `git pull/clone`:
    ///   - core.hooksPath redirected to an attacker-controlled directory
    ///   - core.fsmonitor pointing at an arbitrary binary
    ///   - core.editor / core.pager / sequence.editor / credential.helper pointed at shell loaders
    ///   - url."..".insteadOf rewriting to attacker URLs
    private func scanGitConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let gitConfigs = [
            "\(home)/.gitconfig",
            "\(home)/.config/git/config",
        ]
        let fm = FileManager.default

        for path in gitConfigs {
            guard fm.fileExists(atPath: path),
                  let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // Walk line-by-line so we don't have to share String.Index between cases of `content`.
            // git config keys live as `key = value` (or `key=value`) inside `[section]` headers,
            // but `git config --global` always rewrites in canonical form, so a flat scan works.
            func valueOf(_ key: String) -> String? {
                for raw in content.components(separatedBy: "\n") {
                    let line = raw.trimmingCharacters(in: .whitespaces)
                    if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
                    let lower = line.lowercased()
                    // Match either "key = value" or fully-qualified "section.key = value"
                    guard lower.hasPrefix(key.lowercased() + " ") ||
                          lower.hasPrefix(key.lowercased() + "=") else { continue }
                    let parts = line.split(separator: "=", maxSplits: 1)
                    guard parts.count == 2 else { continue }
                    return String(parts[1])
                        .trimmingCharacters(in: .whitespaces)
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                }
                return nil
            }

            if let hooks = valueOf("hooksPath"), !hooks.isEmpty {
                let suspicious = hooks.hasPrefix("/tmp") || hooks.contains("/.") ||
                                 hooks.hasPrefix("/var/tmp") || hooks.hasPrefix("/private/tmp")
                findings.append(Finding(
                    severity: suspicious ? .high : .medium, category: .persistence,
                    title: "Git core.hooksPath is overridden",
                    detail: "hooksPath = \(hooks) — scripts in this directory run on every git pull/commit",
                    path: path,
                    remediation: "Verify this directory's contents and ownership: ls -la \(hooks)"
                ))
            }

            if valueOf("fsmonitor") != nil {
                findings.append(Finding(
                    severity: .medium, category: .persistence,
                    title: "Git core.fsmonitor is set to a custom hook",
                    detail: "Custom fsmonitor binary runs on every git status/checkout — verify it's expected",
                    path: path,
                    remediation: "Inspect: git config --global core.fsmonitor"
                ))
            }

            // Per-config command-runner directives
            let runnerKeys: [(key: String, label: String)] = [
                ("helper",        "credential.helper"),
                ("editor",        "core.editor / sequence.editor"),
                ("pager",         "core.pager"),
            ]
            for runner in runnerKeys {
                guard let value = valueOf(runner.key), !value.isEmpty else { continue }
                let suspicious = value.hasPrefix("/tmp") || value.hasPrefix("/var/tmp") ||
                                 value.hasPrefix("/private/tmp") || value.contains("/.") ||
                                 value.contains("curl ") || value.contains("base64") ||
                                 value.contains("python -c") || value.contains("bash -c") ||
                                 value.hasPrefix("!")  // shell-prefixed values
                if suspicious {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: "Git \(runner.label) points to suspicious runner",
                        detail: "\(runner.label) = \(value)",
                        path: path,
                        remediation: "Inspect and reset: git config --global --unset \(runner.label)"
                    ))
                }
            }

            // url.<base>.insteadOf — a one-line typo-squat that reroutes every clone
            // to attacker infrastructure.
            for line in content.components(separatedBy: "\n") {
                let lc = line.lowercased().trimmingCharacters(in: .whitespaces)
                if lc.contains("insteadof") {
                    // Flag if it doesn't rewrite to a well-known host
                    let isLegit = lc.contains("github.com") || lc.contains("gitlab.com") ||
                                  lc.contains("bitbucket.org") || lc.contains("ssh://") ||
                                  lc.contains("git@") || lc.contains("apple-")
                    if !isLegit {
                        findings.append(Finding(
                            severity: .medium, category: .persistence,
                            title: "Git URL rewrite rule (insteadOf) present",
                            detail: "\(String(line.prefix(120)))",
                            path: path,
                            remediation: "Verify this rewrite is intentional — it transparently redirects clones/pulls"
                        ))
                    }
                }
            }

            // External alias scripts can hide a backdoor behind `git pull` / `git status`
            if lower.contains("[alias]") {
                for line in content.components(separatedBy: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    let lc = trimmed.lowercased()
                    if lc.hasPrefix("[") || trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
                    if lc.contains("= !") && (
                        lc.contains("curl") || lc.contains("wget") || lc.contains("base64") ||
                        lc.contains("/tmp/") || lc.contains("eval ")
                    ) {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Git alias runs suspicious shell command",
                            detail: "\(String(trimmed.prefix(120)))",
                            path: path,
                            remediation: "Remove the alias: git config --global --unset alias.<name>"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - npm config

    /// Malicious npm scripts are the most common 2024–2025 dev-machine compromise path
    /// (BeaverTail/Contagious Interview, ts-js-yaml supply chain, etc.).
    /// We don't try to scan node_modules — instead we look at:
    ///   - the global .npmrc (custom registries, ignore-scripts disabled in odd ways)
    ///   - lifecycle scripts in the global package list
    private func scanNpmConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let npmrcPaths = ["\(home)/.npmrc", "/usr/local/etc/npmrc", "/etc/npmrc"]
        for path in npmrcPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lines = content.components(separatedBy: "\n")
            for (idx, raw) in lines.enumerated() {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
                let lower = line.lowercased()

                // A non-default registry by itself is fine; pointing at a raw IP or HTTP is not.
                if lower.hasPrefix("registry=") || lower.contains("registry =") {
                    let value = line.split(separator: "=").dropFirst().joined(separator: "=")
                        .trimmingCharacters(in: .whitespaces)
                    let isHttp = value.lowercased().hasPrefix("http://")
                    let isIP = value.range(of: #"://\d+\.\d+\.\d+\.\d+"#, options: .regularExpression) != nil
                    let isOfficial = value.contains("registry.npmjs.org") ||
                                     value.contains("registry.yarnpkg.com") ||
                                     value.contains("pkg.github.com") ||
                                     value.contains("artifactory") ||
                                     value.contains("jfrog") ||
                                     value.contains("nexus") ||
                                     value.contains("verdaccio")
                    if (isHttp || isIP) && !isOfficial {
                        findings.append(Finding(
                            severity: isHttp ? .high : .medium, category: .persistence,
                            title: ".npmrc uses non-standard registry",
                            detail: "Line \(idx + 1): \(line) — packages will be fetched from here on every install",
                            path: path,
                            remediation: "Verify this registry is your employer's. Otherwise reset: npm config delete registry"
                        ))
                    }
                }

                // Tokens belong in a credential manager, not on disk
                if (lower.contains("authtoken") || lower.contains("_auth=") || lower.contains("_authtoken=")) &&
                   !lower.contains("${") {
                    findings.append(Finding(
                        severity: .low, category: .hardening,
                        title: ".npmrc contains a hard-coded auth token",
                        detail: "Line \(idx + 1): \(String(line.prefix(60)))…",
                        path: path,
                        remediation: "Move to env var or 1Password/Bitwarden CLI; rotate the token if exposed"
                    ))
                }
            }
        }
    }

    // MARK: - Python / pip config

    /// PyPI mirrors and pre-install hooks are a common malware vector. We look at:
    ///   - ~/.pip/pip.conf and ~/.config/pip/pip.conf with custom index-url
    ///   - sitecustomize.py / usercustomize.py — auto-imported by every Python process
    private func scanPythonConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let pipConfigs = ["\(home)/.pip/pip.conf", "\(home)/.config/pip/pip.conf"]
        for path in pipConfigs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for raw in content.components(separatedBy: "\n") {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
                let lower = line.lowercased()
                guard lower.hasPrefix("index-url") || lower.hasPrefix("extra-index-url") else { continue }

                let parts = line.split(separator: "=", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let value = String(parts[1]).trimmingCharacters(in: .whitespaces)
                let isHttp = value.lowercased().hasPrefix("http://")
                let isOfficial = value.contains("pypi.org") || value.contains("pythonhosted") ||
                                 value.contains("artifactory") || value.contains("jfrog") ||
                                 value.contains("nexus") || value.contains("devpi")
                if (!isOfficial && !value.isEmpty) || isHttp {
                    findings.append(Finding(
                        severity: isHttp ? .high : .medium, category: .persistence,
                        title: "pip configured to use non-standard package index",
                        detail: "\(lower.hasPrefix("extra-index-url") ? "extra-index-url" : "index-url") = \(value) — Python packages will be fetched from this server",
                        path: path,
                        remediation: "Verify this is your employer's mirror. Otherwise reset: pip config unset global.index-url"
                    ))
                }
            }
        }

        // sitecustomize.py / usercustomize.py — imported by every Python invocation
        let fm = FileManager.default
        let customSearchPaths = [
            "\(home)/.local/lib",
            "/Library/Python",
            "/usr/local/lib/python",
            "\(home)/Library/Python",
        ]
        for root in customSearchPaths {
            guard let enumerator = fm.enumerator(atPath: root) else { continue }
            var checked = 0
            while let entry = enumerator.nextObject() as? String {
                checked += 1
                if checked > 200 { break }  // cap walk
                let name = (entry as NSString).lastPathComponent
                guard name == "sitecustomize.py" || name == "usercustomize.py" else { continue }
                let fullPath = "\(root)/\(entry)"
                if let body = try? String(contentsOfFile: fullPath, encoding: .utf8) {
                    let lc = body.lowercased()
                    let suspicious = lc.contains("subprocess") || lc.contains("os.system") ||
                                     lc.contains("urllib.request") || lc.contains("requests.get") ||
                                     lc.contains("socket") || lc.contains("base64")
                    if suspicious {
                        findings.append(Finding(
                            severity: .high, category: .persistence,
                            title: "Python \(name) executes network/shell code",
                            detail: "This file is auto-imported by every Python process — \(body.count) bytes",
                            path: fullPath,
                            remediation: "Inspect contents; remove if unexpected: cat \"\(fullPath)\""
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Cloud credentials

    /// Cleartext cloud credential files are a high-value target — stealers grab them by name.
    /// We don't report their mere existence (most devs have them); we flag world-readable perms
    /// and copies in tmp/hidden staging dirs.
    private func scanCloudCredentials(home: String, findings: inout [Finding], errors: inout [String]) {
        let credFiles: [(path: String, label: String)] = [
            ("\(home)/.aws/credentials",        "AWS access keys"),
            ("\(home)/.azure/accessTokens.json","Azure tokens"),
            ("\(home)/.config/gcloud/application_default_credentials.json", "gcloud ADC"),
            ("\(home)/.docker/config.json",     "Docker registry credentials"),
            ("\(home)/.kube/config",            "Kubernetes credentials"),
            ("\(home)/.netrc",                  ".netrc credentials"),
        ]
        let fm = FileManager.default

        for cred in credFiles {
            guard fm.fileExists(atPath: cred.path) else { continue }
            guard let attrs = try? fm.attributesOfItem(atPath: cred.path) else { continue }
            let posix = (attrs[.posixPermissions] as? Int) ?? 0

            // Group/other read on a credentials file is a misconfiguration
            if (posix & 0o077) != 0 {
                findings.append(Finding(
                    severity: .medium, category: .hardening,
                    title: "\(cred.label) file is over-permissive",
                    detail: "Permissions: \(String(posix, radix: 8)) on \(cred.path)",
                    path: cred.path,
                    remediation: "Tighten: chmod 600 \"\(cred.path)\""
                ))
            }
        }

        // Look for copies of these files outside their expected location (stealer staging)
        let stealerDirs = ["/tmp", "/private/tmp", "/var/tmp"]
        let targetNames: Set<String> = [
            "credentials", "config.json", "accessTokens.json",
            "application_default_credentials.json", ".netrc",
        ]
        for dir in stealerDirs {
            guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where targetNames.contains(entry) {
                let path = "\(dir)/\(entry)"
                findings.append(Finding(
                    severity: .high, category: .suspiciousFile,
                    title: "Cloud credential-shaped file in temp directory",
                    detail: "\(entry) at \(path) — stealers stage these for exfiltration",
                    path: path,
                    remediation: "Inspect: head -5 \"\(path)\" — rotate any matching credentials and find the process that put it here"
                ))
            }
        }
    }

    // MARK: - Editor workspace tasks (VSCode / Cursor / Claude Code)

    /// `.vscode/tasks.json` and `.vscode/settings.json` (and the Cursor equivalents) can run
    /// arbitrary shell commands automatically on folder open via `runOn: folderOpen` or
    /// `python.terminal.activateEnvironment` style autoruns. Recent supply-chain attacks have
    /// shipped malicious `tasks.json` inside repo templates to compromise developers who clone
    /// a project and let their editor restore the workspace.
    private func scanEditorWorkspaceTasks(home: String, findings: inout [Finding], errors: inout [String]) {
        let candidates = [
            "\(home)/.vscode/settings.json",
            "\(home)/.cursor/settings.json",
            "\(home)/Library/Application Support/Code/User/settings.json",
            "\(home)/Library/Application Support/Cursor/User/settings.json",
            "\(home)/Library/Application Support/Windsurf/User/settings.json",
        ]

        for path in candidates {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lc = content.lowercased()

            // code-runner.executorMap pointing at base64/curl loaders
            if (lc.contains("code-runner.executormap") || lc.contains("code-runner.runinterminal")) &&
               (lc.contains("curl ") || lc.contains("wget ") || lc.contains("base64")) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "VSCode/Cursor code-runner auto-executes remote command",
                    detail: "settings.json contains code-runner config with curl/wget/base64",
                    path: path,
                    remediation: "Open and review: \(path) — remove any code-runner.executorMap that downloads code"
                ))
            }

            // terminal.integrated.shellArgs or env.osx with `-c "curl ... | sh"` pattern
            if lc.contains("terminal.integrated") &&
               (lc.contains("\"-c\"") || lc.contains("'-c'")) &&
               (lc.contains("curl ") || lc.contains("wget ")) {
                findings.append(Finding(
                    severity: .high, category: .persistence,
                    title: "Editor terminal launches with download-and-run command",
                    detail: "settings.json's terminal.integrated config runs curl/wget on every shell open",
                    path: path,
                    remediation: "Open the file and remove any \"-c\" args invoking curl/wget"
                ))
            }
        }
    }

    // MARK: - direnv .envrc files

    /// `direnv` auto-executes `.envrc` files on `cd`. A `.envrc` checked into a malicious repo
    /// is a one-shot RCE; many devs leave `direnv allow` set permissively.
    private func scanEnvrcFiles(home: String, findings: inout [Finding], errors: inout [String]) {
        // Only look in obvious places — we're not walking the whole disk.
        let roots = [home, "\(home)/Developer", "\(home)/Documents", "\(home)/Projects",
                     "\(home)/code", "\(home)/src", "\(home)/work"]
        let fm = FileManager.default
        var checkedCount = 0

        for root in roots {
            guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for entry in entries {
                if checkedCount > 30 { break }  // cap for performance
                let projectDir = "\(root)/\(entry)"
                let envrc = "\(projectDir)/.envrc"
                guard fm.fileExists(atPath: envrc),
                      let body = try? String(contentsOfFile: envrc, encoding: .utf8) else { continue }
                checkedCount += 1

                let lc = body.lowercased()
                // Flag the dangerous patterns; an `export FOO=bar` .envrc is normal.
                let dangerous = (lc.contains("curl ") || lc.contains("wget ")) &&
                                (lc.contains("| sh") || lc.contains("| bash") ||
                                 lc.contains("|sh") || lc.contains("|bash"))
                let evalRemote = lc.contains("eval \"$(curl") || lc.contains("eval \"$(wget") ||
                                  lc.contains("eval $(curl") || lc.contains("eval $(wget")

                if dangerous || evalRemote {
                    findings.append(Finding(
                        severity: .high, category: .persistence,
                        title: ".envrc downloads and runs remote code",
                        detail: "Project: \(entry) — direnv will run this every time you cd into the directory",
                        path: envrc,
                        remediation: "Inspect: cat \"\(envrc)\" — and run: direnv deny \"\(projectDir)\""
                    ))
                }
            }
        }
    }

    // MARK: - Shell history anomalies

    /// Recent shell-history lines that dump credentials, the keychain, or browser cookies
    /// indicate either an interactive intrusion or that a malicious script ran in this shell.
    private func scanShellHistoryAnomalies(home: String, findings: inout [Finding], errors: inout [String]) {
        let histories = ["\(home)/.zsh_history", "\(home)/.bash_history",
                         "\(home)/.local/share/fish/fish_history"]
        let patterns: [(needle: String, why: String)] = [
            ("security dump-keychain",   "macOS keychain dump"),
            ("security find-generic-password", "keychain password lookup"),
            ("security find-internet-password", "keychain password lookup"),
            ("/Login Data",              "Chromium login DB exfil"),
            ("/cookies.sqlite",          "Firefox cookie exfil"),
            (".ssh/id_rsa",              "SSH private key access"),
            (".aws/credentials",         "AWS credential access"),
            ("base64 -D",                "base64 decode + run"),
        ]

        for path in histories {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            // Only the last 2KB — recent activity is what matters
            let tail = String(content.suffix(2048))
            let lc = tail.lowercased()
            for pat in patterns {
                if lc.contains(pat.needle.lowercased()) {
                    findings.append(Finding(
                        severity: .medium, category: .suspiciousFile,
                        title: "Shell history contains \(pat.why)",
                        detail: "Pattern '\(pat.needle)' seen in tail of \((path as NSString).lastPathComponent)",
                        path: path,
                        remediation: "Inspect: tail -100 \"\(path)\" | grep -i \"\(pat.needle)\" — verify you ran this yourself"
                    ))
                    break  // one finding per file per pattern type is enough
                }
            }
        }
    }
}
