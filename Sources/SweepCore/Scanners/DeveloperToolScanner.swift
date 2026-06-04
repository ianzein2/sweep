import Foundation

/// Scans developer-environment attack surfaces that have become major spyware vectors
/// in 2024-2025: malicious Model Context Protocol (MCP) servers wired into AI assistants,
/// hijacked git/SSH/npm/pip configs, and shell aliases that wrap security-sensitive commands.
///
/// Most existing macOS scanners focus on processes and launch agents, leaving the
/// developer toolchain — which routinely executes code with the user's full privileges —
/// largely unexamined. This scanner closes that gap.
public final class DeveloperToolScanner: Scanner {
    public let name = "Developer Tool Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        progress?.update("checking MCP server configurations")
        scanMCPServers(home: home, findings: &findings, errors: &errors)

        progress?.update("checking git configuration")
        scanGitConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking SSH client configuration")
        scanSSHClientConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking shell aliases / functions")
        scanShellAliases(home: home, findings: &findings, errors: &errors)

        progress?.update("checking npm / pip / cargo configuration")
        scanPackageManagerConfig(home: home, findings: &findings, errors: &errors)

        progress?.update("checking VS Code / Cursor settings")
        scanEditorSettings(home: home, findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - MCP Servers (Claude Desktop, Cursor, Cline, Windsurf)

    /// Brand-new attack surface (2024-2025): AI assistants like Claude Desktop and Cursor
    /// run user-configured Model Context Protocol servers as child processes with the user's
    /// privileges. A malicious MCP entry is effectively a launch-on-AI-use payload — and
    /// because it lives in a per-app JSON config rather than LaunchAgents, traditional
    /// persistence scanners miss it entirely.
    private func scanMCPServers(home: String, findings: inout [Finding], errors: inout [String]) {
        // Each tuple: (display name, config path). Several IDEs reuse the same schema.
        let configs: [(name: String, path: String)] = [
            ("Claude Desktop", "\(home)/Library/Application Support/Claude/claude_desktop_config.json"),
            ("Cursor", "\(home)/.cursor/mcp.json"),
            ("Cursor (Library)", "\(home)/Library/Application Support/Cursor/User/mcp.json"),
            ("Cline", "\(home)/.cline/mcp.json"),
            ("Windsurf", "\(home)/.codeium/windsurf/mcp_config.json"),
            ("Continue", "\(home)/.continue/config.json"),
        ]

        for cfg in configs {
            guard let data = FileManager.default.contents(atPath: cfg.path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Both Claude Desktop and Cursor use "mcpServers" as the top-level key.
            let servers = (json["mcpServers"] as? [String: Any])
                ?? (json["servers"] as? [String: Any])
                ?? [:]

            for (serverName, raw) in servers {
                guard let entry = raw as? [String: Any] else { continue }
                let command = entry["command"] as? String ?? ""
                let args = (entry["args"] as? [String])?.joined(separator: " ") ?? ""
                let url = entry["url"] as? String ?? ""

                // Empty entries are template stubs — skip.
                if command.isEmpty && url.isEmpty { continue }

                if !command.isEmpty {
                    let severity = mcpCommandSeverity(command: command, args: args)
                    if let sev = severity {
                        findings.append(Finding(
                            severity: sev.severity, category: .developerTool,
                            title: "\(cfg.name) MCP server runs from \(sev.reason)",
                            detail: "Server \"\(serverName)\" — command: \(command) \(args.prefix(120))",
                            path: cfg.path,
                            remediation: "Open \(cfg.path) and remove the \"\(serverName)\" MCP server if you didn't add it"
                        ))
                    }
                }

                // Remote MCP via plain http:// is trivially man-in-the-middle-able and lets an
                // attacker drive the AI assistant's tool calls.
                if !url.isEmpty, url.lowercased().hasPrefix("http://") {
                    findings.append(Finding(
                        severity: .high, category: .developerTool,
                        title: "\(cfg.name) MCP server uses plain HTTP",
                        detail: "Server \"\(serverName)\" connects to \(url) — traffic can be intercepted and tampered with",
                        path: cfg.path,
                        remediation: "Switch to https:// or remove this MCP server entry"
                    ))
                }
            }
        }
    }

    /// Decide whether an MCP command path is suspicious. Returns nil if it looks benign.
    private func mcpCommandSeverity(command: String, args: String) -> (severity: Severity, reason: String)? {
        // Hidden directory or temp directory = high.
        if command.hasPrefix("/tmp/") || command.hasPrefix("/private/tmp/") || command.hasPrefix("/var/tmp/") {
            return (.high, "/tmp")
        }
        // Hidden directory in path that isn't a known toolchain dir.
        let comps = command.split(separator: "/").map(String.init)
        for comp in comps where comp.hasPrefix(".") && comp != "." && comp != ".." {
            if !DeveloperToolScanner.trustedHiddenDirs.contains(comp) {
                return (.high, "a hidden directory")
            }
        }
        // `curl … | sh` / `bash -c` style commands in MCP entries are loaders, not servers.
        let combined = "\(command) \(args)".lowercased()
        if combined.contains("curl ") && (combined.contains("| sh") || combined.contains("|sh") ||
                                          combined.contains("| bash") || combined.contains("|bash")) {
            return (.high, "a `curl | sh` loader")
        }
        if (command.hasSuffix("/sh") || command.hasSuffix("/bash") || command.hasSuffix("/zsh"))
           && combined.contains(" -c ") {
            return (.medium, "a shell -c invocation")
        }
        return nil
    }

    // MARK: - Git Configuration

    /// Looks for `core.hooksPath` redirection (a stealth persistence trick used in real
    /// 2024 attacks — every `git commit` runs attacker scripts), proxy hijacks, and
    /// alias overrides that wrap built-in git commands.
    private func scanGitConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let gitConfigs = [
            ("\(home)/.gitconfig", "global"),
            ("\(home)/.config/git/config", "XDG"),
            ("/etc/gitconfig", "system"),
        ]

        for (path, scope) in gitConfigs {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            let lines = content.split(separator: "\n").map { String($0) }

            // Parse key=value pairs grouped by [section]
            var currentSection = ""
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                    currentSection = String(trimmed.dropFirst().dropLast())
                    continue
                }
                if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { continue }
                guard let eq = trimmed.range(of: "=") else { continue }
                let key = trimmed[..<eq.lowerBound].trimmingCharacters(in: .whitespaces)
                let value = trimmed[eq.upperBound...].trimmingCharacters(in: .whitespaces)

                let fullKey = "\(currentSection).\(key)".lowercased()

                // core.hooksPath redirection — runs scripts on every git operation
                if fullKey == "core.hookspath" {
                    let untrusted = isUntrustedPath(value)
                    if untrusted {
                        findings.append(Finding(
                            severity: .high, category: .developerTool,
                            title: "Git core.hooksPath redirected (\(scope))",
                            detail: "Git hooks now run from \(value) — every commit / push / merge executes scripts there",
                            path: path,
                            remediation: "Reset: git config --\(scope == "system" ? "system" : "global") --unset core.hooksPath"
                        ))
                    }
                }

                // sshCommand override — git can be coerced to use attacker SSH binary.
                // Only flag when the first token (the executable) is in an untrusted path —
                // teams often legitimately set this to `ssh -i ~/.ssh/work_key` or similar.
                if fullKey == "core.sshcommand" {
                    let firstToken = value.split(separator: " ").first.map(String.init) ?? value
                    if isUntrustedPath(firstToken) {
                        findings.append(Finding(
                            severity: .high, category: .developerTool,
                            title: "Git core.sshCommand points to untrusted binary",
                            detail: "git uses: \(value) for SSH — attacker can swap keys / log credentials",
                            path: path,
                            remediation: "Reset: git config --global --unset core.sshCommand"
                        ))
                    }
                }

                // HTTP proxy injection — silently routes pushes/pulls through MITM
                if fullKey == "http.proxy" || fullKey == "https.proxy" {
                    let lower = value.lowercased()
                    let isLoopback = lower.contains("://127.0.0.1") || lower.contains("://localhost") ||
                                     lower.contains("://[::1]")
                    findings.append(Finding(
                        severity: isLoopback ? .low : .medium, category: .developerTool,
                        title: "Git \(currentSection).\(key) is set (\(scope))",
                        detail: "All git over HTTP(S) routes via \(value)" +
                            (isLoopback ? " (local MITM tool)" : ""),
                        path: path,
                        remediation: isLoopback
                            ? "Expected if you're using Charles/Proxyman — otherwise: git config --global --unset \(fullKey)"
                            : "Verify proxy is your employer's, or: git config --global --unset \(fullKey)"
                    ))
                }

                // Alias overrides that wrap built-in commands with shell payloads (`!…`)
                if currentSection.lowercased() == "alias" && value.hasPrefix("!") {
                    let payload = String(value.dropFirst()).trimmingCharacters(in: .whitespaces)
                    if isShellPayloadSuspicious(payload) {
                        findings.append(Finding(
                            severity: .high, category: .developerTool,
                            title: "Suspicious git alias \"\(key)\"",
                            detail: "Alias runs shell: \(String(payload.prefix(120)))",
                            path: path,
                            remediation: "Remove: git config --global --unset alias.\(key)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - SSH Client Config

    /// `ProxyCommand` and `LocalCommand` directives can be abused to log credentials or run
    /// arbitrary code on every `ssh` invocation. Tailscale, Cloudflare Access, AWS SSM all
    /// legitimately use ProxyCommand, so we only flag when the command path looks attacker-staged.
    private func scanSSHClientConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let configFiles = [
            "\(home)/.ssh/config",
            "/etc/ssh/ssh_config",
        ]
        let fm = FileManager.default

        var checkPaths: [String] = configFiles
        // SSH supports Include directives — check the common drop-in dir too.
        if let dropIns = try? fm.contentsOfDirectory(atPath: "\(home)/.ssh/config.d") {
            for entry in dropIns where !entry.hasPrefix(".") {
                checkPaths.append("\(home)/.ssh/config.d/\(entry)")
            }
        }

        for path in checkPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            var permitLocalCommand = false
            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                let lower = trimmed.lowercased()

                if lower.hasPrefix("permitlocalcommand") && lower.contains("yes") {
                    permitLocalCommand = true
                }

                if lower.hasPrefix("proxycommand ") || lower.hasPrefix("proxycommand\t") {
                    let value = String(trimmed.dropFirst("ProxyCommand".count)).trimmingCharacters(in: .whitespaces)
                    let firstToken = value.split(separator: " ").first.map(String.init) ?? value
                    if isUntrustedPath(firstToken) {
                        findings.append(Finding(
                            severity: .high, category: .developerTool,
                            title: "SSH ProxyCommand points to suspicious binary",
                            detail: "ProxyCommand runs: \(String(value.prefix(140)))",
                            path: path,
                            remediation: "Remove or correct this line in \(path)"
                        ))
                    }
                }

                if lower.hasPrefix("localcommand ") || lower.hasPrefix("localcommand\t") {
                    let value = String(trimmed.dropFirst("LocalCommand".count)).trimmingCharacters(in: .whitespaces)
                    // LocalCommand only fires when PermitLocalCommand=yes. Either way it's
                    // worth surfacing — attackers often set both together.
                    findings.append(Finding(
                        severity: permitLocalCommand ? .high : .medium,
                        category: .developerTool,
                        title: "SSH LocalCommand directive present",
                        detail: "Runs on every ssh invocation: \(String(value.prefix(140)))" +
                            (permitLocalCommand ? " (PermitLocalCommand=yes)" : ""),
                        path: path,
                        remediation: "Remove the LocalCommand line from \(path) unless intentional"
                    ))
                }

                // ControlMaster + non-default ControlPath in /tmp is a recognized credential-reuse
                // pattern: it lets a co-resident process hijack your SSH session.
                if lower.hasPrefix("controlpath ") {
                    let value = String(trimmed.dropFirst("ControlPath".count)).trimmingCharacters(in: .whitespaces)
                    if value.hasPrefix("/tmp/") || value.hasPrefix("/var/tmp/") {
                        findings.append(Finding(
                            severity: .medium, category: .developerTool,
                            title: "SSH ControlPath in world-writable temp directory",
                            detail: "ControlPath: \(value) — other users can hijack the multiplexed session",
                            path: path,
                            remediation: "Move ControlPath under ~/.ssh/cm/ or similar"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - Shell Aliases / Functions

    /// Aliases on security-critical commands let an attacker silently wrap every invocation
    /// of `curl`, `git`, `ssh`, or `sudo`. We only flag if the override points to a
    /// non-system, non-Homebrew location (so user-set `alias ls=eza` etc. are unaffected).
    private func scanShellAliases(home: String, findings: inout [Finding], errors: inout [String]) {
        let configs = [
            "\(home)/.zshrc", "\(home)/.zprofile", "\(home)/.zshenv", "\(home)/.zlogin",
            "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile",
            "\(home)/.config/fish/config.fish",
        ]

        // Commands an attacker would want to wrap to log credentials / exfiltrate data.
        let sensitiveCommands: Set<String> = [
            "curl", "wget", "ssh", "scp", "sftp", "rsync",
            "sudo", "su", "doas",
            "git", "gh", "hub",
            "brew", "npm", "yarn", "pnpm", "pip", "pip3",
            "python", "python3", "node",
            "security",  // keychain access
            "diskutil",  // disk operations
        ]

        for configPath in configs {
            guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else { continue }
            let fileName = URL(fileURLWithPath: configPath).lastPathComponent
            let lines = content.components(separatedBy: "\n")

            for (idx, rawLine) in lines.enumerated() {
                let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

                // alias name=value
                if let alias = parseAlias(trimmed),
                   sensitiveCommands.contains(alias.name),
                   isAliasTargetSuspicious(alias.value) {
                    findings.append(Finding(
                        severity: .high, category: .developerTool,
                        title: "Shell alias hijacks security-sensitive command: \(alias.name)",
                        detail: "\(fileName):\(idx + 1) — \(alias.name)=\(String(alias.value.prefix(100)))",
                        path: configPath,
                        remediation: "Remove this alias from \(configPath)"
                    ))
                    continue
                }

                // function name() { ... } — bash/zsh
                if let funcName = parseFunctionName(trimmed),
                   sensitiveCommands.contains(funcName) {
                    findings.append(Finding(
                        severity: .high, category: .developerTool,
                        title: "Shell function shadows security-sensitive command: \(funcName)",
                        detail: "\(fileName):\(idx + 1) — function definition: \(String(trimmed.prefix(120)))",
                        path: configPath,
                        remediation: "Remove this function from \(configPath)"
                    ))
                }
            }
        }
    }

    private func parseAlias(_ line: String) -> (name: String, value: String)? {
        // Match: alias name=value  or  alias name="value"  or  alias name='value'
        guard line.hasPrefix("alias ") else { return nil }
        let rest = line.dropFirst("alias ".count).trimmingCharacters(in: .whitespaces)
        guard let eq = rest.firstIndex(of: "=") else { return nil }
        let name = String(rest[..<eq]).trimmingCharacters(in: .whitespaces)
        var value = String(rest[rest.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
        // Strip surrounding quotes
        if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
           (value.hasPrefix("'") && value.hasSuffix("'")) {
            value = String(value.dropFirst().dropLast())
        }
        return (name, value)
    }

    private func parseFunctionName(_ line: String) -> String? {
        // bash/zsh: `funcname()` or `function funcname` or `funcname () {`
        if line.hasPrefix("function ") {
            let rest = line.dropFirst("function ".count).trimmingCharacters(in: .whitespaces)
            return rest.split(separator: " ").first.flatMap { name in
                name.split(separator: "(").first.map(String.init)
            }
        }
        if let parenIdx = line.firstIndex(of: "("),
           line[line.index(after: parenIdx)..<line.endIndex].hasPrefix(")") {
            let name = String(line[..<parenIdx]).trimmingCharacters(in: .whitespaces)
            // Names are simple identifiers
            if !name.isEmpty && name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }) {
                return name
            }
        }
        return nil
    }

    private func isAliasTargetSuspicious(_ target: String) -> Bool {
        // Suspicious if it expands to a binary in a non-standard place or runs a
        // shell payload. Pure flag-style aliases like `curl -sS` are fine.
        let trimmed = target.trimmingCharacters(in: .whitespaces)
        let firstToken = trimmed.split(separator: " ").first.map(String.init) ?? trimmed

        // Plain flag-only re-spelling: `curl -sSL` -> first token starts with `-` — benign.
        if firstToken.hasPrefix("-") { return false }

        // Path-based check delegates to the shared isUntrustedPath logic so it agrees
        // with the trusted-dotted-toolchain allowlist used elsewhere in the scanner.
        if firstToken.contains("/") && isUntrustedPath(firstToken) { return true }

        // Embeds a curl|sh pattern
        let lower = trimmed.lowercased()
        if lower.contains("curl ") && (lower.contains("| sh") || lower.contains("|sh") ||
                                       lower.contains("| bash") || lower.contains("|bash")) {
            return true
        }
        if lower.contains("eval ") || lower.contains("base64 -d") || lower.contains("base64 --decode") {
            return true
        }
        return false
    }

    // MARK: - Package Manager Configs

    private func scanPackageManagerConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        // npm — script-shell hijack, malicious registry, plaintext auth tokens
        scanNpmrc(home: home, findings: &findings, errors: &errors)
        // pip — malicious index-url is a known supply-chain vector
        scanPipConf(home: home, findings: &findings, errors: &errors)
        // cargo — git-fetch-with-cli + malicious registry
        scanCargoConfig(home: home, findings: &findings, errors: &errors)
    }

    private func scanNpmrc(home: String, findings: inout [Finding], errors: inout [String]) {
        let paths = ["\(home)/.npmrc", "/usr/local/etc/npmrc", "/opt/homebrew/etc/npmrc"]
        for path in paths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { continue }

                // script-shell points to attacker-controlled shell
                if trimmed.lowercased().hasPrefix("script-shell") {
                    if let eq = trimmed.firstIndex(of: "=") {
                        let value = String(trimmed[trimmed.index(after: eq)...])
                            .trimmingCharacters(in: .whitespaces)
                            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                        if isUntrustedPath(value) {
                            findings.append(Finding(
                                severity: .high, category: .developerTool,
                                title: "npm script-shell points to untrusted binary",
                                detail: "All npm lifecycle scripts execute via \(value)",
                                path: path,
                                remediation: "Remove this line from \(path)"
                            ))
                        }
                    }
                }

                // Non-default registry — supply chain risk
                if trimmed.lowercased().hasPrefix("registry") || trimmed.contains(":registry=") {
                    if let eq = trimmed.firstIndex(of: "=") {
                        let value = String(trimmed[trimmed.index(after: eq)...])
                            .trimmingCharacters(in: .whitespaces)
                        let lower = value.lowercased()
                        let isOfficial = lower.contains("registry.npmjs.org") ||
                                         lower.contains("registry.yarnpkg.com") ||
                                         lower.contains("npm.pkg.github.com")
                        if !isOfficial && !value.isEmpty {
                            findings.append(Finding(
                                severity: lower.hasPrefix("http://") ? .high : .medium,
                                category: .developerTool,
                                title: "npm registry overridden",
                                detail: "Configured registry: \(value)" +
                                    (lower.hasPrefix("http://") ? " — served over plain HTTP" : ""),
                                path: path,
                                remediation: "Verify this is your organization's registry, or restore: npm config delete registry"
                            ))
                        }
                    }
                }

                // auth token in plain text — usually fine but worth flagging if world-readable
                if trimmed.contains("_authToken=") || trimmed.contains("_password=") {
                    // Only flag if file permissions are loose (others can read)
                    if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                       let perms = attrs[.posixPermissions] as? NSNumber,
                       perms.uint16Value & 0o044 != 0 {
                        findings.append(Finding(
                            severity: .medium, category: .developerTool,
                            title: "npm auth token in world-readable .npmrc",
                            detail: "File permissions allow others on this system to read your registry tokens",
                            path: path,
                            remediation: "Tighten permissions: chmod 600 \(path)"
                        ))
                        break  // one finding per file
                    }
                }
            }
        }
    }

    private func scanPipConf(home: String, findings: inout [Finding], errors: inout [String]) {
        let paths = [
            "\(home)/.pip/pip.conf",
            "\(home)/Library/Application Support/pip/pip.conf",
            "\(home)/.config/pip/pip.conf",
        ]
        for path in paths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for line in content.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                let lower = trimmed.lowercased()
                if lower.hasPrefix("index-url") || lower.hasPrefix("extra-index-url") {
                    guard let eq = trimmed.firstIndex(of: "=") else { continue }
                    let value = String(trimmed[trimmed.index(after: eq)...])
                        .trimmingCharacters(in: .whitespaces)
                    let valueLower = value.lowercased()
                    let isOfficial = valueLower.contains("pypi.org") || valueLower.contains("pythonhosted.org")
                    if !isOfficial && !value.isEmpty {
                        findings.append(Finding(
                            severity: valueLower.hasPrefix("http://") ? .high : .medium,
                            category: .developerTool,
                            title: "pip index-url overridden",
                            detail: "Configured index: \(value)" +
                                (valueLower.hasPrefix("http://") ? " — plain HTTP, vulnerable to injection" : ""),
                            path: path,
                            remediation: "Verify this is your organization's mirror, or remove the line from \(path)"
                        ))
                    }
                }
            }
        }
    }

    private func scanCargoConfig(home: String, findings: inout [Finding], errors: inout [String]) {
        let paths = ["\(home)/.cargo/config.toml", "\(home)/.cargo/config"]
        for path in paths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            // crude TOML scan — Cargo config supports `[source.crates-io] replace-with = "..."` for mirror overrides
            if content.contains("replace-with") {
                // Find the registry URL it points to
                let lines = content.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) }
                let urlLine = lines.first { line in
                    let lower = line.lowercased()
                    return (lower.hasPrefix("registry") || lower.hasPrefix("url") || lower.hasPrefix("git"))
                        && line.contains("=")
                }
                if let url = urlLine, url.lowercased().contains("http") {
                    let isOfficial = url.lowercased().contains("crates.io") ||
                                     url.lowercased().contains("github.com/rust-lang/crates.io-index")
                    if !isOfficial {
                        findings.append(Finding(
                            severity: .medium, category: .developerTool,
                            title: "Cargo registry replaced",
                            detail: "Default crates.io is replaced via \(url) — all `cargo install` traffic goes elsewhere",
                            path: path,
                            remediation: "Verify this mirror is intentional, or revert to crates.io in \(path)"
                        ))
                    }
                }
            }
        }
    }

    // MARK: - VS Code / Cursor settings

    /// Specifically: `terminal.integrated.profiles.osx` lets a workspace silently replace
    /// the default shell when the integrated terminal opens. Combined with workspace
    /// trust autotrust, this has been used as a "open the folder and you're owned" vector.
    private func scanEditorSettings(home: String, findings: inout [Finding], errors: inout [String]) {
        let settings = [
            ("VS Code", "\(home)/Library/Application Support/Code/User/settings.json"),
            ("Cursor", "\(home)/Library/Application Support/Cursor/User/settings.json"),
            ("VSCodium", "\(home)/Library/Application Support/VSCodium/User/settings.json"),
            ("Windsurf", "\(home)/Library/Application Support/Windsurf/User/settings.json"),
        ]

        for (editor, path) in settings {
            guard let data = FileManager.default.contents(atPath: path) else { continue }
            // settings.json allows comments; strip a basic // <to-eol> set before parsing.
            let cleaned = stripJSONComments(String(data: data, encoding: .utf8) ?? "")
            guard let jsonData = cleaned.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: jsonData,
                                                               options: [.fragmentsAllowed, .mutableContainers])
                                as? [String: Any] else { continue }

            // Look for terminal profile overrides that point to a suspicious binary
            if let profiles = json["terminal.integrated.profiles.osx"] as? [String: Any] {
                for (profileName, raw) in profiles {
                    guard let profile = raw as? [String: Any],
                          let pathValue = profile["path"] as? String else { continue }
                    if isUntrustedPath(pathValue) {
                        findings.append(Finding(
                            severity: .high, category: .developerTool,
                            title: "\(editor) terminal profile points to suspicious binary",
                            detail: "Profile \"\(profileName)\" launches \(pathValue) — every integrated-terminal session would run this",
                            path: path,
                            remediation: "Edit \(path) and remove the \"\(profileName)\" entry under terminal.integrated.profiles.osx"
                        ))
                    }
                }
            }

            // Default profile name pointing at one of those custom profiles is the trigger.
            if let defaultProfile = json["terminal.integrated.defaultProfile.osx"] as? String,
               let profiles = json["terminal.integrated.profiles.osx"] as? [String: Any],
               let chosen = profiles[defaultProfile] as? [String: Any],
               let pathValue = chosen["path"] as? String,
               isUntrustedPath(pathValue) {
                findings.append(Finding(
                    severity: .high, category: .developerTool,
                    title: "\(editor) default terminal points to suspicious binary",
                    detail: "Default profile \"\(defaultProfile)\" -> \(pathValue)",
                    path: path,
                    remediation: "Reset terminal.integrated.defaultProfile.osx to \"zsh\" or \"bash\""
                ))
            }

            // Auto-trusting all workspaces removes the prompt that gates tasks/debuggers.
            if let trust = json["security.workspace.trust.enabled"] as? Bool, trust == false {
                findings.append(Finding(
                    severity: .medium, category: .developerTool,
                    title: "\(editor) workspace trust is disabled",
                    detail: "Opening any folder will run tasks/debug configs/extensions without confirmation",
                    path: path,
                    remediation: "Re-enable: set \"security.workspace.trust.enabled\": true in \(path)"
                ))
            }
        }
    }

    private func stripJSONComments(_ s: String) -> String {
        // Best-effort: strip `// to end of line` outside string literals. Doesn't try to
        // be a full JSONC parser — we just want enough to pass JSONSerialization for
        // common settings.json files.
        var out = ""
        out.reserveCapacity(s.count)
        var inString = false
        var prev: Character = " "
        var iter = s.makeIterator()
        var pending: Character?
        while let c = pending ?? iter.next() {
            pending = nil
            if inString {
                out.append(c)
                if c == "\"" && prev != "\\" { inString = false }
                prev = c
                continue
            }
            if c == "\"" { inString = true; out.append(c); prev = c; continue }
            if c == "/" {
                if let n = iter.next() {
                    if n == "/" {
                        // skip to end of line
                        while let cc = iter.next(), cc != "\n" {}
                        out.append("\n")
                        prev = "\n"
                        continue
                    } else {
                        out.append(c)
                        pending = n
                        prev = c
                        continue
                    }
                } else {
                    out.append(c)
                    break
                }
            }
            out.append(c)
            prev = c
        }
        return out
    }

    // MARK: - Shared helpers

    /// Treats /tmp, /var/tmp, and unfamiliar hidden directories as untrusted. We
    /// deliberately allow well-known dotted toolchain dirs (`.cargo`, `.nvm`, `.pyenv`,
    /// `.deno`, `.bun`, `.rbenv`, `.local`, `.config`) — they're where every modern dev
    /// stack installs binaries — so we don't drown the user in false positives.
    private static let trustedHiddenDirs: Set<String> = [
        ".cargo", ".rustup", ".nvm", ".npm", ".npm-global", ".pyenv", ".pnpm",
        ".rbenv", ".gem", ".deno", ".bun", ".volta", ".asdf", ".sdkman",
        ".local", ".config", ".cache", ".pixi", ".uv",
        ".vscode", ".cursor", ".windsurf", ".codeium",
        ".docker", ".lima", ".colima", ".orbstack",
        ".oh-my-zsh", ".zsh", ".fzf",
    ]

    private func isUntrustedPath(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
        if trimmed.isEmpty { return false }

        // Bare command name (no path separator) — likely on PATH, not inherently suspicious.
        if !trimmed.contains("/") { return false }

        let suspiciousPrefixes = ["/tmp/", "/private/tmp/", "/var/tmp/"]
        if suspiciousPrefixes.contains(where: { trimmed.hasPrefix($0) }) { return true }

        // Hidden directory anywhere in the path that ISN'T a recognized toolchain dir.
        let comps = trimmed.split(separator: "/").map(String.init)
        for comp in comps where comp.hasPrefix(".") && comp != "." && comp != ".." {
            if !DeveloperToolScanner.trustedHiddenDirs.contains(comp) { return true }
        }

        return false
    }

    private func isShellPayloadSuspicious(_ payload: String) -> Bool {
        let lower = payload.lowercased()
        if lower.contains("curl ") && (lower.contains("| sh") || lower.contains("|sh") ||
                                       lower.contains("| bash") || lower.contains("|bash")) { return true }
        if lower.contains("wget ") && (lower.contains("| sh") || lower.contains("|sh")) { return true }
        if lower.contains("eval ") { return true }
        if lower.contains("base64 -d") || lower.contains("base64 --decode") { return true }
        // `/tmp/` execution from a git alias is always worth flagging — there's no benign
        // reason to invoke `/tmp/...` from `git commit`.
        if lower.contains("/tmp/") || lower.contains("/private/tmp/") || lower.contains("/var/tmp/") {
            return true
        }
        return false
    }
}
