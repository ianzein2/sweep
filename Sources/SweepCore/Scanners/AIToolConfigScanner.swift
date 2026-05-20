import Foundation
import Security

/// Audits AI agent / MCP server configuration files.
///
/// MCP (Model Context Protocol) servers run as long-lived child processes of the AI client
/// (Claude Desktop, Cursor, Continue, Cline, …). The client config tells the runtime
/// which command to launch, with which arguments, and with which environment variables.
/// A malicious MCP server entry is effectively a LaunchAgent that the user installed by
/// pasting JSON they found on the internet, but it doesn't show up in any of Sweep's
/// existing persistence checks because the AI client (not launchd) starts it.
///
/// Things we flag:
/// - `npx -y <pkg>` / `uvx <pkg>` invocations of unpinned packages (silent supply-chain
///   upgrade — the package can be backdoored after the user installs it once)
/// - `command` paths pointing at unsigned binaries, /tmp, hidden directories
/// - Wrapper commands that pipe `curl | sh` (one-shot installer baked into the config)
/// - Environment variables that look like exfil tokens (api keys, sessions) being
///   handed to an MCP server the user can't audit
public final class AIToolConfigScanner: Scanner {
    public let name = "AI Tool / MCP Config Scan"
    public init() {}

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        progress?.update("checking Claude Desktop MCP servers")
        scanClaudeDesktop(findings: &findings, errors: &errors)

        progress?.update("checking Cursor MCP servers")
        scanCursor(findings: &findings, errors: &errors)

        progress?.update("checking Continue / Cline / Codex")
        scanOtherEditors(findings: &findings, errors: &errors)

        progress?.update("checking Claude Code project hooks")
        scanClaudeCodeHooks(findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Claude Desktop

    private func scanClaudeDesktop(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        let path = "\(home)/Library/Application Support/Claude/claude_desktop_config.json"
        guard let data = FileManager.default.contents(atPath: path),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        if let servers = root["mcpServers"] as? [String: Any] {
            for (name, value) in servers {
                guard let entry = value as? [String: Any] else { continue }
                inspectMCPServer(host: "Claude Desktop", configPath: path, name: name,
                                 entry: entry, findings: &findings)
            }
        }
    }

    // MARK: - Cursor

    private func scanCursor(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Cursor's MCP config lives in two places — repo-scoped under .cursor/ and user-scoped
        // under ~/.cursor/mcp.json. We only audit the user-scoped one here.
        let paths = [
            "\(home)/.cursor/mcp.json",
            "\(home)/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/servers.json",
        ]
        for path in paths {
            guard let data = FileManager.default.contents(atPath: path),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Cursor uses either `mcpServers` (matching Claude Desktop) or a top-level `servers` key.
            let servers = (root["mcpServers"] as? [String: Any]) ?? (root["servers"] as? [String: Any]) ?? [:]
            for (name, value) in servers {
                guard let entry = value as? [String: Any] else { continue }
                inspectMCPServer(host: "Cursor", configPath: path, name: name,
                                 entry: entry, findings: &findings)
            }
        }
    }

    // MARK: - Continue, Cline, Codex CLI

    private func scanOtherEditors(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Each of these client tools has its own MCP server config. The schema is mostly aligned
        // with the original Claude Desktop one, so we use the same inspector for each.
        let configs: [(host: String, path: String)] = [
            ("Continue", "\(home)/.continue/config.json"),
            ("Continue", "\(home)/.continue/mcpServers.json"),
            ("Cline", "\(home)/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
            ("Codex CLI", "\(home)/.codex/config.json"),
            ("Codex CLI", "\(home)/.codex/mcp.json"),
        ]

        for (host, path) in configs {
            guard let data = FileManager.default.contents(atPath: path),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Walk the JSON for any nested `mcpServers` / `servers` object — config schemas vary.
            for key in ["mcpServers", "servers", "tools"] {
                if let servers = root[key] as? [String: Any] {
                    for (name, value) in servers {
                        guard let entry = value as? [String: Any] else { continue }
                        inspectMCPServer(host: host, configPath: path, name: name,
                                         entry: entry, findings: &findings)
                    }
                }
            }
        }
    }

    // MARK: - Claude Code project-level hooks and settings

    private func scanClaudeCodeHooks(findings: inout [Finding], errors: inout [String]) {
        let home = ShellRunner.realUserHome
        // Claude Code reads project-level settings.json that can define `hooks` — shell commands
        // that fire on tool-use events. A malicious settings.json checked into a repo will run
        // those commands on every Claude Code session in that repo, without further prompting.
        // We only inspect the user-global file here; per-repo audit is the user's responsibility.
        let paths = [
            "\(home)/.claude/settings.json",
            "\(home)/.config/claude/settings.json",
        ]

        for path in paths {
            guard let data = FileManager.default.contents(atPath: path),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            // Look for any `hooks` object — keys are event names, values describe the shell commands.
            guard let hooks = root["hooks"] as? [String: Any] else { continue }

            // Walk every hook event. Each typically holds an array of matchers and commands.
            // Re-serialise the JSON to a string so we can match against it with one substring
            // search — handles both array-rooted and string-valued hooks without separate code paths.
            for (event, value) in hooks {
                let serialized: String
                if JSONSerialization.isValidJSONObject(value),
                   let data = try? JSONSerialization.data(withJSONObject: value, options: []),
                   let str = String(data: data, encoding: .utf8) {
                    serialized = str
                } else {
                    serialized = String(describing: value)
                }
                let lower = serialized.lowercased()

                let suspicious = lower.contains("curl") || lower.contains("wget") ||
                                 lower.contains("|sh") || lower.contains("| sh") ||
                                 lower.contains("/tmp/") || lower.contains("base64 -d") ||
                                 lower.contains("base64 --decode") || lower.contains("/dev/tcp/")

                if suspicious {
                    findings.append(Finding(
                        severity: .high, category: .aiAgent,
                        title: "Claude Code \(event) hook runs a suspicious command",
                        detail: "Hook for event '\(event)' in \(path) contains: \(String(serialized.prefix(120)))",
                        path: path,
                        remediation: "Review \(path) — hooks run automatically on tool-use events"
                    ))
                }
            }
        }
    }

    // MARK: - Shared MCP server entry inspector

    /// `inspectMCPServer` is the single chokepoint for every MCP entry across every host. New
    /// clients can be added above without duplicating the heuristics.
    private func inspectMCPServer(host: String, configPath: String, name: String,
                                  entry: [String: Any], findings: inout [Finding]) {
        let command = entry["command"] as? String ?? ""
        let args = (entry["args"] as? [String]) ?? []
        let env = (entry["env"] as? [String: Any]) ?? [:]
        let combined = ([command] + args).joined(separator: " ")
        let lower = combined.lowercased()

        // npx -y / uvx with an unpinned (no @version) package and no `--package=` is a silent
        // supply-chain channel: the resolved package can change at any time without the user
        // re-reading the config. Locking the version (e.g. `npx my-pkg@1.2.3`) closes that.
        let isEnvNpx = (command == "/usr/bin/env" || command.hasSuffix("/env")) && args.first == "npx"
        let isDirectNpx = command == "npx" || command.hasSuffix("/npx")
        if isDirectNpx || isEnvNpx {
            // First non-flag argument is the package spec. When invoked via `env npx`, args[0]
            // is `npx` itself — strip it before searching for the package.
            let pkgArgs = isEnvNpx ? Array(args.dropFirst()) : args
            // A pinned spec is one of:
            //   pkg@1.2.3            (has an @ that isn't position 0)
            //   @scope/pkg@1.2.3     (scoped, has an @ after the slash)
            // Anything else — `pkg`, `@scope/pkg`, `pkg@latest` — we treat as unpinned.
            if let pkg = pkgArgs.first(where: { !$0.hasPrefix("-") }) {
                let isPinned: Bool = {
                    // Find any `@` that comes after a character that isn't the start of the string.
                    guard let firstAt = pkg.firstIndex(of: "@") else { return false }
                    // pkg@1.2.3 — `@` is not at the start.
                    if firstAt != pkg.startIndex { return !pkg[pkg.index(after: firstAt)...].isEmpty }
                    // @scope/pkg[@version] — look past the slash for a second `@`.
                    guard let slash = pkg.firstIndex(of: "/") else { return false }
                    return pkg[pkg.index(after: slash)...].contains(where: { $0 == "@" })
                }()
                // `pkg@latest` is treated as unpinned — latest moves.
                let isLatest = pkg.hasSuffix("@latest")
                if !isPinned || isLatest {
                    findings.append(Finding(
                        severity: .medium, category: .aiAgent,
                        title: "\(host) launches an unpinned npx MCP server",
                        detail: "Server '\(name)' runs `npx \(args.joined(separator: " "))` — the package version is unpinned",
                        path: configPath,
                        remediation: "Pin a specific version: change `\(pkg)` to `\(pkg)@<version>` in \(configPath)"
                    ))
                }
            }
        }
        if command == "uvx" || command.hasSuffix("/uvx") {
            // `uvx` resolves the latest version of the package on each launch by default.
            // We don't have a great pin syntax to compare against, so we flag any uvx usage.
            findings.append(Finding(
                severity: .low, category: .aiAgent,
                title: "\(host) launches an MCP server via uvx",
                detail: "Server '\(name)' runs `uvx \(args.joined(separator: " "))` — uvx resolves the package at every launch",
                path: configPath,
                remediation: "Pin a specific version (`uvx <pkg>==<version>`) or install once and call the binary directly"
            ))
        }

        // `sh -c '... curl ... | sh'` style stagers are an immediate red flag — they're not how
        // legitimate MCP server configs are distributed.
        let stager = lower.contains("curl") && (lower.contains("|sh") || lower.contains("| sh") || lower.contains("|bash") || lower.contains("| bash"))
        if stager || lower.contains("base64 -d") || lower.contains("base64 --decode") {
            findings.append(Finding(
                severity: .high, category: .aiAgent,
                title: "\(host) MCP server runs a remote installer",
                detail: "Server '\(name)' command: \(String(combined.prefix(140)))",
                path: configPath,
                remediation: "Remove this entry from \(configPath) — the AI agent will run this command on every launch"
            ))
        }

        // Absolute-path commands pointing at /tmp, hidden directories, or unsigned binaries are
        // all suspicious. We only check signature when the command is an absolute path we can stat.
        if command.hasPrefix("/") {
            let isHidden = command.split(separator: "/").contains(where: { $0.hasPrefix(".") })
            let inTemp = command.hasPrefix("/tmp/") || command.hasPrefix("/private/tmp/") ||
                         command.hasPrefix("/var/tmp/")

            if isHidden || inTemp {
                findings.append(Finding(
                    severity: .high, category: .aiAgent,
                    title: "\(host) MCP server points at \(inTemp ? "/tmp" : "a hidden path")",
                    detail: "Server '\(name)' command: \(command)",
                    path: configPath,
                    remediation: "Remove this entry — MCP server binaries should not live in tmp or hidden directories"
                ))
            } else if FileManager.default.fileExists(atPath: command) {
                if !isCodeSigned(command) {
                    findings.append(Finding(
                        severity: .medium, category: .aiAgent,
                        title: "\(host) MCP server is an unsigned binary",
                        detail: "Server '\(name)' command: \(command)",
                        path: configPath,
                        remediation: "Verify the binary was installed intentionally. Remove the entry if not."
                    ))
                }
            }
        }

        // Environment variables: long, randomly-looking string values are likely tokens. We don't
        // need to identify what the token is for — the point is that the user knows their config
        // is handing a secret to a third-party process the AI agent forks.
        for (envName, value) in env {
            guard let str = value as? String else { continue }
            let isLikelyToken = str.count >= 32 &&
                                str.rangeOfCharacter(from: CharacterSet(charactersIn: ".-_/+")) != nil &&
                                str.rangeOfCharacter(from: .alphanumerics) != nil
            // Some tokens are perfectly fine (e.g., a personal API key the user pasted on purpose).
            // We only flag when the name looks credential-like AND the value is non-empty.
            let credName = ["token", "key", "secret", "pass", "credential", "auth"]
                .contains(where: { envName.lowercased().contains($0) })
            if credName && isLikelyToken {
                findings.append(Finding(
                    severity: .low, category: .aiAgent,
                    title: "\(host) MCP server receives a credential in its environment",
                    detail: "Server '\(name)' env var '\(envName)' is set to a credential-shaped value (\(str.count) chars)",
                    path: configPath,
                    remediation: "Confirm this MCP server is trusted with that credential — anything it forks inherits the env"
                ))
            }
        }
    }

    // MARK: - Signature check

    private func isCodeSigned(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        return SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: 0), nil, nil) == errSecSuccess
    }
}

