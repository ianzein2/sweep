import Foundation

/// Audits configured MCP (Model Context Protocol) servers across Claude Desktop, Cursor,
/// and Windsurf. MCP gives AI clients permission to spawn arbitrary stdio child processes
/// and forward their I/O to the model. A malicious entry — typically curl|sh style
/// commands, NPX of a malicious package, or a remote-loaded script — gives an attacker
/// full local-shell capability the moment the AI client is opened.
///
/// Configs reviewed:
///   Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
///   Cursor:        ~/.cursor/mcp.json  and  ~/Library/Application Support/Cursor/User/mcp.json
///   Windsurf:      ~/.codeium/windsurf/mcp_config.json
///   VS Code/Continue: ~/.continue/config.json (if "mcpServers" present)
public final class MCPServerScanner: Scanner {
    public let name = "MCP Server Scan"
    public init() {}

    private struct ConfigSource {
        let client: String
        let path: String
    }

    /// Commands that should never appear inside an MCP server definition.
    /// curl/wget piped into a shell is the canonical "remote-loaded code" pattern.
    private let bannedCommands: [(token: String, description: String)] = [
        ("curl ",  "downloads and runs remote code at MCP startup"),
        ("wget ",  "downloads and runs remote code at MCP startup"),
        ("base64", "uses base64 — often hides obfuscated payloads"),
        ("eval ",  "evaluates a shell expression — can launch anything"),
        ("nc ",    "spawns netcat — common reverse-shell helper"),
        ("ncat",   "spawns ncat — common reverse-shell helper"),
        ("bash -c", "runs an arbitrary shell command on every MCP startup"),
        ("sh -c",   "runs an arbitrary shell command on every MCP startup"),
        ("zsh -c",  "runs an arbitrary shell command on every MCP startup"),
        ("python -c", "runs inline Python on every MCP startup"),
        ("osascript -e", "runs inline AppleScript on every MCP startup"),
    ]

    /// Environment-variable names that, if forwarded to a remote MCP server, leak
    /// authentication material. Flag any MCP env block that exposes them by name.
    private let sensitiveEnvNames: Set<String> = [
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
        "GITHUB_TOKEN", "GITHUB_PAT", "GH_TOKEN",
        "SLACK_TOKEN", "DISCORD_TOKEN",
        "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
        "DATABASE_URL", "REDIS_URL",
        "NPM_TOKEN", "PYPI_TOKEN",
        "OP_SERVICE_ACCOUNT_TOKEN",  // 1Password CLI
    ]

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []

        let home = ShellRunner.realUserHome
        let appSupport = "\(home)/Library/Application Support"
        let configs: [ConfigSource] = [
            ConfigSource(client: "Claude Desktop",
                         path: "\(appSupport)/Claude/claude_desktop_config.json"),
            ConfigSource(client: "Cursor",
                         path: "\(home)/.cursor/mcp.json"),
            ConfigSource(client: "Cursor",
                         path: "\(appSupport)/Cursor/User/mcp.json"),
            ConfigSource(client: "Windsurf",
                         path: "\(home)/.codeium/windsurf/mcp_config.json"),
            ConfigSource(client: "Continue (VS Code)",
                         path: "\(home)/.continue/config.json"),
        ]

        for config in configs {
            progress?.update("checking \(config.client)")
            inspect(config: config, findings: &findings, errors: &errors)
        }

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    private func inspect(config: ConfigSource, findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: config.path),
              let data = fm.contents(atPath: config.path) else { return }

        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            errors.append("\(config.client): could not parse \(config.path) as JSON")
            return
        }

        // Both Claude Desktop and Cursor use a top-level "mcpServers" map keyed by server name.
        // Continue uses the same key. If absent, there's nothing for us to look at.
        guard let servers = root["mcpServers"] as? [String: Any] else { return }

        for (serverName, raw) in servers {
            guard let entry = raw as? [String: Any] else { continue }

            let command = (entry["command"] as? String) ?? ""
            let args = (entry["args"] as? [Any])?.compactMap { $0 as? String } ?? []
            let env = entry["env"] as? [String: Any] ?? [:]
            let url = entry["url"] as? String
            let combined = ([command] + args).joined(separator: " ")
            let combinedLower = combined.lowercased()

            // 1. SSE / streamable URLs that point off the host machine. MCP "url" entries
            //    are valid (remote MCP servers), but a public-internet URL forwards every
            //    conversation to a third party.
            if let url = url, !url.isEmpty {
                let lowerUrl = url.lowercased()
                let isLocal = lowerUrl.hasPrefix("http://127.0.0.1") ||
                              lowerUrl.hasPrefix("http://localhost") ||
                              lowerUrl.hasPrefix("https://127.0.0.1") ||
                              lowerUrl.hasPrefix("https://localhost") ||
                              lowerUrl.hasPrefix("http://[::1]")
                if !isLocal {
                    let plainHttp = lowerUrl.hasPrefix("http://")
                    findings.append(Finding(
                        severity: plainHttp ? .high : .medium,
                        category: .networkActivity,
                        title: "\(config.client) MCP server points off-host: \(serverName)",
                        detail: "URL: \(url) — every prompt and tool call is forwarded to this server" +
                            (plainHttp ? "; the URL is plain HTTP so traffic is also unencrypted" : ""),
                        path: config.path,
                        remediation: "Verify you trust the operator. If not, remove this server from \(config.path)"
                    ))
                }
            }

            // 2. Banned commands inside the command/args — curl|sh, eval, base64 etc.
            for banned in bannedCommands {
                if combinedLower.contains(banned.token) {
                    findings.append(Finding(
                        severity: .high, category: .suspiciousProcess,
                        title: "\(config.client) MCP server runs risky shell at startup",
                        detail: "Server \"\(serverName)\" — \(banned.description). Command: \(String(combined.prefix(200)))",
                        path: config.path,
                        remediation: "Remove or pin this server in \(config.path) — MCP servers can do anything your shell can"
                    ))
                    break  // one finding per server is enough
                }
            }

            // 3. NPX/uvx-launched servers fetched at startup with `-y` (auto-install). These
            //    are the supply-chain equivalent of `curl|sh`: a single typo-squat publication
            //    runs arbitrary code on every AI-client startup.
            let isAutoInstallNpx = command == "npx" &&
                args.contains(where: { $0 == "-y" || $0 == "--yes" })
            let isAutoInstallUvx = command == "uvx"  // uvx always installs on demand
            if isAutoInstallNpx || isAutoInstallUvx {
                let pkg = args.first(where: { !$0.hasPrefix("-") }) ?? "<unknown>"
                findings.append(Finding(
                    severity: .medium, category: .suspiciousProcess,
                    title: "\(config.client) MCP server auto-installs from registry: \(serverName)",
                    detail: "Server \"\(serverName)\" runs `\(command) … \(pkg)` on every startup — the latest version of \(pkg) executes with your privileges",
                    path: config.path,
                    remediation: "Pin to a known version (e.g. `\(command) \(pkg)@1.2.3`) or remove if you don't recognize the package"
                ))
            }

            // 4. Sensitive environment variables forwarded into the MCP child — flag every
            //    name we recognize. These tokens travel anywhere the MCP server forwards them.
            var leakedNames: [String] = []
            for (envName, _) in env {
                if sensitiveEnvNames.contains(envName) || envName.uppercased().contains("TOKEN") ||
                   envName.uppercased().contains("SECRET") || envName.uppercased().contains("API_KEY") {
                    leakedNames.append(envName)
                }
            }
            if !leakedNames.isEmpty && (url != nil || command == "npx" || command == "uvx") {
                findings.append(Finding(
                    severity: .medium, category: .permission,
                    title: "\(config.client) MCP server gets secret env vars: \(serverName)",
                    detail: "Server \"\(serverName)\" is given: \(leakedNames.sorted().joined(separator: ", "))",
                    path: config.path,
                    remediation: "Confirm the server is trusted to handle these secrets — anything it reads can be exfiltrated"
                ))
            }
        }
    }
}
