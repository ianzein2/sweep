import Foundation

/// Auditor for AI coding-tool configuration files that can silently execute commands.
///
/// Throughout 2024-2025, AI coding tools (Cursor, Claude Code, Windsurf, VS Code Copilot)
/// added powerful auto-execution surfaces — MCP server configs, session hooks, and "run on
/// folder open" tasks. These are all driven by JSON files committed *inside* a repository,
/// which means cloning an attacker-controlled repo can run arbitrary commands the moment
/// the user opens it in their editor.
///
/// This scanner walks the user's project roots and editor config dirs, parses those JSON files,
/// and surfaces anything that auto-runs commands. The aim is awareness — not every match is
/// malicious, but every match is something the user should consciously have approved.
public final class AIAgentScanner: Scanner {
    public let name = "AI Agent Config Scan"
    public init() {}

    /// Project directories we walk looking for editor configs. Only a few common roots.
    /// We intentionally don't recurse the entire home directory — that's too slow and
    /// would hit every node_modules. Most users keep code in one of these.
    private let projectRootCandidates: [String] = [
        "Projects", "Code", "code", "Developer", "Documents", "src", "workspace",
        "repos", "github", "Github", "GitHub", "Sites", "dev",
    ]

    /// Per-project subpaths that, if present, are interesting.
    private let configRelativePaths: [String] = [
        ".vscode/tasks.json",
        ".vscode/settings.json",
        ".cursor/mcp.json",
        ".cursor/settings.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".windsurf/mcp.json",
        ".windsurf/settings.json",
        ".continue/config.json",
        ".aider.conf.yml",
    ]

    /// Cap on number of project directories we'll descend into per root, so a Projects/ folder
    /// full of hundreds of repos doesn't make the scan crawl.
    private let maxProjectsPerRoot = 80

    public func scan(progress: ScanProgress? = nil) -> ScanResult {
        let start = Date()
        var findings: [Finding] = []
        var errors: [String] = []
        let home = ShellRunner.realUserHome

        progress?.update("scanning global agent configs")
        scanGlobalAgentConfigs(home: home, findings: &findings, errors: &errors)

        progress?.update("scanning project agent configs")
        scanProjectAgentConfigs(home: home, findings: &findings, errors: &errors)

        return ScanResult(
            scannerName: name,
            findings: findings,
            errors: errors,
            duration: Date().timeIntervalSince(start)
        )
    }

    // MARK: - Global (user-wide) agent configs

    /// Configs that apply to every project the user opens, e.g. ~/.cursor/mcp.json. A malicious
    /// global config persists across all repos and survives `rm -rf` of any single workspace —
    /// it's effectively a launch agent that the editor invokes on every session.
    private func scanGlobalAgentConfigs(home: String, findings: inout [Finding], errors: inout [String]) {
        let globalPaths: [(path: String, label: String)] = [
            ("\(home)/.cursor/mcp.json", "Cursor global MCP config"),
            ("\(home)/.claude/settings.json", "Claude Code global settings"),
            ("\(home)/.claude.json", "Claude Code global config"),
            ("\(home)/.windsurf/mcp.json", "Windsurf global MCP config"),
            ("\(home)/.continue/config.json", "Continue.dev global config"),
            ("\(home)/Library/Application Support/Code/User/settings.json", "VS Code user settings"),
            ("\(home)/Library/Application Support/Cursor/User/settings.json", "Cursor user settings"),
        ]

        for entry in globalPaths {
            guard FileManager.default.fileExists(atPath: entry.path) else { continue }
            inspectConfig(at: entry.path, label: entry.label, isGlobal: true,
                          findings: &findings, errors: &errors)
        }
    }

    // MARK: - Per-project agent configs

    private func scanProjectAgentConfigs(home: String, findings: inout [Finding], errors: inout [String]) {
        let fm = FileManager.default

        for rootName in projectRootCandidates {
            let rootPath = "\(home)/\(rootName)"
            guard fm.fileExists(atPath: rootPath),
                  let projects = try? fm.contentsOfDirectory(atPath: rootPath) else { continue }

            for project in projects.prefix(maxProjectsPerRoot) {
                if project.hasPrefix(".") { continue }
                let projectPath = "\(rootPath)/\(project)"
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: projectPath, isDirectory: &isDir), isDir.boolValue else { continue }

                for relative in configRelativePaths {
                    let configPath = "\(projectPath)/\(relative)"
                    guard fm.fileExists(atPath: configPath) else { continue }
                    inspectConfig(at: configPath, label: "\(project)/\(relative)", isGlobal: false,
                                  findings: &findings, errors: &errors)
                }
            }
        }
    }

    // MARK: - Per-config inspection

    /// Parses the file and dispatches to a config-specific analyzer based on the filename.
    /// We deliberately keep this format-aware (rather than a single big regex) because each
    /// config has a different shape and false positives are expensive — the user will see
    /// these findings on every scan once a project is opened.
    private func inspectConfig(at path: String, label: String, isGlobal: Bool,
                                findings: inout [Finding], errors: inout [String]) {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            // YAML (e.g. .aider.conf.yml) — fall back to a text scan
            if path.hasSuffix(".yml") || path.hasSuffix(".yaml") {
                scanTextForExecPatterns(at: path, label: label, isGlobal: isGlobal, findings: &findings)
            }
            return
        }

        let name = URL(fileURLWithPath: path).lastPathComponent
        switch name {
        case "tasks.json":
            analyzeVSCodeTasks(json: json, path: path, label: label, findings: &findings)
        case "mcp.json":
            analyzeMCPConfig(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
        case "settings.json", "settings.local.json":
            // Both Claude Code (hooks) and VS Code/Cursor (tasks, mcpServers) drop config here
            analyzeMCPConfig(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
            analyzeClaudeHooks(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
        case ".claude.json":
            analyzeClaudeHooks(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
        case "config.json":
            analyzeMCPConfig(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
        default:
            analyzeMCPConfig(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
            analyzeClaudeHooks(json: json, path: path, label: label, isGlobal: isGlobal, findings: &findings)
        }
    }

    // MARK: - VS Code / Cursor tasks.json

    /// `runOptions.runOn == "folderOpen"` makes a task auto-execute as soon as the workspace is
    /// opened. There is no consent prompt. A malicious repo that ships such a task is a 1-click
    /// RCE: clone, open in editor, payload runs. This is a real-world technique reported in 2024+.
    private func analyzeVSCodeTasks(json: [String: Any], path: String, label: String,
                                     findings: inout [Finding]) {
        guard let tasks = json["tasks"] as? [[String: Any]] else { return }
        for task in tasks {
            let runOn = (task["runOptions"] as? [String: Any])?["runOn"] as? String
            guard runOn == "folderOpen" else { continue }

            let cmd = task["command"] as? String ?? "<unknown>"
            let args = (task["args"] as? [Any]).map { $0.map { "\($0)" }.joined(separator: " ") } ?? ""
            let summary = String("\(cmd) \(args)".trimmingCharacters(in: .whitespaces).prefix(140))

            findings.append(Finding(
                severity: .high,
                category: .persistence,
                title: "VS Code task auto-runs on workspace open",
                detail: "\(label): runs \"\(summary)\" the moment the project is opened — cloning a poisoned repo silently executes this",
                path: path,
                remediation: "Open \(path) and remove the \"runOn\": \"folderOpen\" entry, or delete this task if you didn't add it"
            ))
        }
    }

    // MARK: - MCP server configs (Cursor, Claude Code, Windsurf, Continue.dev)

    /// MCP (Model Context Protocol) server entries specify a command + args + env that the
    /// editor spawns automatically as soon as the project is opened. From the editor's
    /// perspective this is a feature; from a security perspective it is identical to a
    /// LaunchAgent that fires every time the user opens a particular folder.
    private func analyzeMCPConfig(json: [String: Any], path: String, label: String,
                                   isGlobal: Bool, findings: inout [Finding]) {
        // MCP servers live under a few different keys depending on tool/version.
        let candidateKeys = ["mcpServers", "mcp", "servers"]
        var servers: [String: Any] = [:]
        for key in candidateKeys {
            if let dict = json[key] as? [String: Any] {
                for (k, v) in dict { servers[k] = v }
            }
        }
        if servers.isEmpty { return }

        let suspiciousBins: Set<String> = [
            "sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh",
            "curl", "wget", "nc", "ncat", "netcat", "osascript",
            "/usr/bin/curl", "/usr/bin/osascript",
        ]
        let suspiciousArgFragments = [
            "curl ", "wget ", "| sh", "| bash", "base64", "eval ",
            "/tmp/", "/private/tmp/", "/var/tmp/",
            ".onion", "ngrok.io", "trycloudflare.com",
        ]

        for (serverName, raw) in servers {
            guard let server = raw as? [String: Any] else { continue }
            let command = (server["command"] as? String) ?? ""
            let argsRaw = server["args"] as? [Any] ?? []
            let args = argsRaw.map { "\($0)" }
            let envRaw = server["env"] as? [String: Any] ?? [:]

            let argsJoined = args.joined(separator: " ")
            let lowerArgs = argsJoined.lowercased()
            let lowerCmd = command.lowercased()

            // 1) Direct shell-out via the MCP server command itself.
            if suspiciousBins.contains(lowerCmd) ||
               suspiciousBins.contains(URL(fileURLWithPath: command).lastPathComponent.lowercased()) {
                findings.append(Finding(
                    severity: .high,
                    category: .persistence,
                    title: "MCP server runs a shell on \(isGlobal ? "every editor session" : "workspace open")",
                    detail: "\(label) → server \"\(serverName)\" launches \"\(command) \(String(argsJoined.prefix(120)))\"",
                    path: path,
                    remediation: "Remove the \"\(serverName)\" entry from \(path) unless you explicitly added it"
                ))
                continue
            }

            // 2) Suspicious patterns in the args (fetch-and-run, temp paths, tunnel domains).
            if let hit = suspiciousArgFragments.first(where: { lowerArgs.contains($0.lowercased()) }) {
                findings.append(Finding(
                    severity: .high,
                    category: .persistence,
                    title: "MCP server arguments contain suspicious pattern",
                    detail: "\(label) → \"\(serverName)\" includes \"\(hit)\" in its args: \(String(argsJoined.prefix(140)))",
                    path: path,
                    remediation: "Open \(path) and verify the \"\(serverName)\" entry — fetch-and-run from an MCP config is a known attack pattern"
                ))
                continue
            }

            // 3) Env carrying credentials to non-obvious endpoints — flag as MEDIUM for review.
            for (envKey, envVal) in envRaw {
                guard let s = envVal as? String else { continue }
                if s.lowercased().contains("http://") &&
                   (envKey.uppercased().contains("URL") || envKey.uppercased().contains("ENDPOINT")) {
                    findings.append(Finding(
                        severity: .medium,
                        category: .networkActivity,
                        title: "MCP server endpoint uses plain HTTP",
                        detail: "\(label) → \"\(serverName)\" env \(envKey)=\(s) — MCP traffic and any forwarded secrets travel unencrypted",
                        path: path,
                        remediation: "Use https:// for the MCP server endpoint, or remove the entry"
                    ))
                }
            }

            // 4) For globally-installed MCPs we still want to surface their existence (LOW),
            //    because they autoload in every editor session — the user should know what's there.
            if isGlobal {
                findings.append(Finding(
                    severity: .low,
                    category: .persistence,
                    title: "Globally-registered MCP server: \(serverName)",
                    detail: "\(label) auto-launches \"\(command) \(String(argsJoined.prefix(80)))\" in every editor session",
                    path: path,
                    remediation: "Review the entry — if you don't recognize \(serverName), remove it from \(path)"
                ))
            }
        }
    }

    // MARK: - Claude Code hooks

    /// Claude Code's `settings.json` `hooks` block can run shell commands on SessionStart,
    /// PreToolUse, Notification, etc. Used responsibly this is great; injected via a repo's
    /// `.claude/settings.json`, it's an autorun primitive equivalent to `.bashrc`. We flag any
    /// hook command and let the user verify.
    private func analyzeClaudeHooks(json: [String: Any], path: String, label: String,
                                     isGlobal: Bool, findings: inout [Finding]) {
        guard let hooks = json["hooks"] as? [String: Any] else { return }

        for (event, raw) in hooks {
            // The hooks structure is: { "EventName": [ { "hooks": [ { "type": "command", "command": "..." } ] } ] }
            guard let matchers = raw as? [[String: Any]] else { continue }
            for matcher in matchers {
                guard let hookList = matcher["hooks"] as? [[String: Any]] else { continue }
                for hook in hookList {
                    let cmd = (hook["command"] as? String) ?? ""
                    if cmd.isEmpty { continue }
                    let lower = cmd.lowercased()

                    // Always-suspicious patterns inside any hook
                    let badFragments = ["curl ", "wget ", "| sh", "| bash", "base64 -d",
                                        "base64 --decode", "/tmp/", "/private/tmp/",
                                        ".onion", "ngrok.io"]
                    let severity: Severity =
                        badFragments.contains(where: { lower.contains($0) }) ? .high :
                        (isGlobal ? .low : .medium)

                    let summary = String(cmd.prefix(140))
                    findings.append(Finding(
                        severity: severity,
                        category: .persistence,
                        title: "Claude Code \(event) hook installed",
                        detail: "\(label): runs \"\(summary)\" on the \(event) event",
                        path: path,
                        remediation: severity == .high
                            ? "Remove this hook from \(path) — fetch-and-run inside a hook is a known supply-chain attack vector"
                            : "Verify you added this hook intentionally. Hooks run every time the matching event fires."
                    ))
                }
            }
        }
    }

    // MARK: - YAML / text fallback

    private func scanTextForExecPatterns(at path: String, label: String, isGlobal: Bool,
                                          findings: inout [Finding]) {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let lower = content.lowercased()
        let triggers = ["curl ", "wget ", "| sh", "| bash", "eval ",
                        "base64 -d", "base64 --decode"]
        for trigger in triggers {
            if lower.contains(trigger) {
                findings.append(Finding(
                    severity: isGlobal ? .medium : .high,
                    category: .persistence,
                    title: "AI tool config contains fetch-and-run pattern",
                    detail: "\(label) includes \"\(trigger)\" — anything in this config can run on editor session start",
                    path: path,
                    remediation: "Inspect \(path) and remove suspicious commands"
                ))
                return
            }
        }
    }
}
